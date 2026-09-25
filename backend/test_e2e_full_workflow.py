"""
End-to-End Full Workflow Test for JOCKY Forensics (Prompt 4)

Verifies the complete JOCKY forensics pipeline from DSL script parsing to
live collector acquisition, cryptographic evidence vault sealing, SHA-256
verification, graph correlation, timeline reconstruction, heuristic rule evaluation,
and multi-format report generation.
"""

import os
import sys
import json
import tempfile
from pathlib import Path
import pytest

# Ensure repository root is in sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.language import parse_jocky_script, Parser, Lexer, compile_jocky, CaseNode, TargetNode
from backend.app.collectors.system import collect_system_info
from backend.app.collectors.processes import collect_process_info
from backend.app.collectors.network import collect_network_info
from backend.app.collectors.files import collect_files_info
from backend.app.evidence.vault import EvidenceVault
from backend.app.evidence.hashing import compute_sha256, verify_sha256
from backend.app.analysis.correlator import correlate_evidence
from backend.app.analysis.timeline import build_forensic_timeline
from backend.app.analysis.rules import evaluate_forensic_rules
from backend.app.reporting.report_engine import ForensicReportBuilder
from backend.app.engine import execute_jocky_ir


def test_e2e_full_forensics_workflow():
    """
    Executes the complete End-to-End forensic workflow:
    1. Parse a JOCKY DSL script with CASE LAB-2026-FULL-E2E
    2. Execute all 4 collectors: SYSTEM, PROCESSES, NETWORK, FILES
    3. Persist and cryptographically seal artifacts in EvidenceVault
    4. Verify SHA-256 digests and audit vault integrity (INTACT)
    5. Run cross-artifact correlation and timeline reconstruction
    6. Evaluate deterministic forensic rules
    7. Generate HTML and JSON court-admissible forensic reports
    """
    # ── Step 1: Create a safe test directory for FILES collection ────────
    with tempfile.TemporaryDirectory(prefix="jocky_safe_e2e_") as safe_dir:
        safe_path = Path(safe_dir)
        test_file = safe_path / "forensic_target.bin"
        test_file.write_bytes(b"JOCKY-E2E-FORENSIC-TARGET-PAYLOAD-2026" * 32)

        safe_dir_posix = safe_path.as_posix()

        # ── Step 2: Parse JOCKY script ───────────────────────────────────────
        script_text = (
            'CASE "LAB-2026-FULL-E2E"\n'
            'TARGET "TEST-ENDPOINT"\n'
            'COLLECT SYSTEM\n'
            'COLLECT PROCESSES\n'
            'COLLECT NETWORK\n'
            f'COLLECT FILES "{safe_dir_posix}"\n'
            'ANALYZE\n'
            'VERIFY INTEGRITY\n'
            'REPORT FORMAT HTML\n'
        )

        parse_res = parse_jocky_script(script_text)
        assert parse_res["success"] is True
        assert parse_res["execution_plan"]["case_id"] == "LAB-2026-FULL-E2E"
        assert parse_res["execution_plan"]["target"] == "TEST-ENDPOINT"

        program_node = Parser(Lexer(script_text).tokenize()).parse()
        assert len(program_node.statements) == 9
        assert isinstance(program_node.statements[0], CaseNode)
        assert program_node.statements[0].case_id == "LAB-2026-FULL-E2E"
        assert isinstance(program_node.statements[1], TargetNode)
        assert program_node.statements[1].target_name == "TEST-ENDPOINT"



        # Also verify compiler produces valid JOCKY IR
        compile_res = compile_jocky(script_text)
        assert compile_res["success"] is True, f"Compilation failed: {compile_res.get('error')}"
        ir = compile_res["ir"]
        assert ir["case_id"] == "LAB-2026-FULL-E2E"
        assert ir["target"] == "TEST-ENDPOINT"
        assert len(ir["operations"]) >= 7

        # ── Step 3: Execute all 4 Collectors ─────────────────────────────────
        # 1. SYSTEM
        system_data = collect_system_info()
        assert isinstance(system_data, dict), "SYSTEM collector must return dict"
        assert "os" in system_data, "SYSTEM collector must include 'os'"
        assert "hostname" in system_data, "SYSTEM collector must include 'hostname'"
        assert "architecture" in system_data, "SYSTEM collector must include 'architecture'"
        assert "cpu" in system_data, "SYSTEM collector must include 'cpu'"

        # 2. PROCESSES
        proc_data = collect_process_info()
        assert isinstance(proc_data, dict), "PROCESSES collector must return dict"
        assert proc_data.get("count", 0) > 0, "PROCESSES collector must enumerate active processes"
        assert len(proc_data.get("processes", [])) > 0, "PROCESSES collector must return non-empty processes list"
        sample_proc = proc_data["processes"][0]
        assert "pid" in sample_proc, "Process entry must have 'pid'"
        assert "name" in sample_proc, "Process entry must have 'name'"

        # 3. NETWORK
        net_data = collect_network_info()
        assert isinstance(net_data, dict), "NETWORK collector must return dict"
        assert "connections" in net_data, "NETWORK collector must return 'connections'"
        assert isinstance(net_data.get("connections"), list), "'connections' must be a list"

        # 4. FILES
        files_data = collect_files_info(target_path=str(safe_path))
        assert isinstance(files_data, dict), "FILES collector must return dict"
        assert files_data.get("count", 0) >= 1, "FILES collector must find safe test directory file"
        assert len(files_data.get("files", [])) >= 1, "FILES collector must return file records"
        sample_file = files_data["files"][0]
        assert "path" in sample_file, "File entry must have 'path'"
        assert "sha256" in sample_file, "File entry must have 'sha256'"
        assert sample_file["sha256"] not in (None, ""), "File entry must have computed SHA-256 digest"

        collected_evidence = {
            "system": system_data,
            "processes": proc_data,
            "network": net_data,
            "files": files_data,
        }

        # ── Step 4: Persist Evidence in Vault ─────────────────────────────────
        with tempfile.TemporaryDirectory(prefix="jocky_e2e_vault_") as vault_dir:
            vault = EvidenceVault(base_dir=vault_dir)

            sealed_records = {}
            for source_name, data_payload in collected_evidence.items():
                sealed = vault.seal_artifact(
                    case_id="LAB-2026-FULL-E2E",
                    source=source_name,
                    data=data_payload,
                    who="JOCKY E2E Automation",
                    why=f"Automated full workflow acquisition for {source_name}",
                    execution_id="EXEC-E2E-FULL-001",
                    target_host="TEST-ENDPOINT",
                )
                sealed_records[source_name] = sealed
                assert sealed["evidence_id"].startswith("EVID-LAB-2026-FULL-E2E-")
                assert len(sealed["sha256"]) == 64, "SHA-256 must be 64-char hex string"

                # Verify file actually persisted physically on disk in the vault
                case_dir = vault.cases_dir / "LAB-2026-FULL-E2E"
                artifact_file = case_dir / f"{sealed['evidence_id']}.json"
                assert artifact_file.exists(), f"Vault artifact file does not exist on disk: {artifact_file}"
                assert artifact_file.stat().st_size > 0, "Artifact file on disk must not be empty"

                # Verify artifact retrieval from disk
                retrieved = vault.get_artifact(sealed["evidence_id"])
                assert retrieved is not None, f"Artifact not retrieved: {sealed['evidence_id']}"
                assert retrieved["sha256"] == sealed["sha256"], "Retrieved artifact hash must match sealed record"
                assert retrieved["case_id"] == "LAB-2026-FULL-E2E"

            # ── Step 5: SHA-256 / Hash Verification & Vault Audit ────────────
            for source_name, sealed in sealed_records.items():
                v_res = vault.verify_artifact(
                    evidence_id=sealed["evidence_id"],
                    who="Forensic Integrity Verifier",
                    why="E2E cryptographic verification",
                )
                assert v_res["valid"] is True, f"SHA-256 verification failed for {source_name}"
                assert v_res["stored_hash"] == sealed["sha256"]
                assert v_res["recomputed_hash"] == sealed["sha256"]


            # Audit entire vault for case
            audit_result = vault.verify_vault_integrity(case_id="LAB-2026-FULL-E2E")
            assert audit_result["vault_status"] == "INTACT", f"Vault status expected INTACT, got {audit_result['vault_status']}"
            assert audit_result["total_artifacts"] == 4, f"Expected 4 artifacts, got {audit_result['total_artifacts']}"
            assert audit_result["valid_count"] == 4, f"Expected 4 valid artifacts, got {audit_result['valid_count']}"
            assert audit_result["tampered_count"] == 0, f"Expected 0 tampered, got {audit_result['tampered_count']}"
            assert len(audit_result["tampered_artifacts"]) == 0

            # ── Step 6: Correlation & Timeline ───────────────────────────────────
            correlation = correlate_evidence(collected_evidence)
            assert isinstance(correlation, dict), "Correlation must return dictionary"
            assert "summary" in correlation, "Correlation must have 'summary'"
            assert "entities" in correlation, "Correlation must have 'entities'"
            assert "relationships" in correlation, "Correlation must have 'relationships'"
            assert "correlated_chains" in correlation, "Correlation must have 'correlated_chains'"
            assert correlation["summary"]["process_count"] > 0
            assert correlation["summary"]["total_entities"] > 0

            timeline = build_forensic_timeline(collected_evidence)
            assert isinstance(timeline, list), "Timeline must return a list of events"
            assert len(timeline) > 0, "Timeline should reconstruct events from collected evidence"
            first_event = timeline[0]
            assert "timestamp" in first_event, "Timeline event must have timestamp"
            assert "event_type" in first_event, "Timeline event must have event_type"

            # ── Step 7: Forensic Rules Engine ────────────────────────────────────
            detections = evaluate_forensic_rules(collected_evidence)
            assert isinstance(detections, list), "Forensic rules must return list of detections"
            for det in detections:
                assert "rule_id" in det, "Detection must include rule_id"
                assert "severity" in det, "Detection must include severity"

            # ── Step 8: Multi-Format Report Generation ───────────────────────────
            builder = ForensicReportBuilder(
                case_id="LAB-2026-FULL-E2E",
                target="TEST-ENDPOINT",
                examiner="JOCKY Lead Forensic Examiner",
                execution_id="EXEC-E2E-FULL-001",
            )
            report_data = builder.build_report_data(
                collected_data=collected_evidence,
                correlation=correlation,
                timeline=timeline,
                detections=detections,
                vault_audit=audit_result,
            )
            assert report_data["case_id"] == "LAB-2026-FULL-E2E"
            assert report_data["target"] == "TEST-ENDPOINT"
            assert "attestation" in report_data, "Report data must include cryptographic attestation"
            assert report_data["attestation"]["vault_status"] == "INTACT"

            # HTML Report Generation
            html_report = builder.generate_html(report_data)
            assert isinstance(html_report, str), "HTML report must be a string"
            assert "<!DOCTYPE html>" in html_report, "HTML report must have DOCTYPE"
            assert "LAB-2026-FULL-E2E" in html_report, "HTML report must contain case ID"
            assert "TEST-ENDPOINT" in html_report, "HTML report must contain target"
            assert len(html_report) > 500, "HTML report must not be trivial"

            # JSON Report Generation
            json_report_str = builder.generate_json(report_data)
            assert isinstance(json_report_str, str), "JSON report must be a string"
            json_report_parsed = json.loads(json_report_str)
            assert json_report_parsed["case_id"] == "LAB-2026-FULL-E2E"
            assert json_report_parsed["target"] == "TEST-ENDPOINT"

            # Markdown Report Generation
            md_report = builder.generate_markdown(report_data)
            assert isinstance(md_report, str), "Markdown report must be a string"
            assert "LAB-2026-FULL-E2E" in md_report, "Markdown report must contain case ID"

        # ── Step 9: IR Engine Full Pipeline Execution ─────────────────────────
        ir_receipt = execute_jocky_ir(ir)
        assert ir_receipt["success"] is True, f"IR Execution failed: {ir_receipt.get('error')}"
        assert ir_receipt["case_id"] == "LAB-2026-FULL-E2E"
        assert ir_receipt["target"] == "TEST-ENDPOINT"
        assert "system" in ir_receipt["collected_data"]
        assert "processes" in ir_receipt["collected_data"]
        assert "network" in ir_receipt["collected_data"]
        assert "files" in ir_receipt["collected_data"]
        assert ir_receipt["integrity_status"]["verified"] is True
        assert ir_receipt["report"]["format"] == "HTML"
        assert len(ir_receipt["report"]["content"]) > 0



if __name__ == "__main__":
    print("[*] Running JOCKY Forensics End-to-End Full Workflow Test...")
    test_e2e_full_forensics_workflow()
    print("[+] ALL E2E STEPS PASSED SUCCESSFULLY!")
