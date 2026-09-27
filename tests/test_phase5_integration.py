"""
Phase 5: Advanced Technique Findings Integration Tests.

Validates the full pipeline:
    Evidence (Collected & Sealed)
    → Advanced Technique Finding
    → Forensic Correlation Graph
    → Unified Chronological Timeline
    → MITRE ATT&CK Matrix Mapping
    → Forensic Explanation & Evidence Vault Traceability

Verifies:
1. Evidence collection & cryptographic sealing in Evidence Vault.
2. Advanced Technique Findings detection and schema validation.
3. Correlation graph enrichment (technique entities, EXHIBITS_TECHNIQUE, BACKED_BY_EVIDENCE).
4. Timeline integration distinguishing OBSERVED_EVIDENCE from ANALYTICAL_INTERPRETATION.
5. MITRE ATT&CK kill-chain mapping and tactic sequence.
6. Evidence Vault artifact traceability and verification.
7. End-to-end JOCKY DSL IR compilation and execution.
"""

import pytest
from backend.app.evidence.store import EvidenceStore
from backend.app.analysis import (
    ForensicContext,
    build_forensic_timeline,
    build_mitre_analysis,
    correlate_evidence,
    analyze_evidence_techniques,
)
from backend.app.analysis.analyzers import AdvancedAnalysisPipeline
from backend.app.language import compile_jocky
from backend.app.engine import execute_jocky_ir, LocalCollectorProvider


@pytest.fixture
def sealed_vault_and_evidence(tmp_path):
    """
    Sets up a real Evidence Vault and seals synthetic multi-artifact evidence.
    """
    vault = EvidenceStore(base_dir=str(tmp_path / "vault"))
    case_id = "CASE-PHASE5-INT"
    device_id = "DEV-AGENT-P5"

    # Raw telemetry artifacts
    proc_data = {
        "count": 3,
        "processes": [
            {
                "pid": 2040,
                "ppid": 1020,
                "name": "winword.exe",
                "exe": r"C:\Program Files\Office\winword.exe",
                "create_time": "2026-09-27T14:00:00Z",
                "username": "CORP\\Victim",
            },
            {
                "pid": 3050,
                "ppid": 2040,
                "name": "powershell.exe",
                "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "cmdline": ["powershell.exe", "-nop", "-enc", "SQBFAFgA"],
                "create_time": "2026-09-27T14:00:05Z",
                "username": "CORP\\Victim",
            },
            {
                "pid": 4090,
                "ppid": 3050,
                "name": "dropper.exe",
                "exe": r"C:\Users\Victim\AppData\Local\Temp\dropper.exe",
                "create_time": "2026-09-27T14:00:10Z",
                "username": "CORP\\Victim",
            },
        ],
    }

    net_data = {
        "count": 1,
        "connections": [
            {
                "pid": 4090,
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "laddr": {"ip": "192.168.1.100", "port": 49910},
                "raddr": {"ip": "198.51.100.99", "port": 4444},
                "timestamp": "2026-09-27T14:00:15Z",
            }
        ],
    }

    files_data = {
        "files": [
            {
                "path": r"C:\Users\Victim\AppData\Local\Temp\dropper.exe",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size_bytes": 1048576,
                "modified_time": "2026-09-27T14:00:08Z",
            }
        ]
    }

    # 1. Seal artifacts in Evidence Vault with cryptographic SHA-256
    proc_ev = vault.save_evidence(
        case_id=case_id,
        source="processes",
        data=proc_data,
        who="ProcessCollector",
    )
    net_ev = vault.save_evidence(
        case_id=case_id,
        source="network",
        data=net_data,
        who="NetworkCollector",
    )
    files_ev = vault.save_evidence(
        case_id=case_id,
        source="files",
        data=files_data,
        who="FileCollector",
    )

    evidence_ids = {
        "processes": proc_ev["evidence_id"],
        "network": net_ev["evidence_id"],
        "files": files_ev["evidence_id"],
    }

    collected_evidence = {
        "case_id": case_id,
        "device_id": device_id,
        "execution_id": "EXEC-P5-TEST",
        "target": "WORKSTATION-P5",
        "evidence_ids": evidence_ids,
        "processes": proc_data,
        "network": net_data,
        "files": files_data,
        "timestamp_utc": "2026-09-27T14:00:20Z",
    }

    return vault, collected_evidence, evidence_ids


# ── Integration Test 1: Evidence Collection & Vault Sealing ──────────────────

def test_stage1_evidence_collection_and_sealing(sealed_vault_and_evidence):
    vault, evidence, evidence_ids = sealed_vault_and_evidence

    # Verify all artifacts are cryptographically registered
    assert len(evidence_ids) == 3
    for source, ev_id in evidence_ids.items():
        assert ev_id.startswith("EVID-")
        verification = vault.verify_evidence(ev_id, who="TestAuditor", why="Stage 1 Integrity Verification")
        assert verification["valid"] is True
        assert verification["stored_hash"] == verification["recomputed_hash"]


# ── Integration Test 2: Advanced Finding Extraction ──────────────────────────

def test_stage2_advanced_finding_synthesis(sealed_vault_and_evidence):
    vault, evidence, evidence_ids = sealed_vault_and_evidence
    pipeline = AdvancedAnalysisPipeline()
    findings = pipeline.analyze(evidence)

    assert len(findings) >= 3
    tech_ids = {f.technique_id for f in findings}

    # Verify expected techniques detected
    assert "TECH-PROC-SPAWN" in tech_ids  # winword.exe -> powershell.exe
    assert "TECH-TMP-EXEC" in tech_ids    # dropper.exe in Temp
    assert "TECH-NET-BACKDOOR" in tech_ids  # socket to port 4444

    # Verify all required top-level fields on every finding
    for f in findings:
        assert f.finding_id.startswith("FIND-")
        assert f.case_id == "CASE-PHASE5-INT"
        assert f.device_id == "DEV-AGENT-P5"
        assert len(f.technique) > 0
        assert len(f.evidence_ids) > 0
        assert len(f.timestamp) > 0
        assert len(f.observed_indicator) > 0
        assert len(f.explanation) > 0
        assert f.confidence in ("HIGH", "MEDIUM", "LOW")
        assert f.status == "DETECTED"


# ── Integration Test 3: Correlation Graph Integration ────────────────────────

def test_stage3_correlation_graph_enrichment(sealed_vault_and_evidence):
    vault, evidence, evidence_ids = sealed_vault_and_evidence
    pipeline = AdvancedAnalysisPipeline()
    findings = pipeline.analyze(evidence)

    correlation = correlate_evidence(evidence, findings=findings)

    # 1. Verify technique entities are present and distinguished
    assert "techniques" in correlation["entities"]
    tech_entities = correlation["entities"]["techniques"]
    assert len(tech_entities) == len(findings)

    for te in tech_entities:
        assert te["is_analytical"] is True
        assert te["entity_class"] == "ANALYTICAL_INTERPRETATION"
        assert te["type"] == "technique_finding"
        assert len(te["evidence_ids"]) > 0

    # 2. Verify EXHIBITS_TECHNIQUE and BACKED_BY_EVIDENCE relationships
    rel_types = {r["type"] for r in correlation["relationships"]}
    assert "EXHIBITS_TECHNIQUE" in rel_types
    assert "BACKED_BY_EVIDENCE" in rel_types

    # 3. Verify process chains link to techniques
    chains = correlation["correlated_chains"]
    dropper_chain = next((c for c in chains if c["pid"] == 4090), None)
    assert dropper_chain is not None
    assert dropper_chain["has_technique"] is True
    assert any(t["technique_id"] == "TECH-TMP-EXEC" for t in dropper_chain["techniques"])

    # 4. Summary metrics
    summary = correlation["summary"]
    assert summary["technique_count"] == len(findings)
    assert summary["total_entities"] >= len(findings) + 3


# ── Integration Test 4: Unified Chronological Timeline ────────────────────────

def test_stage4_timeline_integration_and_class_distinction(sealed_vault_and_evidence):
    vault, evidence, evidence_ids = sealed_vault_and_evidence
    pipeline = AdvancedAnalysisPipeline()
    findings = pipeline.analyze(evidence)

    timeline = build_forensic_timeline(evidence, findings=findings)

    assert len(timeline) >= 6

    # 1. Distinguish OBSERVED_EVIDENCE from ANALYTICAL_INTERPRETATION
    event_classes = {e["event_class"] for e in timeline}
    assert "OBSERVED_EVIDENCE" in event_classes
    assert "ANALYTICAL_INTERPRETATION" in event_classes

    observed_events = [e for e in timeline if e["event_class"] == "OBSERVED_EVIDENCE"]
    analytical_events = [e for e in timeline if e["event_class"] == "ANALYTICAL_INTERPRETATION"]

    assert len(observed_events) >= 3  # Processes, sockets, files
    assert len(analytical_events) == len(findings)

    for oe in observed_events:
        assert oe["is_analytical"] is False

    for ae in analytical_events:
        assert ae["is_analytical"] is True
        assert ae["event_type"] == "TECHNIQUE_DETECTED"
        assert len(ae["evidence_ids"]) > 0
        assert ae["evidence_id"].startswith("EVID-")

    # 2. Verify chronological order is maintained
    timestamps = [e.get("timestamp") for e in timeline if e.get("timestamp")]
    assert timestamps == sorted(timestamps)


# ── Integration Test 5: MITRE ATT&CK Matrix Mapping ──────────────────────────

def test_stage5_mitre_mapping_and_killchain_sequence(sealed_vault_and_evidence):
    vault, evidence, evidence_ids = sealed_vault_and_evidence
    pipeline = AdvancedAnalysisPipeline()
    findings = pipeline.analyze(evidence)

    mitre_data = build_mitre_analysis(findings)

    # 1. Summary
    assert mitre_data["summary"]["total_findings"] == len(findings)
    assert mitre_data["summary"]["total_techniques"] >= 3
    assert mitre_data["summary"]["total_tactics"] >= 2
    assert mitre_data["summary"]["mitre_mapped_count"] >= 2

    # 2. Tactic matrix includes Execution and Command and Control
    tactics = mitre_data["tactics"]
    assert "Execution" in tactics or "Defense Evasion" in tactics
    assert "Command and Control" in tactics

    # 3. Verify kill-chain sequence ordering
    matrix_tactics = [t["tactic"] for t in mitre_data["tactic_matrix"]]
    if "Execution" in matrix_tactics and "Command and Control" in matrix_tactics:
        assert matrix_tactics.index("Execution") < matrix_tactics.index("Command and Control")

    # 4. Explanations narrative
    assert len(mitre_data["explanations"]) >= 2
    assert any("ATT&CK" in exp for exp in mitre_data["explanations"])


# ── Integration Test 6: Evidence Vault Traceability ──────────────────────────

def test_stage6_evidence_traceability_back_to_vault(sealed_vault_and_evidence):
    vault, evidence, evidence_ids = sealed_vault_and_evidence
    pipeline = AdvancedAnalysisPipeline()
    findings = pipeline.analyze(evidence)
    mitre_data = build_mitre_analysis(findings)

    traceability = mitre_data["traceability"]

    # Every technique entry in the traceability matrix must resolve to sealed Evidence Vault IDs
    for key, trace_item in traceability.items():
        assert len(trace_item["evidence_ids"]) > 0
        for ev_id in trace_item["evidence_ids"]:
            # Verify the ID actually exists in our vault
            stored_artifact = vault.get_evidence(ev_id)
            assert stored_artifact is not None
            assert stored_artifact["case_id"] == "CASE-PHASE5-INT"
            assert stored_artifact["evidence_id"] == ev_id

            # Verify cryptographic integrity
            vr = vault.verify_evidence(ev_id, who="TraceabilityVerifier", why="Phase 5 Audit")
            assert vr["valid"] is True


# ── Integration Test 7: End-to-End JOCKY IR Executor Integration ─────────────

def test_stage7_e2e_jocky_ir_executor_integration(tmp_path):
    """
    Executes a complete JOCKY script through compiler and IR executor,
    validating that correlation, timeline, MITRE analysis, and technique findings
    are unified in the final result.
    """
    script = (
        'CASE "CASE-E2E-P5"\n'
        'TARGET "localhost"\n'
        'COLLECT SYSTEM\n'
        'COLLECT PROCESSES\n'
        'COLLECT NETWORK\n'
        'ANALYZE PROCESS_NETWORK\n'
        'VERIFY INTEGRITY\n'
        'REPORT FORMAT JSON\n'
    )
    comp_result = compile_jocky(script)
    assert comp_result["success"] is True
    ir = comp_result["ir"]

    vault = EvidenceStore(base_dir=str(tmp_path / "e2e_vault"))
    provider = LocalCollectorProvider()

    execution_result = execute_jocky_ir(
        ir=ir,
        evidence_store=vault,
        collector_provider=provider,
    )

    assert execution_result["success"] is True
    assert execution_result["case_id"] == "CASE-E2E-P5"

    analyze_step = execution_result.get("analysis")
    assert analyze_step is not None
    assert analyze_step.get("status") == "COMPLETED"

    # Verify correlation, timeline, mitre_analysis, and technique_findings are present
    assert "correlation" in analyze_step
    assert "timeline" in analyze_step
    assert "mitre_analysis" in analyze_step
    assert "technique_findings" in analyze_step

    # Verify correlation includes techniques
    corr = analyze_step["correlation"]
    assert "entities" in corr
    assert "techniques" in corr["entities"]

    # Verify timeline includes event_class distinction
    timeline = analyze_step["timeline"]
    assert isinstance(timeline, list)
    for event in timeline:
        assert event["event_class"] in ("OBSERVED_EVIDENCE", "ANALYTICAL_INTERPRETATION")
        assert isinstance(event["is_analytical"], bool)
