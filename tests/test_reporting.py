"""
Tests for Phase 8: JOCKY Forensic Report Generation Engine.

Validates:
1. ForensicReportBuilder data assembly and executive summary calculations.
2. Structured JSON report export.
3. Court-admissible Markdown report generation.
4. Standalone, print-ready HTML generation with embedded styles and attestation certificate.
5. Cryptographic attestation certificate generation and manifest hash binding.
6. IRExecutor integration with REPORT FORMAT JSON / HTML / MD.
7. REST API endpoints POST /api/forensics/report and GET /api/forensics/report/download.
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.reporting.report_engine import ForensicReportBuilder
from backend.app.engine import execute_jocky_ir
from backend.app.language.compiler import compile_jocky
from backend.app.main import app

client = TestClient(app)


@pytest.fixture
def sample_case_data():
    return {
        "collected_data": {
            "system": {"hostname": "SEC-DESK-01", "os": "Windows 11", "os_version": "10.0.22631", "architecture": "AMD64", "boot_time": "2026-09-20T08:00:00Z"},
            "processes": {"count": 2, "processes": [{"pid": 404, "name": "cmd.exe", "cmdline": "cmd.exe /c whoami"}]},
            "network": {"count": 1, "connections": [{"pid": 404, "protocol": "TCP", "laddr": "192.168.1.50:49200", "raddr": "198.51.100.22:4444", "status": "ESTABLISHED"}]},
            "files": {"count": 1, "files": [{"path": "C:\\Windows\\Temp\\beacon.exe", "name": "beacon.exe", "size_bytes": 1024, "sha256": "f" * 64}]},
            "users": {"current_user": {"username": "admin", "is_admin": True}},
        },
        "correlation": {
            "chains": [
                {
                    "chain_type": "Process Tree",
                    "processes": [{"pid": 100, "name": "explorer.exe", "cmdline": "explorer.exe"}, {"pid": 404, "name": "cmd.exe", "cmdline": "cmd.exe /c whoami"}],
                }
            ]
        },
        "timeline": [
            {"event_type": "PROCESS_START", "timestamp": "2026-09-20T09:00:00Z", "summary": "Process cmd.exe started", "confidence": "HIGH"}
        ],
        "detections": [
            {
                "rule_id": "RULE-001",
                "rule_name": "Execution from Temporary Directory",
                "severity": "HIGH",
                "description": "Process binary launched from temporary folder",
                "evidence_refs": ["file:C:\\Windows\\Temp\\beacon.exe"],
            }
        ],
        "evidence_ids": {"system": "EVID-SYS-01", "processes": "EVID-PROC-01"},
        "sha256_hashes": {"system": "a" * 64, "processes": "b" * 64},
        "vault_audit": {"vault_status": "INTACT"},
    }


def test_build_report_data_assembly(sample_case_data):
    builder = ForensicReportBuilder(
        case_id="CASE-TST-001",
        target="ENDPOINT-01",
        examiner="Special Agent Dana",
    )
    rep_data = builder.build_report_data(
        collected_data=sample_case_data["collected_data"],
        correlation=sample_case_data["correlation"],
        timeline=sample_case_data["timeline"],
        detections=sample_case_data["detections"],
        evidence_ids=sample_case_data["evidence_ids"],
        sha256_hashes=sample_case_data["sha256_hashes"],
        vault_audit=sample_case_data["vault_audit"],
    )

    assert rep_data["case_id"] == "CASE-TST-001"
    assert rep_data["target"] == "ENDPOINT-01"
    assert rep_data["examiner"] == "Special Agent Dana"

    es = rep_data["executive_summary"]
    assert es["assessment"] == "COMPROMISE_DETECTED"
    assert es["severity_counts"]["high"] == 1
    assert es["vault_status"] == "INTACT"

    # Attestation
    att = rep_data["attestation"]
    assert att["certificate_id"].startswith("CERT-CASE-TST-001-")
    assert len(att["manifest_sha256"]) == 64
    assert att["vault_status"] == "INTACT"
    assert "strictly via authorized read-only forensic mechanisms" in att["statement"]


def test_generate_json_format(sample_case_data):
    builder = ForensicReportBuilder(case_id="CASE-JSON-01")
    rep_data = builder.build_report_data(**sample_case_data)
    json_str = builder.generate_json(rep_data)

    parsed = json.loads(json_str)
    assert parsed["case_id"] == "CASE-JSON-01"
    assert "attestation" in parsed
    assert "executive_summary" in parsed


def test_generate_markdown_format(sample_case_data):
    builder = ForensicReportBuilder(case_id="CASE-MD-01", examiner="Auditor Fox")
    rep_data = builder.build_report_data(**sample_case_data)
    md_str = builder.generate_markdown(rep_data)

    assert "# JOCKY Digital Forensic Investigation Report: CASE-MD-01" in md_str
    assert "## 1. Executive Summary" in md_str
    assert "RULE-001" in md_str
    assert "Execution from Temporary Directory" in md_str
    assert "## 6. Examiner Attestation & Cryptographic Certificate" in md_str
    assert "Auditor Fox" in md_str


def test_generate_html_format(sample_case_data):
    builder = ForensicReportBuilder(case_id="CASE-HTML-01")
    rep_data = builder.build_report_data(**sample_case_data)
    html_str = builder.generate_html(rep_data)

    assert "<!DOCTYPE html>" in html_str
    assert "<title>JOCKY Digital Forensic Investigation Report: CASE-HTML-01</title>" in html_str
    assert "Executive Summary" in html_str
    assert "RULE-001" in html_str
    assert "HIGH" in html_str
    assert "Cryptographic Evidence Attestation" in html_str
    assert rep_data["attestation"]["manifest_sha256"] in html_str


def test_ir_executor_report_format_integration():
    script = """CASE "CASE-REP-IR"
TARGET "PC-01"
COLLECT SYSTEM
VERIFY INTEGRITY
REPORT FORMAT HTML"""

    compile_res = compile_jocky(script)
    assert compile_res["success"] is True

    receipt = execute_jocky_ir(compile_res["ir"])
    assert receipt["success"] is True
    report = receipt["report"]
    assert report["format"] == "HTML"
    assert "<!DOCTYPE html>" in report["content"]
    assert "attestation" in report
    assert report["attestation"]["vault_status"] == "INTACT"


def test_ir_executor_report_format_md():
    script = """CASE "CASE-REP-MD"
TARGET "PC-02"
COLLECT SYSTEM
REPORT FORMAT MD"""

    compile_res = compile_jocky(script)
    assert compile_res["success"] is True

    receipt = execute_jocky_ir(compile_res["ir"])
    assert receipt["success"] is True
    report = receipt["report"]
    assert report["format"] == "MD"
    assert "# JOCKY Digital Forensic Investigation Report" in report["content"]


def test_api_report_generation_endpoint(sample_case_data):
    payload = {
        "case_id": "API-CASE-REP",
        "target": "SRV-TEST",
        "format": "HTML",
        "examiner": "Investigator Lee",
        "evidence": sample_case_data["collected_data"],
    }
    res = client.post("/api/forensics/report", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["format"] == "HTML"
    assert "<!DOCTYPE html>" in data["content"]
    assert data["attestation"]["examiner"] == "Investigator Lee"


def test_api_report_download_endpoint():
    res = client.get("/api/forensics/report/download?format=html&case_id=CASE-DL-01")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert 'filename="jocky_report_CASE-DL-01.html"' in res.headers["content-disposition"]
    assert "<!DOCTYPE html>" in res.text


def test_report_contains_all_required_forensic_elements(sample_case_data):
    """
    Prompt 5 Verification:
    Ensures all 9 required forensic elements exist and are consistent across
    Report Data, JSON, Markdown, and HTML:
    1. Case ID and target
    2. Investigation/execution timestamp
    3. Evidence/artifact IDs
    4. SHA-256 hashes
    5. Chain-of-custody information
    6. Collector/source information
    7. Correlation/timeline findings
    8. Integrity verification result
    9. Forensic rule results
    """
    builder = ForensicReportBuilder(
        case_id="CASE-POLISH-2026",
        target="ENDPOINT-POLISH",
        examiner="Lead Forensic Inspector Smith",
        execution_id="EXEC-POLISH-999",
    )
    rep_data = builder.build_report_data(**sample_case_data)

    # 1. Case ID & Target
    assert rep_data["case_id"] == "CASE-POLISH-2026"
    assert rep_data["target"] == "ENDPOINT-POLISH"

    # 2. Investigation/execution timestamp
    assert "investigation_timestamp" in rep_data
    assert "generated_at_utc" in rep_data
    assert "EXEC-POLISH-999" in rep_data["execution_id"]

    # 3. Evidence/artifact IDs
    manifest = rep_data["evidence_manifest"]
    assert len(manifest) >= 2
    eids = [m["evidence_id"] for m in manifest]
    assert "EVID-SYS-01" in eids
    assert "EVID-PROC-01" in eids

    # 4. SHA-256 hashes
    for m in manifest:
        assert len(m["sha256"]) == 64
    assert len(rep_data["attestation"]["manifest_sha256"]) == 64

    # 5. Chain-of-custody information
    custody = rep_data["chain_of_custody"]
    assert len(custody) >= 2
    actions = [c["action"] for c in custody]
    assert "ACQUIRED" in actions
    for c in custody:
        assert "who" in c
        assert "what" in c
        assert "why" in c
        assert "when" in c
        assert "sha256" in c

    # 6. Collector/source information
    collectors = rep_data["collector_info"]
    assert len(collectors) >= 2
    sources = [c["source"] for c in collectors]
    assert "system" in sources
    assert "processes" in sources
    for col in collectors:
        assert col["mode"] == "NON-INVASIVE READ-ONLY"
        assert col["items_captured"] >= 1
        assert "evidence_id" in col
        assert len(col["sha256"]) == 64

    # 7. Correlation/timeline findings
    assert len(rep_data["correlated_chains"]) >= 1
    assert len(rep_data["timeline_highlights"]) >= 1
    assert rep_data["timeline_highlights"][0]["event_type"] == "PROCESS_START"

    # 8. Integrity verification result
    iv = rep_data["integrity_verification"]
    assert iv["vault_status"] == "INTACT"
    assert iv["algorithm"] == "SHA-256"
    assert iv["tampered_count"] == 0

    # 9. Forensic rule results
    dets = rep_data["detections"]
    assert len(dets) >= 1
    assert dets[0]["rule_id"] == "RULE-001"
    assert dets[0]["severity"] == "HIGH"

    # Verify JSON representations
    json_out = builder.generate_json(rep_data)
    parsed_json = json.loads(json_out)
    assert parsed_json["case_id"] == "CASE-POLISH-2026"
    assert "chain_of_custody" in parsed_json
    assert "collector_info" in parsed_json
    assert "integrity_verification" in parsed_json
    assert "evidence_manifest" in parsed_json

    # Verify Markdown representations
    md_out = builder.generate_markdown(rep_data)
    assert "CASE-POLISH-2026" in md_out
    assert "ENDPOINT-POLISH" in md_out
    assert "## 7. Forensic Chain of Custody Ledger" in md_out
    assert "## 8. Collector Acquisition Scope & Sources" in md_out
    assert "## 9. Chronological Forensic Timeline" in md_out
    assert "RULE-001" in md_out
    assert "EVID-SYS-01" in md_out

    # Verify HTML representations
    html_out = builder.generate_html(rep_data)
    assert "<!DOCTYPE html>" in html_out
    assert "CASE-POLISH-2026" in html_out
    assert "ENDPOINT-POLISH" in html_out
    assert "Forensic Chain of Custody Ledger" in html_out
    assert "Collector Acquisition Scope &amp; Sources" in html_out
    assert "Chronological Forensic Timeline Highlights" in html_out
    assert "EVID-SYS-01" in html_out
    assert "RULE-001" in html_out
    assert "Lead Forensic Inspector Smith" in html_out


def test_save_report_to_disk_and_independent_reading(sample_case_data, tmp_path):
    """
    Verifies that generated reports (HTML, JSON, Markdown) can be saved to disk
    and opened/read independently by external systems.
    """
    builder = ForensicReportBuilder(
        case_id="CASE-SAVE-TEST",
        target="ENDPOINT-SAVE",
    )
    rep_data = builder.build_report_data(**sample_case_data)

    # Save HTML
    html_content = builder.generate_html(rep_data)
    html_file = builder.save_report(html_content, format_type="HTML", output_dir=tmp_path)
    assert html_file.is_file()
    read_html = html_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in read_html
    assert "CASE-SAVE-TEST" in read_html

    # Save JSON
    json_content = builder.generate_json(rep_data)
    json_file = builder.save_report(json_content, format_type="JSON", output_dir=tmp_path)
    assert json_file.is_file()
    read_json = json_file.read_text(encoding="utf-8")
    parsed = json.loads(read_json)
    assert parsed["case_id"] == "CASE-SAVE-TEST"
    assert parsed["target"] == "ENDPOINT-SAVE"

    # Save Markdown
    md_content = builder.generate_markdown(rep_data)
    md_file = builder.save_report(md_content, format_type="MD", output_dir=tmp_path)
    assert md_file.is_file()
    read_md = md_file.read_text(encoding="utf-8")
    assert "# JOCKY Digital Forensic Investigation Report: CASE-SAVE-TEST" in read_md
    assert "## 7. Forensic Chain of Custody Ledger" in read_md


def test_api_report_returns_saved_path(sample_case_data):
    """
    Verifies that POST /api/forensics/report saves the report to disk and returns saved_path.
    """
    payload = {
        "case_id": "API-SAVE-CHECK",
        "target": "SRV-SAVE",
        "format": "HTML",
        "examiner": "Detective Miller",
        "evidence": sample_case_data["collected_data"],
    }
    res = client.post("/api/forensics/report", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "saved_path" in data
    assert data["saved_path"] is not None

    # Verify physical file existence and readability
    p = Path(data["saved_path"])
    assert p.is_file()
    assert "API-SAVE-CHECK" in p.read_text(encoding="utf-8")

