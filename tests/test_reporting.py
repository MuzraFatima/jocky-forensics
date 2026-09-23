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
