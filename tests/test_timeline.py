"""
Unit tests for JOCKY Forensic Timeline Engine & Heuristic Detection Rules (Phase 5).
"""

import pytest
from backend.app.analysis.rules import (
    ForensicRuleEngine,
    evaluate_forensic_rules,
)
from backend.app.analysis.timeline import (
    ForensicTimeline,
    build_forensic_timeline,
)


def test_timeline_normalization_and_ordering():
    """Verify event normalization across all evidence sources and chronological ordering."""
    evidence = {
        "timestamp_utc": "2026-09-23T10:00:00Z",
        "evidence_ids": {
            "system": "EVID-SYS-01",
            "processes": "EVID-PROC-01",
            "network": "EVID-NET-01",
            "files": "EVID-FILE-01",
            "users": "EVID-USER-01",
            "windows_metadata": "EVID-REG-01",
        },
        "system": {
            "hostname": "SECOPS-WORKSTATION",
            "boot_time": "2026-09-23T08:00:00Z",
            "os": "Windows",
            "os_version": "11",
            "architecture": "x64",
        },
        "processes": {
            "processes": [
                {
                    "pid": 1200,
                    "ppid": 800,
                    "name": "calc.exe",
                    "username": "Analyst",
                    "create_time": "2026-09-23T08:30:00Z",
                    "exe": r"C:\Windows\System32\calc.exe",
                },
                {
                    "pid": 1400,
                    "ppid": 1200,
                    "name": "worker.exe",
                    "username": "Analyst",
                    "create_time": "2026-09-23T09:15:00Z",
                    "exe": r"C:\Tools\worker.exe",
                },
            ]
        },
        "network": {
            "connections": [
                {
                    "pid": 1400,
                    "protocol": "TCP",
                    "laddr": {"ip": "192.168.1.100", "port": 50000},
                    "raddr": {"ip": "1.1.1.1", "port": 443},
                    "status": "ESTABLISHED",
                }
            ]
        },
        "files": {
            "files": [
                {
                    "path": r"C:\Tools\worker.exe",
                    "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                    "modified_time": "2026-09-23T08:15:00Z",
                }
            ]
        },
        "users": {
            "current_user": {
                "username": "Analyst",
                "is_admin": False,
                "login_time": "2026-09-23T08:05:00Z",
            }
        },
        "windows_metadata": {
            "autoruns": [
                {
                    "name": "SecurityMonitor",
                    "value": r"C:\Tools\monitor.exe",
                    "hive": "HKCU",
                }
            ]
        },
    }

    timeline = build_forensic_timeline(evidence)
    assert len(timeline) >= 6

    # Verify standard schema
    for evt in timeline:
        assert "timestamp" in evt
        assert "event_type" in evt
        assert "source" in evt
        assert "entity" in evt
        assert "description" in evt
        assert "evidence_id" in evt

    # Verify chronological ordering
    # Earliest is system boot at 08:00:00Z
    assert timeline[0]["event_type"] == "SYSTEM_BOOT"
    assert timeline[0]["timestamp"] == "2026-09-23T08:00:00Z"
    assert timeline[0]["evidence_id"] == "EVID-SYS-01"


def test_timeline_graceful_missing_timestamps():
    """Verify timeline handles missing timestamps without crashing."""
    evidence = {
        "processes": [{"pid": 999, "name": "orphan.exe", "create_time": None}],
        "files": [{"path": r"C:\unknown.bin", "modified_time": None}],
    }
    timeline = build_forensic_timeline(evidence)
    assert len(timeline) == 2
    assert timeline[0]["entity"].startswith("ENT-")


def test_rule_001_temp_execution():
    """Verify RULE-001 fires for execution from temp directory."""
    engine = ForensicRuleEngine()
    evidence = {
        "processes": [
            {
                "pid": 3333,
                "name": "dropper.exe",
                "exe": r"C:\Users\Target\AppData\Local\Temp\dropper.exe",
                "username": "Target",
            }
        ]
    }
    detections = engine.evaluate(evidence)
    assert len(detections) >= 1
    match = next(d for d in detections if d["rule_id"] == "RULE-001")
    assert match["severity"] == "HIGH"
    assert "temporary directory" in match["name"].lower()
    assert match["evidence"]["pid"] == 3333


def test_rule_002_suspicious_parent_child():
    """Verify RULE-002 fires when Office process spawns PowerShell."""
    engine = ForensicRuleEngine()
    evidence = {
        "processes": [
            {
                "pid": 4000,
                "ppid": None,
                "name": "winword.exe",
                "exe": r"C:\Program Files\Office\winword.exe",
            },
            {
                "pid": 4001,
                "ppid": 4000,
                "name": "powershell.exe",
                "cmdline": ["powershell.exe", "-ExecutionPolicy", "Bypass"],
                "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            },
        ]
    }
    detections = engine.evaluate(evidence)
    assert any(d["rule_id"] == "RULE-002" for d in detections)
    match = next(d for d in detections if d["rule_id"] == "RULE-002")
    assert match["severity"] == "HIGH"
    assert match["evidence"]["parent_name"] == "winword.exe"


def test_rule_003_anomalous_outbound_port():
    """Verify RULE-003 fires when connection to port 4444 (Metasploit) is detected."""
    engine = ForensicRuleEngine()
    evidence = {
        "processes": [
            {"pid": 5000, "name": "payload.exe"}
        ],
        "network": {
            "connections": [
                {
                    "pid": 5000,
                    "raddr": {"ip": "198.51.100.25", "port": 4444},
                    "laddr": {"ip": "192.168.1.5", "port": 49152},
                    "status": "ESTABLISHED",
                }
            ]
        }
    }
    detections = engine.evaluate(evidence)
    match = next((d for d in detections if d["rule_id"] == "RULE-003"), None)
    assert match is not None
    assert match["severity"] == "MEDIUM"
    assert match["evidence"]["raddr"]["port"] == 4444


def test_rule_004_unmapped_binary():
    """Verify RULE-004 fires for unmapped executable paths (excluding PID 0 and 4)."""
    engine = ForensicRuleEngine()
    evidence = {
        "processes": [
            {"pid": 6000, "name": "hollowed.exe", "exe": None, "username": "SYSTEM"}
        ]
    }
    detections = engine.evaluate(evidence)
    match = next((d for d in detections if d["rule_id"] == "RULE-004"), None)
    assert match is not None
    assert match["severity"] == "LOW"


def test_rule_005_suspicious_persistence_script():
    """Verify RULE-005 fires for script-based autorun entries."""
    engine = ForensicRuleEngine()
    evidence = {
        "windows_metadata": {
            "autoruns": [
                {
                    "name": "BackdoorRun",
                    "value": r"powershell.exe -WindowStyle Hidden -File C:\Tools\run.ps1",
                    "hive": "HKCU",
                }
            ]
        }
    }
    detections = engine.evaluate(evidence)
    match = next((d for d in detections if d["rule_id"] == "RULE-005"), None)
    assert match is not None
    assert match["severity"] == "MEDIUM"


def test_clean_baseline_no_high_alerts():
    """Verify standard legitimate processes do not trigger false positive HIGH alerts."""
    engine = ForensicRuleEngine()
    evidence = {
        "processes": [
            {
                "pid": 800,
                "ppid": 4,
                "name": "services.exe",
                "exe": r"C:\Windows\System32\services.exe",
            },
            {
                "pid": 804,
                "ppid": 800,
                "name": "svchost.exe",
                "exe": r"C:\Windows\System32\svchost.exe",
            },
        ]
    }
    detections = engine.evaluate(evidence)
    high_alerts = [d for d in detections if d["severity"] == "HIGH"]
    assert len(high_alerts) == 0
