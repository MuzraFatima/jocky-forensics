"""
Unit tests for JOCKY Forensic Correlation Engine (Phase 4).
"""

import pytest
from backend.app.analysis.correlator import (
    ForensicCorrelator,
    correlate_evidence,
    generate_file_entity_id,
    generate_network_entity_id,
    generate_process_entity_id,
    generate_user_entity_id,
)


def test_entity_id_generation():
    """Verify deterministic entity ID formats."""
    proc_id = generate_process_entity_id(4567)
    assert proc_id == "ENT-PROC-4567"

    file_id_hash = generate_file_entity_id(
        r"C:\Windows\System32\notepad.exe",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert file_id_hash == "ENT-FILE-e3b0c44298fc1c14"

    file_id_nohash = generate_file_entity_id(r"C:\Tools\custom.exe")
    assert file_id_nohash.startswith("ENT-FILE-")

    net_id = generate_network_entity_id(
        "tcp",
        {"ip": "127.0.0.1", "port": 8080},
        {"ip": "192.168.1.10", "port": 443},
    )
    assert net_id.startswith("ENT-NET-TCP-")

    user_id = generate_user_entity_id(r"CORP\SecOpsUser")
    assert user_id == "ENT-USER-CORP_SECOPSUSER"


def test_process_network_file_correlation():
    """Verify linking of process to its file executable and network socket."""
    correlator = ForensicCorrelator()

    mock_processes = [
        {
            "pid": 2048,
            "ppid": 1024,
            "name": "agent.exe",
            "cmdline": ["agent.exe", "--port", "9000"],
            "username": "SYSTEM",
            "exe": r"C:\Security\agent.exe",
            "status": "running",
            "create_time": "2026-09-23T10:00:00Z",
        },
        {
            "pid": 1024,
            "ppid": 4,
            "name": "services.exe",
            "cmdline": ["services.exe"],
            "username": "SYSTEM",
            "exe": r"C:\Windows\System32\services.exe",
            "status": "running",
            "create_time": "2026-09-23T09:00:00Z",
        },
    ]

    mock_network = [
        {
            "pid": 2048,
            "protocol": "TCP",
            "status": "ESTABLISHED",
            "laddr": {"ip": "192.168.1.50", "port": 49200},
            "raddr": {"ip": "10.0.0.1", "port": 443},
        }
    ]

    mock_files = [
        {
            "path": r"C:\Security\agent.exe",
            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "size_bytes": 1048576,
        }
    ]

    mock_users = [
        {"name": "SYSTEM", "is_admin": True}
    ]

    result = correlator.correlate(
        processes=mock_processes,
        network=mock_network,
        files=mock_files,
        users=mock_users,
    )

    assert "summary" in result
    assert result["summary"]["process_count"] == 2
    assert result["summary"]["network_count"] == 1
    assert result["summary"]["total_relationships"] > 0

    # Verify relationships
    rel_types = [r["type"] for r in result["relationships"]]
    assert "SPAWNED_CHILD" in rel_types
    assert "OPENED_SOCKET" in rel_types
    assert "EXECUTED_FROM" in rel_types

    # Find chain for agent.exe
    agent_chain = next(c for c in result["correlated_chains"] if c["pid"] == 2048)
    assert agent_chain["has_network"] is True
    assert agent_chain["has_parent"] is True
    assert agent_chain["parent"]["pid"] == 1024
    assert agent_chain["executable"]["sha256"] == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    assert len(agent_chain["network_connections"]) == 1


def test_process_tree_hierarchy():
    """Verify recursive parent/child process tree reconstruction."""
    correlator = ForensicCorrelator()

    mock_procs = [
        {"pid": 100, "ppid": None, "name": "system_init.exe"},
        {"pid": 200, "ppid": 100, "name": "service_host.exe"},
        {"pid": 300, "ppid": 200, "name": "worker.exe"},
        {"pid": 400, "ppid": 200, "name": "monitor.exe"},
    ]

    result = correlator.correlate(processes=mock_procs)
    tree = result["process_tree"]

    # Root should be system_init (pid 100)
    assert len(tree) == 1
    root = tree[0]
    assert root["pid"] == 100
    assert len(root["children"]) == 1

    svc_host = root["children"][0]
    assert svc_host["pid"] == 200
    assert len(svc_host["children"]) == 2

    child_pids = {c["pid"] for c in svc_host["children"]}
    assert child_pids == {300, 400}


def test_cycle_resilience_in_process_tree():
    """Ensure cycle detection handles anomalous or corrupted parent-child loops gracefully."""
    correlator = ForensicCorrelator()

    # Artificially cyclic ppid structure
    mock_procs = [
        {"pid": 10, "ppid": 20, "name": "a.exe"},
        {"pid": 20, "ppid": 10, "name": "b.exe"},
    ]

    result = correlator.correlate(processes=mock_procs)
    assert "process_tree" in result
    assert isinstance(result["process_tree"], list)


def test_correlate_evidence_wrapper():
    """Verify the correlate_evidence helper with raw collector mapping."""
    evidence = {
        "processes": {
            "processes": [
                {"pid": 500, "ppid": None, "name": "test.exe", "exe": r"C:\test.exe"}
            ]
        },
        "network": {
            "connections": [
                {"pid": 500, "protocol": "TCP", "laddr": {"ip": "0.0.0.0", "port": 80}}
            ]
        },
        "files": {
            "files": [
                {"path": r"C:\test.exe", "sha256": "1234567890abcdef1234567890abcdef"}
            ]
        },
    }

    result = correlate_evidence(evidence)
    assert result["summary"]["process_count"] == 1
    assert result["summary"]["network_count"] == 1
    assert len(result["correlated_chains"]) == 1
    assert result["correlated_chains"][0]["has_network"] is True
