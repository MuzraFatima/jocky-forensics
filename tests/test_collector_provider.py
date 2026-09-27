"""
Unit Tests for Step 4: CollectorProvider Abstraction

Validates:
1. LocalCollectorProvider delegates to standard local collectors.
2. IRExecutor works seamlessly without explicitly passing a provider (default local execution).
3. EndpointEvidenceProvider returns pre-collected evidence without touching local collectors.
4. EndpointEvidenceProvider strictly validates collector allowlist (rejects unsupported collectors).
5. EndpointEvidenceProvider rejects submissions with mismatched device_id or execution_id scoping.
6. Endpoint evidence is validated as passive structured data (non-dict rejected).
7. Downstream processing (WHERE filtering, correlation, timeline, rules, and receipt generation)
   runs identically on endpoint evidence.
8. 100% backward compatibility of IRExecutor and execute_jocky_ir.
"""

import pytest

from backend.app.engine.providers import (
    ALLOWED_COLLECTORS,
    CollectorProvider,
    EndpointEvidenceProvider,
    LocalCollectorProvider,
)
from backend.app.engine.ir_executor import IRExecutor, execute_jocky_ir
from backend.app.language import compile_jocky
from backend.app.agents.models import AllowedCollector, EvidenceSubmission


def test_local_collector_provider_returns_live_telemetry():
    """Verify LocalCollectorProvider calls live host collectors."""
    provider = LocalCollectorProvider()
    sys_data = provider.collect_system()
    assert isinstance(sys_data, dict)
    assert "platform" in sys_data or "os" in sys_data or "system" in sys_data

    proc_data = provider.collect_processes()
    assert isinstance(proc_data, dict)
    assert "processes" in proc_data

    net_data = provider.collect_network()
    assert isinstance(net_data, dict)
    assert "connections" in net_data


def test_executor_defaults_to_local_provider_without_argument():
    """Verify IRExecutor functions identically with default LocalCollectorProvider."""
    script = """
    CASE "TEST-LOCAL-PROVIDER"
    TARGET "LOCAL-HOST"
    COLLECT SYSTEM
    ANALYZE
    VERIFY INTEGRITY
    REPORT
    """
    compile_res = compile_jocky(script)
    assert compile_res["success"] is True
    ir = compile_res["ir"]

    executor = IRExecutor()
    assert isinstance(executor.collector_provider, LocalCollectorProvider)

    receipt = executor.execute_jocky_ir(ir)
    assert receipt["success"] is True
    assert "system" in receipt["collected_data"]
    assert receipt["analysis"] is not None


def test_endpoint_evidence_provider_returns_precollected_data():
    """Verify EndpointEvidenceProvider returns pre-collected data and never runs local collection."""
    mock_system = {
        "hostname": "REMOTE-INVESTIGATOR-PC",
        "os": "Windows 11 Enterprise",
        "cpu_count": 16,
    }
    mock_processes = {
        "processes": [
            {"pid": 404, "name": "custom_agent.exe", "status": "running"},
            {"pid": 101, "name": "cmd.exe", "status": "running"},
        ],
        "count": 2,
    }

    provider = EndpointEvidenceProvider(
        evidence={
            "system": mock_system,
            "processes": mock_processes,
        }
    )

    sys_out = provider.collect_system()
    assert sys_out == mock_system
    assert sys_out["hostname"] == "REMOTE-INVESTIGATOR-PC"

    proc_out = provider.collect_processes()
    assert proc_out == mock_processes
    assert len(proc_out["processes"]) == 2


def test_endpoint_provider_unsupported_collector_rejected():
    """Verify EndpointEvidenceProvider rejects unauthorized collector types."""
    # Initialization with illegal collector key
    with pytest.raises(ValueError, match="Unsupported or unauthorized collector type"):
        EndpointEvidenceProvider(
            evidence={
                "arbitrary_shell_exec": {"command": "dir"},
            }
        )

    # Retrieval of unknown collector
    valid_provider = EndpointEvidenceProvider(evidence={"system": {"os": "Linux"}})
    with pytest.raises(ValueError, match="Unsupported collector type"):
        valid_provider.get_evidence("kill_process")

    # Missing pre-collected collector
    with pytest.raises(KeyError, match="No pre-collected endpoint evidence available"):
        valid_provider.collect_network()


def test_endpoint_provider_device_and_execution_scoping():
    """Verify EndpointEvidenceProvider enforces device_id and execution_id validation."""
    submission = {
        "device_id": "DEV-CORRECT-11",
        "execution_id": "EXEC-CORRECT-99",
        "collector": "system",
        "payload": {"os": "macOS Sonoma"},
    }

    # Valid scoping
    provider = EndpointEvidenceProvider(
        evidence=[submission],
        expected_device_id="DEV-CORRECT-11",
        expected_execution_id="EXEC-CORRECT-99",
    )
    assert provider.collect_system() == {"os": "macOS Sonoma"}

    # Device ID mismatch
    with pytest.raises(ValueError, match="does not match expected device"):
        EndpointEvidenceProvider(
            evidence=[submission],
            expected_device_id="DEV-WRONG-22",
            expected_execution_id="EXEC-CORRECT-99",
        )

    # Execution ID mismatch
    with pytest.raises(ValueError, match="does not match expected execution"):
        EndpointEvidenceProvider(
            evidence=[submission],
            expected_device_id="DEV-CORRECT-11",
            expected_execution_id="EXEC-WRONG-00",
        )


def test_endpoint_provider_payload_must_be_data_dict():
    """Verify that non-dict or executable-like payloads are rejected."""
    with pytest.raises(ValueError, match="must be a dictionary"):
        EndpointEvidenceProvider(
            evidence={
                "system": "raw string or executable shell payload",
            }
        )


def test_ir_executor_with_endpoint_provider_downstream_pipeline():
    """
    Verify that IRExecutor with EndpointEvidenceProvider executes the full downstream
    pipeline: WHERE filtering, correlation, timeline, rules, and receipt generation.
    """
    endpoint_system = {
        "hostname": "ENDPOINT-WORKSTATION",
        "os": "Windows 11 Pro",
        "kernel": "10.0.22631",
    }
    endpoint_processes = {
        "processes": [
            {"pid": 1000, "ppid": 500, "name": "powershell.exe", "status": "running"},
            {"pid": 1001, "ppid": 500, "name": "notepad.exe", "status": "stopped"},
        ],
        "count": 2,
    }
    endpoint_network = {
        "connections": [
            {
                "local_address": "127.0.0.1",
                "local_port": 8080,
                "remote_address": "10.0.0.5",
                "remote_port": 443,
                "status": "ESTABLISHED",
                "pid": 1000,
                "protocol": "TCP",
            }
        ],
        "count": 1,
    }

    provider = EndpointEvidenceProvider(
        evidence={
            "system": endpoint_system,
            "processes": endpoint_processes,
            "network": endpoint_network,
        },
        expected_device_id="DEV-TEST-01",
        expected_execution_id="EXEC-TEST-01",
    )

    script = """CASE "LAB-ENDPOINT-E2E"
TARGET "ENDPOINT-WORKSTATION"

COLLECT SYSTEM
COLLECT PROCESSES
    WHERE status == RUNNING
COLLECT NETWORK
    WHERE state == ESTABLISHED

ANALYZE
VERIFY INTEGRITY
REPORT"""
    comp = compile_jocky(script)
    assert comp["success"] is True
    ir = comp["ir"]

    executor = IRExecutor(collector_provider=provider)
    receipt = executor.execute_jocky_ir(ir)

    assert receipt["success"] is True
    assert receipt["target"] == "ENDPOINT-WORKSTATION"
    assert "system" in receipt["collected_data"]
    assert receipt["collected_data"]["system"]["hostname"] == "ENDPOINT-WORKSTATION"

    # Verify WHERE STATUS == RUNNING filter was applied post-collection on endpoint data
    filtered_procs = receipt["collected_data"]["processes"]["processes"]
    assert len(filtered_procs) == 1
    assert filtered_procs[0]["name"] == "powershell.exe"

    # Verify downstream correlation ran on endpoint data
    assert receipt["correlation"] is not None
    assert "entities" in receipt["correlation"]
    opened_socket_rels = [r for r in receipt["correlation"]["relationships"] if r["type"] == "OPENED_SOCKET"]
    assert len(opened_socket_rels) == 1
    rel = opened_socket_rels[0]
    assert rel["type"] == "OPENED_SOCKET"

    # Verify timeline and report were generated
    assert receipt["timeline"] is not None
    assert receipt["report"] is not None
