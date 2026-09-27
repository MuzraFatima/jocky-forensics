"""
Unit & Integration Tests for Step 5: Backend Endpoint Execution & Evidence Vault Sealing Integration

Validates:
1. Backward compatibility: /api/jocky/execute with no device_id runs local collectors as before.
2. Error handling: Unknown or revoked device_id is rejected with HTTP 400.
3. Timeout handling: If agent does not submit evidence before timeout, returns HTTP 408 EndpointTimeout.
4. End-to-end endpoint execution & vault sealing:
   - Script posted with device_id.
   - Job is queued for device.
   - Agent worker thread polls job and submits verified evidence.
   - Backend completes execution, runs analysis, and seals evidence in Evidence Vault with endpoint metadata.
   - Sealed artifacts have target_host=agent.hostname and collector_identity='JOCKY-Endpoint-Agent'.
"""

import datetime
import threading
import time
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.evidence.hashing import compute_sha256
from backend.app.evidence import _default_vault

client = TestClient(app)


@pytest.fixture
def enrolled_device():
    """Logs in, generates a pairing code, and enrolls a test endpoint device."""
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "investigator@jocky.local", "password": "jocky-forensics-2026"},
    )
    assert login_resp.status_code == 200
    user_token = login_resp.json()["session"]["token"]

    gen_resp = client.post(
        "/api/agents/pairing/generate",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"device_name": "Test-Endpoint-Laptop"},
    )
    assert gen_resp.status_code == 200
    code = gen_resp.json()["pairing_code"]

    pair_resp = client.post(
        "/api/agents/pair",
        json={
            "pairing_code": code,
            "hostname": "WORKSTATION-REMOTE-01",
            "platform": "Windows 11 Pro",
            "agent_version": "1.0.0",
        },
    )
    assert pair_resp.status_code == 200
    data = pair_resp.json()
    return {
        "device_id": data["device_id"],
        "device_token": data["device_token"],
        "hostname": "WORKSTATION-REMOTE-01",
        "user_token": user_token,
    }


def test_local_execution_backward_compatibility():
    """Verify that omitting device_id runs local execution as before."""
    script = """CASE "LOCAL-COMPAT-01"
TARGET "LOCAL-MACHINE"
COLLECT SYSTEM
ANALYZE
VERIFY INTEGRITY
REPORT"""
    resp = client.post("/api/jocky/execute", json={"script": script})
    assert resp.status_code == 200
    receipt = resp.json()
    assert receipt["success"] is True
    assert "system" in receipt["collected_data"]
    assert receipt["target"] == "LOCAL-MACHINE"


def test_remote_execution_unknown_or_revoked_device(enrolled_device):
    """Verify that executing against an invalid or revoked device_id returns 400."""
    script = """CASE "TEST-REJECT"
TARGET "REMOTE"
COLLECT SYSTEM
REPORT"""
    # 1. Unknown device
    resp_unknown = client.post(
        "/api/jocky/execute",
        json={"script": script, "device_id": "DEV-DOES-NOT-EXIST"},
    )
    assert resp_unknown.status_code == 400
    assert resp_unknown.json()["error_type"] == "DeviceNotFound"

    # 2. Revoke device then attempt execution
    dev_id = enrolled_device["device_id"]
    user_tok = enrolled_device["user_token"]
    revoke_resp = client.post(
        f"/api/agents/devices/{dev_id}/revoke",
        headers={"Authorization": f"Bearer {user_tok}"},
    )
    assert revoke_resp.status_code == 200

    resp_revoked = client.post(
        "/api/jocky/execute",
        json={"script": script, "device_id": dev_id},
    )
    assert resp_revoked.status_code == 400
    assert resp_revoked.json()["error_type"] == "DeviceNotActive"


def test_remote_execution_timeout(enrolled_device):
    """Verify that execution times out if endpoint agent never submits evidence."""
    script = """CASE "TEST-TIMEOUT"
TARGET "REMOTE"
COLLECT SYSTEM
REPORT"""
    dev_id = enrolled_device["device_id"]
    # Fast 5-second timeout (minimum allowed by AgentJob model)
    resp = client.post(
        "/api/jocky/execute",
        json={"script": script, "device_id": dev_id, "wait_timeout": 5},
    )
    assert resp.status_code == 408
    data = resp.json()
    assert data["error_type"] == "EndpointTimeout"
    assert "Timed out waiting for endpoint agent" in data["message"]


def test_remote_execution_and_vault_sealing_success(enrolled_device):
    """
    Full end-to-end integration test:
    - POST /api/jocky/execute with device_id
    - Background agent thread polls job, executes mock collector, and submits evidence
    - Backend consumes evidence, runs analysis, and seals into Evidence Vault with endpoint metadata
    """
    dev_id = enrolled_device["device_id"]
    dev_tok = enrolled_device["device_token"]
    case_id = "CASE-REMOTE-E2E-01"

    script = f"""CASE "{case_id}"
TARGET "WORKSTATION-REMOTE-01"
COLLECT SYSTEM
COLLECT PROCESSES
    WHERE status == RUNNING
ANALYZE
VERIFY INTEGRITY
REPORT"""

    # Background agent worker simulating endpoint agent polling and uploading evidence
    def agent_worker():
        # Wait for job to be enqueued
        for _ in range(50):
            poll_resp = client.get(
                "/api/agents/jobs",
                headers={"Authorization": f"Bearer {dev_tok}", "X-Device-Id": dev_id},
            )
            if poll_resp.status_code == 200 and poll_resp.json().get("job"):
                job = poll_resp.json()["job"]
                exec_id = job["execution_id"]
                now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

                # Upload SYSTEM evidence
                sys_payload = {
                    "hostname": "WORKSTATION-REMOTE-01",
                    "os": "Windows 11 Enterprise",
                    "kernel": "10.0.22631",
                    "cpu_count": 8,
                }
                client.post(
                    "/api/agents/result",
                    headers={"Authorization": f"Bearer {dev_tok}", "X-Device-Id": dev_id},
                    json={
                        "device_id": dev_id,
                        "execution_id": exec_id,
                        "collector": "system",
                        "collector_version": "1.0.0",
                        "acquisition_timestamp": now_iso,
                        "payload": sys_payload,
                        "agent_sha256": compute_sha256(sys_payload),
                    },
                )

                # Upload PROCESSES evidence
                proc_payload = {
                    "processes": [
                        {"pid": 2048, "ppid": 100, "name": "incident_tool.exe", "status": "running"},
                        {"pid": 2049, "ppid": 100, "name": "stopped_service.exe", "status": "stopped"},
                    ],
                    "count": 2,
                }
                client.post(
                    "/api/agents/result",
                    headers={"Authorization": f"Bearer {dev_tok}", "X-Device-Id": dev_id},
                    json={
                        "device_id": dev_id,
                        "execution_id": exec_id,
                        "collector": "processes",
                        "collector_version": "1.0.0",
                        "acquisition_timestamp": now_iso,
                        "payload": proc_payload,
                        "agent_sha256": compute_sha256(proc_payload),
                    },
                )
                break
            time.sleep(0.05)

    worker_thread = threading.Thread(target=agent_worker)
    worker_thread.start()

    # Post execution request targeting the enrolled endpoint
    exec_resp = client.post(
        "/api/jocky/execute",
        json={"script": script, "device_id": dev_id, "wait_timeout": 10},
    )
    worker_thread.join()

    assert exec_resp.status_code == 200
    receipt = exec_resp.json()
    assert receipt["success"] is True
    assert receipt["target_device_id"] == dev_id
    assert receipt["target_host"] == "WORKSTATION-REMOTE-01"
    assert receipt["collector_identity"] == "JOCKY-Endpoint-Agent"

    # Verify filtering was applied to the endpoint's uploaded processes
    filtered_procs = receipt["collected_data"]["processes"]["processes"]
    assert len(filtered_procs) == 1
    assert filtered_procs[0]["name"] == "incident_tool.exe"

    # Verify artifacts were sealed in the central Evidence Vault
    assert "evidence_collected" in receipt
    assert len(receipt["evidence_collected"]) == 2

    # Check vault on disk for the sealed artifact
    sys_evid_id = [e["evidence_id"] for e in receipt["evidence_collected"] if e["category"] == "system"][0]
    sys_artifact = _default_vault.get_artifact(sys_evid_id)
    assert sys_artifact is not None
    assert sys_artifact["target_host"] == "WORKSTATION-REMOTE-01"
    assert sys_artifact["collector_identity"] == "JOCKY-Endpoint-Agent"
    assert "JOCKY Endpoint Agent" in sys_artifact["custody_log"][0]["who"]
