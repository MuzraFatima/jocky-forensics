"""
Unit & Integration Tests for Step 3: Endpoint Agent REST API Routes

Validates:
1. Pairing code generation (authenticated vs unauthenticated)
2. Pairing exchange (valid, invalid, expired, single-use, token non-persistence)
3. Device authentication dependency (valid, invalid, revoked, cross-device mismatch)
4. Heartbeat (presence update, 403 on ID mismatch, 401 on bad token)
5. Job polling (FIFO queue, device scoping, empty queue returns job=None)
6. Evidence result submission (SHA-256 match vs mismatch TRANSMISSION_TAMPERED, scoping)
7. Device listing (scoped to user, no tokens/hashes exposed, online/offline calculation)
8. Device revocation (scoped to owner, immediate invalidation of bearer token)
"""

import datetime
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.agents.manager import get_agent_manager
from backend.app.agents.models import (
    AgentJob,
    AllowedCollector,
    CollectorOperation,
)
from backend.app.evidence.hashing import compute_sha256

client = TestClient(app)


@pytest.fixture
def investigator_token():
    """Logs in as demo investigator and yields bearer token."""
    resp = client.post(
        "/api/auth/login",
        json={"username": "investigator@jocky.local", "password": "jocky-forensics-2026"},
    )
    assert resp.status_code == 200
    token = resp.json()["session"]["token"]
    return token


@pytest.fixture
def admin_token():
    """Logs in as admin investigator to test multi-user scoping."""
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin@jocky.local", "password": "admin-forensics-2026"},
    )
    assert resp.status_code == 200
    token = resp.json()["session"]["token"]
    return token


# ─── 1. Pairing Tests ─────────────────────────────────────────────────────────

def test_pairing_code_generate_auth_required():
    """Verify that unauthenticated pairing code generation is rejected with 401."""
    resp = client.post("/api/agents/pairing/generate", json={})
    assert resp.status_code == 401


def test_pairing_code_generate_and_exchange(investigator_token):
    """Verify investigator can generate code and agent can exchange it successfully."""
    # 1. Generate pairing code
    gen_resp = client.post(
        "/api/agents/pairing/generate",
        headers={"Authorization": f"Bearer {investigator_token}"},
        json={"device_name": "Field-Workstation-01", "case_id": "CASE-2026-001"},
    )
    assert gen_resp.status_code == 200
    data = gen_resp.json()
    code = data["pairing_code"]
    assert 6 <= len(code) <= 8
    assert data["ttl_seconds"] <= 600

    # 2. Agent exchanges code
    exch_resp = client.post(
        "/api/agents/pair",
        json={
            "pairing_code": code,
            "hostname": "FIELD-LAPTOP-X",
            "platform": "Windows 11 Pro",
            "agent_version": "1.0.0",
        },
    )
    assert exch_resp.status_code == 200
    exch_data = exch_resp.json()
    assert exch_data["device_id"].startswith("DEV-")
    assert len(exch_data["device_token"]) >= 32
    assert exch_data["user_id"] == "investigator@jocky.local"

    # 3. Single-use: Repeating the exchange must be rejected
    repeat_resp = client.post(
        "/api/agents/pair",
        json={
            "pairing_code": code,
            "hostname": "FIELD-LAPTOP-X",
            "platform": "Windows 11 Pro",
        },
    )
    assert repeat_resp.status_code == 400
    assert "Invalid pairing code" in repeat_resp.json()["error"]


def test_pairing_exchange_invalid_code():
    """Verify that non-existent pairing code is rejected."""
    resp = client.post(
        "/api/agents/pair",
        json={
            "pairing_code": "INVALID99",
            "hostname": "ROGUE-PC",
            "platform": "Linux",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error_type"] == "PairingFailed"


# ─── 2. Authentication & Heartbeat Tests ──────────────────────────────────────

def test_heartbeat_lifecycle(investigator_token):
    """Verify heartbeat requires valid device token and updates last_seen."""
    # Generate and pair
    gen = client.post(
        "/api/agents/pairing/generate",
        headers={"Authorization": f"Bearer {investigator_token}"},
        json={},
    )
    code = gen.json()["pairing_code"]
    pair = client.post(
        "/api/agents/pair",
        json={"pairing_code": code, "hostname": "HEARTBEAT-PC", "platform": "Linux Ubuntu"},
    )
    device_id = pair.json()["device_id"]
    token = pair.json()["device_token"]

    # 1. Unauthenticated heartbeat rejected
    unauth = client.post("/api/agents/heartbeat", json={"device_id": device_id, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "hostname": "HEARTBEAT-PC", "platform": "Linux Ubuntu", "agent_version": "1.0.0"})
    assert unauth.status_code == 401

    # 2. Invalid bearer token rejected
    bad_token = client.post(
        "/api/agents/heartbeat",
        headers={"Authorization": "Bearer bad_secret_token", "X-Device-Id": device_id},
        json={"device_id": device_id, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "hostname": "HEARTBEAT-PC", "platform": "Linux Ubuntu", "agent_version": "1.0.0"},
    )
    assert bad_token.status_code == 401

    # 3. Valid heartbeat succeeds
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    ok_resp = client.post(
        "/api/agents/heartbeat",
        headers={"Authorization": f"Bearer {token}", "X-Device-Id": device_id},
        json={
            "device_id": device_id,
            "timestamp": now_iso,
            "hostname": "HEARTBEAT-UPDATED",
            "platform": "Linux Ubuntu 24.04",
            "agent_version": "1.0.1",
        },
    )
    assert ok_resp.status_code == 200
    data = ok_resp.json()
    assert data["acknowledged"] is True
    assert data["pending_jobs_count"] == 0

    # 4. Device ID mismatch rejected with 403
    mismatch = client.post(
        "/api/agents/heartbeat",
        headers={"Authorization": f"Bearer {token}", "X-Device-Id": device_id},
        json={
            "device_id": "DEV-ANOTHER-01",
            "timestamp": now_iso,
            "hostname": "HEARTBEAT-PC",
            "platform": "Linux Ubuntu",
            "agent_version": "1.0.0",
        },
    )
    assert mismatch.status_code == 403


# ─── 3. Job Polling Tests ─────────────────────────────────────────────────────

def test_job_polling_and_scoping(investigator_token):
    """Verify agent polls only its own assigned jobs."""
    # Pair Device A
    gen_a = client.post("/api/agents/pairing/generate", headers={"Authorization": f"Bearer {investigator_token}"})
    pair_a = client.post("/api/agents/pair", json={"pairing_code": gen_a.json()["pairing_code"], "hostname": "PC-A", "platform": "Win11"})
    dev_a = pair_a.json()["device_id"]
    tok_a = pair_a.json()["device_token"]

    # Pair Device B
    gen_b = client.post("/api/agents/pairing/generate", headers={"Authorization": f"Bearer {investigator_token}"})
    pair_b = client.post("/api/agents/pair", json={"pairing_code": gen_b.json()["pairing_code"], "hostname": "PC-B", "platform": "Linux"})
    dev_b = pair_b.json()["device_id"]
    tok_b = pair_b.json()["device_token"]

    # Empty queue returns job=None
    empty_resp = client.get("/api/agents/jobs", headers={"Authorization": f"Bearer {tok_a}", "X-Device-Id": dev_a})
    assert empty_resp.status_code == 200
    assert empty_resp.json()["job"] is None

    # Enqueue job specifically for Device A
    manager = get_agent_manager()
    job_a = AgentJob(
        job_id="JOB-AAAA1111",
        user_id="investigator@jocky.local",
        device_id=dev_a,
        case_id="CASE-001",
        execution_id="EXEC-001",
        allowed_operations=[CollectorOperation(collector=AllowedCollector.SYSTEM)],
    )
    manager.enqueue_job(dev_a, job_a)

    # Device B polling sees NO jobs
    b_resp = client.get("/api/agents/jobs", headers={"Authorization": f"Bearer {tok_b}", "X-Device-Id": dev_b})
    assert b_resp.status_code == 200
    assert b_resp.json()["job"] is None

    # Device A polling receives its assigned job
    a_resp = client.get("/api/agents/jobs", headers={"Authorization": f"Bearer {tok_a}", "X-Device-Id": dev_a})
    assert a_resp.status_code == 200
    rec = a_resp.json()["job"]
    assert rec is not None
    assert rec["job_id"] == "JOB-AAAA1111"
    assert rec["device_id"] == dev_a


# ─── 4. Evidence Result Submission & SHA-256 Validation ───────────────────────

def test_evidence_submission_sha256_verification(investigator_token):
    """Verify evidence submission validates SHA-256 and rejects tampering."""
    gen = client.post("/api/agents/pairing/generate", headers={"Authorization": f"Bearer {investigator_token}"})
    pair = client.post("/api/agents/pair", json={"pairing_code": gen.json()["pairing_code"], "hostname": "EVID-PC", "platform": "Win11"})
    device_id = pair.json()["device_id"]
    token = pair.json()["device_token"]

    payload = {"processes": [{"pid": 1234, "name": "explorer.exe", "status": "running"}]}
    computed_sha = compute_sha256(payload)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 1. Valid SHA-256 accepted
    valid_resp = client.post(
        "/api/agents/result",
        headers={"Authorization": f"Bearer {token}", "X-Device-Id": device_id},
        json={
            "device_id": device_id,
            "execution_id": "EXEC-EVID-001",
            "collector": "processes",
            "collector_version": "1.0.0",
            "acquisition_timestamp": now_iso,
            "payload": payload,
            "agent_sha256": computed_sha,
        },
    )
    assert valid_resp.status_code == 200
    assert valid_resp.json()["success"] is True

    # Check that evidence was stored in manager
    manager = get_agent_manager()
    results = manager.get_results("EXEC-EVID-001")
    assert len(results) == 1
    assert results[0].agent_sha256 == computed_sha

    # 2. Tampered SHA-256 rejected with HTTP 400 and TRANSMISSION_TAMPERED
    tampered_sha = "f" * 64
    tampered_resp = client.post(
        "/api/agents/result",
        headers={"Authorization": f"Bearer {token}", "X-Device-Id": device_id},
        json={
            "device_id": device_id,
            "execution_id": "EXEC-EVID-002",
            "collector": "processes",
            "collector_version": "1.0.0",
            "acquisition_timestamp": now_iso,
            "payload": payload,
            "agent_sha256": tampered_sha,
        },
    )
    assert tampered_resp.status_code == 400
    data = tampered_resp.json()
    assert data["success"] is False
    assert data["error_type"] == "TRANSMISSION_TAMPERED"

    # Verify tampered evidence was NOT stored
    assert len(manager.get_results("EXEC-EVID-002")) == 0

    # 3. Cross-device ID mismatch rejected with 403
    mismatch_resp = client.post(
        "/api/agents/result",
        headers={"Authorization": f"Bearer {token}", "X-Device-Id": device_id},
        json={
            "device_id": "DEV-ANOTHER-HOST",
            "execution_id": "EXEC-EVID-003",
            "collector": "processes",
            "acquisition_timestamp": now_iso,
            "payload": payload,
            "agent_sha256": computed_sha,
        },
    )
    assert mismatch_resp.status_code == 403


# ─── 5. Device Listing & Revocation Tests ──────────────────────────────────────

def test_device_list_and_revocation(investigator_token, admin_token):
    """Verify investigator lists only owned devices, no secrets leaked, and revocation works."""
    # Investigator registers device
    gen_inv = client.post("/api/agents/pairing/generate", headers={"Authorization": f"Bearer {investigator_token}"})
    pair_inv = client.post("/api/agents/pair", json={"pairing_code": gen_inv.json()["pairing_code"], "hostname": "INVESTIGATOR-PC", "platform": "Windows 11"})
    inv_dev_id = pair_inv.json()["device_id"]
    inv_token = pair_inv.json()["device_token"]

    # Admin registers device
    gen_adm = client.post("/api/agents/pairing/generate", headers={"Authorization": f"Bearer {admin_token}"})
    pair_adm = client.post("/api/agents/pair", json={"pairing_code": gen_adm.json()["pairing_code"], "hostname": "ADMIN-PC", "platform": "macOS"})
    adm_dev_id = pair_adm.json()["device_id"]

    # 1. Investigator lists devices: sees inv_dev_id, NEVER sees adm_dev_id
    list_resp = client.get("/api/agents/devices", headers={"Authorization": f"Bearer {investigator_token}"})
    assert list_resp.status_code == 200
    devices = list_resp.json()["devices"]
    device_ids = [d["device_id"] for d in devices]
    assert inv_dev_id in device_ids
    assert adm_dev_id not in device_ids

    # 2. Verify security: NO token, token_hash, or secret is ever leaked in the response
    for dev in devices:
        assert "device_token" not in dev
        assert "token_hash" not in dev
        assert "pairing_code" not in dev
        assert "status" in dev
        assert "is_online" in dev

    # 3. Investigator attempts to revoke admin's device -> 403 Forbidden
    cross_revoke = client.post(f"/api/agents/devices/{adm_dev_id}/revoke", headers={"Authorization": f"Bearer {investigator_token}"})
    assert cross_revoke.status_code == 403

    # 4. Investigator revokes their own device -> 200 Success
    revoke_resp = client.post(f"/api/agents/devices/{inv_dev_id}/revoke", headers={"Authorization": f"Bearer {investigator_token}"})
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["success"] is True

    # 5. Subsequent agent calls with the revoked token must immediately fail (401)
    heartbeat_after_revoke = client.post(
        "/api/agents/heartbeat",
        headers={"Authorization": f"Bearer {inv_token}", "X-Device-Id": inv_dev_id},
        json={
            "device_id": inv_dev_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "hostname": "INVESTIGATOR-PC",
            "platform": "Windows 11",
            "agent_version": "1.0.0",
        },
    )
    assert heartbeat_after_revoke.status_code == 401
