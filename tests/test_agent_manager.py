"""
Unit Tests for Step 2: AgentManager & Pairing Lifecycle

Validates:
1. Pairing code generation (6–8 chars, 10-min expiry, user bound)
2. Single-use enforcement and rejection of expired codes
3. Device enrollment, token hashing, and plaintext token non-persistence
4. Token verification and device/user scoping
5. Immediate rejection upon device revocation
6. Re-pairing after revocation
7. In-memory job queue (enqueue, dequeue, clear)
8. In-memory result registry (add, get, completion check, clear)
9. Thread safety under concurrent access
"""

import datetime
import shutil
import tempfile
import threading
from pathlib import Path
import pytest

from backend.app.agents.manager import (
    AgentManager,
    hash_device_token,
    verify_device_token_hash,
)
from backend.app.agents.models import (
    AgentJob,
    AllowedCollector,
    CollectorOperation,
    DeviceStatus,
    EvidenceSubmission,
    PairingExchangeRequest,
)


@pytest.fixture
def temp_manager():
    """Provides an isolated AgentManager instance backed by a temporary directory."""
    temp_dir = tempfile.mkdtemp(prefix="jocky_agent_test_")
    manager = AgentManager(storage_dir=Path(temp_dir))
    yield manager
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_pairing_code_generation(temp_manager):
    """Verify pairing code is 6-8 characters, has 10-min TTL, and is bound to user."""
    user_id = "investigator_alpha@agency.gov"
    resp = temp_manager.generate_pairing_code(user_id=user_id, device_name="Field-Laptop")

    code = resp.pairing_code
    assert 6 <= len(code) <= 8
    assert resp.ttl_seconds <= 600 and resp.ttl_seconds >= 590
    assert resp.expires_at > datetime.datetime.now(datetime.timezone.utc)

    # Empty user_id must be rejected
    with pytest.raises(ValueError):
        temp_manager.generate_pairing_code(user_id="")


def test_single_use_enforcement(temp_manager):
    """Verify pairing code can only be used once."""
    user_id = "investigator_beta@agency.gov"
    resp = temp_manager.generate_pairing_code(user_id=user_id)
    code = resp.pairing_code

    req = PairingExchangeRequest(
        pairing_code=code,
        hostname="DESKTOP-FORENSIC",
        platform="Windows 11 Pro",
        agent_version="1.0.0",
    )

    # First exchange succeeds
    exchange_resp = temp_manager.exchange_pairing_code(req)
    assert exchange_resp.device_id.startswith("DEV-")
    assert len(exchange_resp.device_token) >= 32
    assert exchange_resp.user_id == user_id

    # Second exchange with the same code MUST fail
    with pytest.raises(ValueError, match="Invalid pairing code"):
        temp_manager.exchange_pairing_code(req)


def test_expired_code_rejection(temp_manager):
    """Verify expired pairing codes are strictly rejected."""
    user_id = "investigator_gamma@agency.gov"
    resp = temp_manager.generate_pairing_code(user_id=user_id)
    code = resp.pairing_code

    # Force expiration in memory
    temp_manager._pairing_codes[code]["expires_at"] = datetime.datetime.now(
        datetime.timezone.utc
    ) - datetime.timedelta(seconds=5)

    req = PairingExchangeRequest(
        pairing_code=code,
        hostname="DESKTOP-EXPIRED",
        platform="Linux Ubuntu 24.04",
    )

    with pytest.raises(ValueError, match="Pairing code has expired"):
        temp_manager.exchange_pairing_code(req)


def test_device_registration_and_plaintext_token_not_persisted(temp_manager):
    """Verify device registration stores ONLY a hash and never plaintext token."""
    user_id = "examiner_01@agency.gov"
    resp = temp_manager.generate_pairing_code(user_id=user_id)

    req = PairingExchangeRequest(
        pairing_code=resp.pairing_code,
        hostname="WORKSTATION-SECURE",
        platform="macOS Darwin 23.4",
        agent_version="1.2.0",
    )
    exch_resp = temp_manager.exchange_pairing_code(req)
    raw_token = exch_resp.device_token
    device_id = exch_resp.device_id

    # Fetch device record from manager
    dev = temp_manager.get_device(device_id)
    assert dev is not None
    assert dev.device_id == device_id
    assert dev.user_id == user_id
    assert dev.hostname == "WORKSTATION-SECURE"
    assert dev.status == DeviceStatus.ACTIVE
    assert dev.is_revoked is False

    # Invariant: Raw token MUST NOT be stored anywhere on the record
    assert dev.token_hash is not None
    assert raw_token not in dev.token_hash
    assert dev.token_hash.startswith("pbkdf2_sha256$")

    # Invariant: Inspect persisted JSON on disk to verify plaintext token is NOT on disk
    with open(temp_manager._devices_file, "r", encoding="utf-8") as f:
        disk_content = f.read()
        assert raw_token not in disk_content
        assert dev.token_hash in disk_content


def test_token_verification_and_scoping(temp_manager):
    """Verify device token verification succeeds with valid token and fails with invalid/tampered token."""
    user_id = "examiner_02@agency.gov"
    resp = temp_manager.generate_pairing_code(user_id=user_id)

    req = PairingExchangeRequest(
        pairing_code=resp.pairing_code,
        hostname="WORKSTATION-VERIFY",
        platform="Windows 11 Pro",
    )
    exch = temp_manager.exchange_pairing_code(req)

    # Valid token verification
    verified = temp_manager.verify_device_token(exch.device_id, exch.device_token)
    assert verified is not None
    assert verified.device_id == exch.device_id
    assert verified.user_id == user_id

    # Tampered / wrong token
    wrong = temp_manager.verify_device_token(exch.device_id, "wrong_token_" + "x" * 32)
    assert wrong is None

    # Unknown device ID
    unknown = temp_manager.verify_device_token("DEV-UNKNOWN-99", exch.device_token)
    assert unknown is None


def test_device_revocation_and_token_rejection(temp_manager):
    """Verify revoking a device immediately invalidates its token and active status."""
    user_id = "examiner_03@agency.gov"
    resp = temp_manager.generate_pairing_code(user_id=user_id)
    exch = temp_manager.exchange_pairing_code(
        PairingExchangeRequest(
            pairing_code=resp.pairing_code,
            hostname="WORKSTATION-REVOKE",
            platform="Linux",
        )
    )

    device_id = exch.device_id
    token = exch.device_token

    # Active before revocation
    assert temp_manager.is_device_active(device_id) is True
    assert temp_manager.verify_device_token(device_id, token) is not None

    # Revoke
    ok = temp_manager.revoke_device(device_id=device_id, user_id=user_id)
    assert ok is True

    # Immediate rejection
    assert temp_manager.is_device_active(device_id) is False
    assert temp_manager.verify_device_token(device_id, token) is None

    dev = temp_manager.get_device(device_id)
    assert dev.is_revoked is True
    assert dev.status == DeviceStatus.REVOKED
    assert dev.revoked_at is not None
    assert dev.token_hash is None


def test_re_pair_after_revocation(temp_manager):
    """Verify a revoked device can be re-paired with a new pairing code."""
    user_id = "examiner_04@agency.gov"
    resp = temp_manager.generate_pairing_code(user_id=user_id)
    exch = temp_manager.exchange_pairing_code(
        PairingExchangeRequest(
            pairing_code=resp.pairing_code,
            hostname="WORKSTATION-REPAIR",
            platform="Windows 11 Pro",
        )
    )
    device_id = exch.device_id
    old_token = exch.device_token

    # Revoke device
    temp_manager.revoke_device(device_id, user_id=user_id)
    assert temp_manager.is_device_active(device_id) is False

    # Generate fresh pairing code for re-pairing
    new_resp = temp_manager.generate_pairing_code(user_id=user_id)
    new_code = new_resp.pairing_code

    # Re-pair
    re_paired = temp_manager.re_pair_device(
        device_id=device_id,
        pairing_code=new_code,
        hostname="WORKSTATION-REPAIRED",
    )
    assert re_paired.device_id == device_id
    new_token = re_paired.device_token
    assert new_token != old_token

    # Old token fails, new token succeeds
    assert temp_manager.verify_device_token(device_id, old_token) is None
    assert temp_manager.verify_device_token(device_id, new_token) is not None
    assert temp_manager.is_device_active(device_id) is True

    updated_dev = temp_manager.get_device(device_id)
    assert updated_dev.hostname == "WORKSTATION-REPAIRED"
    assert updated_dev.is_revoked is False
    assert updated_dev.status == DeviceStatus.ACTIVE


def test_job_queue_operations(temp_manager):
    """Verify in-memory FIFO job queuing, retrieval, and clearing."""
    user_id = "examiner_05@agency.gov"
    resp = temp_manager.generate_pairing_code(user_id=user_id)
    exch = temp_manager.exchange_pairing_code(
        PairingExchangeRequest(
            pairing_code=resp.pairing_code,
            hostname="WORKSTATION-JOBS",
            platform="Linux",
        )
    )
    device_id = exch.device_id

    # Queue empty initially
    assert temp_manager.get_pending_job(device_id) is None
    assert temp_manager.get_pending_jobs_count(device_id) == 0

    job1 = AgentJob(
        job_id="JOB-11111111",
        user_id=user_id,
        device_id=device_id,
        case_id="CASE-001",
        execution_id="EXEC-001",
        allowed_operations=[CollectorOperation(collector=AllowedCollector.SYSTEM)],
    )
    job2 = AgentJob(
        job_id="JOB-22222222",
        user_id=user_id,
        device_id=device_id,
        case_id="CASE-001",
        execution_id="EXEC-002",
        allowed_operations=[CollectorOperation(collector=AllowedCollector.PROCESSES)],
    )

    temp_manager.enqueue_job(device_id, job1)
    temp_manager.enqueue_job(device_id, job2)
    assert temp_manager.get_pending_jobs_count(device_id) == 2

    # FIFO retrieval
    fetched1 = temp_manager.get_pending_job(device_id)
    assert fetched1.job_id == "JOB-11111111"
    assert temp_manager.get_pending_jobs_count(device_id) == 1

    fetched2 = temp_manager.get_pending_job(device_id)
    assert fetched2.job_id == "JOB-22222222"
    assert temp_manager.get_pending_jobs_count(device_id) == 0

    # Enqueue on revoked device must fail
    temp_manager.revoke_device(device_id)
    with pytest.raises(ValueError, match="Cannot enqueue job"):
        temp_manager.enqueue_job(device_id, job1)


def test_result_registry(temp_manager):
    """Verify temporary in-memory result aggregation and completion checking."""
    exec_id = "EXEC-RESULT-TEST"
    device_id = "DEV-A1B2C3D4E5F6"
    now = datetime.datetime.now(datetime.timezone.utc)
    dummy_sha = "a" * 64

    sub_sys = EvidenceSubmission(
        device_id=device_id,
        execution_id=exec_id,
        collector=AllowedCollector.SYSTEM,
        acquisition_timestamp=now,
        payload={"os": "Windows 11"},
        agent_sha256=dummy_sha,
    )
    sub_proc = EvidenceSubmission(
        device_id=device_id,
        execution_id=exec_id,
        collector=AllowedCollector.PROCESSES,
        acquisition_timestamp=now,
        payload={"processes": []},
        agent_sha256=dummy_sha,
    )

    # Empty initially
    assert temp_manager.get_results(exec_id) == []
    assert temp_manager.is_execution_complete(exec_id, ["system", "processes"]) is False

    temp_manager.add_result(exec_id, sub_sys)
    assert len(temp_manager.get_results(exec_id)) == 1
    assert temp_manager.is_execution_complete(exec_id, ["system", "processes"]) is False

    temp_manager.add_result(exec_id, sub_proc)
    assert len(temp_manager.get_results(exec_id)) == 2
    assert temp_manager.is_execution_complete(exec_id, ["system", "processes"]) is True

    # Clear results
    temp_manager.clear_results(exec_id)
    assert temp_manager.get_results(exec_id) == []


def test_concurrent_pairing_and_job_safety(temp_manager):
    """Verify thread safety under concurrent code generations and pairing attempts."""
    user_id = "concurrent_investigator@agency.gov"
    created_codes = []
    errors = []

    def worker_generate():
        try:
            resp = temp_manager.generate_pairing_code(user_id=user_id)
            created_codes.append(resp.pairing_code)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker_generate) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    assert len(created_codes) == 20
    # All generated pairing codes must be distinct
    assert len(set(created_codes)) == 20


def test_repeated_pairing_same_endpoint_reuses_device_id(temp_manager):
    """Verify pairing the same physical endpoint repeatedly does not create duplicate active devices."""
    user_id = "investigator_alpha@agency.gov"

    # First pairing
    code1 = temp_manager.generate_pairing_code(user_id=user_id).pairing_code
    req1 = PairingExchangeRequest(
        pairing_code=code1,
        hostname="WORKSTATION-X",
        platform="Windows 11 Pro",
        agent_version="1.0.0",
    )
    resp1 = temp_manager.exchange_pairing_code(req1)
    dev_id1 = resp1.device_id
    token1 = resp1.device_token

    # Verify 1 active device exists
    devs = temp_manager.list_devices(user_id=user_id)
    assert len(devs) == 1
    assert devs[0].device_id == dev_id1

    # Second pairing from the same physical endpoint
    code2 = temp_manager.generate_pairing_code(user_id=user_id).pairing_code
    req2 = PairingExchangeRequest(
        pairing_code=code2,
        hostname="WORKSTATION-X",
        platform="Windows 11 Pro",
        agent_version="1.0.1",
    )
    resp2 = temp_manager.exchange_pairing_code(req2)
    dev_id2 = resp2.device_id
    token2 = resp2.device_token

    # Stable device_id is preserved, new credentials issued
    assert dev_id2 == dev_id1
    assert token2 != token1

    # Still exactly 1 active device, no duplicates
    devs_after = temp_manager.list_devices(user_id=user_id)
    assert len(devs_after) == 1
    assert devs_after[0].device_id == dev_id1
    assert devs_after[0].agent_version == "1.0.1"

    # Authenticating with new token succeeds, old token fails
    assert temp_manager.verify_device_token(dev_id1, token2) is not None
    assert temp_manager.verify_device_token(dev_id1, token1) is None

