"""
Unit Tests for Step 1: JOCKY Endpoint Agent Backend Data Models
"""

import datetime
import pytest
from pydantic import ValidationError

from backend.app.agents.models import (
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentJob,
    AllowedCollector,
    CollectorOperation,
    DeviceRecord,
    DeviceStatus,
    EvidenceSubmission,
    PairingCodeGenerateRequest,
    PairingCodeGenerateResponse,
    PairingExchangeRequest,
    PairingExchangeResponse,
)


def test_allowed_collector_enum():
    """Verify only the approved read-only collectors exist."""
    approved = {"system", "processes", "network", "files", "users", "registry"}
    actual = {c.value for c in AllowedCollector}
    assert actual == approved

    # Case-insensitive resolution works
    assert AllowedCollector("SYSTEM") == AllowedCollector.SYSTEM
    assert AllowedCollector("processes") == AllowedCollector.PROCESSES


def test_collector_operation_strict_validation():
    """Verify collector operation validates allowed collectors and rejects dangerous params."""
    # Valid operation
    op = CollectorOperation(
        collector="system",
        params={"target_path": "evidence/cases"},
        filters=[{"field": "status", "operator": "==", "value": "RUNNING"}],
    )
    assert op.collector == AllowedCollector.SYSTEM

    # Disallowed collector
    with pytest.raises(ValidationError):
        CollectorOperation(collector="arbitrary_exec")

    # Forbidden keys in params
    with pytest.raises(ValidationError):
        CollectorOperation(
            collector="system",
            params={"command": "whoami"},
        )

    with pytest.raises(ValidationError):
        CollectorOperation(
            collector="files",
            params={"target_path": "../../etc/shadow"},
        )

    # Extra fields forbidden
    with pytest.raises(ValidationError):
        CollectorOperation(
            collector="network",
            rogue_field="unexpected",
        )


def test_pairing_models():
    """Verify pairing request/response structure and validation."""
    gen_req = PairingCodeGenerateRequest(device_name="Examiner-Laptop-01", case_id="CASE-2026-001")
    assert gen_req.device_name == "Examiner-Laptop-01"

    now = datetime.datetime.now(datetime.timezone.utc)
    gen_resp = PairingCodeGenerateResponse(
        pairing_code="PAIR-94A2",
        expires_at=now + datetime.timedelta(minutes=10),
        ttl_seconds=600,
    )
    assert gen_resp.pairing_code == "PAIR-94A2"

    exch_req = PairingExchangeRequest(
        pairing_code="PAIR-94A2",
        hostname="WORKSTATION-X",
        platform="Windows 11 Pro",
        agent_version="1.0.0",
    )
    assert exch_req.hostname == "WORKSTATION-X"

    exch_resp = PairingExchangeResponse(
        device_id="DEV-A1B2C3D4E5F6",
        device_token="a" * 32,
        user_id="investigator@agency.gov",
        status=DeviceStatus.ACTIVE,
        paired_at=now,
    )
    assert exch_resp.status == DeviceStatus.ACTIVE


def test_heartbeat_models():
    """Verify agent heartbeat models."""
    now = datetime.datetime.now(datetime.timezone.utc)
    hb_req = AgentHeartbeatRequest(
        device_id="DEV-A1B2C3D4E5F6",
        timestamp=now,
        hostname="WORKSTATION-X",
        platform="Linux Ubuntu 24.04",
        agent_version="1.0.0",
    )
    assert hb_req.device_id == "DEV-A1B2C3D4E5F6"

    hb_resp = AgentHeartbeatResponse(acknowledged=True, pending_jobs_count=0)
    assert hb_resp.acknowledged is True


def test_job_contract_model():
    """Verify job contract model requires mandatory fields and at least one allowed operation."""
    now = datetime.datetime.now(datetime.timezone.utc)
    job = AgentJob(
        job_id="JOB-12345678",
        user_id="investigator@agency.gov",
        device_id="DEV-A1B2C3D4E5F6",
        case_id="LAB-2026-001",
        execution_id="EXEC-99887766",
        allowed_operations=[
            CollectorOperation(collector=AllowedCollector.SYSTEM),
            CollectorOperation(collector=AllowedCollector.PROCESSES),
        ],
        created_at=now,
        timeout_seconds=30,
    )
    assert len(job.allowed_operations) == 2
    assert job.timeout_seconds == 30

    # Must contain at least one operation
    with pytest.raises(ValidationError):
        AgentJob(
            job_id="JOB-12345678",
            user_id="investigator@agency.gov",
            device_id="DEV-A1B2C3D4E5F6",
            case_id="LAB-2026-001",
            execution_id="EXEC-99887766",
            allowed_operations=[],
        )


def test_evidence_submission_contract():
    """Verify evidence submission validates SHA-256 and required fields."""
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    sub = EvidenceSubmission(
        device_id="DEV-A1B2C3D4E5F6",
        execution_id="EXEC-99887766",
        collector=AllowedCollector.NETWORK,
        collector_version="1.0.0",
        acquisition_timestamp=now,
        payload={"connections": [{"local_port": 8000, "protocol": "TCP"}]},
        agent_sha256=valid_sha.upper(),  # Should be normalized to lowercase
    )
    assert sub.agent_sha256 == valid_sha

    # Invalid SHA-256 (wrong length or characters)
    with pytest.raises(ValidationError):
        EvidenceSubmission(
            device_id="DEV-A1B2C3D4E5F6",
            execution_id="EXEC-99887766",
            collector=AllowedCollector.NETWORK,
            acquisition_timestamp=now,
            payload={},
            agent_sha256="not-a-valid-sha256",
        )


def test_device_record_model():
    """Verify device record model tracks status and revocation."""
    now = datetime.datetime.now(datetime.timezone.utc)
    rec = DeviceRecord(
        device_id="DEV-A1B2C3D4E5F6",
        user_id="investigator@agency.gov",
        hostname="WORKSTATION-X",
        platform="Windows 11 Pro",
        agent_version="1.0.0",
        created_at=now,
        status=DeviceStatus.ACTIVE,
        is_revoked=False,
    )
    assert rec.status == DeviceStatus.ACTIVE
    assert rec.is_revoked is False

    # Simulate revocation
    rec.status = DeviceStatus.REVOKED
    rec.is_revoked = True
    rec.revoked_at = now
    assert rec.is_revoked is True
    assert rec.status == DeviceStatus.REVOKED
