"""Signed jobs: the agent runs only jobs the server signed, for this device, before expiry, once."""

import base64
import copy
import datetime
import secrets

import pytest
from fastapi.testclient import TestClient

from backend.app.agents.manager import get_agent_manager
from backend.app.agents.models import AgentJob, AllowedCollector, CollectorOperation
from backend.app.agents.signing import JobSigner, JobVerifier, canonical_job_bytes, get_job_signer
from backend.app.main import app

client = TestClient(app)


def _pair(hostname="SIGNED-BOX"):
    login = client.post("/api/auth/login", json={"username": "investigator@jocky.local",
                                                 "password": "jocky-forensics-2026"})
    token = login.json()["session"]["token"]
    code = client.post("/api/agents/pairing/generate", headers={"Authorization": f"Bearer {token}"},
                       json={"device_name": "Signed-Job-Box"}).json()["pairing_code"]
    pair = client.post("/api/agents/pair", json={"pairing_code": code, "hostname": hostname,
                                                 "platform": "Ubuntu 24.04", "agent_version": "1.0.0"}).json()
    return pair


def _job(device_id, **overrides):
    fields = dict(
        job_id=f"JOB-{secrets.token_hex(5).upper()}",
        user_id="investigator@jocky.local",
        device_id=device_id,
        case_id="CASE-SIGNED",
        execution_id=f"EXEC-{secrets.token_hex(4)}",
        allowed_operations=[CollectorOperation(collector=AllowedCollector.SYSTEM)],
    )
    fields.update(overrides)
    return AgentJob(**fields)


def _poll(pair):
    headers = {"Authorization": f"Bearer {pair['device_token']}", "X-Device-Id": pair["device_id"]}
    return client.get("/api/agents/jobs", headers=headers).json()["job"]


@pytest.fixture
def paired():
    return _pair()


def test_pairing_hands_the_agent_the_server_public_key(paired):
    assert paired["job_signing_public_key"] == get_job_signer().public_key_b64
    assert len(base64.b64decode(paired["job_signing_public_key"])) == 32


def test_job_signed_by_server_verifies_on_the_agent_after_travelling_over_http(paired):
    get_agent_manager().enqueue_job(paired["device_id"], _job(paired["device_id"]))
    job = _poll(paired)
    assert job["signature"] and job["nonce"] and job["expires_at"]
    verifier = JobVerifier(paired["job_signing_public_key"], paired["device_id"])
    assert verifier.check(job) == (True, "ok")


def test_tampered_operations_are_refused(paired):
    get_agent_manager().enqueue_job(paired["device_id"], _job(paired["device_id"]))
    job = _poll(paired)
    job["allowed_operations"][0]["collector"] = "files"
    job["allowed_operations"][0]["params"] = {"target_path": "/etc"}
    ok, reason = JobVerifier(paired["job_signing_public_key"], paired["device_id"]).check(job)
    assert not ok and "signature" in reason


def test_replayed_job_is_refused(paired):
    get_agent_manager().enqueue_job(paired["device_id"], _job(paired["device_id"]))
    job = _poll(paired)
    verifier = JobVerifier(paired["job_signing_public_key"], paired["device_id"])
    assert verifier.check(copy.deepcopy(job))[0] is True
    ok, reason = verifier.check(job)
    assert not ok and "replay" in reason


def test_expired_job_is_refused(paired):
    get_agent_manager().enqueue_job(paired["device_id"], _job(paired["device_id"]))
    job = _poll(paired)
    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    ok, reason = JobVerifier(paired["job_signing_public_key"], paired["device_id"]).check(job, now=later)
    assert not ok and "expired" in reason


def test_job_for_another_device_is_refused(paired):
    other = _pair("OTHER-BOX")
    assert other["device_id"] != paired["device_id"]
    get_agent_manager().enqueue_job(other["device_id"], _job(other["device_id"]))
    job = _poll(other)
    ok, reason = JobVerifier(paired["job_signing_public_key"], paired["device_id"]).check(job)
    assert not ok and "addressed to" in reason


def test_job_signed_with_a_different_key_is_refused(paired):
    rogue = JobSigner.from_seed(secrets.token_bytes(32))
    job = rogue.sign(_job(paired["device_id"])).model_dump(mode="json")
    ok, reason = JobVerifier(paired["job_signing_public_key"], paired["device_id"]).check(job)
    assert not ok and "signature" in reason


def test_unsigned_job_is_refused(paired):
    job = _job(paired["device_id"]).model_dump(mode="json")
    assert JobVerifier(paired["job_signing_public_key"], paired["device_id"]).check(job) == (False, "job is not signed")


def test_canonical_bytes_ignore_signature_and_key_order():
    a = {"b": 1, "a": [1, 2], "signature": "x"}
    b = {"a": [1, 2], "b": 1}
    assert canonical_job_bytes(a) == canonical_job_bytes(b)


def test_agent_client_refuses_bad_jobs_before_running_them(paired, tmp_path):
    from agent.client import EndpointAgentClient
    from agent.config import AgentConfig

    config = AgentConfig(server_url="http://unused", device_id=paired["device_id"],
                         device_token=paired["device_token"], config_path=str(tmp_path / "a.json"),
                         job_signing_public_key=paired["job_signing_public_key"])
    agent = EndpointAgentClient(config)
    ran = []
    agent.runner.execute_job = lambda job: ran.append(job["job_id"]) or []
    agent.send_heartbeat = lambda: True

    get_agent_manager().enqueue_job(paired["device_id"], _job(paired["device_id"]))
    good = _poll(paired)
    forged = copy.deepcopy(good)
    forged["job_id"] = "JOB-FORGED0001"
    agent.poll_jobs = lambda: [good, forged, copy.deepcopy(good)]

    assert agent.run_once() == 1
    assert ran == [good["job_id"]]
