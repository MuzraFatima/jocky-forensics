"""
Experiment E6 / blueprint §10: one case coordinated across several endpoints.

Real EndpointAgentClient instances talk to the API through the test client,
verify their signed jobs, run collectors and upload evidence.
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from agent.client import EndpointAgentClient
from agent.config import AgentConfig
from backend.app.main import app

client = TestClient(app)


class _Session:
    """Adapts requests.Session calls onto the FastAPI TestClient."""

    def get(self, url, **kw):
        kw.pop("timeout", None)
        return client.get(url.replace("http://jocky.test", ""), **kw)

    def post(self, url, **kw):
        kw.pop("timeout", None)
        return client.post(url.replace("http://jocky.test", ""), **kw)


def _login(user="investigator@jocky.local", password="jocky-forensics-2026"):
    token = client.post("/api/auth/login", json={"username": user, "password": password}).json()["session"]["token"]
    return {"Authorization": f"Bearer {token}"}


def _paired_agent(headers, tmp_path, hostname):
    code = client.post("/api/agents/pairing/generate", headers=headers, json={"device_name": hostname}).json()["pairing_code"]
    agent = EndpointAgentClient(AgentConfig(config_path=str(tmp_path / f"{hostname}.json")))
    agent.session = _Session()
    assert agent.pair("http://jocky.test", code, custom_hostname=hostname)
    assert agent.config.job_signing_public_key
    return agent


@pytest.fixture
def investigator():
    return _login()


def test_one_case_runs_across_several_endpoints(investigator, tmp_path):
    case_id = f"CASE-MULTI-{uuid.uuid4().hex[:6].upper()}"
    win = _paired_agent(investigator, tmp_path, "LAB-WIN-01")
    ubu = _paired_agent(investigator, tmp_path, "LAB-UBUNTU-01")
    silent = _paired_agent(investigator, tmp_path, "LAB-OFFLINE-01")

    resp = client.post(
        f"/api/agents/cases/{case_id}/dispatch",
        headers=investigator,
        json={"device_ids": [win.config.device_id, ubu.config.device_id, silent.config.device_id, "DEV-DOESNOTEXIST"],
              "collectors": ["system", "dns"]},
    ).json()
    assert resp["success"] is True
    assert len(resp["dispatched"]) == 3
    assert resp["rejected"] == [{"device_id": "DEV-DOESNOTEXIST", "reason": "unknown device"}]

    status = client.get(f"/api/agents/cases/{case_id}", headers=investigator).json()
    assert status["states"] == {"queued": 3}

    assert win.run_once() == 1
    assert ubu.run_once() == 1

    status = client.get(f"/api/agents/cases/{case_id}", headers=investigator).json()
    by_host = {e["hostname"]: e for e in status["endpoints"]}
    assert by_host["LAB-WIN-01"]["state"] == "completed"
    assert by_host["LAB-UBUNTU-01"]["state"] == "completed"
    assert by_host["LAB-WIN-01"]["received"] == ["dns", "system"]
    assert by_host["LAB-OFFLINE-01"]["state"] == "queued"
    assert by_host["LAB-OFFLINE-01"]["missing"] == ["system", "dns"]
    assert status["complete"] is False
    assert status["states"] == {"completed": 2, "queued": 1}


def test_dispatch_refuses_other_investigators_devices(investigator, tmp_path):
    mine = _paired_agent(investigator, tmp_path, "LAB-MINE-01")
    other = _login("admin@jocky.local", "admin-forensics-2026")
    resp = client.post("/api/agents/cases/CASE-X/dispatch", headers=other,
                       json={"device_ids": [mine.config.device_id], "collectors": ["system"]}).json()
    assert resp["success"] is False
    assert resp["rejected"][0]["reason"] == "device belongs to another investigator"


def test_dispatch_needs_an_investigator_session():
    resp = client.post("/api/agents/cases/CASE-X/dispatch", json={"device_ids": ["DEV-ABCDEFGH"], "collectors": ["system"]})
    assert resp.status_code == 401


def test_unknown_collector_is_rejected_by_the_schema(investigator):
    resp = client.post("/api/agents/cases/CASE-X/dispatch", headers=investigator,
                       json={"device_ids": ["DEV-ABCDEFGH"], "collectors": ["shell"]})
    assert resp.status_code == 422
