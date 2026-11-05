"""Sign-in and role enforcement on the forensic API, with enforcement switched on."""

import uuid

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.security.audit import get_audit_events
from backend.app.security.rbac import ADMIN, INVESTIGATOR, VIEWER, required_level, role_level

client = TestClient(app)
SCRIPT = 'CASE "RBAC"\nTARGET "lab"\nCOLLECT SYSTEM'


@pytest.fixture(autouse=True)
def enforce(monkeypatch):
    monkeypatch.delenv("JOCKY_AUTH_DISABLED", raising=False)


def _token(role):
    username = f"rbac_{uuid.uuid4().hex[:8]}@lab.local"
    resp = client.post("/api/auth/register", json={"username": username, "password": "Str0ng-Pass-2026!", "role": role})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['session']['token']}"}


@pytest.fixture(scope="module")
def viewer():
    return _token("Digital Evidence Auditor")


@pytest.fixture(scope="module")
def investigator():
    return _token("Incident Responder")


@pytest.fixture(scope="module")
def admin():
    resp = client.post("/api/auth/login", json={"username": "admin@jocky.local", "password": "admin-forensics-2026"})
    return {"Authorization": f"Bearer {resp.json()['session']['token']}"}


def test_open_endpoints_stay_open():
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/status").status_code == 200


@pytest.mark.parametrize("method, path", [
    ("GET", "/api/forensics/vault/list"),
    ("POST", "/api/jocky/compile"),
    ("GET", "/api/forensics/collect/dns"),
    ("POST", "/api/forensics/detect"),
])
def test_forensic_endpoints_require_sign_in(method, path):
    resp = client.request(method, path, json={"script": SCRIPT})
    assert resp.status_code == 401
    assert resp.json()["error_type"] == "AuthenticationRequired"


def test_garbage_token_is_rejected():
    resp = client.get("/api/forensics/vault/list", headers={"Authorization": "Bearer jocky_auth_forged"})
    assert resp.status_code == 401


def test_viewer_can_read_compile_and_verify(viewer):
    assert client.get("/api/forensics/vault/list", headers=viewer).status_code == 200
    assert client.post("/api/jocky/compile", headers=viewer, json={"script": SCRIPT}).status_code == 200
    assert client.get("/api/forensics/detections/rules", headers=viewer).status_code == 200


def test_viewer_cannot_collect_or_execute(viewer):
    denied = client.get("/api/forensics/collect/dns", headers=viewer)
    assert denied.status_code == 403
    assert denied.json()["required"] == "investigator"
    assert client.post("/api/jocky/execute", headers=viewer, json={"script": SCRIPT}).status_code == 403
    assert client.post("/api/forensics/detect", headers=viewer, json={"sources": ["dns"]}).status_code == 403


def test_denials_are_audited(viewer):
    client.get("/api/forensics/collect/startup", headers=viewer)
    events = get_audit_events(limit=5, action="ACCESS_DENIED")
    assert any(e["details"].get("path") == "/api/forensics/collect/startup" for e in events)


def test_investigator_can_collect_but_not_simulate_tampering(investigator):
    assert client.get("/api/forensics/collect/dns", headers=investigator).status_code == 200
    resp = client.post("/api/forensics/vault/simulate-tampering", headers=investigator, json={"evidence_id": "EVID-x"})
    assert resp.status_code == 403
    assert resp.json()["required"] == "admin"


def test_admin_reaches_the_tamper_demo(admin):
    resp = client.post("/api/forensics/vault/simulate-tampering", headers=admin, json={"evidence_id": "EVID-none"})
    assert resp.status_code != 403


def test_cors_headers_survive_a_401():
    resp = client.get("/api/forensics/vault/list", headers={"Origin": "http://localhost:5173"})
    assert resp.status_code == 401
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_nobody_can_self_register_as_admin(investigator, admin):
    body = {"username": f"x_{uuid.uuid4().hex[:6]}@lab.local", "password": "Str0ng-Pass-2026!",
            "role": "SOC Incident Commander"}
    assert client.post("/api/auth/register", json=body).status_code == 403
    assert client.post("/api/auth/register", json=body, headers=investigator).status_code == 403
    assert client.post("/api/auth/register", json=body, headers=admin).status_code == 200


def test_level_table():
    assert role_level("Digital Evidence Auditor") == VIEWER
    assert role_level("Lead Forensic Examiner") == INVESTIGATOR
    assert role_level("SOC Incident Commander") == ADMIN
    assert role_level(None) == INVESTIGATOR
    assert required_level("POST", "/api/jocky/validate") == VIEWER
    assert required_level("GET", "/api/forensics/timeline") == INVESTIGATOR
    assert required_level("GET", "/api/forensics/vault/list") == VIEWER
    assert required_level("POST", "/api/forensics/vault/seal") == INVESTIGATOR
