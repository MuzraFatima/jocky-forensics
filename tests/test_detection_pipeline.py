"""Detection is reachable from scripts (analyze detections) and from the API."""

from fastapi.testclient import TestClient

from backend.app.engine.ir_executor import IRExecutor
from backend.app.engine.providers import EndpointEvidenceProvider
from backend.app.language import compile_jocky
from backend.app.main import app

SCRIPT = 'investigation "DET-1" { target "lab-ubuntu" collect services collect dns analyze detections }'

EVIDENCE = {
    "services": {"collector": "services", "collection_status": "collected", "count": 1,
                 "items": [{"name": "upd.service", "executable": "/dev/shm/upd", "binary_path": "/dev/shm/upd"}]},
    "dns": {"collector": "dns", "collection_status": "collected", "count": 1,
            "items": [{"kind": "hosts_entry", "value": "198.51.100.4", "names": ["security.ubuntu.com"]}]},
}


def test_analyze_detections_compiles_with_its_capability():
    ir = compile_jocky(SCRIPT)["ir"]
    assert ir["operations"][-1]["capability"] == "ANALYZE_DETECTIONS"
    flat = compile_jocky('CASE "a"\nTARGET "b"\nCOLLECT DNS\nANALYZE threats')["ir"]
    assert flat["operations"][1]["target"] == "DETECTIONS"


def test_script_runs_rules_over_endpoint_evidence_and_stores_findings():
    ir = compile_jocky(SCRIPT)["ir"]
    out = IRExecutor(collector_provider=EndpointEvidenceProvider(evidence=EVIDENCE)).execute_jocky_ir(ir)
    assert out["success"] is True
    detections = out["rule_detections"]
    assert {f["rule_id"] for f in detections["findings"]} == {"JKY-DET-001", "JKY-DET-006"}
    assert all(f["evidence_id"] for f in detections["findings"])
    assert detections["correlation"]["independent_sources"] == 2
    assert "detections" in out["evidence_ids"]
    receipt = out["receipts"][-1]
    assert receipt["capability"] == "ANALYZE_DETECTIONS"
    assert receipt["record_count"] == 2


def test_rules_endpoint_lists_rules():
    body = TestClient(app).get("/api/forensics/detections/rules").json()
    assert body["count"] >= 5
    assert all(r["attack"] for r in body["rules"])


def test_detect_endpoint_runs_live_and_rejects_unknown_sources():
    client = TestClient(app)
    live = client.post("/api/forensics/detect", json={"sources": ["dns", "listening_ports"]}).json()
    assert live["success"] is True
    assert set(live["sources_seen"]) == {"dns", "listening_ports"}
    assert "correlation" in live
    bad = client.post("/api/forensics/detect", json={"sources": ["registry_hives"]})
    assert bad.status_code == 400
