"""The new inventory targets flow through language, policy, provider, executor and API."""

import pytest
from fastapi.testclient import TestClient

from backend.app.collectors import get_collectors
from backend.app.engine import execute_jocky_ir
from backend.app.engine.providers import EndpointEvidenceProvider, LocalCollectorProvider
from backend.app.language import compile_jocky
from backend.app.main import app

TARGETS = ["SERVICES", "STARTUP", "DRIVERS", "LISTENING_PORTS", "DNS"]


@pytest.mark.parametrize(
    "word, expected",
    [
        ("services", "SERVICES"),
        ("installed_services", "SERVICES"),
        ("startup_entries", "STARTUP"),
        ("kernel_modules", "DRIVERS"),
        ("drivers", "DRIVERS"),
        ("open_ports", "LISTENING_PORTS"),
        ("listening_ports", "LISTENING_PORTS"),
        ("dns_cache", "DNS"),
    ],
)
def test_collect_words_compile_to_inventory_targets(word, expected):
    result = compile_jocky(f'investigation "i" {{ target "h" collect {word} }}')
    assert result["success"], result.get("error")
    assert result["ir"]["operations"][0]["target"] == expected


def test_inventory_targets_take_no_where_clause():
    result = compile_jocky('CASE "a"\nTARGET "b"\nCOLLECT SERVICES WHERE status == RUNNING')
    assert result["success"] is False


def test_drivers_are_unsupported_on_macos_at_compile_time():
    result = compile_jocky('CASE "a"\nTARGET "b"\nCOLLECT DRIVERS', platform="macos")
    assert result["backend"]["unsupported"] == ["op-1"]


def test_verify_integrity_accepts_inventory_as_evidence():
    assert compile_jocky('CASE "a"\nTARGET "b"\nCOLLECT DNS\nVERIFY INTEGRITY')["success"]


def test_executor_stores_each_inventory_source_as_evidence():
    ir = compile_jocky('CASE "INV-PIPE"\nTARGET "h"\n' + "\n".join(f"COLLECT {t}" for t in TARGETS))["ir"]
    out = execute_jocky_ir(ir)
    assert out["success"] is True
    receipts = [r for r in out["receipts"] if r["type"] == "COLLECT"]
    assert len(receipts) == 5
    for receipt in receipts:
        assert receipt["status"] in ("COMPLETED", "UNSUPPORTED")
        assert receipt["evidence_id"]
        assert len(receipt["sha256"]) == 64
        assert receipt["collection_status"] in ("collected", "partial", "unsupported", "denied", "error")


def test_unsupported_source_produces_unsupported_receipt():
    class MacLikeProvider(LocalCollectorProvider):
        def collect_inventory(self, name, params=None):
            from backend.app.collectors.inventory import collect_drivers

            return collect_drivers(platform_name="Darwin")

    from backend.app.engine.ir_executor import IRExecutor

    ir = compile_jocky('CASE "INV-MAC"\nTARGET "h"\nCOLLECT DRIVERS')["ir"]
    out = IRExecutor(collector_provider=MacLikeProvider()).execute_jocky_ir(ir)
    receipt = next(r for r in out["receipts"] if r["type"] == "COLLECT")
    assert receipt["status"] == "UNSUPPORTED"
    assert receipt["collection_status"] == "unsupported"


def test_endpoint_provider_serves_inventory_evidence():
    provider = EndpointEvidenceProvider(evidence={"services": {"collector": "services", "items": [], "count": 0}})
    assert provider.get_evidence("services")["collector"] == "services"
    assert provider.collect_inventory("services")["count"] == 0


def test_collect_api_exposes_inventory_sources():
    assert {"services", "startup", "drivers", "listening_ports", "dns"} <= set(get_collectors())
    client = TestClient(app)
    response = client.get("/api/forensics/collect/dns")
    assert response.status_code == 200
    assert response.json()["artifact"]["collector"] == "dns"
