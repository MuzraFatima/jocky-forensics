"""Platform backend: IR is lowered per OS and unsupported operations are reported, never dropped."""

import pytest
from fastapi.testclient import TestClient

from backend.app.language import compile_jocky
from backend.app.language.backend import host_platform_name, lower_ir, normalise_platform, resolve_platform
from backend.app.main import app

SCRIPT = 'CASE "B1"\nTARGET "h"\nCOLLECT SYSTEM\nCOLLECT REGISTRY\nANALYZE MAGIC\nREPORT'


def _ir(source=SCRIPT):
    return compile_jocky(source)["ir"]


def test_windows_supports_registry_collection():
    plan = lower_ir(_ir(), "windows")
    statuses = {op["id"]: op["status"] for op in plan["operations"]}
    assert statuses["op-1"] == "supported"
    assert statuses["op-2"] == "supported"


def test_linux_marks_registry_unsupported_with_a_reason():
    plan = lower_ir(_ir(), "ubuntu")
    registry = plan["operations"][1]
    assert plan["platform"] == "LINUX"
    assert registry["status"] == "unsupported"
    assert "Windows" in registry["reason"]
    assert registry["source"]["line"] == 4
    assert "op-2" in plan["unsupported"]
    assert plan["fully_supported"] is False


def test_uncatalogued_operations_are_flagged_unknown():
    plan = lower_ir(_ir(), "linux")
    assert plan["operations"][2]["status"] == "unknown"


def test_portable_script_is_fully_supported_everywhere():
    ir = _ir('CASE "p"\nTARGET "h"\nCOLLECT SYSTEM\nCOLLECT PROCESSES\nVERIFY INTEGRITY\nREPORT')
    for target in ("windows", "linux", "macos"):
        assert lower_ir(ir, target)["fully_supported"] is True


def test_script_platform_declaration_is_used_when_no_override():
    ir = _ir('investigation "x" { target "h" platform linux collect registry }')
    assert resolve_platform(ir) == "LINUX"
    assert resolve_platform(ir, "windows") == "WINDOWS"


def test_auto_platform_falls_back_to_the_host():
    assert resolve_platform(_ir()) == host_platform_name()


def test_unknown_platform_request_is_an_error():
    with pytest.raises(ValueError):
        resolve_platform(_ir(), "beos")
    result = compile_jocky(SCRIPT, platform="beos")
    assert result["success"] is False
    assert result["error"]["code"] == "JKY211"


def test_normalise_platform_aliases():
    assert normalise_platform("Darwin") == "MACOS"
    assert normalise_platform("win32") == "WINDOWS"
    assert normalise_platform(None) is None


def test_compile_result_includes_backend_plan():
    result = compile_jocky(SCRIPT, platform="linux")
    assert result["backend"]["platform"] == "LINUX"


def test_compile_api_accepts_platform_and_returns_codes():
    client = TestClient(app)
    ok = client.post("/api/jocky/compile", json={"script": SCRIPT, "platform": "linux"})
    assert ok.status_code == 200
    assert ok.json()["backend"]["unsupported"] == ["op-2", "op-3"]

    bad = client.post("/api/jocky/compile", json={"script": 'CASE "a"\nTARGET "b"\nCOLECT SYSTEM'})
    assert bad.status_code == 400
    body = bad.json()
    assert body["code"] == "JKY205"
    assert body["hint"] == "Did you mean 'COLLECT'?"
