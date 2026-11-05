"""IR v2: every operation carries an id, declared capability, output schema, platforms and source position."""

from backend.app.engine.ir_policy import _CAPABILITY_MAP, evaluate_ir_policy
from backend.app.language import compile_jocky
from backend.app.language.capabilities import OPERATIONS, lookup

SCRIPT = """CASE "IR2"
TARGET "host"
COLLECT SYSTEM
COLLECT PROCESSES
    WHERE status == RUNNING
COLLECT REGISTRY
VERIFY INTEGRITY
REPORT FORMAT HTML
"""


def _ir(source=SCRIPT):
    result = compile_jocky(source)
    assert result["success"], result.get("error")
    return result["ir"]


def test_version_is_two():
    assert _ir()["version"] == "2.0"


def test_operations_have_sequential_ids():
    assert [op["id"] for op in _ir()["operations"]] == ["op-1", "op-2", "op-3", "op-4", "op-5"]


def test_operations_map_back_to_source_lines():
    lines = [op["source"]["line"] for op in _ir()["operations"]]
    assert lines == [3, 4, 6, 7, 8]


def test_operations_declare_capabilities_and_schemas():
    ops = _ir()["operations"]
    assert [op["capability"] for op in ops] == [
        "COLLECT_SYSTEM",
        "COLLECT_PROCESSES",
        "COLLECT_REGISTRY",
        "VERIFY_INTEGRITY",
        "REPORT_HTML",
    ]
    assert ops[1]["output_schema"] == "jocky.process_list.v1"


def test_platform_support_is_declared_per_operation():
    ops = _ir()["operations"]
    assert ops[0]["platforms"] == ["LINUX", "MACOS", "WINDOWS"]
    assert ops[2]["platforms"] == ["WINDOWS"]


def test_required_capabilities_are_listed_once_and_sorted():
    ir = _ir()
    assert ir["required_capabilities"] == sorted(set(ir["required_capabilities"]))
    assert "COLLECT_REGISTRY" in ir["required_capabilities"]


def test_unknown_analysis_has_no_capability():
    ir = _ir('CASE "a"\nTARGET "b"\nCOLLECT SYSTEM\nANALYZE MAGIC')
    analyze = ir["operations"][1]
    assert analyze["capability"] is None
    assert analyze["platforms"] == []
    assert "UNKNOWN" not in ir["required_capabilities"]


def test_v1_fields_are_unchanged():
    op = _ir()["operations"][1]
    assert op["type"] == "COLLECT"
    assert op["target"] == "PROCESSES"
    assert op["filters"] == [{"field": "status", "operator": "==", "value": "RUNNING"}]


def test_catalog_matches_the_runtime_allow_list():
    """The compiler must never declare a capability the policy engine does not know, or label it differently."""
    assert set(OPERATIONS) == set(_CAPABILITY_MAP)
    for key, spec in OPERATIONS.items():
        assert _CAPABILITY_MAP[key] == spec.capability, key


def test_policy_approves_every_declared_capability():
    ir = _ir()
    decision = evaluate_ir_policy(ir)
    assert decision["allowed"] is True
    approved = {op["capability"] for op in decision["approved_operations"]}
    assert approved == set(ir["required_capabilities"])


def test_lookup_is_case_insensitive():
    assert lookup("collect", "system").capability == "COLLECT_SYSTEM"
    assert lookup("COLLECT", "PASSWORDS") is None
