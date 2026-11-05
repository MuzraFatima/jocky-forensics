"""The investigation-block form from blueprint §4.3 and its equivalence with the flat syntax."""

from backend.app.language import compile_jocky

FLAT = """CASE "AUDIT-1"
TARGET "lab-pc"
COLLECT SYSTEM
COLLECT PROCESSES
WHERE status == RUNNING
COLLECT NETWORK
VERIFY INTEGRITY
REPORT FORMAT HTML
"""

BLOCK = """investigation "AUDIT-1" {
    target "lab-pc"
    collect system
    collect processes where status == running
    collect network
    verify integrity
    report format html
}
"""


def _ops(source):
    result = compile_jocky(source)
    assert result["success"], result.get("error")
    return result["ir"]


def test_block_and_flat_forms_compile_to_the_same_operations():
    flat, block = _ops(FLAT), _ops(BLOCK)
    assert flat["case_id"] == block["case_id"] == "AUDIT-1"
    assert flat["target"] == block["target"] == "lab-pc"
    strip = lambda ops: [{k: v for k, v in op.items() if k != "source"} for op in ops]  # noqa: E731
    assert strip(flat["operations"]) == strip(block["operations"])


def test_blueprint_one_line_example_compiles():
    source = (
        'investigation "System_Audit_001" { target "localhost" platform detect '
        "collect system_information collect running_processes collect active_network_connections "
        'verify integrity report format json }'
    )
    ir = _ops(source)
    assert [op["target"] for op in ir["operations"][:3]] == ["SYSTEM", "PROCESSES", "NETWORK"]
    assert ir["platform"] == "AUTO"


def test_semicolons_separate_statements():
    ir = _ops('investigation "S" { target "h"; collect system; report }')
    assert [op["type"] for op in ir["operations"]] == ["COLLECT", "REPORT"]


def test_platform_names_are_normalised():
    ir = _ops('investigation "P" { target "h" platform ubuntu collect system }')
    assert ir["platform"] == "LINUX"


def test_missing_closing_brace_is_reported():
    err = compile_jocky('investigation "x" { target "a" collect system')["error"]
    assert err["code"] == "JKY209"


def test_stray_closing_brace_is_reported():
    err = compile_jocky('CASE "a"\nTARGET "b"\nCOLLECT SYSTEM\n}')["error"]
    assert err["code"] == "JKY209"
    assert err["line"] == 4


def test_block_requires_a_quoted_name():
    err = compile_jocky("investigation audit { target \"a\" collect system }")["error"]
    assert err["code"] == "JKY202"


def test_invalid_platform_is_rejected_with_suggestion():
    err = compile_jocky('investigation "x" { target "a" platform windws collect system }')["error"]
    assert err["code"] == "JKY211"
    assert err["hint"] == "Did you mean 'WINDOWS'?"


def test_duplicate_platform_is_rejected():
    err = compile_jocky('investigation "x" { target "a" platform linux platform windows collect system }')["error"]
    assert err["code"] == "JKY308"


def test_unknown_alias_suggests_the_closest_name():
    err = compile_jocky('investigation "x" { target "a" collect running_proceses }')["error"]
    assert err["code"] == "JKY206"
    assert err["hint"] == "Did you mean 'RUNNING_PROCESSES'?"


def test_flat_scripts_still_reject_two_statements_on_one_line():
    err = compile_jocky('CASE "a"\nTARGET "b"\nCOLLECT SYSTEM COLLECT NETWORK')["error"]
    assert err["code"] == "JKY201"


def test_shipped_block_example_compiles():
    from pathlib import Path

    source = (Path(__file__).resolve().parent.parent / "examples" / "block_audit.jocky").read_text(encoding="utf-8")
    ir = _ops(source)
    assert ir["case_id"] == "System_Audit_001"
    assert len(ir["operations"]) == 7
