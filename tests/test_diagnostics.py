"""Diagnostics: every compiler error carries a stable code, position and, where useful, a hint."""

import pytest

from backend.app.language import compile_jocky
from backend.app.language.errors import ERROR_CODES, JockySyntaxError, suggest

HEADER = 'CASE "C-1"\nTARGET "HOST"\n'


@pytest.mark.parametrize(
    "source, code",
    [
        ('CASE "open', "JKY101"),
        ('CASE "a"\nTARGET "b"\nCOLLECT SYSTEM @', "JKY102"),
        (HEADER + "COLLECT SYSTEM extra", "JKY201"),
        ("CASE 42", "JKY202"),
        ('CASE "a"\nTARGET host', "JKY203"),
        (HEADER + "COLLECT SYSTEM\nVERIFY HASHES", "JKY204"),
        (HEADER + "INJECT MALWARE", "JKY205"),
        (HEADER + "COLLECT PASSWORDS", "JKY206"),
        (HEADER + "COLLECT FILES", "JKY207"),
        (HEADER + "COLLECT PROCESSES\nWHERE status RUNNING", "JKY210"),
        ('TARGET "b"\nCOLLECT SYSTEM', "JKY301"),
        (HEADER + 'CASE "again"\nCOLLECT SYSTEM', "JKY302"),
        ('CASE "a"\nCOLLECT SYSTEM', "JKY303"),
        (HEADER + "REPORT", "JKY307"),
        (HEADER + "COLLECT PROCESSES\nWHERE state == RUNNING", "JKY310"),
        (HEADER + "COLLECT PROCESSES\nWHERE status == FLYING", "JKY311"),
        (HEADER + "VERIFY INTEGRITY\nCOLLECT SYSTEM", "JKY320"),
        (HEADER + "COLLECT SYSTEM\nREPORT FORMAT PDF", "JKY330"),
    ],
)
def test_each_failure_reports_its_code(source, code):
    result = compile_jocky(source)
    assert result["success"] is False
    err = result["error"]
    assert err["code"] == code
    assert code in ERROR_CODES
    assert err["line"] is not None


def test_misspelt_command_gets_a_suggestion():
    err = compile_jocky(HEADER + "COLECT SYSTEM")["error"]
    assert err["hint"] == "Did you mean 'COLLECT'?"


def test_misspelt_collect_target_gets_a_suggestion():
    err = compile_jocky(HEADER + "COLLECT PROCESES")["error"]
    assert err["hint"] == "Did you mean 'PROCESSES'?"


def test_misspelt_filter_value_gets_a_suggestion():
    err = compile_jocky(HEADER + "COLLECT PROCESSES\nWHERE status == RUNING")["error"]
    assert err["hint"] == "Did you mean 'RUNNING'?"


def test_unrelated_word_gets_no_suggestion():
    err = compile_jocky(HEADER + "INJECT MALWARE")["error"]
    assert err["hint"] is None


def test_suggest_ignores_non_strings():
    assert suggest(42, ["COLLECT"]) is None
    assert suggest("", ["COLLECT"]) is None


def test_string_form_includes_code_and_hint():
    err = JockySyntaxError("bad", line=3, column=1, code="JKY205", hint="Did you mean 'COLLECT'?")
    text = str(err)
    assert "[JKY205]" in text
    assert "line 3" in text
    assert "Did you mean 'COLLECT'?" in text
