"""
Unit tests for JOCKY DSL Parser, Validator, and Execution Plan generation.
"""

import pytest
from backend.app.language import (
    JockySyntaxError,
    JockyValidationError,
    parse_jocky_script,
)


def test_valid_canonical_script():
    """1. Test valid canonical script with all supported statements."""
    script = """
    CASE "LAB-2026-001"
    TARGET "LAB-PC"
    COLLECT SYSTEM
    COLLECT PROCESSES
    COLLECT NETWORK
    COLLECT FILES "./evidence"
    ANALYZE
    VERIFY INTEGRITY
    REPORT
    """
    result = parse_jocky_script(script)

    assert result["success"] is True
    assert result["ast"]["type"] == "ProgramNode"
    assert len(result["ast"]["statements"]) == 9

    plan = result["execution_plan"]
    assert plan["case_id"] == "LAB-2026-001"
    assert plan["target"] == "LAB-PC"
    assert plan["metadata"]["read_only"] is True
    assert plan["metadata"]["total_tasks"] == 7

    task_actions = [t["action"] for t in plan["tasks"]]
    assert task_actions == ["COLLECT", "COLLECT", "COLLECT", "COLLECT", "ANALYZE", "VERIFY", "REPORT"]
    assert plan["tasks"][3]["params"]["path"] == "./evidence"


def test_invalid_command():
    """2. Test invalid command raises JockySyntaxError."""
    script = """
    CASE "LAB-001"
    TARGET "LAB-PC"
    INJECT MALWARE
    """
    with pytest.raises(JockySyntaxError) as exc_info:
        parse_jocky_script(script)

    assert "Unknown command" in exc_info.value.message or "Unexpected" in exc_info.value.message
    assert exc_info.value.line == 4
    assert exc_info.value.column is not None


def test_missing_case():
    """3. Test missing CASE declaration raises JockyValidationError."""
    script = """
    TARGET "LAB-PC"
    COLLECT SYSTEM
    REPORT
    """
    with pytest.raises(JockyValidationError) as exc_info:
        parse_jocky_script(script)

    assert "Missing mandatory 'CASE'" in exc_info.value.message


def test_missing_target():
    """4. Test missing TARGET declaration raises JockyValidationError."""
    script = """
    CASE "LAB-001"
    COLLECT SYSTEM
    REPORT
    """
    with pytest.raises(JockyValidationError) as exc_info:
        parse_jocky_script(script)

    assert "Missing mandatory 'TARGET'" in exc_info.value.message


def test_duplicate_case():
    """5. Test duplicate CASE raises JockyValidationError."""
    script = """
    CASE "LAB-001"
    CASE "LAB-002"
    TARGET "LAB-PC"
    COLLECT SYSTEM
    """
    with pytest.raises(JockyValidationError) as exc_info:
        parse_jocky_script(script)

    assert "Duplicate 'CASE'" in exc_info.value.message
    assert exc_info.value.line == 3


def test_duplicate_target():
    """6. Test duplicate TARGET raises JockyValidationError."""
    script = """
    CASE "LAB-001"
    TARGET "PC-1"
    TARGET "PC-2"
    COLLECT SYSTEM
    """
    with pytest.raises(JockyValidationError) as exc_info:
        parse_jocky_script(script)

    assert "Duplicate 'TARGET'" in exc_info.value.message
    assert exc_info.value.line == 4


def test_invalid_collect_command():
    """7. Test invalid COLLECT target raises JockySyntaxError."""
    script = """
    CASE "LAB-001"
    TARGET "LAB-PC"
    COLLECT MEMORY_DUMP
    """
    with pytest.raises(JockySyntaxError) as exc_info:
        parse_jocky_script(script)

    assert "Invalid COLLECT target" in exc_info.value.message
    assert exc_info.value.line == 4


def test_invalid_syntax_with_line_column_info():
    """8. Test invalid syntax provides precise line and column numbers."""
    script = """CASE "LAB-001"
TARGET "LAB-PC"
COLLECT FILES
REPORT"""
    # Missing directory string for COLLECT FILES
    with pytest.raises(JockySyntaxError) as exc_info:
        parse_jocky_script(script)

    err = exc_info.value
    assert err.line == 3
    assert err.column > 0
    assert "Expected directory path string after 'COLLECT FILES'" in err.message


def test_unterminated_string_line_column():
    """Test unterminated string reports correct line and column."""
    script = 'CASE "LAB-001\nTARGET "LAB-PC"'
    with pytest.raises(JockySyntaxError) as exc_info:
        parse_jocky_script(script)

    assert exc_info.value.line == 1
    assert exc_info.value.column == 6
