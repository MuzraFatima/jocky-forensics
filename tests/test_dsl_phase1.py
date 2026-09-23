"""
JOCKY DSL Phase-1 Tests

Covers:
  - Lexer: keyword recognition, strings, identifiers, operators, integers, newlines, comments
  - Parser: complete valid program, all collection types, filters, analyze, verify, report
  - Semantic Validation: missing CASE/TARGET, no collection, duplicate CASE/TARGET,
                         invalid filter field/value, invalid report format, verify ordering
  - IR: correct structure, case_id, target, operations, filters, report format
  - Compiler (compile_jocky): success path, syntax error path, validation error path

All existing tests are preserved in their respective test files.
"""

import pytest

from backend.app.language import (
    JockySyntaxError,
    JockyValidationError,
    compile_jocky,
    parse_jocky_script,
)
from backend.app.language.ir import IR_VERSION, build_ir
from backend.app.language.lexer import Lexer
from backend.app.language.parser import Parser
from backend.app.language.tokens import TokenType
from backend.app.language.validator import Validator


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — LEXER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestLexer:

    def _lex(self, source: str):
        return Lexer(source).tokenize()

    def _types(self, source: str):
        return [t.type for t in self._lex(source) if t.type not in (TokenType.NEWLINE, TokenType.EOF)]

    # 1.1 Keyword recognition
    def test_all_phase1_keywords_recognized(self):
        source = "CASE TARGET COLLECT SYSTEM PROCESSES NETWORK ANALYZE VERIFY INTEGRITY REPORT"
        types = self._types(source)
        assert TokenType.CASE in types
        assert TokenType.TARGET in types
        assert TokenType.COLLECT in types
        assert TokenType.SYSTEM in types
        assert TokenType.PROCESSES in types
        assert TokenType.NETWORK in types
        assert TokenType.ANALYZE in types
        assert TokenType.VERIFY in types
        assert TokenType.INTEGRITY in types
        assert TokenType.REPORT in types

    def test_filter_keywords_recognized(self):
        source = "WHERE STATUS RUNNING STATE ESTABLISHED FORMAT JSON PROCESS_NETWORK"
        types = self._types(source)
        assert TokenType.WHERE in types
        assert TokenType.STATUS in types
        assert TokenType.RUNNING in types
        assert TokenType.STATE in types
        assert TokenType.ESTABLISHED in types
        assert TokenType.FORMAT in types
        assert TokenType.JSON in types
        assert TokenType.PROCESS_NETWORK in types

    def test_keywords_case_insensitive(self):
        tokens = self._lex("case \"X\"\ntarget \"Y\"")
        types = [t.type for t in tokens]
        assert TokenType.CASE in types
        assert TokenType.TARGET in types

    # 1.2 String literals
    def test_string_token(self):
        tokens = self._lex('"hello world"')
        assert tokens[0].type == TokenType.STRING
        assert tokens[0].value == "hello world"

    def test_string_with_escape(self):
        tokens = self._lex(r'"line1\nline2"')
        assert tokens[0].type == TokenType.STRING
        assert "\n" in tokens[0].value

    def test_unterminated_string_raises(self):
        with pytest.raises(JockySyntaxError):
            self._lex('"no closing quote')

    # 1.3 Identifiers
    def test_unknown_word_is_identifier(self):
        tokens = self._lex("FOOBAR")
        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[0].value == "FOOBAR"

    # 1.4 EQ operator
    def test_eq_operator(self):
        tokens = self._lex("==")
        assert tokens[0].type == TokenType.EQ
        assert tokens[0].value == "=="

    # 1.5 Integer literals
    def test_integer_token(self):
        tokens = self._lex("42")
        assert tokens[0].type == TokenType.INTEGER
        assert tokens[0].value == 42

    # 1.6 Newlines
    def test_newlines_emitted(self):
        tokens = self._lex("CASE\nTARGET")
        newlines = [t for t in tokens if t.type == TokenType.NEWLINE]
        assert len(newlines) >= 1

    def test_consecutive_newlines_deduplicated(self):
        tokens = self._lex("CASE\n\n\nTARGET")
        newlines = [t for t in tokens if t.type == TokenType.NEWLINE]
        # Should have at most one newline between keywords
        assert len(newlines) <= 2

    # 1.7 Comments
    def test_hash_comment_ignored(self):
        types = self._types("# this is a comment\nCASE")
        assert TokenType.CASE in types
        assert TokenType.IDENTIFIER not in types

    def test_double_slash_comment_ignored(self):
        types = self._types("// this is a comment\nCASE")
        assert TokenType.CASE in types

    # 1.8 Line/column tracking
    def test_line_column_tracking(self):
        tokens = self._lex('CASE "X"\nTARGET "Y"')
        case_tok = next(t for t in tokens if t.type == TokenType.CASE)
        target_tok = next(t for t in tokens if t.type == TokenType.TARGET)
        assert case_tok.line == 1
        assert target_tok.line == 2

    # 1.9 Unexpected character
    def test_unexpected_character_raises(self):
        with pytest.raises(JockySyntaxError):
            self._lex("@BAD")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — PARSER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestParser:

    def _parse(self, source: str):
        tokens = Lexer(source).tokenize()
        return Parser(tokens).parse()

    # 2.1 Complete valid program (Phase-1 canonical)
    def test_parse_canonical_phase1_program(self):
        source = '''\
CASE "LAB-2026-001"
TARGET "LAB-PC"
COLLECT SYSTEM
COLLECT PROCESSES
    WHERE status == RUNNING
COLLECT NETWORK
    WHERE state == ESTABLISHED
ANALYZE PROCESS_NETWORK
VERIFY INTEGRITY
REPORT FORMAT JSON
'''
        program = self._parse(source)
        assert program is not None
        assert len(program.statements) == 8  # CASE, TARGET, 3×COLLECT, ANALYZE, VERIFY, REPORT

    # 2.2 CASE node
    def test_parse_case_node(self):
        from backend.app.language.ast import CaseNode
        program = self._parse('CASE "LAB-001"\nTARGET "H"\nCOLLECT SYSTEM')
        case_node = program.statements[0]
        assert isinstance(case_node, CaseNode)
        assert case_node.case_id == "LAB-001"

    # 2.3 TARGET node
    def test_parse_target_node(self):
        from backend.app.language.ast import TargetNode
        program = self._parse('CASE "C"\nTARGET "LAB-PC"\nCOLLECT SYSTEM')
        target_node = program.statements[1]
        assert isinstance(target_node, TargetNode)
        assert target_node.target_name == "LAB-PC"

    # 2.4 COLLECT SYSTEM — no filter
    def test_parse_collect_system_no_filter(self):
        from backend.app.language.ast import CollectNode
        program = self._parse('CASE "C"\nTARGET "T"\nCOLLECT SYSTEM')
        collect = program.statements[2]
        assert isinstance(collect, CollectNode)
        assert collect.category == "SYSTEM"
        assert collect.filters == []

    # 2.5 COLLECT PROCESSES with WHERE filter
    def test_parse_collect_processes_with_filter(self):
        from backend.app.language.ast import CollectNode, FilterExpression
        program = self._parse('CASE "C"\nTARGET "T"\nCOLLECT PROCESSES\n    WHERE status == RUNNING')
        collect = program.statements[2]
        assert isinstance(collect, CollectNode)
        assert collect.category == "PROCESSES"
        assert len(collect.filters) == 1
        f = collect.filters[0]
        assert isinstance(f, FilterExpression)
        assert f.field == "status"
        assert f.operator == "=="
        assert f.value == "RUNNING"

    # 2.6 COLLECT NETWORK with WHERE filter
    def test_parse_collect_network_with_filter(self):
        from backend.app.language.ast import CollectNode
        program = self._parse('CASE "C"\nTARGET "T"\nCOLLECT NETWORK\n    WHERE state == ESTABLISHED')
        collect = program.statements[2]
        assert isinstance(collect, CollectNode)
        assert collect.category == "NETWORK"
        assert len(collect.filters) == 1
        assert collect.filters[0].field == "state"
        assert collect.filters[0].value == "ESTABLISHED"

    # 2.7 COLLECT without filter
    def test_parse_collect_processes_no_filter(self):
        from backend.app.language.ast import CollectNode
        program = self._parse('CASE "C"\nTARGET "T"\nCOLLECT PROCESSES')
        collect = program.statements[2]
        assert isinstance(collect, CollectNode)
        assert collect.filters == []

    # 2.8 ANALYZE with PROCESS_NETWORK target
    def test_parse_analyze_process_network(self):
        from backend.app.language.ast import AnalyzeNode
        program = self._parse('CASE "C"\nTARGET "T"\nCOLLECT SYSTEM\nANALYZE PROCESS_NETWORK')
        analyze = program.statements[3]
        assert isinstance(analyze, AnalyzeNode)
        assert analyze.analysis_target == "PROCESS_NETWORK"

    # 2.9 ANALYZE without target (backward-compat)
    def test_parse_analyze_no_target(self):
        from backend.app.language.ast import AnalyzeNode
        program = self._parse('CASE "C"\nTARGET "T"\nCOLLECT SYSTEM\nANALYZE')
        analyze = program.statements[3]
        assert isinstance(analyze, AnalyzeNode)
        assert analyze.analysis_target is None

    # 2.10 VERIFY INTEGRITY
    def test_parse_verify_integrity(self):
        from backend.app.language.ast import VerifyNode
        program = self._parse('CASE "C"\nTARGET "T"\nCOLLECT SYSTEM\nVERIFY INTEGRITY')
        verify = program.statements[3]
        assert isinstance(verify, VerifyNode)
        assert verify.verify_target == "INTEGRITY"

    # 2.11 REPORT FORMAT JSON
    def test_parse_report_format_json(self):
        from backend.app.language.ast import ReportNode
        program = self._parse('CASE "C"\nTARGET "T"\nCOLLECT SYSTEM\nREPORT FORMAT JSON')
        report = program.statements[3]
        assert isinstance(report, ReportNode)
        assert report.format == "JSON"

    # 2.12 REPORT without format
    def test_parse_report_no_format(self):
        from backend.app.language.ast import ReportNode
        program = self._parse('CASE "C"\nTARGET "T"\nCOLLECT SYSTEM\nREPORT')
        report = program.statements[3]
        assert isinstance(report, ReportNode)
        assert report.format is None

    # 2.13 Unknown command raises JockySyntaxError
    def test_parse_unknown_command_raises(self):
        with pytest.raises(JockySyntaxError) as exc_info:
            self._parse('CASE "C"\nTARGET "T"\nCOLLECT CAMERA')
        assert exc_info.value.line is not None

    # 2.14 Invalid COLLECT category with helpful message
    def test_parse_invalid_collect_target_message(self):
        with pytest.raises(JockySyntaxError) as exc_info:
            self._parse('CASE "C"\nTARGET "T"\nCOLLECT CAMERA')
        assert "CAMERA" in exc_info.value.message or "Invalid" in exc_info.value.message

    # 2.15 Invalid WHERE field raises
    def test_parse_where_missing_eq_raises(self):
        with pytest.raises(JockySyntaxError):
            self._parse('CASE "C"\nTARGET "T"\nCOLLECT PROCESSES\n    WHERE status RUNNING')

    # 2.16 VERIFY without INTEGRITY raises
    def test_parse_verify_without_integrity_raises(self):
        with pytest.raises(JockySyntaxError):
            self._parse('CASE "C"\nTARGET "T"\nCOLLECT SYSTEM\nVERIFY SYSTEM')


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — SEMANTIC VALIDATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidation:

    def _validate(self, source: str):
        """Convenience: lex → parse → validate → execution plan."""
        return parse_jocky_script(source)

    # 3.1 Missing CASE
    def test_missing_case_raises(self):
        with pytest.raises(JockyValidationError) as exc_info:
            self._validate('TARGET "T"\nCOLLECT SYSTEM')
        assert "CASE" in exc_info.value.message

    # 3.2 Missing TARGET
    def test_missing_target_raises(self):
        with pytest.raises(JockyValidationError) as exc_info:
            self._validate('CASE "C"\nCOLLECT SYSTEM')
        assert "TARGET" in exc_info.value.message

    # 3.3 No COLLECT
    def test_no_collect_raises(self):
        with pytest.raises(JockyValidationError) as exc_info:
            self._validate('CASE "C"\nTARGET "T"\nANALYZE\nREPORT')
        assert "COLLECT" in exc_info.value.message

    # 3.4 Duplicate CASE
    def test_duplicate_case_raises(self):
        with pytest.raises(JockyValidationError) as exc_info:
            self._validate('CASE "C1"\nCASE "C2"\nTARGET "T"\nCOLLECT SYSTEM')
        assert "Duplicate" in exc_info.value.message and "CASE" in exc_info.value.message

    # 3.5 Duplicate TARGET
    def test_duplicate_target_raises(self):
        with pytest.raises(JockyValidationError) as exc_info:
            self._validate('CASE "C"\nTARGET "T1"\nTARGET "T2"\nCOLLECT SYSTEM')
        assert "Duplicate" in exc_info.value.message and "TARGET" in exc_info.value.message

    # 3.6 Invalid filter field for PROCESSES
    def test_invalid_filter_field_processes_raises(self):
        with pytest.raises(JockyValidationError) as exc_info:
            self._validate('CASE "C"\nTARGET "T"\nCOLLECT PROCESSES\n    WHERE state == RUNNING')
        assert "Invalid filter field" in exc_info.value.message

    # 3.7 Invalid filter field for NETWORK
    def test_invalid_filter_field_network_raises(self):
        with pytest.raises(JockyValidationError) as exc_info:
            self._validate('CASE "C"\nTARGET "T"\nCOLLECT NETWORK\n    WHERE status == ESTABLISHED')
        assert "Invalid filter field" in exc_info.value.message

    # 3.8 Invalid filter value
    def test_invalid_filter_value_raises(self):
        with pytest.raises(JockyValidationError) as exc_info:
            self._validate('CASE "C"\nTARGET "T"\nCOLLECT PROCESSES\n    WHERE status == INVISIBLE')
        assert "Invalid filter value" in exc_info.value.message

    # 3.9 VERIFY before any COLLECT evidence
    def test_verify_without_evidence_collect_raises(self):
        with pytest.raises(JockyValidationError) as exc_info:
            self._validate('CASE "C"\nTARGET "T"\nVERIFY INTEGRITY\nCOLLECT SYSTEM')
        assert "VERIFY" in exc_info.value.message or "evidence" in exc_info.value.message.lower()

    # 3.10 Unsupported report format
    def test_unsupported_report_format_raises(self):
        with pytest.raises(JockyValidationError) as exc_info:
            self._validate('CASE "C"\nTARGET "T"\nCOLLECT SYSTEM\nREPORT FORMAT XML')
        assert "format" in exc_info.value.message.lower() or "XML" in exc_info.value.message

    # 3.11 Valid program with all Phase-1 features passes validation
    def test_full_phase1_program_validates(self):
        result = self._validate('''\
CASE "LAB-2026-001"
TARGET "LAB-PC"
COLLECT SYSTEM
COLLECT PROCESSES
    WHERE status == RUNNING
COLLECT NETWORK
    WHERE state == ESTABLISHED
ANALYZE PROCESS_NETWORK
VERIFY INTEGRITY
REPORT FORMAT JSON
''')
        assert result["success"] is True
        assert result["execution_plan"]["case_id"] == "LAB-2026-001"
        assert result["execution_plan"]["target"] == "LAB-PC"

    # 3.12 Filters appear in execution plan tasks
    def test_filter_in_execution_plan(self):
        result = self._validate(
            'CASE "C"\nTARGET "T"\nCOLLECT PROCESSES\n    WHERE status == RUNNING'
        )
        tasks = result["execution_plan"]["tasks"]
        collect_task = next(t for t in tasks if t["action"] == "COLLECT" and t["category"] == "PROCESSES")
        assert "filters" in collect_task
        assert collect_task["filters"][0]["field"] == "status"
        assert collect_task["filters"][0]["value"] == "RUNNING"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — IR TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestIR:

    CANONICAL = '''\
CASE "LAB-2026-001"
TARGET "LAB-PC"
COLLECT SYSTEM
COLLECT PROCESSES
    WHERE status == RUNNING
COLLECT NETWORK
    WHERE state == ESTABLISHED
ANALYZE PROCESS_NETWORK
VERIFY INTEGRITY
REPORT FORMAT JSON
'''

    def _build_ir(self, source: str):
        from backend.app.language.lexer import Lexer
        from backend.app.language.parser import Parser
        tokens = Lexer(source).tokenize()
        program = Parser(tokens).parse()
        return build_ir(program)

    def test_ir_version(self):
        ir = self._build_ir(self.CANONICAL)
        assert ir["version"] == IR_VERSION
        assert ir["version"] == "1.0"

    def test_ir_case_id(self):
        ir = self._build_ir(self.CANONICAL)
        assert ir["case_id"] == "LAB-2026-001"

    def test_ir_target(self):
        ir = self._build_ir(self.CANONICAL)
        assert ir["target"] == "LAB-PC"

    def test_ir_operation_count(self):
        ir = self._build_ir(self.CANONICAL)
        # COLLECT SYSTEM, COLLECT PROCESSES, COLLECT NETWORK, ANALYZE, VERIFY, REPORT = 6 ops
        assert len(ir["operations"]) == 6

    def test_ir_operation_order(self):
        ir = self._build_ir(self.CANONICAL)
        types = [op["type"] for op in ir["operations"]]
        assert types == ["COLLECT", "COLLECT", "COLLECT", "ANALYZE", "VERIFY", "REPORT"]

    def test_ir_collect_system_no_filters(self):
        ir = self._build_ir(self.CANONICAL)
        collect_system = ir["operations"][0]
        assert collect_system["type"] == "COLLECT"
        assert collect_system["target"] == "SYSTEM"
        assert "filters" not in collect_system

    def test_ir_collect_processes_filter(self):
        ir = self._build_ir(self.CANONICAL)
        collect_proc = ir["operations"][1]
        assert collect_proc["target"] == "PROCESSES"
        assert "filters" in collect_proc
        assert len(collect_proc["filters"]) == 1
        f = collect_proc["filters"][0]
        assert f["field"] == "status"
        assert f["operator"] == "=="
        assert f["value"] == "RUNNING"

    def test_ir_collect_network_filter(self):
        ir = self._build_ir(self.CANONICAL)
        collect_net = ir["operations"][2]
        assert collect_net["target"] == "NETWORK"
        filters = collect_net["filters"]
        assert filters[0]["field"] == "state"
        assert filters[0]["value"] == "ESTABLISHED"

    def test_ir_analyze_target(self):
        ir = self._build_ir(self.CANONICAL)
        analyze_op = ir["operations"][3]
        assert analyze_op["type"] == "ANALYZE"
        assert analyze_op.get("target") == "PROCESS_NETWORK"

    def test_ir_verify_target(self):
        ir = self._build_ir(self.CANONICAL)
        verify_op = ir["operations"][4]
        assert verify_op["type"] == "VERIFY"
        assert verify_op["target"] == "INTEGRITY"

    def test_ir_report_format(self):
        ir = self._build_ir(self.CANONICAL)
        report_op = ir["operations"][5]
        assert report_op["type"] == "REPORT"
        assert report_op.get("format") == "JSON"

    def test_ir_no_operations_for_declarations(self):
        """CASE and TARGET must NOT appear as IR operations."""
        ir = self._build_ir(self.CANONICAL)
        op_types = [op["type"] for op in ir["operations"]]
        assert "CASE" not in op_types
        assert "TARGET" not in op_types


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — COMPILER ENTRY POINT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCompiler:

    VALID_SOURCE = '''\
CASE "LAB-2026-001"
TARGET "LAB-PC"
COLLECT SYSTEM
COLLECT PROCESSES
    WHERE status == RUNNING
COLLECT NETWORK
    WHERE state == ESTABLISHED
ANALYZE PROCESS_NETWORK
VERIFY INTEGRITY
REPORT FORMAT JSON
'''

    def test_successful_compilation_returns_success_true(self):
        result = compile_jocky(self.VALID_SOURCE)
        assert result["success"] is True

    def test_successful_compilation_returns_ast(self):
        result = compile_jocky(self.VALID_SOURCE)
        assert "ast" in result
        assert result["ast"]["type"] == "ProgramNode"

    def test_successful_compilation_returns_ir(self):
        result = compile_jocky(self.VALID_SOURCE)
        assert "ir" in result
        ir = result["ir"]
        assert ir["version"] == "1.0"
        assert ir["case_id"] == "LAB-2026-001"
        assert ir["target"] == "LAB-PC"
        assert len(ir["operations"]) == 6

    def test_successful_compilation_returns_execution_plan(self):
        """execution_plan key preserved for backward compat."""
        result = compile_jocky(self.VALID_SOURCE)
        assert "execution_plan" in result

    def test_successful_compilation_tokens_count_positive(self):
        result = compile_jocky(self.VALID_SOURCE)
        assert result["tokens_count"] > 0

    def test_syntax_error_returns_success_false(self):
        result = compile_jocky('CASE "C"\nTARGET "T"\nCOLLECT CAMERA')
        assert result["success"] is False

    def test_syntax_error_contains_error_dict(self):
        result = compile_jocky('CASE "C"\nTARGET "T"\nCOLLECT CAMERA')
        assert "error" in result
        err = result["error"]
        assert "error_type" in err
        assert "message" in err

    def test_syntax_error_line_info(self):
        result = compile_jocky('CASE "C"\nTARGET "T"\nCOLLECT CAMERA')
        assert result["error"]["line"] == 3

    def test_semantic_error_returns_success_false(self):
        result = compile_jocky('TARGET "T"\nCOLLECT SYSTEM')
        assert result["success"] is False
        assert "CASE" in result["error"]["message"]

    def test_compile_jocky_never_raises(self):
        """compile_jocky must never raise — all errors returned in result dict."""
        # Various malformed inputs
        for bad_source in [
            "",
            "THIS IS COMPLETELY INVALID @@@",
            'CASE "C"\nCOLLECT SYSTEM',
            'CASE "C"\nTARGET "T"\nCOLLECT PROCESSES\n    WHERE status == INVISIBLE',
        ]:
            try:
                result = compile_jocky(bad_source)
                assert "success" in result
            except Exception as exc:
                pytest.fail(f"compile_jocky raised an exception for input {bad_source!r}: {exc}")

    def test_compile_jocky_pipeline_label(self):
        """The full pipeline must produce the expected stages."""
        result = compile_jocky(self.VALID_SOURCE)
        # IR operations should include COLLECT, ANALYZE, VERIFY, REPORT
        types = [op["type"] for op in result["ir"]["operations"]]
        assert "COLLECT" in types
        assert "ANALYZE" in types
        assert "VERIFY" in types
        assert "REPORT" in types
