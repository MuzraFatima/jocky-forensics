"""
JOCKY DSL Language Package

Implements lexing, parsing, AST generation, semantic validation,
IR emission, and compiler orchestration for the JOCKY forensic language.

Phase-1 pipeline:
    Source → Lexer → Parser → AST → Semantic Validation → JOCKY IR
"""

from typing import Any, Dict

from .ast import (
    AnalyzeNode,
    ASTNode,
    CaseNode,
    CollectNode,
    FilterExpression,
    ProgramNode,
    ReportNode,
    TargetNode,
    VerifyNode,
)
from .compiler import compile_jocky
from .errors import JockyError, JockySyntaxError, JockyValidationError
from .ir import build_ir, IR_VERSION
from .lexer import Lexer
from .parser import Parser
from .tokens import Token, TokenType
from .validator import Validator


def parse_jocky_script(script_text: str) -> Dict[str, Any]:
    """
    Complete pipeline:
        Source Code → Tokens → AST → Validated Execution Plan.

    Returns a dict with::

        {
            "success": True,
            "tokens_count": ...,
            "ast": <dict>,
            "execution_plan": <dict>,
            "ir": <dict>
        }

    Raises JockySyntaxError or JockyValidationError on failure.

    Note:
        This function is the legacy entry point, preserved for backward
        compatibility with all existing tests and API endpoints.
        For new code, prefer :func:`compile_jocky` which never raises.
    """
    lexer = Lexer(script_text)
    tokens = lexer.tokenize()

    parser = Parser(tokens)
    ast_node = parser.parse()

    validator = Validator()
    plan = validator.validate_and_plan(ast_node)

    ir = build_ir(ast_node)

    return {
        "success": True,
        "tokens_count": len(tokens),
        "ast": ast_node.to_dict(),
        "execution_plan": plan,
        "ir": ir,
    }


__all__ = [
    # Tokens
    "TokenType",
    "Token",
    # Core pipeline
    "Lexer",
    "Parser",
    "Validator",
    # AST nodes
    "ASTNode",
    "ProgramNode",
    "CaseNode",
    "TargetNode",
    "CollectNode",
    "FilterExpression",
    "AnalyzeNode",
    "VerifyNode",
    "ReportNode",
    # IR
    "build_ir",
    "IR_VERSION",
    # Compiler
    "compile_jocky",
    # Errors
    "JockyError",
    "JockySyntaxError",
    "JockyValidationError",
    # Legacy entry point
    "parse_jocky_script",
]
