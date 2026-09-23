"""
JOCKY DSL Compiler

Single entry point for the full Phase-1 compilation pipeline:

    Source
      ↓
    Lexer   (tokenize)
      ↓
    Parser  (build AST)
      ↓
    Semantic Validator  (validate AST, build execution plan)
      ↓
    IR Builder  (emit JOCKY IR)

Usage:
    from backend.app.language.compiler import compile_jocky

    result = compile_jocky(source)
    if result["success"]:
        ast = result["ast"]        # ProgramNode serialised as dict
        ir  = result["ir"]         # JOCKY IR dict (version, case_id, target, operations)
    else:
        print(result["error"])     # structured error dict

The compiler does NOT execute any operations.
"""

from typing import Any, Dict

from .errors import JockyError
from .ir import build_ir
from .lexer import Lexer
from .parser import Parser
from .validator import Validator


def compile_jocky(source: str) -> Dict[str, Any]:
    """
    Compile a JOCKY source string through the full Phase-1 pipeline.

    Returns on SUCCESS::

        {
            "success": True,
            "tokens_count": <int>,
            "ast": <dict>,           # ProgramNode.to_dict()
            "ir": <dict>,            # JOCKY IR v1.0
            "execution_plan": <dict> # legacy alias kept for backward-compat
        }

    Returns on FAILURE::

        {
            "success": False,
            "error": {
                "error_type": "<class name>",
                "message": "<human-readable>",
                "line": <int|None>,
                "column": <int|None>
            }
        }

    Raises:
        Never raises — all JockyError subclasses are caught and returned
        in the failure dict above.
    """
    try:
        # Step 1: Lex
        lexer = Lexer(source)
        tokens = lexer.tokenize()

        # Step 2: Parse
        parser = Parser(tokens)
        ast_node = parser.parse()

        # Step 3: Validate + build execution plan (legacy alias)
        validator = Validator()
        execution_plan = validator.validate_and_plan(ast_node)

        # Step 4: Build IR
        ir = build_ir(ast_node)

        return {
            "success": True,
            "tokens_count": len(tokens),
            "ast": ast_node.to_dict(),
            "ir": ir,
            # kept for existing tests and the /api/jocky/parse endpoint
            "execution_plan": execution_plan,
        }

    except JockyError as exc:
        return {
            "success": False,
            "error": exc.to_dict(),
        }
