"""
JOCKY DSL Parser

Parses a stream of tokens into an Abstract Syntax Tree (ProgramNode).
Ensures strict command syntax and raises JockySyntaxError with line and column info.

Phase-1 additions:
  - COLLECT PROCESSES / NETWORK accepts an optional WHERE <field> == <value> clause
  - ANALYZE accepts an optional analysis target (e.g., PROCESS_NETWORK)
  - REPORT accepts an optional FORMAT <format> qualifier (e.g., FORMAT JSON)
  - Useful error messages that name expected tokens vs received token
"""

from typing import List, Optional
from .tokens import Token, TokenType
from .ast import (
    ASTNode,
    AnalyzeNode,
    CaseNode,
    CollectNode,
    FilterExpression,
    ProgramNode,
    ReportNode,
    TargetNode,
    VerifyNode,
)
from .errors import JockySyntaxError


# ---------------------------------------------------------------------------
# Token sets
# ---------------------------------------------------------------------------

# Tokens that can appear as the field name in a WHERE clause
_FILTER_FIELD_TOKENS = {
    TokenType.STATUS,
    TokenType.STATE,
    TokenType.IDENTIFIER,
}

# Tokens that can appear as the value in a WHERE clause
_FILTER_VALUE_TOKENS = {
    TokenType.RUNNING,
    TokenType.ESTABLISHED,
    TokenType.IDENTIFIER,
    TokenType.STRING,
    TokenType.INTEGER,
}

# Supported COLLECT categories
_COLLECT_CATEGORIES = {
    TokenType.SYSTEM,
    TokenType.PROCESSES,
    TokenType.NETWORK,
    TokenType.FILES,
    TokenType.USERS,
    TokenType.REGISTRY,
    TokenType.WINDOWS_METADATA,
}

# COLLECT categories that support WHERE filters
_FILTERABLE_CATEGORIES = {
    TokenType.PROCESSES,
    TokenType.NETWORK,
}


class Parser:
    """Recursive descent parser for JOCKY DSL."""

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.position = 0

    # ─── Core token navigation ────────────────────────────────────────────────

    def _peek(self) -> Token:
        if self.position < len(self.tokens):
            return self.tokens[self.position]
        return self.tokens[-1]

    def _advance(self) -> Token:
        token = self._peek()
        if self.position < len(self.tokens):
            self.position += 1
        return token

    def _check(self, token_type: TokenType) -> bool:
        return self._peek().type == token_type

    def _match(self, token_type: TokenType) -> bool:
        if self._check(token_type):
            self._advance()
            return True
        return False

    def _consume(self, token_type: TokenType, error_message: str) -> Token:
        token = self._peek()
        if token.type == token_type:
            return self._advance()
        raise JockySyntaxError(error_message, token.line, token.column)

    def _skip_newlines(self) -> None:
        while self._match(TokenType.NEWLINE):
            pass

    def _assert_end_of_statement(self, command_name: str) -> None:
        """Ensure the current position is at a NEWLINE or EOF."""
        token = self._peek()
        if token.type not in (TokenType.NEWLINE, TokenType.EOF):
            raise JockySyntaxError(
                f"Unexpected token '{token.value}' after {command_name} statement",
                token.line,
                token.column,
            )

    # ─── WHERE clause parser ──────────────────────────────────────────────────

    def _try_parse_where_filter(self) -> Optional[FilterExpression]:
        """
        Attempt to parse an optional WHERE clause that follows a COLLECT statement.

        Grammar (simplified):
            where_clause := NEWLINE WHERE field_token EQ value_token

        The WHERE keyword must appear on the very next non-empty line.
        Returns None if no WHERE is found (the clause is optional).
        """
        # Save position so we can backtrack if no WHERE found
        saved_pos = self.position

        # Skip exactly one newline then look for WHERE
        if not self._check(TokenType.NEWLINE):
            return None
        self._advance()  # consume NEWLINE

        # Skip any additional blank lines
        while self._check(TokenType.NEWLINE):
            self._advance()

        if not self._check(TokenType.WHERE):
            # Not a WHERE clause — restore position so caller keeps the newlines
            self.position = saved_pos
            return None

        where_tok = self._advance()  # consume WHERE

        # Expect a field name (STATUS, STATE, or an identifier)
        field_tok = self._peek()
        if field_tok.type not in _FILTER_FIELD_TOKENS:
            raise JockySyntaxError(
                f"Expected filter field name (e.g., 'status', 'state') after WHERE, got '{field_tok.value}'",
                field_tok.line,
                field_tok.column,
            )
        field_tok = self._advance()

        # Expect == operator
        eq_tok = self._peek()
        if eq_tok.type != TokenType.EQ:
            raise JockySyntaxError(
                f"Expected '==' after filter field '{field_tok.value}', got '{eq_tok.value}'",
                eq_tok.line,
                eq_tok.column,
            )
        self._advance()  # consume ==

        # Expect a value
        val_tok = self._peek()
        if val_tok.type not in _FILTER_VALUE_TOKENS:
            raise JockySyntaxError(
                f"Expected filter value (e.g., RUNNING, ESTABLISHED) after '==', got '{val_tok.value}'",
                val_tok.line,
                val_tok.column,
            )
        val_tok = self._advance()

        return FilterExpression(
            field=field_tok.value.lower(),
            operator="==",
            value=val_tok.value if isinstance(val_tok.value, str) else str(val_tok.value),
            line=where_tok.line,
            column=where_tok.column,
        )

    # ─── Top-level parse ──────────────────────────────────────────────────────

    def parse(self) -> ProgramNode:
        """Parse all tokens into a ProgramNode."""
        statements: List[ASTNode] = []
        start_line = self.tokens[0].line if self.tokens else 1
        start_col = self.tokens[0].column if self.tokens else 1

        self._skip_newlines()

        while not self._check(TokenType.EOF):
            stmt = self._parse_statement()
            statements.append(stmt)
            self._skip_newlines()

        return ProgramNode(statements=statements, line=start_line, column=start_col)

    # ─── Statement parsers ────────────────────────────────────────────────────

    def _parse_statement(self) -> ASTNode:
        token = self._peek()

        # 1. CASE "<id>"
        if self._match(TokenType.CASE):
            str_tok = self._peek()
            if str_tok.type != TokenType.STRING:
                raise JockySyntaxError(
                    f"Expected case identifier string after CASE, got '{str_tok.value}'",
                    str_tok.line,
                    str_tok.column,
                )
            self._advance()
            self._assert_end_of_statement("CASE")
            return CaseNode(case_id=str_tok.value, line=token.line, column=token.column)

        # 2. TARGET "<name>"
        if self._match(TokenType.TARGET):
            str_tok = self._peek()
            if str_tok.type != TokenType.STRING:
                raise JockySyntaxError(
                    f"Expected target name string after TARGET, got '{str_tok.value}'",
                    str_tok.line,
                    str_tok.column,
                )
            self._advance()
            self._assert_end_of_statement("TARGET")
            return TargetNode(target_name=str_tok.value, line=token.line, column=token.column)

        # 3. COLLECT <category> [WHERE <field> == <value>]
        if self._match(TokenType.COLLECT):
            return self._parse_collect(token)

        # 4. ANALYZE [<target>]
        if self._match(TokenType.ANALYZE):
            return self._parse_analyze(token)

        # 5. VERIFY INTEGRITY
        if self._match(TokenType.VERIFY):
            target_tok = self._peek()
            if target_tok.type != TokenType.INTEGRITY:
                raise JockySyntaxError(
                    f"Expected 'INTEGRITY' after 'VERIFY', got '{target_tok.value}'",
                    target_tok.line,
                    target_tok.column,
                )
            self._advance()
            self._assert_end_of_statement("VERIFY INTEGRITY")
            return VerifyNode(verify_target="INTEGRITY", line=token.line, column=token.column)

        # 6. REPORT [FORMAT <format>]
        if self._match(TokenType.REPORT):
            return self._parse_report(token)

        # Unknown / unrecognized command
        raise JockySyntaxError(
            f"Unknown command or unexpected token '{token.value}'.\n"
            f"Expected: CASE | TARGET | COLLECT | ANALYZE | VERIFY | REPORT",
            token.line,
            token.column,
        )

    def _parse_collect(self, collect_token: Token) -> CollectNode:
        """Parse: COLLECT <category> [WHERE <field> == <value>]"""
        cat_tok = self._peek()

        if cat_tok.type not in _COLLECT_CATEGORIES:
            raise JockySyntaxError(
                f"Invalid COLLECT target '{cat_tok.value}'.\n"
                f"Expected: SYSTEM | PROCESSES | NETWORK | FILES | USERS | REGISTRY | WINDOWS_METADATA",
                cat_tok.line,
                cat_tok.column,
            )

        self._advance()  # consume category

        # COLLECT FILES "<path>"
        if cat_tok.type == TokenType.FILES:
            path_tok = self._peek()
            if path_tok.type != TokenType.STRING:
                raise JockySyntaxError(
                    f"Expected directory path string after 'COLLECT FILES', got '{path_tok.value}'",
                    path_tok.line,
                    path_tok.column,
                )
            self._advance()
            self._assert_end_of_statement("COLLECT FILES")
            return CollectNode(
                category="FILES",
                path=path_tok.value,
                line=collect_token.line,
                column=collect_token.column,
            )

        # Standalone collections without filters: SYSTEM, USERS, REGISTRY, WINDOWS_METADATA
        if cat_tok.type in (TokenType.SYSTEM, TokenType.USERS, TokenType.REGISTRY, TokenType.WINDOWS_METADATA):
            self._assert_end_of_statement(f"COLLECT {cat_tok.value}")
            return CollectNode(
                category=cat_tok.value,
                line=collect_token.line,
                column=collect_token.column,
            )

        # COLLECT PROCESSES / NETWORK — optional WHERE clause
        filters = []
        f = self._try_parse_where_filter()
        if f is not None:
            filters.append(f)

        return CollectNode(
            category=cat_tok.value,
            filters=filters,
            line=collect_token.line,
            column=collect_token.column,
        )

    def _parse_analyze(self, analyze_token: Token) -> AnalyzeNode:
        """Parse: ANALYZE [PROCESS_NETWORK | <identifier>]"""
        # Optional analysis target on same line
        next_tok = self._peek()
        analysis_target: Optional[str] = None

        if next_tok.type == TokenType.PROCESS_NETWORK:
            self._advance()
            analysis_target = "PROCESS_NETWORK"
        elif next_tok.type == TokenType.IDENTIFIER:
            # Accept bare identifiers as targets for forward compatibility
            self._advance()
            analysis_target = next_tok.value.upper()

        self._assert_end_of_statement("ANALYZE")
        return AnalyzeNode(
            analysis_target=analysis_target,
            line=analyze_token.line,
            column=analyze_token.column,
        )

    def _parse_report(self, report_token: Token) -> ReportNode:
        """Parse: REPORT [FORMAT JSON]"""
        fmt: Optional[str] = None

        next_tok = self._peek()
        if next_tok.type == TokenType.FORMAT:
            self._advance()  # consume FORMAT
            fmt_val_tok = self._peek()
            if fmt_val_tok.type == TokenType.JSON:
                self._advance()
                fmt = "JSON"
            elif fmt_val_tok.type == TokenType.IDENTIFIER:
                self._advance()
                fmt = fmt_val_tok.value.upper()
            else:
                raise JockySyntaxError(
                    f"Expected report format (e.g., JSON) after FORMAT, got '{fmt_val_tok.value}'",
                    fmt_val_tok.line,
                    fmt_val_tok.column,
                )

        self._assert_end_of_statement("REPORT")
        return ReportNode(
            format=fmt,
            line=report_token.line,
            column=report_token.column,
        )
