"""
JOCKY DSL Error Types

Structured exceptions for the lexer, parser and validator. Every diagnostic
carries a source position, a stable error code and, where one makes sense,
a hint suggesting a correction (blueprint §4.2, "Diagnostics").

Error code ranges:
    JKY1xx  lexical errors (bad characters, unterminated strings)
    JKY2xx  syntax errors (unexpected or missing tokens)
    JKY3xx  semantic errors (missing declarations, invalid filters, ordering)
"""

import difflib
from typing import Iterable, Optional

ERROR_CODES = {
    "JKY101": "Unterminated string literal",
    "JKY102": "Unexpected character",
    "JKY200": "Expected token not found",
    "JKY201": "Unexpected trailing token after statement",
    "JKY202": "CASE requires a quoted identifier",
    "JKY203": "TARGET requires a quoted host name",
    "JKY204": "VERIFY must be followed by INTEGRITY",
    "JKY205": "Unknown command",
    "JKY206": "Unknown COLLECT target",
    "JKY207": "COLLECT FILES requires a quoted path",
    "JKY208": "Invalid report format token",
    "JKY209": "Unbalanced investigation block",
    "JKY210": "Malformed WHERE clause",
    "JKY211": "Invalid PLATFORM value",
    "JKY301": "Missing CASE declaration",
    "JKY302": "Duplicate CASE declaration",
    "JKY303": "Missing TARGET declaration",
    "JKY304": "Duplicate TARGET declaration",
    "JKY305": "Empty identifier",
    "JKY306": "Empty COLLECT FILES path",
    "JKY307": "No COLLECT operation",
    "JKY308": "Duplicate PLATFORM declaration",
    "JKY310": "Invalid filter field",
    "JKY311": "Invalid filter value",
    "JKY320": "VERIFY INTEGRITY before any evidence collection",
    "JKY330": "Unsupported report format",
}


def suggest(word: object, candidates: Iterable[str]) -> Optional[str]:
    """Return a 'did you mean' hint for a misspelt keyword, or None."""
    if not isinstance(word, str) or not word:
        return None
    pool = {c.upper(): c for c in candidates}
    matches = difflib.get_close_matches(word.upper(), list(pool), n=1, cutoff=0.6)
    if not matches:
        return None
    return f"Did you mean '{pool[matches[0]]}'?"


class JockyError(Exception):
    """Base class for all JOCKY DSL exceptions."""

    def __init__(
        self,
        message: str,
        line: Optional[int] = None,
        column: Optional[int] = None,
        code: Optional[str] = None,
        hint: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.line = line
        self.column = column
        self.code = code
        self.hint = hint

    def to_dict(self) -> dict:
        return {
            "error_type": self.__class__.__name__,
            "code": self.code,
            "message": self.message,
            "hint": self.hint,
            "line": self.line,
            "column": self.column,
        }

    def __str__(self) -> str:
        loc = []
        if self.line is not None:
            loc.append(f"line {self.line}")
        if self.column is not None:
            loc.append(f"column {self.column}")
        location_str = f" at {', '.join(loc)}" if loc else ""
        code_str = f" [{self.code}]" if self.code else ""
        hint_str = f" Hint: {self.hint}" if self.hint else ""
        return f"{self.__class__.__name__}{code_str}{location_str}: {self.message}{hint_str}"


class JockySyntaxError(JockyError):
    """Raised during tokenization or syntactic parsing failure."""


class JockyValidationError(JockyError):
    """Raised when an AST violates grammatical, structural, or policy rules."""
