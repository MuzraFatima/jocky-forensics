"""
JOCKY DSL Error Types

Provides structured exceptions for Lexer, Parser, and Validator errors
with line and column context for easy troubleshooting and investigator reporting.
"""

from typing import Optional


class JockyError(Exception):
    """Base class for all JOCKY DSL exceptions."""

    def __init__(self, message: str, line: Optional[int] = None, column: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.line = line
        self.column = column

    def to_dict(self) -> dict:
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
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
        return f"{self.__class__.__name__}{location_str}: {self.message}"


class JockySyntaxError(JockyError):
    """Raised during tokenization or syntactic parsing failure."""
    pass


class JockyValidationError(JockyError):
    """Raised when an AST violates grammatical, structural, or policy rules."""
    pass
