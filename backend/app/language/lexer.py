"""
JOCKY DSL Lexer (Tokenizer)

Converts raw JOCKY script text into a linear stream of Token instances,
tracking line and column coordinates for syntax reporting.

Phase-1 additions:
  - Tokenises the `==` operator (EQ)
  - Tokenises integer literals
  - Recognises all Phase-1 keywords via the updated KEYWORDS map
  - Comment support: # and //
"""

from typing import List
from .tokens import KEYWORDS, Token, TokenType
from .errors import JockySyntaxError


class Lexer:
    """Tokenizer for the JOCKY Domain-Specific Language."""

    def __init__(self, source: str):
        self.source = source
        self.length = len(source)
        self.index = 0
        self.line = 1
        self.column = 1

    # ─── Internal helpers ────────────────────────────────────────────────────

    def _peek(self) -> str:
        """Look at the current character without advancing."""
        if self.index >= self.length:
            return ""
        return self.source[self.index]

    def _peek_next(self) -> str:
        """Look one character ahead without advancing."""
        if self.index + 1 >= self.length:
            return ""
        return self.source[self.index + 1]

    def _advance(self) -> str:
        """Consume and return the current character, updating position."""
        if self.index >= self.length:
            return ""
        ch = self.source[self.index]
        self.index += 1
        self.column += 1
        return ch

    def _skip_comment(self) -> None:
        """Skip characters until end-of-line (exclusive)."""
        while self.index < self.length and self._peek() not in ("\n", "\r"):
            self._advance()

    # ─── Token readers ────────────────────────────────────────────────────────

    def _read_string(self) -> Token:
        """Read a double-quoted string literal, handling basic escape sequences."""
        start_line = self.line
        start_col = self.column

        # Consume the opening quote
        self._advance()

        chars: List[str] = []
        while self.index < self.length:
            ch = self._peek()

            if ch == '"':
                self._advance()  # consume closing quote
                return Token(TokenType.STRING, "".join(chars), start_line, start_col)

            if ch in ("\n", "\r"):
                raise JockySyntaxError(
                    "Unterminated string literal: unexpected newline before closing quote",
                    start_line,
                    start_col,
                )

            if ch == "\\":
                self._advance()  # skip escape backslash
                escaped = self._advance()
                if escaped == "n":
                    chars.append("\n")
                elif escaped == "t":
                    chars.append("\t")
                elif escaped == '"':
                    chars.append('"')
                elif escaped == "\\":
                    chars.append("\\")
                else:
                    chars.append(escaped)
            else:
                chars.append(self._advance())

        raise JockySyntaxError(
            "Unterminated string literal: reached end-of-file without closing quote",
            start_line,
            start_col,
        )

    def _read_word(self) -> Token:
        """Read an alphanumeric keyword or identifier (allows _ and -)."""
        start_line = self.line
        start_col = self.column

        chars: List[str] = []
        while self.index < self.length:
            ch = self._peek()
            if ch.isalnum() or ch in ("_", "-"):
                chars.append(self._advance())
            else:
                break

        word = "".join(chars)
        upper_word = word.upper()

        if upper_word in KEYWORDS:
            return Token(KEYWORDS[upper_word], upper_word, start_line, start_col)

        return Token(TokenType.IDENTIFIER, word, start_line, start_col)

    def _read_integer(self) -> Token:
        """Read a non-negative integer literal."""
        start_line = self.line
        start_col = self.column

        digits: List[str] = []
        while self.index < self.length and self._peek().isdigit():
            digits.append(self._advance())

        return Token(TokenType.INTEGER, int("".join(digits)), start_line, start_col)

    # ─── Main entry point ─────────────────────────────────────────────────────

    def tokenize(self) -> List[Token]:
        """Scan the entire source string and return a list of Tokens."""
        tokens: List[Token] = []

        while self.index < self.length:
            ch = self._peek()

            # Skip horizontal whitespace
            if ch in (" ", "\t"):
                self._advance()
                continue

            # Handle newlines (CRLF or LF)
            if ch in ("\r", "\n"):
                start_line = self.line
                start_col = self.column

                if ch == "\r":
                    self._advance()
                    if self._peek() == "\n":
                        self._advance()
                else:
                    self._advance()

                self.line += 1
                self.column = 1

                # Emit at most one consecutive NEWLINE
                if tokens and tokens[-1].type != TokenType.NEWLINE:
                    tokens.append(Token(TokenType.NEWLINE, "\n", start_line, start_col))
                continue

            # Comments: # or //
            if ch == "#":
                self._skip_comment()
                continue

            if ch == "/" and self._peek_next() == "/":
                self._skip_comment()
                continue

            # == operator
            if ch == "=" and self._peek_next() == "=":
                start_line = self.line
                start_col = self.column
                self._advance()  # first '='
                self._advance()  # second '='
                tokens.append(Token(TokenType.EQ, "==", start_line, start_col))
                continue

            # String literals
            if ch == '"':
                tokens.append(self._read_string())
                continue

            # Integer literals
            if ch.isdigit():
                tokens.append(self._read_integer())
                continue

            # Keywords / Identifiers
            if ch.isalpha() or ch == "_":
                tokens.append(self._read_word())
                continue

            # Unexpected character
            start_line = self.line
            start_col = self.column
            bad_char = self._advance()
            raise JockySyntaxError(
                f"Unexpected character '{bad_char}'",
                start_line,
                start_col,
            )

        # Ensure trailing NEWLINE + EOF sentinel
        if tokens and tokens[-1].type != TokenType.NEWLINE:
            tokens.append(Token(TokenType.NEWLINE, "\n", self.line, self.column))

        tokens.append(Token(TokenType.EOF, "", self.line, self.column))
        return tokens
