"""
Evidence record storage with optional AES-256-GCM encryption at rest
(blueprint §3.4 and §11).

Records are written either as plain JSON (the original format) or as an
encrypted envelope:

    {
        "jocky_envelope": "AES-256-GCM",
        "key_id": "<first 16 hex of SHA-256(key)>",
        "nonce": "<base64, 12 bytes>",
        "ciphertext": "<base64>"
    }

The evidence ID is bound as associated data, so a ciphertext copied onto
another evidence ID fails authentication just like an edited one. Reading
detects the format, so evidence sealed before encryption was enabled stays
readable.

Encryption is enabled when a key is configured:
    JOCKY_EVIDENCE_KEY       base64 of 32 random bytes, or
    JOCKY_ENCRYPT_EVIDENCE=1 a key is generated once in
                             <JOCKY_STORAGE_DIR or data/>/evidence.key
The key file is git-ignored. Losing it means losing the evidence.
"""

import base64
import binascii
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_FORMAT = "AES-256-GCM"
KEY_FILE_NAME = "evidence.key"


class EvidenceDecryptionError(Exception):
    """The stored ciphertext failed authentication: it was altered, moved, or the key is wrong."""


class EvidenceCipher:
    """AES-256-GCM with a random 96-bit nonce per write."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256-GCM needs a 32-byte key")
        self._aead = AESGCM(key)
        self.key_id = hashlib.sha256(key).hexdigest()[:16]

    def seal(self, plaintext: bytes, associated_data: str) -> Dict[str, str]:
        nonce = secrets.token_bytes(12)
        ciphertext = self._aead.encrypt(nonce, plaintext, associated_data.encode("utf-8"))
        return {
            "jocky_envelope": ENVELOPE_FORMAT,
            "key_id": self.key_id,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

    def open(self, envelope: Dict[str, Any], associated_data: str) -> bytes:
        if envelope.get("key_id") != self.key_id:
            raise EvidenceDecryptionError(
                f"Evidence was encrypted with key {envelope.get('key_id')}, not the configured key {self.key_id}"
            )
        try:
            nonce = base64.b64decode(envelope["nonce"])
            ciphertext = base64.b64decode(envelope["ciphertext"])
            return self._aead.decrypt(nonce, ciphertext, associated_data.encode("utf-8"))
        except (InvalidTag, KeyError, ValueError, binascii.Error) as exc:
            raise EvidenceDecryptionError("Ciphertext failed AES-GCM authentication") from exc


def _default_key_path() -> Path:
    base = os.getenv("JOCKY_STORAGE_DIR")
    if base:
        return Path(base) / KEY_FILE_NAME
    return Path(__file__).resolve().parent.parent.parent.parent / "data" / KEY_FILE_NAME


def cipher_from_environment() -> Optional[EvidenceCipher]:
    """Build the configured cipher, or None when encryption at rest is not enabled."""
    raw = os.getenv("JOCKY_EVIDENCE_KEY")
    if raw:
        try:
            return EvidenceCipher(base64.b64decode(raw))
        except (ValueError, binascii.Error) as exc:
            raise ValueError("JOCKY_EVIDENCE_KEY must be base64 of exactly 32 bytes") from exc
    if os.getenv("JOCKY_ENCRYPT_EVIDENCE", "").strip().lower() in ("1", "true", "yes"):
        key_path = _default_key_path()
        if key_path.is_file():
            return EvidenceCipher(base64.b64decode(key_path.read_text(encoding="ascii").strip()))
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        key_path.write_text(base64.b64encode(key).decode("ascii"), encoding="ascii")
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return EvidenceCipher(key)
    return None


def is_envelope(document: Any) -> bool:
    return isinstance(document, dict) and document.get("jocky_envelope") == ENVELOPE_FORMAT


def write_record(path: Path, record: Dict[str, Any], cipher: Optional[EvidenceCipher]) -> None:
    """Write an evidence record, encrypted when a cipher is configured."""
    if cipher is None:
        document: Any = record
    else:
        plaintext = json.dumps(record, sort_keys=True, default=str).encode("utf-8")
        document = cipher.seal(plaintext, associated_data=str(record.get("evidence_id", "")))
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True, default=str)


def read_record(path: Path, cipher: Optional[EvidenceCipher], evidence_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Read an evidence record in either format.

    Raises EvidenceDecryptionError if an encrypted record fails
    authentication or no key is configured to open it.
    """
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not is_envelope(document):
        return document
    if cipher is None:
        raise EvidenceDecryptionError(f"{path.name} is encrypted but no evidence key is configured")
    aad = evidence_id if evidence_id is not None else path.stem
    return json.loads(cipher.open(document, associated_data=aad))
