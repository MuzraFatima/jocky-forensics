"""
JOCKY Evidence Hashing & Integrity Primitives

Provides deterministic cryptographic SHA-256 hashing and verification
for forensic evidence payloads, ensuring mathematical tamper-evidence.
"""

import hashlib
import hmac
import json
from typing import Any, Union


def compute_sha256(data: Any) -> str:
    """
    Computes a deterministic SHA-256 hexadecimal digest for raw bytes, strings,
    or arbitrary Python dictionaries and lists.

    For dictionary/list structures, keys are sorted and separators standardized
    to guarantee canonical, deterministic serializations regardless of key ordering.
    """
    if isinstance(data, bytes):
        raw_bytes = data
    elif isinstance(data, str):
        raw_bytes = data.encode("utf-8")
    else:
        # Standardized canonical JSON encoding
        raw_bytes = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")

    return hashlib.sha256(raw_bytes).hexdigest()


def verify_sha256(data: Any, expected_hash: str) -> bool:
    """
    Verifies that the given data recomputes to the expected SHA-256 hash.
    Uses constant-time comparison to protect against timing discrepancies.
    """
    if not expected_hash:
        return False

    computed = compute_sha256(data)
    return hmac.compare_digest(computed.lower(), expected_hash.lower())


def hash_file(file_path: Union[str, Any], max_bytes: int = 25 * 1024 * 1024) -> Optional[str]:
    """
    Safely computes SHA-256 digest of an on-disk file in 64KB blocks.
    Returns None if file cannot be accessed or exceeds max_bytes.
    """
    import os
    try:
        if os.path.getsize(file_path) > max_bytes:
            return None
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None
