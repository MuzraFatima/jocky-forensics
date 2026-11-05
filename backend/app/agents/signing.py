"""
Signed investigation jobs (blueprint §9.4 and §10).

The server signs every job it queues with an Ed25519 key. Agents receive the
matching public key when they pair and refuse any job whose signature,
target device, expiry or nonce does not check out. The scheme is asymmetric,
so a compromised device token is not enough to forge jobs for any endpoint,
and a captured job cannot be replayed once it has run or expired.

Key source, in order:
    JOCKY_JOB_SIGNING_KEY   base64 of a 32-byte Ed25519 private seed
    <JOCKY_STORAGE_DIR or data/>/job-signing.key, generated once (git-ignored)
"""

import base64
import binascii
import datetime
import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

KEY_FILE_NAME = "job-signing.key"
# How long after its own timeout a queued job stays valid (the agent may be polling slowly)
JOB_GRACE_SECONDS = 300


def canonical_job_bytes(job: Dict[str, Any]) -> bytes:
    """The exact bytes that are signed: every field except the signature, keys sorted, no whitespace."""
    body = {k: v for k, v in job.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class JobSigner:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._key = private_key

    @classmethod
    def from_seed(cls, seed: bytes) -> "JobSigner":
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_key_b64(self) -> str:
        raw = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def sign(self, job: Any) -> Any:
        """
        Stamp an AgentJob with a nonce and expiry (if missing) and sign it.
        Returns the same model, updated in place.
        """
        if not job.nonce:
            job.nonce = secrets.token_hex(16)
        if not job.expires_at:
            created = job.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=datetime.timezone.utc)
            job.expires_at = created + datetime.timedelta(seconds=job.timeout_seconds + JOB_GRACE_SECONDS)
        payload = job.model_dump(mode="json")
        job.signature = base64.b64encode(self._key.sign(canonical_job_bytes(payload))).decode("ascii")
        return job


def _key_path() -> Path:
    base = os.getenv("JOCKY_STORAGE_DIR")
    root = Path(base) if base else Path(__file__).resolve().parent.parent.parent.parent / "data"
    return root / KEY_FILE_NAME


def load_or_create_signer() -> JobSigner:
    raw = os.getenv("JOCKY_JOB_SIGNING_KEY")
    if raw:
        try:
            return JobSigner.from_seed(base64.b64decode(raw))
        except (ValueError, binascii.Error) as exc:
            raise ValueError("JOCKY_JOB_SIGNING_KEY must be base64 of a 32-byte Ed25519 seed") from exc
    path = _key_path()
    if path.is_file():
        return JobSigner.from_seed(base64.b64decode(path.read_text(encoding="ascii").strip()))
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(base64.b64encode(seed).decode("ascii"), encoding="ascii")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return JobSigner(key)


_signer: Optional[JobSigner] = None
_signer_lock = threading.Lock()


def get_job_signer() -> JobSigner:
    global _signer
    with _signer_lock:
        if _signer is None:
            _signer = load_or_create_signer()
        return _signer


# ---------------------------------------------------------------------------
# Agent-side verification
# ---------------------------------------------------------------------------

class JobVerifier:
    """Checks jobs on the endpoint before anything runs. Remembers nonces it has accepted."""

    def __init__(self, public_key_b64: str, device_id: str, max_remembered: int = 10_000):
        self._public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        self._device_id = device_id
        self._seen: Set[str] = set()
        self._order: list = []
        self._max = max_remembered

    def check(self, job: Dict[str, Any], now: Optional[datetime.datetime] = None) -> Tuple[bool, str]:
        now = now or datetime.datetime.now(datetime.timezone.utc)
        signature = job.get("signature")
        if not signature:
            return False, "job is not signed"
        try:
            self._public_key.verify(base64.b64decode(signature), canonical_job_bytes(job))
        except (InvalidSignature, ValueError, binascii.Error):
            return False, "signature does not match the job contents or the server key"
        if job.get("device_id") != self._device_id:
            return False, f"job is addressed to {job.get('device_id')}, not this device"
        expires = job.get("expires_at")
        try:
            expiry = datetime.datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
        except ValueError:
            return False, "job has no valid expiry"
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        if now > expiry:
            return False, f"job expired at {expires}"
        nonce = job.get("nonce")
        if not nonce:
            return False, "job has no nonce"
        if nonce in self._seen:
            return False, "job nonce was already used (replay)"
        self._seen.add(nonce)
        self._order.append(nonce)
        if len(self._order) > self._max:
            self._seen.discard(self._order.pop(0))
        return True, "ok"
