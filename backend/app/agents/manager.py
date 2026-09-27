"""
JOCKY Endpoint Agent — Device Manager & Pairing Lifecycle

Manages cryptographically secure endpoint enrollment, pairing codes,
device token verification, in-memory job dispatch queues, and evidence result intake.

Safety Invariants:
- Pairing codes are single-use, 6–8 characters, and strictly expire in 10 minutes.
- Plaintext device tokens are NEVER persisted or logged.
- Only PBKDF2-HMAC-SHA256 salted hashes of tokens are stored.
- Device authorization is strictly scoped to (user_id, device_id).
- Revoked devices fail authentication immediately.
- Re-pairing after revocation is fully supported.
- Thread-safe state synchronization across concurrent requests.
"""

import collections
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
from typing import Any, Dict, List, Optional, Set

from .models import (
    AgentJob,
    AllowedCollector,
    DeviceRecord,
    DeviceStatus,
    EvidenceSubmission,
    PairingCodeGenerateResponse,
    PairingExchangeRequest,
    PairingExchangeResponse,
)

# Unambiguous alphanumeric characters for pairing codes (no 0/O, 1/I)
PAIRING_CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
PAIRING_CODE_LENGTH = 8
PAIRING_TTL_MINUTES = 10


def hash_device_token(token: str) -> str:
    """Computes secure PBKDF2-HMAC-SHA256 hash of a device token with a random cryptographic salt."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt.encode("utf-8"), 50_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def verify_device_token_hash(token: str, stored_hash: Optional[str]) -> bool:
    """Verifies a raw device token against stored PBKDF2-HMAC-SHA256 hash using timing-safe comparison."""
    if not token or not stored_hash:
        return False
    parts = stored_hash.split("$")
    if len(parts) == 3 and parts[0] == "pbkdf2_sha256":
        salt = parts[1]
        expected_dk = parts[2]
        computed_dk = hashlib.pbkdf2_hmac(
            "sha256", token.encode("utf-8"), salt.encode("utf-8"), 50_000
        ).hex()
        return hmac.compare_digest(computed_dk, expected_dk)
    return False


def _get_default_storage_dir() -> Path:
    """Resolves data directory for device records."""
    env_dir = os.getenv("JOCKY_STORAGE_DIR")
    if env_dir:
        d = Path(env_dir)
    else:
        current_dir = Path(__file__).resolve().parent
        repo_root = current_dir.parent.parent.parent
        d = repo_root / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


class AgentManager:
    """
    Thread-safe orchestrator for Endpoint Agent pairing, device lifecycle,
    in-memory job queuing, and temporary result aggregation.
    """

    def __init__(self, storage_dir: Optional[Path] = None):
        self._lock = threading.RLock()
        self._storage_dir = Path(storage_dir) if storage_dir else _get_default_storage_dir()
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._devices_file = self._storage_dir / "devices.json"

        # In-memory pairing code registry: code -> metadata dict
        # {code: {"user_id": str, "case_id": Optional[str], "device_name": Optional[str], "expires_at": datetime, "used": bool}}
        self._pairing_codes: Dict[str, Dict[str, Any]] = {}

        # In-memory device registry: device_id -> DeviceRecord
        self._devices: Dict[str, DeviceRecord] = {}

        # In-memory job queues: device_id -> collections.deque[AgentJob]
        self._job_queues: Dict[str, collections.deque] = collections.defaultdict(collections.deque)

        # In-memory results store: execution_id -> List[EvidenceSubmission]
        self._results: Dict[str, List[EvidenceSubmission]] = collections.defaultdict(list)

        # Load persisted devices from disk
        self._load_devices()

    # ─── Persistence Helpers ──────────────────────────────────────────────────

    def _load_devices(self) -> None:
        """Loads registered device records from disk."""
        with self._lock:
            if not self._devices_file.exists():
                return
            try:
                with open(self._devices_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            try:
                                dev = DeviceRecord(**item)
                                self._devices[dev.device_id] = dev
                            except Exception:
                                pass
            except Exception:
                pass

    def _persist_devices(self) -> None:
        """Persists registered devices atomically to disk."""
        with self._lock:
            records = [dev.model_dump(mode="json") for dev in self._devices.values()]
            tmp_file = self._devices_file.with_suffix(".tmp")
            try:
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=2, default=str)
                # Atomic rename on Windows/POSIX
                if os.name == "nt" and self._devices_file.exists():
                    os.replace(tmp_file, self._devices_file)
                else:
                    tmp_file.replace(self._devices_file)
            except Exception:
                if tmp_file.exists():
                    try:
                        tmp_file.unlink()
                    except Exception:
                        pass

    # ─── 1. Pairing Lifecycle ─────────────────────────────────────────────────

    def generate_pairing_code(
        self,
        user_id: str,
        device_name: Optional[str] = None,
        case_id: Optional[str] = None,
    ) -> PairingCodeGenerateResponse:
        """
        Generates an 8-character single-use pairing code bound to the investigator with 10-minute TTL.
        """
        if not user_id or not user_id.strip():
            raise ValueError("user_id is mandatory to generate a pairing code")

        with self._lock:
            # Generate collision-resistant 8-character code
            code = "".join(secrets.choice(PAIRING_CHARSET) for _ in range(PAIRING_CODE_LENGTH))
            now = datetime.datetime.now(datetime.timezone.utc)
            expires_at = now + datetime.timedelta(minutes=PAIRING_TTL_MINUTES)
            ttl_seconds = int((expires_at - now).total_seconds())

            self._pairing_codes[code] = {
                "user_id": user_id.strip(),
                "device_name": device_name.strip() if device_name else None,
                "case_id": case_id.strip() if case_id else None,
                "expires_at": expires_at,
                "created_at": now,
                "used": False,
            }

            return PairingCodeGenerateResponse(
                pairing_code=code,
                expires_at=expires_at,
                ttl_seconds=ttl_seconds,
            )

    def exchange_pairing_code(
        self,
        request: PairingExchangeRequest,
    ) -> PairingExchangeResponse:
        """
        Validates pairing code, enrolls the endpoint device, issues a scoped device token,
        and invalidates the pairing code immediately (single-use).
        """
        code = request.pairing_code.strip()
        now = datetime.datetime.now(datetime.timezone.utc)

        with self._lock:
            # 1. Verify existence of pairing code
            if code not in self._pairing_codes:
                raise ValueError("Invalid pairing code")

            meta = self._pairing_codes[code]

            # 2. Verify single-use invariant
            if meta.get("used"):
                raise ValueError("Pairing code has already been used")

            # 3. Verify 10-minute expiry
            expires_at = meta["expires_at"]
            if now > expires_at:
                del self._pairing_codes[code]
                raise ValueError("Pairing code has expired")

            # Mark code as used and clean up
            meta["used"] = True
            user_id = meta["user_id"]
            del self._pairing_codes[code]

            # 4. Check if this physical endpoint is already actively enrolled for this investigator
            # Pairing the same physical endpoint repeatedly updates the existing device without creating duplicate active devices (Req 12)
            existing_dev = None
            req_hostname = request.hostname.strip().lower()
            req_platform = request.platform.strip().lower()

            for dev in self._devices.values():
                if dev.user_id == user_id and not dev.is_revoked and dev.status == DeviceStatus.ACTIVE:
                    if request.device_fingerprint and getattr(dev, "device_fingerprint", None):
                        if dev.device_fingerprint == request.device_fingerprint:
                            existing_dev = dev
                            break
                    elif dev.hostname.strip().lower() == req_hostname and dev.platform.strip().lower() == req_platform:
                        existing_dev = dev
                        break

            raw_device_token = secrets.token_urlsafe(32)
            token_hash = hash_device_token(raw_device_token)

            if existing_dev:
                device_id = existing_dev.device_id
                existing_dev.token_hash = token_hash
                existing_dev.last_seen = now
                existing_dev.agent_version = request.agent_version
                existing_dev.status = DeviceStatus.ACTIVE
                # Clear any stale unconsumed jobs from prior session
                if device_id in self._job_queues:
                    self._job_queues[device_id].clear()
                self._persist_devices()

                return PairingExchangeResponse(
                    device_id=device_id,
                    device_token=raw_device_token,
                    user_id=user_id,
                    status=DeviceStatus.ACTIVE,
                    paired_at=now,
                )

            # 5. Otherwise generate new device credentials
            device_id = f"DEV-{secrets.token_hex(6).upper()}"

            record = DeviceRecord(
                device_id=device_id,
                user_id=user_id,
                hostname=request.hostname,
                platform=request.platform,
                agent_version=request.agent_version,
                created_at=now,
                last_seen=now,
                status=DeviceStatus.ACTIVE,
                is_revoked=False,
                revoked_at=None,
                token_hash=token_hash,
            )

            self._devices[device_id] = record
            self._persist_devices()

            return PairingExchangeResponse(
                device_id=device_id,
                device_token=raw_device_token,
                user_id=user_id,
                status=DeviceStatus.ACTIVE,
                paired_at=now,
            )

    # ─── 2. Device Registry & Lifecycle ───────────────────────────────────────

    def get_device(self, device_id: str) -> Optional[DeviceRecord]:
        """Retrieves device record by ID."""
        with self._lock:
            return self._devices.get(device_id)

    def list_devices(self, user_id: Optional[str] = None) -> List[DeviceRecord]:
        """Lists device records, optionally filtered by owning investigator."""
        with self._lock:
            devices = list(self._devices.values())
            if user_id:
                clean_uid = user_id.strip()
                devices = [d for d in devices if d.user_id == clean_uid]
            return devices

    def update_heartbeat(
        self,
        device_id: str,
        hostname: Optional[str] = None,
        platform: Optional[str] = None,
        agent_version: Optional[str] = None,
    ) -> bool:
        """Updates last_seen and telemetry for an active device."""
        with self._lock:
            dev = self._devices.get(device_id)
            if not dev or dev.is_revoked or dev.status == DeviceStatus.REVOKED:
                return False

            now = datetime.datetime.now(datetime.timezone.utc)
            dev.last_seen = now
            dev.status = DeviceStatus.ACTIVE
            if hostname:
                dev.hostname = hostname
            if platform:
                dev.platform = platform
            if agent_version:
                dev.agent_version = agent_version

            self._persist_devices()
            return True

    def revoke_device(self, device_id: str, user_id: Optional[str] = None) -> bool:
        """Revokes a device token and marks the device as revoked immediately."""
        with self._lock:
            dev = self._devices.get(device_id)
            if not dev:
                return False

            if user_id and dev.user_id != user_id.strip():
                return False

            now = datetime.datetime.now(datetime.timezone.utc)
            dev.is_revoked = True
            dev.revoked_at = now
            dev.status = DeviceStatus.REVOKED
            dev.token_hash = None  # Invalidate stored token hash immediately

            # Clear any pending jobs for the revoked device
            if device_id in self._job_queues:
                self._job_queues[device_id].clear()

            self._persist_devices()
            return True

    def is_device_active(self, device_id: str) -> bool:
        """Checks if a device exists, is not revoked, and is in ACTIVE status."""
        with self._lock:
            dev = self._devices.get(device_id)
            if not dev:
                return False
            return not dev.is_revoked and dev.status == DeviceStatus.ACTIVE

    def verify_device_token(self, device_id: str, raw_token: str) -> Optional[DeviceRecord]:
        """
        Verifies a bearer device token against the stored hash.
        Fails immediately if device is revoked or nonexistent.
        """
        if not device_id or not raw_token:
            return None

        with self._lock:
            dev = self._devices.get(device_id)
            if not dev:
                return None

            if dev.is_revoked or dev.status == DeviceStatus.REVOKED:
                return None

            if not dev.token_hash:
                return None

            if verify_device_token_hash(raw_token, dev.token_hash):
                return dev

            return None

    def re_pair_device(
        self,
        device_id: str,
        pairing_code: str,
        hostname: Optional[str] = None,
        platform: Optional[str] = None,
        agent_version: Optional[str] = None,
    ) -> PairingExchangeResponse:
        """
        Re-enrolls a previously revoked or inactive device using a fresh pairing code.
        Issues a new device token and re-activates the device record.
        """
        with self._lock:
            dev = self._devices.get(device_id)
            if not dev:
                raise ValueError("Device not found for re-pairing")

            # Validate pairing code
            code = pairing_code.strip()
            now = datetime.datetime.now(datetime.timezone.utc)

            if code not in self._pairing_codes:
                raise ValueError("Invalid pairing code")

            meta = self._pairing_codes[code]
            if meta.get("used"):
                raise ValueError("Pairing code has already been used")

            if now > meta["expires_at"]:
                del self._pairing_codes[code]
                raise ValueError("Pairing code has expired")

            # Single-use consume
            del self._pairing_codes[code]

            # Re-generate credentials
            new_raw_token = secrets.token_urlsafe(32)
            new_token_hash = hash_device_token(new_raw_token)

            dev.is_revoked = False
            dev.revoked_at = None
            dev.status = DeviceStatus.ACTIVE
            dev.last_seen = now
            dev.token_hash = new_token_hash
            if hostname:
                dev.hostname = hostname
            if platform:
                dev.platform = platform
            if agent_version:
                dev.agent_version = agent_version

            self._persist_devices()

            return PairingExchangeResponse(
                device_id=dev.device_id,
                device_token=new_raw_token,
                user_id=dev.user_id,
                status=DeviceStatus.ACTIVE,
                paired_at=now,
            )

    # ─── 3. In-Memory Job Queue ───────────────────────────────────────────────

    def enqueue_job(self, device_id: str, job: AgentJob) -> None:
        """Enqueues an approved forensic collection job for an active endpoint device."""
        with self._lock:
            if not self.is_device_active(device_id):
                raise ValueError(f"Cannot enqueue job: device {device_id} is not active or has been revoked")

            if job.device_id != device_id:
                raise ValueError(f"Job device_id {job.device_id} mismatch with target {device_id}")

            self._job_queues[device_id].append(job)

    def get_pending_job(self, device_id: str) -> Optional[AgentJob]:
        """Pops and returns the oldest pending job for a device, or None if queue is empty."""
        with self._lock:
            if not self.is_device_active(device_id):
                return None

            q = self._job_queues[device_id]
            if q:
                return q.popleft()
            return None

    def get_pending_jobs_count(self, device_id: str) -> int:
        """Returns the number of queued jobs for a device."""
        with self._lock:
            return len(self._job_queues[device_id])

    def clear_device_jobs(self, device_id: str) -> None:
        """Clears all pending jobs for a device."""
        with self._lock:
            if device_id in self._job_queues:
                self._job_queues[device_id].clear()

    # ─── 4. In-Memory Result Registry ─────────────────────────────────────────

    def add_result(self, execution_id: str, result: EvidenceSubmission) -> None:
        """Records an incoming evidence submission for an ongoing investigation run."""
        with self._lock:
            clean_exec_id = execution_id.strip()
            self._results[clean_exec_id].append(result)

    def get_results(self, execution_id: str) -> List[EvidenceSubmission]:
        """Retrieves all evidence submissions received for an execution ID."""
        with self._lock:
            clean_exec_id = execution_id.strip()
            return list(self._results.get(clean_exec_id, []))

    def is_execution_complete(
        self,
        execution_id: str,
        expected_collectors: List[str],
    ) -> bool:
        """
        Checks whether all expected collector types have submitted evidence for an execution run.
        """
        with self._lock:
            clean_exec_id = execution_id.strip()
            received_collectors = {
                r.collector.value if hasattr(r.collector, "value") else str(r.collector).lower()
                for r in self._results.get(clean_exec_id, [])
            }
            expected = {c.lower() for c in expected_collectors}
            return expected.issubset(received_collectors)

    def clear_results(self, execution_id: str) -> None:
        """Frees memory by removing stored evidence submissions after backend vault sealing."""
        with self._lock:
            clean_exec_id = execution_id.strip()
            if clean_exec_id in self._results:
                del self._results[clean_exec_id]


# Global singleton instance for backend use
_default_agent_manager: Optional[AgentManager] = None


def get_agent_manager() -> AgentManager:
    """Returns the process-wide AgentManager instance."""
    global _default_agent_manager
    if _default_agent_manager is None:
        _default_agent_manager = AgentManager()
    return _default_agent_manager
