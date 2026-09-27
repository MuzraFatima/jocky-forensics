"""
JOCKY Endpoint Agent — Data Models & Schemas

Strict Pydantic models governing device pairing, heartbeats, jobs, evidence submissions,
and device records for authorized JOCKY Endpoint Agents.

Safety Invariants:
- Strict allowlist of forensic collectors ONLY (system, processes, network, files, users, registry).
- Extra fields are strictly forbidden (extra="forbid") to reject unauthorized parameters.
- Rejects arbitrary shell execution, scripts, process killing, file write, or privilege escalation.
- Validates SHA-256 formatting (lowercase 64-character hexadecimal digest).
"""

import datetime
from enum import Enum
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


# ─── Enumerations ─────────────────────────────────────────────────────────────

class AllowedCollector(str, Enum):
    """
    Strict allowlist of permissible forensic collector types.
    Arbitrary execution or write directives are strictly excluded.
    """
    SYSTEM = "system"
    PROCESSES = "processes"
    NETWORK = "network"
    FILES = "files"
    USERS = "users"
    REGISTRY = "registry"

    @classmethod
    def _missing_(cls, value: object):
        # Allow case-insensitive matching (e.g. "SYSTEM" -> "system")
        if isinstance(value, str):
            for member in cls:
                if member.value == value.lower():
                    return member
        return None


class DeviceStatus(str, Enum):
    """Lifecycle status of an authorized endpoint device."""
    ACTIVE = "active"
    PENDING = "pending"
    OFFLINE = "offline"
    REVOKED = "revoked"


# ─── 1. Collector Operation Specification ─────────────────────────────────────

class CollectorOperation(BaseModel):
    """
    Defines a single authorized forensic collection operation within an agent job.
    """
    model_config = ConfigDict(extra="forbid")

    collector: AllowedCollector = Field(
        ...,
        description="Target forensic collector from the strict allowlist",
    )
    params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Safe, read-only parameters for the collector (e.g. target_path)",
    )
    filters: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Declarative post-collection filters (e.g. WHERE status == RUNNING)",
    )

    @field_validator("params")
    @classmethod
    def validate_safe_params(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Ensures collector params contain no destructive or traversal directives."""
        # Forbid dangerous keys
        forbidden_keys = {"command", "cmd", "exec", "shell", "script", "code", "eval", "write", "kill", "delete"}
        found_forbidden = set(k.lower() for k in v.keys()).intersection(forbidden_keys)
        if found_forbidden:
            raise ValueError(f"Forbidden collector parameter keys detected: {found_forbidden}")

        # Check target_path for directory traversal if present
        target_path = v.get("target_path")
        if target_path and isinstance(target_path, str):
            if ".." in target_path or "\x00" in target_path:
                raise ValueError("Path traversal ('..') or null-bytes are strictly forbidden in target_path")

        return v


# ─── 2. Pairing Models ────────────────────────────────────────────────────────

class PairingCodeGenerateRequest(BaseModel):
    """Request by an authenticated investigator to generate a temporary pairing code."""
    model_config = ConfigDict(extra="forbid")

    device_name: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Optional human-readable label for the target device",
    )
    case_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Case docket to bind the pairing authorization to",
    )


class PairingCodeGenerateResponse(BaseModel):
    """Response containing the single-use, short-lived pairing code."""
    model_config = ConfigDict(extra="forbid")

    pairing_code: str = Field(
        ...,
        pattern=r"^[A-Za-z0-9_-]{4,16}$",
        description="Short-lived single-use pairing code (e.g. PAIR-94A2)",
    )
    expires_at: datetime.datetime = Field(
        ...,
        description="UTC expiration timestamp (typically 10-minute TTL)",
    )
    ttl_seconds: int = Field(
        ...,
        ge=60,
        le=3600,
        description="Remaining time-to-live in seconds",
    )


class PairingExchangeRequest(BaseModel):
    """Request submitted by the Endpoint Agent client to claim a pairing code."""
    model_config = ConfigDict(extra="forbid")

    pairing_code: str = Field(
        ...,
        min_length=4,
        max_length=32,
        description="Short-lived single-use pairing code issued by the investigator",
    )
    hostname: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Target machine hostname",
    )
    platform: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Operating system description (e.g. Windows 11 Pro, Ubuntu 24.04, Darwin 23.4)",
    )
    agent_version: str = Field(
        default="1.0.0",
        min_length=1,
        max_length=32,
        description="JOCKY Endpoint Agent software version",
    )
    device_fingerprint: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Deterministic hardware or OS fingerprint for device tracking",
    )


class PairingExchangeResponse(BaseModel):
    """Response returned to the Agent client upon successful pairing."""
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(
        ...,
        pattern=r"^DEV-[A-Za-z0-9_-]{8,32}$",
        description="Permanent identifier assigned to the paired device",
    )
    device_token: str = Field(
        ...,
        min_length=32,
        description="Cryptographically random bearer token for endpoint agent authentication",
    )
    user_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Investigator account ID owning this paired device",
    )
    status: DeviceStatus = Field(
        default=DeviceStatus.ACTIVE,
        description="Initial device operational status",
    )
    paired_at: datetime.datetime = Field(
        ...,
        description="UTC timestamp when the pairing took place",
    )


# ─── 3. Heartbeat Models ──────────────────────────────────────────────────────

class AgentHeartbeatRequest(BaseModel):
    """Periodic health and presence beacon sent by the Endpoint Agent."""
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(
        ...,
        pattern=r"^DEV-[A-Za-z0-9_-]{8,32}$",
        description="Assigned device identifier",
    )
    timestamp: datetime.datetime = Field(
        ...,
        description="UTC timestamp of the heartbeat dispatch",
    )
    hostname: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Current hostname of the device",
    )
    platform: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Current OS platform details",
    )
    agent_version: str = Field(
        default="1.0.0",
        min_length=1,
        max_length=32,
        description="Active agent build version",
    )


class AgentHeartbeatResponse(BaseModel):
    """Response acknowledging heartbeat receipt."""
    model_config = ConfigDict(extra="forbid")

    acknowledged: bool = Field(default=True)
    server_time: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))
    pending_jobs_count: int = Field(default=0, ge=0)


# ─── 4. Job Contract Models ───────────────────────────────────────────────────

class AgentJob(BaseModel):
    """
    Contract describing a forensic collection job dispatched from the backend to an agent.
    """
    model_config = ConfigDict(extra="forbid")

    job_id: str = Field(
        ...,
        pattern=r"^JOB-[A-Za-z0-9_-]{8,32}$",
        description="Unique identifier for this forensic dispatch",
    )
    user_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Investigator user ID who dispatched the investigation",
    )
    device_id: str = Field(
        ...,
        pattern=r"^DEV-[A-Za-z0-9_-]{8,32}$",
        description="Target paired device identifier",
    )
    case_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Case docket associated with the investigation",
    )
    execution_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Execution run ID tying the evidence to the investigation plan",
    )
    allowed_operations: List[CollectorOperation] = Field(
        ...,
        min_length=1,
        description="Strict list of approved, read-only collector operations to execute",
    )
    created_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        description="UTC dispatch timestamp",
    )
    timeout_seconds: int = Field(
        default=60,
        ge=5,
        le=600,
        description="Maximum execution timeout before the agent should abort",
    )


# ─── 5. Evidence Submission Contract ──────────────────────────────────────────

class EvidenceSubmission(BaseModel):
    """
    Payload submitted by an Endpoint Agent to upload acquired forensic evidence.
    """
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(
        ...,
        pattern=r"^DEV-[A-Za-z0-9_-]{8,32}$",
        description="Device identifier that performed the acquisition",
    )
    execution_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Execution ID tying this payload to the specific job",
    )
    collector: AllowedCollector = Field(
        ...,
        description="Collector that produced this evidence payload",
    )
    collector_version: str = Field(
        default="1.0.0",
        min_length=1,
        max_length=32,
        description="Version of the collector implementation",
    )
    acquisition_timestamp: datetime.datetime = Field(
        ...,
        description="UTC timestamp at the exact moment of collection on the endpoint",
    )
    payload: Dict[str, Any] = Field(
        ...,
        description="Raw collected forensic telemetry dictionary",
    )
    agent_sha256: str = Field(
        ...,
        pattern=r"^[a-fA-F0-9]{64}$",
        description="SHA-256 digest calculated by the agent immediately upon acquisition",
    )

    @field_validator("agent_sha256")
    @classmethod
    def normalize_sha256(cls, v: str) -> str:
        """Enforces canonical lowercase 64-hex string representation."""
        clean = v.strip().lower()
        if not re.fullmatch(r"^[a-f0-9]{64}$", clean):
            raise ValueError("agent_sha256 must be a valid 64-character lowercase hex string")
        return clean


# ─── 6. Device Record Model ───────────────────────────────────────────────────

class DeviceRecord(BaseModel):
    """
    Persistent server-side record for an authorized investigator endpoint device.
    """
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(
        ...,
        pattern=r"^DEV-[A-Za-z0-9_-]{8,32}$",
        description="Unique device identifier",
    )
    user_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Owner investigator identifier",
    )
    hostname: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Hostname of the device",
    )
    platform: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="OS platform details",
    )
    agent_version: str = Field(
        default="1.0.0",
        min_length=1,
        max_length=32,
    )
    created_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        description="Enrollment timestamp",
    )
    last_seen: Optional[datetime.datetime] = Field(
        default=None,
        description="Timestamp of last successful heartbeat or operation",
    )
    status: DeviceStatus = Field(
        default=DeviceStatus.ACTIVE,
        description="Current operational status",
    )
    is_revoked: bool = Field(
        default=False,
        description="Whether this device token has been revoked",
    )
    revoked_at: Optional[datetime.datetime] = Field(
        default=None,
        description="Timestamp when revocation occurred, if applicable",
    )
    token_hash: Optional[str] = Field(
        default=None,
        description="Secure salted hash of the device token (never plaintext)",
    )
