"""
JOCKY Endpoint Agent — Local Execution Runner

Executes authorized collection operations on the local endpoint, enforces
the forensic allowlist, and calculates deterministic SHA-256 integrity hashes
prior to transmission.

Safety Invariants:
- Strictly executes authorized collectors only (SYSTEM, PROCESSES, NETWORK, FILES, USERS, REGISTRY).
- Completely forbids and rejects any execution of arbitrary shell commands, scripts,
  process manipulation, or file writing.
- Generates canonical cryptographic SHA-256 digests matching backend verification.
"""

import datetime
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Set

from .adapter import CollectorAdapter

logger = logging.getLogger("jocky.agent.runner")

# Strict allowlist of permissible collector operations
STRICT_ALLOWED_COLLECTORS: Set[str] = {
    "system",
    "processes",
    "network",
    "files",
    "users",
    "registry",
    "windows_metadata",
}

# Forbidden keywords in parameters or directives
FORBIDDEN_KEYWORDS: Set[str] = {
    "command",
    "script",
    "code",
    "shell",
    "exec",
    "eval",
    "bash",
    "sh",
    "cmd",
    "powershell",
    "sudo",
    "su",
    "rm",
    "del",
    "delete",
    "write",
    "kill",
    "terminate",
    "reboot",
    "shutdown",
    "drop",
}


def compute_canonical_sha256(payload: Any) -> str:
    """
    Computes a deterministic cryptographic SHA-256 hash using canonical JSON serialization:
    sorted keys, standard compact separators (",", ":"), and UTF-8 encoding.
    Matches `backend.app.evidence.hashing.compute_sha256` exactly.
    """
    if isinstance(payload, bytes):
        raw_bytes = payload
    elif isinstance(payload, str):
        raw_bytes = payload.encode("utf-8")
    else:
        raw_bytes = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    return hashlib.sha256(raw_bytes).hexdigest()


class AgentRunner:
    """
    Orchestrates the safe, sandboxed execution of forensic collection operations on the endpoint.
    """

    def __init__(self, adapter: Optional[CollectorAdapter] = None):
        self.adapter = adapter or CollectorAdapter()

    def validate_operation(self, operation: Dict[str, Any]) -> str:
        """
        Validates an operation against the strict forensic allowlist and safety rules.

        Raises:
            ValueError: If operation attempts forbidden actions or unapproved collectors.
        """
        raw_collector = operation.get("collector")
        if not raw_collector:
            raise ValueError("Operation missing 'collector' field.")

        col_name = str(raw_collector).strip().lower()
        if col_name not in STRICT_ALLOWED_COLLECTORS:
            raise ValueError(
                f"SECURITY VIOLATION: Unauthorized collector '{col_name}'. "
                f"Allowed collectors: {sorted(list(STRICT_ALLOWED_COLLECTORS))}"
            )

        # Inspect parameters for forbidden keys or dangerous keywords
        params = operation.get("params") or {}
        if not isinstance(params, dict):
            raise ValueError("Operation 'params' must be a dictionary.")

        for key, val in params.items():
            k_lower = str(key).strip().lower()
            if k_lower in FORBIDDEN_KEYWORDS:
                raise ValueError(f"SECURITY VIOLATION: Forbidden parameter key detected: '{key}'")
            if isinstance(val, str):
                v_lower = val.lower()
                for bad in ("..", "\x00", ";", "&&", "||", "`", "$("):
                    if bad in v_lower:
                        raise ValueError(f"SECURITY VIOLATION: Dangerous character sequence in parameter '{key}': '{bad}'")

        return col_name

    def execute_job(self, job_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Executes all authorized operations in a job and returns sealed evidence submissions.

        Args:
            job_data: Dictionary representing an AgentJob received from central backend.

        Returns:
            List of dictionaries formatted as EvidenceSubmission ready for POST /api/agents/result.
        """
        device_id = job_data.get("device_id", "")
        execution_id = job_data.get("execution_id", "")
        operations = job_data.get("allowed_operations", [])

        if not execution_id:
            raise ValueError("Job data missing required 'execution_id'.")

        submissions: List[Dict[str, Any]] = []

        logger.info(f"Executing job {job_data.get('job_id')} (execution_id: {execution_id}) with {len(operations)} operations")

        for op in operations:
            if hasattr(op, "model_dump"):
                op_dict = op.model_dump()
            elif isinstance(op, dict):
                op_dict = op
            else:
                op_dict = {"collector": str(op)}

            col_name = self.validate_operation(op_dict)
            params = op_dict.get("params") or {}

            # Execute via adapter
            logger.info(f"Running collector '{col_name}' locally on endpoint...")
            start_time = datetime.datetime.now(datetime.timezone.utc)
            payload = self.adapter.collect(col_name, params=params)

            # Mathematical integrity digest
            sha256_digest = compute_canonical_sha256(payload)

            submission = {
                "device_id": device_id,
                "execution_id": execution_id,
                "collector": col_name,
                "collector_version": op_dict.get("collector_version", "1.0.0"),
                "acquisition_timestamp": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "payload": payload,
                "agent_sha256": sha256_digest,
            }
            submissions.append(submission)

        return submissions
