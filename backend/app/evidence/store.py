"""
JOCKY Local Evidence Store

Manages evidence artifacts, SHA-256 integrity verification, and chain-of-custody records
using local, tamper-evident JSON storage.

Design Principles:
- Strictly non-destructive: only stores acquired forensic telemetry without altering live system targets.
- Integrity-locked: every artifact is bound to its cryptographic SHA-256 digest at creation.
- Auditable: every access and integrity check is appended to the chain-of-custody ledger.
"""

import datetime
import json
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .custody import CustodyRecord
from .hashing import compute_sha256, verify_sha256


class EvidenceStore:
    """Local JSON-backed evidence store with cryptographic chain of custody."""

    def __init__(self, base_dir: Optional[str] = None):
        # Default to repository evidence directory if not specified
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            # Locate jocky-forensics/evidence relative to backend
            current_dir = Path(__file__).resolve().parent
            # navigate to jocky-forensics root
            repo_root = current_dir.parent.parent.parent
            self.base_dir = repo_root / "evidence"

        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _generate_evidence_id(self, case_id: str, source: str) -> str:
        """Generate an unambiguous, collision-resistant evidence ID."""
        ts_slug = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
        rand_slug = uuid.uuid4().hex[:6]
        safe_source = source.lower().replace(" ", "_")
        return f"EVID-{case_id}-{safe_source}-{ts_slug}-{rand_slug}"

    def _get_evidence_path(self, evidence_id: str, case_id: Optional[str] = None) -> Path:
        """Resolve the JSON storage path for an evidence record."""
        if case_id:
            case_dir = self.base_dir / case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            return case_dir / f"{evidence_id}.json"
        
        # Search in subdirectories if case_id not directly provided
        for item in self.base_dir.glob(f"**/{evidence_id}.json"):
            return item

        return self.base_dir / f"{evidence_id}.json"

    def save_evidence(
        self,
        case_id: str,
        source: str,
        data: Any,
        who: str = "Forensic Investigator",
        why: str = "Authorized read-only forensic collection",
        what: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Calculates SHA-256 hash, creates initial chain-of-custody entry,
        and persists the evidence record as a JSON document.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evidence_id = self._generate_evidence_id(case_id, source)
        digest = compute_sha256(data)
        artifact_description = what or f"{source.upper()} evidence payload"

        initial_custody = CustodyRecord.create(
            who=who,
            what=artifact_description,
            why=why,
            action="ACQUIRED",
            sha256=digest,
            integrity_valid=True,
            when=now_utc,
        )

        record: Dict[str, Any] = {
            "evidence_id": evidence_id,
            "case_id": case_id,
            "source": source,
            "timestamp_utc": now_utc,
            "sha256": digest,
            "data": data,
            "custody_log": [initial_custody.to_dict()],
        }

        # Persist to disk
        file_path = self._get_evidence_path(evidence_id, case_id=case_id)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, sort_keys=True, default=str)

        return record

    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an evidence record by ID."""
        file_path = self._get_evidence_path(evidence_id)
        if not file_path.exists():
            return None

        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def verify_evidence(
        self,
        evidence_id: str,
        who: str = "Forensic Verifier",
        why: str = "Cryptographic integrity verification",
    ) -> Dict[str, Any]:
        """
        Verifies evidence integrity by recomputing the SHA-256 digest of the payload.
        Appends the verification result to the evidence artifact's chain-of-custody log.
        """
        record = self.get_evidence(evidence_id)
        if not record:
            raise FileNotFoundError(f"Evidence artifact '{evidence_id}' not found.")

        stored_hash = record["sha256"]
        is_valid = verify_sha256(record["data"], stored_hash)
        recomputed_hash = compute_sha256(record["data"])

        # Create verification custody record
        verification_custody = CustodyRecord.create(
            who=who,
            what=f"Integrity check of {evidence_id}",
            why=why,
            action="VERIFIED",
            sha256=recomputed_hash,
            integrity_valid=is_valid,
        )

        record["custody_log"].append(verification_custody.to_dict())

        # Update persistent file with updated custody record
        file_path = self._get_evidence_path(evidence_id, case_id=record.get("case_id"))
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, sort_keys=True, default=str)

        return {
            "evidence_id": evidence_id,
            "case_id": record.get("case_id"),
            "valid": is_valid,
            "stored_hash": stored_hash,
            "recomputed_hash": recomputed_hash,
            "custody_entry": verification_custody.to_dict(),
        }

    def list_evidence(self, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists metadata summaries for stored evidence artifacts."""
        summaries: List[Dict[str, Any]] = []

        pattern = f"{case_id}/*.json" if case_id else "**/*.json"
        for json_file in self.base_dir.glob(pattern):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    rec = json.load(f)
                    summaries.append({
                        "evidence_id": rec.get("evidence_id"),
                        "case_id": rec.get("case_id"),
                        "source": rec.get("source"),
                        "timestamp_utc": rec.get("timestamp_utc"),
                        "sha256": rec.get("sha256"),
                        "custody_events": len(rec.get("custody_log", [])),
                    })
            except Exception:
                continue

        return summaries
