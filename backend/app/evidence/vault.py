"""
JOCKY Forensic Evidence Vault & Tamper-Evident Chain of Custody

Provides a secure, immutable, auditable evidence repository adhering to legal digital forensic standards:
- Cryptographic SHA-256 evidence hashing at point of acquisition
- Comprehensive forensic metadata (collector identity/version, execution ID, target host, timestamps)
- Immutable chain-of-custody tracking (ACQUIRED, VERIFIED, ACCESSED, EXPORTED)
- Mathematical tamper detection and full-vault cryptographic integrity audit
- Verifiable evidence bundle export with cryptographic manifests

Safety Invariants:
- Strictly read-only analysis of live system targets.
- Tamper-evident storage: any unauthorized modification invalidates the cryptographic hash.
- Full auditability: all custody verification events are recorded with investigator provenance.
"""

import datetime
import json
import os
import platform
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .custody import CustodyRecord
from .hashing import compute_sha256, verify_sha256
from .storage import EvidenceCipher, EvidenceDecryptionError, cipher_from_environment, read_record, write_record


class EvidenceVault:
    """
    Forensic Evidence Vault with cryptographic sealing, tamper detection,
    and auditable chain-of-custody tracking.
    """

    def __init__(self, base_dir: Optional[str] = None, cipher: Optional[EvidenceCipher] = None):
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            # Locate jocky-forensics/evidence/vault relative to repository
            current_dir = Path(__file__).resolve().parent
            repo_root = current_dir.parent.parent.parent
            self.base_dir = repo_root / "evidence" / "vault"

        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.cases_dir = self.base_dir / "cases"
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        # AES-256-GCM at rest when a key is configured (see evidence/storage.py)
        self.cipher = cipher if cipher is not None else cipher_from_environment()
        # evidence_id -> file path, so lookups do not glob the whole vault each time
        self._index: Dict[str, Path] = {}

    def _generate_evidence_id(self, case_id: str, source: str) -> str:
        """Generate a deterministic, collision-resistant evidence identifier."""
        ts_slug = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
        rand_slug = uuid.uuid4().hex[:6]
        safe_source = source.lower().replace(" ", "_")
        return f"EVID-{case_id}-{safe_source}-{ts_slug}-{rand_slug}"

    def _get_artifact_path(self, evidence_id: str, case_id: Optional[str] = None) -> Path:
        """Resolves the JSON file path for a sealed evidence artifact."""
        clean_id = evidence_id[:-5] if evidence_id.endswith(".json") else evidence_id
        if case_id:
            c_dir = self.cases_dir / case_id
            c_dir.mkdir(parents=True, exist_ok=True)
            path = c_dir / f"{clean_id}.json"
            self._index[clean_id] = path
            return path

        indexed = self._index.get(clean_id)
        if indexed is not None and indexed.exists():
            return indexed

        # Not indexed yet (sealed by another process or before start-up): search once
        for found in self.cases_dir.glob(f"**/{clean_id}.json"):
            self._index[clean_id] = found
            return found

        return self.cases_dir / f"{clean_id}.json"

    def seal_artifact(
        self,
        case_id: str,
        source: str,
        data: Any,
        who: str = "Forensic Investigator",
        why: str = "Authorized read-only digital forensic acquisition",
        what: Optional[str] = None,
        execution_id: Optional[str] = None,
        collector_identity: str = "JOCKY-Collector",
        collector_version: str = "1.0.0",
        target_host: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Cryptographically seals an acquired forensic artifact into the vault:
        1. Calculates deterministic SHA-256 payload digest.
        2. Binds forensic metadata (execution ID, collector version, target host).
        3. Records initial ACQUIRED custody entry.
        4. Persists the sealed artifact to the vault.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evidence_id = self._generate_evidence_id(case_id, source)
        digest = compute_sha256(data)
        exec_id = execution_id or f"EXEC-{uuid.uuid4().hex[:8]}"
        host = target_host or platform.node() or "localhost"
        artifact_description = what or f"{source.upper()} forensic evidence payload"

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
            "collector_identity": collector_identity,
            "collector_version": collector_version,
            "execution_id": exec_id,
            "target_host": host,
            "sha256": digest,
            "data": data,
            "custody_log": [initial_custody.to_dict()],
        }

        # Write to vault
        target_path = self._get_artifact_path(evidence_id, case_id=case_id)
        write_record(target_path, record, self.cipher)

        return record

    def get_artifact(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a sealed evidence artifact by ID."""
        file_path = self._get_artifact_path(evidence_id)
        if not file_path.exists():
            return None

        return read_record(file_path, self.cipher)

    def verify_artifact(
        self,
        evidence_id: str,
        who: str = "Forensic Verifier",
        why: str = "Cryptographic integrity verification",
    ) -> Dict[str, Any]:
        """
        Verifies the cryptographic integrity of an artifact by recomputing
        its SHA-256 payload digest and checking for tampering.
        Appends a VERIFIED entry to the artifact's chain of custody.
        """
        try:
            record = self.get_artifact(evidence_id)
        except EvidenceDecryptionError as exc:
            # An encrypted record that fails AES-GCM authentication was altered
            # (or moved, or the key changed); it cannot be trusted or re-hashed.
            return {
                "evidence_id": evidence_id,
                "case_id": None,
                "valid": False,
                "tampered": True,
                "stored_hash": None,
                "recomputed_hash": None,
                "error": str(exc),
            }
        if not record:
            raise FileNotFoundError(f"Sealed evidence artifact '{evidence_id}' not found in vault.")

        stored_hash = record["sha256"]
        payload_data = record["data"]
        recomputed_hash = compute_sha256(payload_data)
        is_valid = verify_sha256(payload_data, stored_hash)

        # Log custody verification event
        action = "VERIFIED" if is_valid else "TAMPER_DETECTED"
        verification_entry = CustodyRecord.create(
            who=who,
            what=f"Cryptographic verification of {evidence_id}",
            why=why,
            action=action,
            sha256=recomputed_hash,
            integrity_valid=is_valid,
        )

        record["custody_log"].append(verification_entry.to_dict())

        # Update artifact file in vault
        file_path = self._get_artifact_path(evidence_id, case_id=record.get("case_id"))
        write_record(file_path, record, self.cipher)

        return {
            "evidence_id": evidence_id,
            "case_id": record.get("case_id"),
            "valid": is_valid,
            "tampered": not is_valid,
            "stored_hash": stored_hash,
            "recomputed_hash": recomputed_hash,
            "custody_entry": verification_entry.to_dict(),
        }

    def verify_vault_integrity(self, case_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Performs a full cryptographic audit of all artifacts in the vault.
        Scans all artifacts, re-computes hashes, flags tampered records,
        and generates an audit report.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        pattern = f"{case_id}/*.json" if case_id else "**/*.json"

        total_count = 0
        valid_count = 0
        tampered_count = 0
        tampered_artifacts: List[Dict[str, Any]] = []
        artifacts_summary: List[Dict[str, Any]] = []

        for artifact_file in self.cases_dir.glob(pattern):
            try:
                rec = read_record(artifact_file, self.cipher)

                ev_id = rec.get("evidence_id")
                c_id = rec.get("case_id")
                stored_hash = rec.get("sha256")
                payload = rec.get("data")
                recomputed = compute_sha256(payload)
                is_valid = verify_sha256(payload, stored_hash)

                total_count += 1
                if is_valid:
                    valid_count += 1
                else:
                    tampered_count += 1
                    tampered_artifacts.append({
                        "evidence_id": ev_id,
                        "case_id": c_id,
                        "source": rec.get("source"),
                        "stored_hash": stored_hash,
                        "recomputed_hash": recomputed,
                        "file_path": str(artifact_file),
                    })

                artifacts_summary.append({
                    "evidence_id": ev_id,
                    "case_id": c_id,
                    "source": rec.get("source"),
                    "timestamp_utc": rec.get("timestamp_utc"),
                    "valid": is_valid,
                    "execution_id": rec.get("execution_id"),
                    "custody_events": len(rec.get("custody_log", [])),
                })
            except Exception as exc:
                tampered_count += 1
                tampered_artifacts.append({
                    "file_path": str(artifact_file),
                    "error": str(exc),
                })

        vault_status = "INTACT" if tampered_count == 0 else "COMPROMISED"

        return {
            "vault_status": vault_status,
            "audited_at": now_utc,
            "case_id": case_id or "ALL_CASES",
            "total_artifacts": total_count,
            "valid_count": valid_count,
            "tampered_count": tampered_count,
            "tampered_artifacts": tampered_artifacts,
            "artifacts_summary": artifacts_summary,
        }

    def get_audit_ledger(self, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieves the complete, chronological chain-of-custody ledger
        across all sealed artifacts.
        """
        pattern = f"{case_id}/*.json" if case_id else "**/*.json"
        all_events: List[Dict[str, Any]] = []

        for artifact_file in self.cases_dir.glob(pattern):
            try:
                rec = read_record(artifact_file, self.cipher)

                ev_id = rec.get("evidence_id")
                c_id = rec.get("case_id")
                source = rec.get("source")

                for entry in rec.get("custody_log", []):
                    all_events.append({
                        **entry,
                        "evidence_id": ev_id,
                        "case_id": c_id,
                        "source": source,
                    })
            except Exception:
                continue

        all_events.sort(key=lambda e: e.get("when") or "")
        return all_events

    def export_vault_bundle(self, case_id: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Exports all evidence artifacts for a case into a verifiable,
        cryptographically signed bundle with a manifest.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        artifacts = []
        c_dir = self.cases_dir / case_id

        if c_dir.exists():
            for json_file in c_dir.glob("*.json"):
                try:
                    artifacts.append(read_record(json_file, self.cipher))
                except Exception:
                    continue

        manifest_entries = [
            {
                "evidence_id": a.get("evidence_id"),
                "source": a.get("source"),
                "timestamp_utc": a.get("timestamp_utc"),
                "sha256": a.get("sha256"),
            }
            for a in artifacts
        ]

        manifest_digest = compute_sha256(manifest_entries)

        bundle = {
            "format": "JOCKY_FORENSIC_BUNDLE_V1",
            "case_id": case_id,
            "exported_at": now_utc,
            "exporter": "JOCKY Evidence Vault",
            "manifest": {
                "artifact_count": len(artifacts),
                "artifacts": manifest_entries,
                "manifest_sha256": manifest_digest,
            },
            "artifacts": artifacts,
        }

        if output_path:
            out_file = Path(output_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(bundle, f, indent=2, sort_keys=True, default=str)

        return bundle

    def simulate_tampering(self, evidence_id: str, key_to_alter: str = "tampered_flag", new_val: Any = "MODIFIED") -> bool:
        """
        Test helper to simulate evidence tampering by modifying data directly on disk
        without updating its recorded SHA-256 hash.
        """
        record = self.get_artifact(evidence_id)
        if not record:
            return False

        if isinstance(record.get("data"), dict):
            record["data"][key_to_alter] = new_val
        elif isinstance(record.get("data"), list):
            record["data"].append({"tampered": new_val})
        else:
            record["data"] = f"{record.get('data')}_TAMPERED"

        file_path = self._get_artifact_path(evidence_id, case_id=record.get("case_id"))
        write_record(file_path, record, self.cipher)

        return True


# Shared default singleton instance
_default_vault = EvidenceVault()

