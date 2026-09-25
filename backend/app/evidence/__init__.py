"""
JOCKY Evidence Store, Vault & Chain of Custody Module

Provides cryptographic SHA-256 hashing, tamper-evident local evidence storage,
Evidence Vault with full integrity audits, and immutable chain-of-custody tracking
for forensic investigations.
"""

from .custody import CustodyRecord
from .hashing import compute_sha256, hash_file, verify_sha256
from .store import EvidenceStore
from .vault import EvidenceVault, _default_vault

# Shared default instances
_default_store = EvidenceStore()



def record_custody(case_id: str, artifact_name: str, sha256_hash: str, who: str = "investigator", why: str = "Evidence preservation"):
    """Creates a standardized custody record for an artifact."""
    return CustodyRecord.create(
        who=who,
        what=artifact_name,
        why=why,
        action="ACQUIRED",
        sha256=sha256_hash,
        integrity_valid=True,
    ).to_dict()


__all__ = [
    "compute_sha256",
    "verify_sha256",
    "hash_file",
    "CustodyRecord",
    "EvidenceStore",
    "EvidenceVault",
    "record_custody",
    "_default_store",
    "_default_vault",
]
