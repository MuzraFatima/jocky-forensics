"""
JOCKY Forensic Chain of Custody

Maintains auditable, cryptographic custody records capturing:
- WHO: Operator, agent, or investigator identity
- WHAT: Specific evidence artifact handled
- WHEN: Accurate ISO 8601 UTC timestamp
- WHY: Legal, administrative, or operational justification
- ACTION: Operation performed (ACQUIRED, VERIFIED, ACCESSED, etc.)
"""

import datetime
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class CustodyRecord:
    who: str
    what: str
    when: str
    why: str
    action: str
    sha256: str
    integrity_valid: Optional[bool] = None

    @classmethod
    def create(
        cls,
        who: str,
        what: str,
        why: str,
        action: str,
        sha256: str,
        integrity_valid: Optional[bool] = None,
        when: Optional[str] = None,
    ) -> "CustodyRecord":
        """Factory method generating timestamped custody entries."""
        timestamp = when or datetime.datetime.now(datetime.timezone.utc).isoformat()
        return cls(
            who=who,
            what=what,
            when=timestamp,
            why=why,
            action=action.upper(),
            sha256=sha256,
            integrity_valid=integrity_valid,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to a clean, JSON-serializable dictionary."""
        data = asdict(self)
        if self.integrity_valid is None:
            del data["integrity_valid"]
        return data
