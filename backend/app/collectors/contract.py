"""
Collector result contract (blueprint §6.2) and normalized process schema (§5.3).

Every inventory collector returns the same envelope, so the evidence store,
analyzers and reports never have to special-case an operating system:

    {
        "collector": "services",
        "collector_version": "1.0.0",
        "read_only": True,
        "platform": "Linux",
        "endpoint": "<hostname>",
        "collected_at": "<ISO-8601 UTC>",
        "collection_status": "collected" | "partial" | "unsupported" | "denied" | "error",
        "count": <int>,
        "items": [ ... ],
        "errors": [ "<path or source>: <reason>", ... ],
        "provenance": { ... },
    }

"unsupported" means the platform has no such source (for example Windows
drivers on macOS). It is reported, never silently treated as "nothing found".
"""

import datetime
import platform as host_platform
from typing import Any, Dict, Iterable, List, Optional

from .provenance import create_provenance

COLLECTOR_VERSION = "1.0.0"

COLLECTED = "collected"
PARTIAL = "partial"
UNSUPPORTED = "unsupported"
DENIED = "denied"
ERROR = "error"


def make_result(
    collector: str,
    items: Iterable[Dict[str, Any]],
    *,
    method: str,
    platform_name: str,
    errors: Optional[List[str]] = None,
    status: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build a collector result in the standard envelope.

    If no status is given it is derived: errors with no items -> error,
    errors alongside items -> partial, otherwise collected.
    """
    item_list = list(items)
    error_list = list(errors or [])
    if status is None:
        if error_list and not item_list:
            status = ERROR
        elif error_list:
            status = PARTIAL
        else:
            status = COLLECTED
    result: Dict[str, Any] = {
        "collector": collector,
        "collector_version": COLLECTOR_VERSION,
        "read_only": True,
        "platform": platform_name,
        "endpoint": host_platform.node() or "unknown_host",
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "collection_status": status,
        "count": len(item_list),
        "items": item_list,
        "errors": error_list,
        "provenance": create_provenance(collector_name=collector, method=method),
    }
    if extra:
        result.update(extra)
    return result


def unsupported(collector: str, platform_name: str, reason: str) -> Dict[str, Any]:
    """Result for a source that does not exist on this platform."""
    return make_result(
        collector,
        [],
        method="not_applicable",
        platform_name=platform_name,
        status=UNSUPPORTED,
        extra={"reason": reason},
    )


# ---------------------------------------------------------------------------
# §5.3 normalized process schema
# ---------------------------------------------------------------------------

PROCESS_SCHEMA_FIELDS = (
    "process_id",
    "parent_process_id",
    "process_name",
    "executable_path",
    "user_identity",
    "start_time",
    "command_line",
    "source_platform",
    "collection_status",
)


def normalize_process(record: Dict[str, Any], source_platform: str) -> Dict[str, Any]:
    """
    Map a raw process record from any platform collector onto the blueprint's
    common schema. Fields the collector could not read become None, and
    collection_status says whether the record is complete.
    """
    cmdline = record.get("cmdline")
    if isinstance(cmdline, list):
        cmdline = " ".join(str(part) for part in cmdline) or None
    normalized = {
        "process_id": record.get("pid"),
        "parent_process_id": record.get("ppid"),
        "process_name": record.get("name") if record.get("name") not in (None, "unknown") else None,
        "executable_path": record.get("exe") or None,
        "user_identity": record.get("username") or record.get("user") or None,
        "start_time": record.get("create_time") or record.get("start_time") or None,
        "command_line": cmdline or None,
        "source_platform": source_platform,
    }
    detail_fields = ("executable_path", "user_identity", "command_line")
    missing = [f for f in detail_fields if normalized[f] is None]
    if normalized["process_id"] is None:
        normalized["collection_status"] = ERROR
    elif len(missing) == len(detail_fields):
        normalized["collection_status"] = DENIED
    elif missing:
        normalized["collection_status"] = PARTIAL
    else:
        normalized["collection_status"] = COLLECTED
    return normalized


def normalize_process_list(records: Iterable[Dict[str, Any]], source_platform: str) -> List[Dict[str, Any]]:
    return [normalize_process(r, source_platform) for r in records]
