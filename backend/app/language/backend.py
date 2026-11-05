"""
JOCKY platform backend.

Lowers platform-independent IR onto a concrete operating system
(blueprint §4.1 step 6). Each operation is marked supported or
unsupported for that platform, with a reason, so nothing is silently
skipped at run time (§4.5).

The backend does not execute anything; the runtime still re-checks
authorisation before dispatching a collector.
"""

import platform as host_platform
from typing import Any, Dict, Optional

SUPPORTED = "supported"
UNSUPPORTED = "unsupported"
UNKNOWN = "unknown"

_ALIASES = {
    "WINDOWS": "WINDOWS",
    "WIN32": "WINDOWS",
    "LINUX": "LINUX",
    "UBUNTU": "LINUX",
    "MACOS": "MACOS",
    "DARWIN": "MACOS",
}


def normalise_platform(name: Optional[str]) -> Optional[str]:
    """Map a platform name (any case, common aliases) to WINDOWS / LINUX / MACOS, or None if unknown."""
    if not name:
        return None
    return _ALIASES.get(name.strip().upper())


def host_platform_name() -> str:
    """The platform this process is running on, in canonical form (defaults to LINUX for other Unixes)."""
    return normalise_platform(host_platform.system()) or "LINUX"


def resolve_platform(ir: Dict[str, Any], requested: Optional[str] = None) -> str:
    """
    Pick the platform to lower for: an explicit request wins, then the
    script's PLATFORM declaration, then the host running the compiler.
    """
    explicit = normalise_platform(requested)
    if requested and explicit is None:
        raise ValueError(f"Unknown platform '{requested}'. Expected one of: windows, linux, macos")
    if explicit:
        return explicit
    declared = normalise_platform(ir.get("platform"))
    return declared or host_platform_name()


def lower_ir(ir: Dict[str, Any], platform: Optional[str] = None) -> Dict[str, Any]:
    """
    Produce a per-operation support plan for one platform.

    Returns::

        {
            "platform": "LINUX",
            "fully_supported": bool,
            "operations": [
                {"id": "op-1", "capability": "COLLECT_SYSTEM",
                 "status": "supported" | "unsupported" | "unknown", "reason": str},
                ...
            ],
            "unsupported": ["op-3", ...]
        }
    """
    target = resolve_platform(ir, platform)
    lowered = []
    for op in ir.get("operations", []):
        capability = op.get("capability")
        platforms = op.get("platforms") or []
        label = f"{op.get('type', '')} {op.get('target') or op.get('format') or ''}".strip()
        if not capability:
            status = UNKNOWN
            reason = f"'{label}' is not a catalogued capability; the runtime policy will deny it."
        elif target in platforms:
            status = SUPPORTED
            reason = f"{capability} is implemented by the {target.title()} adapter."
        else:
            status = UNSUPPORTED
            supported_on = ", ".join(p.title() for p in platforms) or "no platform"
            reason = f"{capability} is only available on {supported_on}."
        lowered.append(
            {
                "id": op.get("id"),
                "capability": capability,
                "status": status,
                "reason": reason,
                "source": op.get("source"),
            }
        )

    unsupported = [entry["id"] for entry in lowered if entry["status"] != SUPPORTED]
    return {
        "platform": target,
        "fully_supported": not unsupported,
        "operations": lowered,
        "unsupported": unsupported,
    }
