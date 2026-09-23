"""
JOCKY Forensic Timeline Engine

Constructs a unified chronological timeline from disparate forensic evidence sources:
- System boot events
- Process creation events
- Network connection sockets
- File modification/inspection events
- User session events
- Registry persistence autoruns

Safety Invariants:
- Strictly read-only analysis.
- Deterministic, explainable chronological ordering with robust tie-breaking.
- Tolerates missing timestamps, invalid dates, and incomplete records.
"""

import datetime
from typing import Any, Dict, List, Optional
from .correlator import (
    generate_file_entity_id,
    generate_network_entity_id,
    generate_process_entity_id,
    generate_user_entity_id,
)


def _parse_iso_to_epoch(ts_str: Optional[str]) -> float:
    """Parse ISO timestamp or date string to epoch float for comparison. Fallback to 0."""
    if not ts_str or not isinstance(ts_str, str):
        return 0.0
    try:
        dt = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0.0


class ForensicTimeline:
    """
    Normalizes multi-source forensic evidence into a unified chronological event stream.
    """

    def __init__(self):
        pass

    def build_timeline(self, evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Builds and sorts the unified timeline of forensic events.
        """
        events: List[Dict[str, Any]] = []

        # 1. System Events
        sys_data = evidence_data.get("system", {})
        if isinstance(sys_data, dict):
            boot_time = sys_data.get("boot_time")
            if boot_time:
                events.append({
                    "timestamp": boot_time,
                    "event_type": "SYSTEM_BOOT",
                    "source": "system",
                    "entity": f"ENT-SYS-{sys_data.get('hostname', 'HOST')}",
                    "description": f"System boot detected for host {sys_data.get('hostname', 'localhost')}",
                    "evidence_id": evidence_data.get("evidence_ids", {}).get("system", "EVID-SYS"),
                    "metadata": {
                        "os": sys_data.get("os"),
                        "os_version": sys_data.get("os_version"),
                        "architecture": sys_data.get("architecture"),
                    },
                })

        # 2. Process Spawn Events
        procs_raw = evidence_data.get("processes", {})
        procs_list = procs_raw.get("processes", []) if isinstance(procs_raw, dict) else (procs_raw if isinstance(procs_raw, list) else [])
        for p in procs_list:
            pid = p.get("pid")
            create_time = p.get("create_time")
            name = p.get("name", "unknown")
            ppid = p.get("ppid")
            user = p.get("username") or "UNKNOWN"
            ent_id = generate_process_entity_id(pid)

            events.append({
                "timestamp": create_time,
                "event_type": "PROCESS_SPAWN",
                "source": "processes",
                "entity": ent_id,
                "description": f"Process '{name}' (PID: {pid}, PPID: {ppid}) executed by {user}",
                "evidence_id": evidence_data.get("evidence_ids", {}).get("processes", "EVID-PROC"),
                "metadata": {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "exe": p.get("exe"),
                    "username": user,
                    "cmdline": p.get("cmdline"),
                },
            })

        # 3. Network Connection Events
        net_raw = evidence_data.get("network", {})
        net_list = net_raw.get("connections", []) if isinstance(net_raw, dict) else (net_raw if isinstance(net_raw, list) else [])
        for conn in net_list:
            proto = conn.get("protocol") or conn.get("type", "TCP")
            laddr = conn.get("laddr")
            raddr = conn.get("raddr")
            status = conn.get("status", "UNKNOWN")
            pid = conn.get("pid")
            net_ent_id = generate_network_entity_id(proto, laddr, raddr)

            l_str = f"{laddr.get('ip', '*')}:{laddr.get('port', '*')}" if isinstance(laddr, dict) else "*"
            r_str = f"{raddr.get('ip', '*')}:{raddr.get('port', '*')}" if isinstance(raddr, dict) and raddr.get('ip') else "LISTEN"

            events.append({
                "timestamp": conn.get("timestamp") or evidence_data.get("timestamp_utc"),
                "event_type": "NETWORK_SOCKET",
                "source": "network",
                "entity": net_ent_id,
                "description": f"Network socket {proto} {l_str} -> {r_str} ({status}) mapped to PID {pid}",
                "evidence_id": evidence_data.get("evidence_ids", {}).get("network", "EVID-NET"),
                "metadata": {
                    "pid": pid,
                    "protocol": proto,
                    "status": status,
                    "laddr": laddr,
                    "raddr": raddr,
                },
            })

        # 4. Filesystem & Binary Events
        files_raw = evidence_data.get("files", {})
        files_list = []
        if isinstance(files_raw, dict):
            files_list.extend(files_raw.get("files", []))
            files_list.extend(files_raw.get("process_binaries", []))
        elif isinstance(files_raw, list):
            files_list = files_raw

        for f in files_list:
            path = f.get("path")
            if not path:
                continue
            sha256 = f.get("sha256")
            ts = f.get("modified_time") or f.get("created_time")
            f_ent_id = generate_file_entity_id(path, sha256)
            hash_display = sha256[:16] + "..." if sha256 and len(sha256) >= 16 else "UNHASHED"

            events.append({
                "timestamp": ts,
                "event_type": "FILE_INSPECTED",
                "source": "files",
                "entity": f_ent_id,
                "description": f"File inspected at '{path}' (SHA-256: {hash_display})",
                "evidence_id": evidence_data.get("evidence_ids", {}).get("files", "EVID-FILE"),
                "metadata": {
                    "path": path,
                    "sha256": sha256,
                    "size_bytes": f.get("size_bytes"),
                    "permissions": f.get("permissions"),
                },
            })

        # 5. User Sessions
        users_raw = evidence_data.get("users", {})
        if isinstance(users_raw, dict):
            cu = users_raw.get("current_user")
            if cu:
                uname = cu.get("username", "UNKNOWN")
                events.append({
                    "timestamp": cu.get("login_time") or evidence_data.get("timestamp_utc"),
                    "event_type": "USER_SESSION",
                    "source": "users",
                    "entity": generate_user_entity_id(uname),
                    "description": f"Security context for user '{uname}' (Admin: {cu.get('is_admin')})",
                    "evidence_id": evidence_data.get("evidence_ids", {}).get("users", "EVID-USER"),
                    "metadata": cu,
                })

        # 6. Windows Persistence Autoruns
        wm_raw = evidence_data.get("windows_metadata") or evidence_data.get("registry", {})
        if isinstance(wm_raw, dict):
            autoruns = wm_raw.get("autoruns", [])
            for entry in autoruns:
                name = entry.get("name", "UnknownAutorun")
                val = entry.get("value", "")
                hive = entry.get("hive", "REGISTRY")
                events.append({
                    "timestamp": entry.get("timestamp") or evidence_data.get("timestamp_utc"),
                    "event_type": "PERSISTENCE_ENTRY",
                    "source": "windows_metadata",
                    "entity": f"ENT-REG-{name}",
                    "description": f"Windows autorun key [{hive}]: '{name}' -> '{val}'",
                    "evidence_id": evidence_data.get("evidence_ids", {}).get("windows_metadata", "EVID-REG"),
                    "metadata": entry,
                })

        # Chronological sort with deterministic tie-breaker
        events.sort(key=lambda e: (
            _parse_iso_to_epoch(e.get("timestamp")),
            e.get("timestamp") or "",
            e.get("event_type", ""),
            e.get("entity", ""),
            e.get("description", ""),
        ))

        return events


def build_forensic_timeline(evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convenience helper to build and return timeline events."""
    return ForensicTimeline().build_timeline(evidence_data)
