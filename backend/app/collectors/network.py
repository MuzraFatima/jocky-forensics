"""
JOCKY Safe Network Forensic Collector

Authorized read-only digital forensic collector for active network connections,
gathering socket endpoints (local/remote addresses and ports), connection status,
associated PID, and protocol (TCP/UDP).

Safety Invariants:
- Strictly read-only: does not open, close, inject, or intercept any sockets.
- No packet capture, promiscuous mode, or network interference.
- Gracefully handles AccessDenied and missing endpoint metadata without crashing.
- No security evasion, bypass, or firewall tampering.
"""

import datetime
import socket
from typing import Any, Dict, List, Optional
import psutil


def _format_protocol(sock_type: Optional[int]) -> str:
    """Map socket type constants to canonical protocol names."""
    if sock_type == socket.SOCK_STREAM:
        return "TCP"
    if sock_type == socket.SOCK_DGRAM:
        return "UDP"
    return "UNKNOWN"


def collect_network_info() -> Dict[str, Any]:
    """
    Safely enumerates active network sockets and connections.

    Gracefully handles psutil.AccessDenied, missing connection tuples,
    and unavailable socket descriptors.

    Returns:
        JSON-serializable dictionary adhering to the JOCKY collector schema.
    """
    connection_records: List[Dict[str, Any]] = []

    raw_conns: List[Any] = []
    try:
        raw_conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        # Fallback: attempt per-process connection inspection for accessible processes
        try:
            for proc in psutil.process_iter(attrs=["pid"]):
                try:
                    p_conns = proc.net_connections(kind="inet")
                    for c in p_conns:
                        raw_conns.append(c)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception:
                    continue
        except Exception:
            raw_conns = []
    except Exception:
        raw_conns = []

    for conn in raw_conns:
        try:
            # Local address and port
            laddr = getattr(conn, "laddr", None)
            local_address = getattr(laddr, "ip", None) if laddr else None
            local_port = getattr(laddr, "port", None) if laddr else None

            # Remote address and port (may be empty for listening sockets)
            raddr = getattr(conn, "raddr", None)
            remote_address = getattr(raddr, "ip", None) if raddr else None
            remote_port = getattr(raddr, "port", None) if raddr else None

            # Status string
            status = getattr(conn, "status", None)
            if not status or status == psutil.CONN_NONE:
                status = "NONE"

            # Protocol
            sock_type = getattr(conn, "type", None)
            protocol = _format_protocol(sock_type)

            # Associating PID
            pid = getattr(conn, "pid", None)

            connection_records.append({
                "local_address": local_address,
                "local_port": local_port,
                "remote_address": remote_address,
                "remote_port": remote_port,
                "status": status,
                "pid": pid,
                "protocol": protocol,
            })
        except (psutil.AccessDenied, AttributeError):
            continue
        except Exception:
            continue

    return {
        "collector": "network",
        "read_only": True,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "connections": connection_records,
        "count": len(connection_records),
    }
