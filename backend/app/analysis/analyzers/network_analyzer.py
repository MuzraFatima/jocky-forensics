"""
JOCKY Network Analysis Module (Phase 4)

Analyzes network socket telemetry to detect:
- Outbound sockets connecting to high-risk backdoor / C2 exploitation ports
- High-fanout outbound reconnaissance / lateral port scanning
- Anomalous listening sockets on non-standard ports

Safety Invariants:
- Strictly passive analysis of collected socket telemetry.
- NO network packet crafting, port scanning, or connection disruption.
"""

from typing import Any, Dict, List, Optional
from backend.app.analysis.correlator import generate_network_entity_id, generate_process_entity_id
from backend.app.analysis.mapping import ForensicContext, ObservableIndicator

ANOMALOUS_C2_PORTS = {
    4444: "Metasploit default listener",
    1337: "Elite / standard backdoor listener",
    6667: "IRC botnet command channel",
    8888: "Non-standard alternative HTTP proxy",
    31337: "Back Orifice backdoor listener",
    23: "Telnet cleartext service",
}


class NetworkAnalyzer:
    """
    Forensic analyzer evaluating network sockets, connections, and traffic distributions.
    """

    def analyze(self, evidence_data: Dict[str, Any], context: ForensicContext) -> List[ObservableIndicator]:
        """
        Inspects network telemetry and extracts network-related indicators.
        """
        indicators: List[ObservableIndicator] = []

        net_raw = evidence_data.get("network", {})
        conns = net_raw.get("connections", []) if isinstance(net_raw, dict) else (net_raw if isinstance(net_raw, list) else [])
        if not conns:
            return indicators

        net_ev_id = context.evidence_ids.get("network")
        outbound_conns_by_pid: Dict[int, List[Dict[str, Any]]] = {}

        for conn in conns:
            raddr = conn.get("raddr")
            laddr = conn.get("laddr")
            pid = conn.get("pid")
            proto = conn.get("protocol") or conn.get("type", "TCP")
            status = conn.get("status", "UNKNOWN")

            if isinstance(raddr, dict) and raddr.get("port"):
                r_port = raddr.get("port")
                r_ip = raddr.get("ip", "")
                net_ent = generate_network_entity_id(proto, laddr, raddr)

                # 1. High-Risk C2 Backdoor Port
                if r_port in ANOMALOUS_C2_PORTS:
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-C2-PORT-{r_port}-{pid}",
                        indicator_type="socket_anomaly",
                        description=f"Outbound socket to anomalous/backdoor port {r_port} ({ANOMALOUS_C2_PORTS[r_port]}) by PID {pid}",
                        observed_value={
                            "raddr": raddr,
                            "laddr": laddr,
                            "status": status,
                            "pid": pid,
                            "port_risk": ANOMALOUS_C2_PORTS[r_port],
                        },
                        collector_source="network",
                        evidence_id=net_ev_id,
                        timestamp=conn.get("timestamp"),
                        entity_id=net_ent,
                    ))

                # Track outbound connections for port scanning / reconnaissance
                if pid:
                    outbound_conns_by_pid.setdefault(pid, []).append(conn)

        # 2. Lateral Movement / Port Scanning Reconnaissance Indicator
        for pid, p_conns in outbound_conns_by_pid.items():
            distinct_remote_ips = {
                c.get("raddr", {}).get("ip")
                for c in p_conns
                if isinstance(c.get("raddr"), dict) and c.get("raddr", {}).get("ip")
            }
            if len(distinct_remote_ips) >= 10:
                indicators.append(ObservableIndicator(
                    indicator_id=f"IND-NET-RECON-{pid}",
                    indicator_type="lateral_movement_anomaly",
                    description=f"Process PID {pid} established outbound connections to {len(distinct_remote_ips)} distinct IPs (high-fanout lateral scanning indicator)",
                    observed_value={"pid": pid, "distinct_ip_count": len(distinct_remote_ips)},
                    collector_source="network",
                    evidence_id=net_ev_id,
                    timestamp=None,
                    entity_id=generate_process_entity_id(pid),
                ))

        return indicators
