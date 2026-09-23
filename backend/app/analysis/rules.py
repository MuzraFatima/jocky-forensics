"""
JOCKY Deterministic Forensic Heuristic Rules Engine

Automated rule-based detection for suspicious forensic indicators:
- RULE-001: Execution from Temporary Directories (HIGH)
- RULE-002: Suspicious Parent-Child Process Spawning (HIGH)
- RULE-003: Anomalous Outbound Network Socket (MEDIUM)
- RULE-004: Unmapped Binary Execution (MEDIUM)
- RULE-005: Suspicious Persistence Autorun Entry (MEDIUM)

Safety Invariants:
- 100% deterministic and explainable logic.
- NO external LLMs, probabilistic models, or online queries.
- Strictly read-only analysis of collected forensic evidence.
"""

import os
from typing import Any, Dict, List, Optional
from .correlator import generate_process_entity_id


TEMP_PATHS = [
    r"\temp",
    r"\tmp",
    r"\appdata\local\temp",
    r"\windows\temp",
]

OFFICE_BROWSERS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
    "acrobat.exe",
}

SUSPICIOUS_SPAWNED_SHELLS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "curl.exe",
}

SUSPICIOUS_OUTBOUND_PORTS = {
    4444,   # Metasploit default
    1337,   # Elite / Backdoor
    6667,   # IRC botnet
    8888,   # Common alternative proxy
    31337,  # Back Orifice
    23,     # Telnet
}


class ForensicRuleEngine:
    """
    Evaluates normalized forensic evidence against deterministic detection rules.
    """

    def __init__(self):
        pass

    def evaluate(self, evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs all heuristic rules against the evidence dataset.
        Returns a list of explainable detection records.
        """
        detections: List[Dict[str, Any]] = []

        procs_raw = evidence_data.get("processes", {})
        procs = procs_raw.get("processes", []) if isinstance(procs_raw, dict) else (procs_raw if isinstance(procs_raw, list) else [])
        
        proc_by_pid = {p.get("pid"): p for p in procs if p.get("pid") is not None}

        # ── RULE-001: Execution from Temporary Directories ─────────────────────
        for p in procs:
            exe = p.get("exe")
            if exe and isinstance(exe, str):
                exe_lower = exe.lower()
                if any(t in exe_lower for t in TEMP_PATHS):
                    pid = p.get("pid")
                    detections.append({
                        "rule_id": "RULE-001",
                        "name": "Execution from Temporary Directory",
                        "severity": "HIGH",
                        "entity": generate_process_entity_id(pid),
                        "description": (
                            f"Process '{p.get('name')}' (PID: {pid}) executed from temporary directory: '{exe}'. "
                            "Legitimate software rarely executes directly from volatile temporary paths."
                        ),
                        "evidence": {
                            "pid": pid,
                            "name": p.get("name"),
                            "exe": exe,
                            "username": p.get("username"),
                        },
                        "recommendation": "Inspect binary hash in Evidence Vault and verify digital signatures.",
                    })

        # ── RULE-002: Suspicious Parent-Child Process Spawning ──────────────────
        for p in procs:
            p_name = (p.get("name") or "").lower()
            ppid = p.get("ppid")
            if p_name in SUSPICIOUS_SPAWNED_SHELLS and ppid and ppid in proc_by_pid:
                parent = proc_by_pid[ppid]
                parent_name = (parent.get("name") or "").lower()
                if parent_name in OFFICE_BROWSERS:
                    pid = p.get("pid")
                    detections.append({
                        "rule_id": "RULE-002",
                        "name": "Suspicious Parent-Child Process Spawning",
                        "severity": "HIGH",
                        "entity": generate_process_entity_id(pid),
                        "description": (
                            f"Productivity/Document application '{parent_name}' (PID: {ppid}) spawned "
                            f"command shell interpreter '{p_name}' (PID: {pid}). "
                            "This pattern is heavily associated with malicious macro/payload execution."
                        ),
                        "evidence": {
                            "pid": pid,
                            "name": p.get("name"),
                            "parent_pid": ppid,
                            "parent_name": parent.get("name"),
                            "cmdline": p.get("cmdline"),
                        },
                        "recommendation": "Review process arguments and inspect opened network sockets.",
                    })

        # ── RULE-003: Anomalous Outbound Network Socket ────────────────────────
        net_raw = evidence_data.get("network", {})
        conns = net_raw.get("connections", []) if isinstance(net_raw, dict) else (net_raw if isinstance(net_raw, list) else [])
        for conn in conns:
            raddr = conn.get("raddr")
            if isinstance(raddr, dict) and raddr.get("port"):
                r_port = raddr.get("port")
                r_ip = raddr.get("ip", "")
                if r_port in SUSPICIOUS_OUTBOUND_PORTS:
                    pid = conn.get("pid")
                    proc = proc_by_pid.get(pid, {})
                    detections.append({
                        "rule_id": "RULE-003",
                        "name": "Anomalous Outbound Network Socket",
                        "severity": "MEDIUM",
                        "entity": generate_process_entity_id(pid) if pid else "ENT-NET-SOCKET",
                        "description": (
                            f"Process '{proc.get('name', 'unknown')}' (PID: {pid}) established outbound connection "
                            f"to anomalous port {r_port} ({r_ip}:{r_port}). "
                            "This port is frequently utilized by backdoor shells and known exploitation tools."
                        ),
                        "evidence": {
                            "pid": pid,
                            "process_name": proc.get("name"),
                            "raddr": raddr,
                            "laddr": conn.get("laddr"),
                            "status": conn.get("status"),
                        },
                        "recommendation": "Verify remote host IP reputation and correlate with network perimeter logs.",
                    })

        # ── RULE-004: Unmapped Binary Execution ─────────────────────────────────
        for p in procs:
            pid = p.get("pid")
            name = (p.get("name") or "").lower()
            exe = p.get("exe")
            # Exclude known kernel/system pseudoprocesses (PID 0, 4)
            if pid not in (0, 4) and (exe is None or not str(exe).strip()) and name not in ("system", "system idle process"):
                detections.append({
                    "rule_id": "RULE-004",
                    "name": "Unmapped Binary Execution",
                    "severity": "LOW",
                    "entity": generate_process_entity_id(pid),
                    "description": (
                        f"Running process '{p.get('name')}' (PID: {pid}) has no accessible executable file path on disk. "
                        "May indicate process hollowing, permission disparity, or an ephemeral process."
                    ),
                    "evidence": {
                        "pid": pid,
                        "name": p.get("name"),
                        "username": p.get("username"),
                    },
                    "recommendation": "Inspect process memory privileges or elevated security context.",
                })

        # ── RULE-005: Suspicious Persistence Autorun Entry ─────────────────────
        wm_raw = evidence_data.get("windows_metadata") or evidence_data.get("registry", {})
        if isinstance(wm_raw, dict):
            autoruns = wm_raw.get("autoruns", [])
            for entry in autoruns:
                val = str(entry.get("value", "")).lower()
                name = entry.get("name", "")
                if any(ext in val for ext in [".vbs", ".ps1", ".bat", ".cmd", "powershell", "wscript", "cscript"]):
                    detections.append({
                        "rule_id": "RULE-005",
                        "name": "Suspicious Persistence Script Autorun",
                        "severity": "MEDIUM",
                        "entity": f"ENT-REG-{name}",
                        "description": (
                            f"Windows autorun entry '{name}' executes script interpreter or batch file: '{entry.get('value')}'. "
                            "Script-based autorun persistence is a common stealth persistence mechanism."
                        ),
                        "evidence": entry,
                        "recommendation": "Audit registry Run keys and verify if script is cryptographically signed.",
                    })

        return detections


def evaluate_forensic_rules(evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convenience helper to evaluate heuristic rules on evidence."""
    return ForensicRuleEngine().evaluate(evidence_data)
