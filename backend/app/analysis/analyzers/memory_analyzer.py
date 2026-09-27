"""
JOCKY Memory & Privilege Indicator Analysis Module (Phase 4)

Analyzes observable memory and security-context indicators from collected evidence:
- Unmapped binary execution / Process hollowing indicators (process running without accessible on-disk binary)
- Memory allocation footprint anomalies (anomalous resident set size / virtual memory)
- Process security context disparity (elevation disparity between parent and child processes)

Safety Invariants:
- Strictly passive analysis of collected process memory metrics and username fields.
- NO memory injection, process hollowing, reflective DLL injection, or memory modification.
"""

from typing import Any, Dict, List, Optional
from backend.app.analysis.correlator import generate_process_entity_id
from backend.app.analysis.mapping import ForensicContext, ObservableIndicator


class MemoryAnalyzer:
    """
    Forensic analyzer evaluating memory-related process indicators and security contexts.
    """

    def analyze(self, evidence_data: Dict[str, Any], context: ForensicContext) -> List[ObservableIndicator]:
        """
        Inspects process memory metadata and user context to extract observable indicators.
        """
        indicators: List[ObservableIndicator] = []

        procs_raw = evidence_data.get("processes", {})
        procs = procs_raw.get("processes", []) if isinstance(procs_raw, dict) else (procs_raw if isinstance(procs_raw, list) else [])
        if not procs:
            return indicators

        proc_ev_id = context.evidence_ids.get("processes")
        proc_by_pid = {p.get("pid"): p for p in procs if p.get("pid") is not None}

        for p in procs:
            pid = p.get("pid")
            ppid = p.get("ppid")
            name = (p.get("name") or "unknown").lower()
            exe = p.get("exe")
            ent_id = generate_process_entity_id(pid)
            p_time = p.get("create_time")
            user = p.get("username") or ""

            # 1. Unmapped Binary Execution (Process Hollowing Indicator)
            # A process image executing in memory without an accessible on-disk file
            if pid not in (0, 4) and (exe is None or not str(exe).strip()) and name not in ("system", "system idle process"):
                indicators.append(ObservableIndicator(
                    indicator_id=f"IND-UNMAPPED-BIN-{pid}",
                    indicator_type="binary_anomaly",
                    description=f"Running process '{name}' (PID: {pid}) has no accessible executable file path on disk (in-memory execution / hollowing indicator)",
                    observed_value={"pid": pid, "name": name, "username": user},
                    collector_source="processes",
                    evidence_id=proc_ev_id,
                    timestamp=p_time,
                    entity_id=ent_id,
                ))

            # 2. Process Memory Footprint Anomaly
            # Flag non-standard script interpreters allocating excessive memory
            mem_info = p.get("memory_info") or {}
            rss_bytes = mem_info.get("rss", 0) if isinstance(mem_info, dict) else 0
            if rss_bytes > 500 * 1024 * 1024 and name in ("cmd.exe", "powershell.exe", "wscript.exe", "bash", "sh"):
                indicators.append(ObservableIndicator(
                    indicator_id=f"IND-MEM-FOOTPRINT-{pid}",
                    indicator_type="memory_footprint_anomaly",
                    description=f"Shell interpreter '{name}' (PID: {pid}) consumes anomalous memory ({round(rss_bytes / (1024*1024), 1)} MB RSS)",
                    observed_value={"pid": pid, "name": name, "rss_bytes": rss_bytes},
                    collector_source="processes",
                    evidence_id=proc_ev_id,
                    timestamp=p_time,
                    entity_id=ent_id,
                ))

            # 3. Privilege Elevation Context Disparity
            # Parent is standard user, child is NT AUTHORITY\SYSTEM or root without standard service broker
            if ppid and ppid in proc_by_pid:
                parent = proc_by_pid[ppid]
                parent_user = (parent.get("username") or "").lower()
                child_user = user.lower()

                if child_user in ("nt authority\\system", "root") and parent_user and parent_user not in ("nt authority\\system", "root", "system"):
                    indicators.append(ObservableIndicator(
                        indicator_id=f"IND-PRIV-DISPARITY-{pid}",
                        indicator_type="privilege_disparity",
                        description=f"Process '{name}' (PID: {pid}) running as elevated '{user}' spawned by non-administrative user '{parent.get('username')}'",
                        observed_value={"pid": pid, "child_user": user, "parent_pid": ppid, "parent_user": parent.get("username")},
                        collector_source="processes",
                        evidence_id=proc_ev_id,
                        timestamp=p_time,
                        entity_id=ent_id,
                    ))

        return indicators
