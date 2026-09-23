"""
JOCKY Forensic Correlation Engine

Links disparate forensic artifacts into a unified correlation graph:
- Process ↔ Executable/Binary File (via exe path & SHA-256 hash)
- Process ↔ Network Connections (via PID mapping)
- Parent ↔ Child Process Hierarchy (via PPID tree reconstruction)
- Process ↔ User/Security Context (via username)

Safety Invariants:
- Strictly read-only analysis of collected data.
- Deterministic, explainable graph and entity ID generation.
- Handles missing, partial, or orphaned records gracefully without throwing exceptions.
"""

import hashlib
import os
from typing import Any, Dict, List, Optional, Set, Tuple


def generate_process_entity_id(pid: Any) -> str:
    """Generate deterministic entity ID for a process."""
    return f"ENT-PROC-{pid}"


def generate_file_entity_id(path: Optional[str], sha256: Optional[str] = None) -> str:
    """Generate deterministic entity ID for a file or binary."""
    if sha256 and len(sha256) >= 16:
        return f"ENT-FILE-{sha256[:16].lower()}"
    if path:
        norm_path = os.path.normpath(path).lower()
        path_hash = hashlib.sha256(norm_path.encode("utf-8")).hexdigest()[:16]
        return f"ENT-FILE-{path_hash}"
    return "ENT-FILE-UNKNOWN"


def generate_network_entity_id(
    proto: Optional[str],
    laddr: Optional[Dict[str, Any]],
    raddr: Optional[Dict[str, Any]] = None,
    fd: Optional[int] = None,
) -> str:
    """Generate deterministic entity ID for a network connection."""
    protocol = (proto or "NET").upper()
    l_ip = laddr.get("ip", "*") if isinstance(laddr, dict) else "*"
    l_port = laddr.get("port", "*") if isinstance(laddr, dict) else "*"
    
    if isinstance(raddr, dict) and raddr.get("ip"):
        r_ip = raddr.get("ip", "*")
        r_port = raddr.get("port", "*")
        target = f"{r_ip}:{r_port}"
    else:
        target = "LISTEN"
        
    endpoint_str = f"{l_ip}:{l_port}_{target}"
    ep_hash = hashlib.sha256(endpoint_str.encode("utf-8")).hexdigest()[:12]
    return f"ENT-NET-{protocol}-{ep_hash}"


def generate_user_entity_id(username: Optional[str]) -> str:
    """Generate deterministic entity ID for a user security context."""
    if not username:
        return "ENT-USER-SYSTEM"
    clean = username.strip().replace("\\", "_").replace(" ", "_").upper()
    return f"ENT-USER-{clean}"


class ForensicCorrelator:
    """
    Correlates collected forensic evidence records across processes,
    network sockets, files, and user sessions.
    """

    def __init__(self):
        pass

    def correlate(
        self,
        processes: Optional[List[Dict[str, Any]]] = None,
        network: Optional[List[Dict[str, Any]]] = None,
        files: Optional[List[Dict[str, Any]]] = None,
        users: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Builds the complete correlation graph.
        Accepts lists of normalized forensic records.
        """
        proc_list = processes or []
        net_list = network or []
        file_list = files or []
        user_list = users or []

        # Index processes by PID
        proc_by_pid: Dict[int, Dict[str, Any]] = {}
        for p in proc_list:
            pid = p.get("pid")
            if pid is not None:
                proc_by_pid[pid] = p

        # Index files by normalized path
        files_by_norm_path: Dict[str, Dict[str, Any]] = {}
        for f in file_list:
            p = f.get("path")
            if p:
                files_by_norm_path[os.path.normpath(p).lower()] = f

        entities: Dict[str, List[Dict[str, Any]]] = {
            "processes": [],
            "network": [],
            "files": [],
            "users": [],
        }
        relationships: List[Dict[str, Any]] = []

        # Track registered entity IDs to avoid duplicates
        registered_entity_ids: Set[str] = set()

        # 1. Process Entities
        for p in proc_list:
            pid = p.get("pid")
            ent_id = generate_process_entity_id(pid)
            if ent_id not in registered_entity_ids:
                registered_entity_ids.add(ent_id)
                entities["processes"].append({
                    "entity_id": ent_id,
                    "type": "process",
                    "pid": pid,
                    "ppid": p.get("ppid"),
                    "name": p.get("name"),
                    "cmdline": p.get("cmdline"),
                    "username": p.get("username"),
                    "exe": p.get("exe"),
                    "status": p.get("status"),
                    "create_time": p.get("create_time"),
                })

            # User relationship
            uname = p.get("username")
            if uname:
                user_ent_id = generate_user_entity_id(uname)
                relationships.append({
                    "source": user_ent_id,
                    "type": "OWNS_PROCESS",
                    "target": ent_id,
                })
                if user_ent_id not in registered_entity_ids:
                    registered_entity_ids.add(user_ent_id)
                    entities["users"].append({
                        "entity_id": user_ent_id,
                        "type": "user",
                        "username": uname,
                    })

            # Process ↔ Parent Process relationship
            ppid = p.get("ppid")
            if ppid is not None and ppid != pid and ppid in proc_by_pid:
                parent_ent_id = generate_process_entity_id(ppid)
                relationships.append({
                    "source": parent_ent_id,
                    "type": "SPAWNED_CHILD",
                    "target": ent_id,
                })

            # Process ↔ File relationship
            exe_path = p.get("exe")
            if exe_path:
                norm_exe = os.path.normpath(exe_path).lower()
                matched_file = files_by_norm_path.get(norm_exe)
                file_sha256 = matched_file.get("sha256") if matched_file else None
                file_ent_id = generate_file_entity_id(exe_path, file_sha256)

                relationships.append({
                    "source": ent_id,
                    "type": "EXECUTED_FROM",
                    "target": file_ent_id,
                })

                if file_ent_id not in registered_entity_ids:
                    registered_entity_ids.add(file_ent_id)
                    entities["files"].append({
                        "entity_id": file_ent_id,
                        "type": "file",
                        "path": exe_path,
                        "name": os.path.basename(exe_path),
                        "sha256": file_sha256,
                        "size_bytes": matched_file.get("size_bytes") if matched_file else None,
                    })

        # 2. Network Entities & Process ↔ Network Relationships
        # Group network connections by PID for chain construction
        net_by_pid: Dict[int, List[Dict[str, Any]]] = {}
        for conn in net_list:
            conn_pid = conn.get("pid")
            proto = conn.get("protocol") or conn.get("type")
            laddr = conn.get("laddr")
            raddr = conn.get("raddr")
            net_ent_id = generate_network_entity_id(proto, laddr, raddr)

            net_record = {
                "entity_id": net_ent_id,
                "type": "network_connection",
                "pid": conn_pid,
                "protocol": proto,
                "status": conn.get("status"),
                "laddr": laddr,
                "raddr": raddr,
            }

            if net_ent_id not in registered_entity_ids:
                registered_entity_ids.add(net_ent_id)
                entities["network"].append(net_record)

            if conn_pid is not None:
                if conn_pid not in net_by_pid:
                    net_by_pid[conn_pid] = []
                net_by_pid[conn_pid].append(net_record)

                if conn_pid in proc_by_pid:
                    proc_ent_id = generate_process_entity_id(conn_pid)
                    relationships.append({
                        "source": proc_ent_id,
                        "type": "OPENED_SOCKET",
                        "target": net_ent_id,
                    })

        # 3. Explicit File Entities (from standalone file collector)
        for f in file_list:
            p = f.get("path")
            sha256 = f.get("sha256")
            if p:
                file_ent_id = generate_file_entity_id(p, sha256)
                if file_ent_id not in registered_entity_ids:
                    registered_entity_ids.add(file_ent_id)
                    entities["files"].append({
                        "entity_id": file_ent_id,
                        "type": "file",
                        "path": p,
                        "name": f.get("name") or os.path.basename(p),
                        "sha256": sha256,
                        "size_bytes": f.get("size_bytes"),
                    })

        # 4. Explicit User Entities (from standalone user collector)
        for u in user_list:
            uname = u.get("name") or u.get("username")
            if uname:
                user_ent_id = generate_user_entity_id(uname)
                if user_ent_id not in registered_entity_ids:
                    registered_entity_ids.add(user_ent_id)
                    entities["users"].append({
                        "entity_id": user_ent_id,
                        "type": "user",
                        "username": uname,
                        "is_admin": u.get("is_admin", False),
                    })

        # 5. Build Process Tree (PPID -> Children)
        children_map: Dict[int, List[int]] = {}
        for p in proc_list:
            pid = p.get("pid")
            ppid = p.get("ppid")
            if pid is not None:
                if ppid is not None and ppid != pid and ppid in proc_by_pid:
                    children_map.setdefault(ppid, []).append(pid)

        # Roots are processes whose ppid is None, or ppid not in running set, or ppid == pid
        root_pids = [
            p.get("pid") for p in proc_list
            if p.get("pid") is not None and (
                p.get("ppid") is None
                or p.get("ppid") not in proc_by_pid
                or p.get("ppid") == p.get("pid")
            )
        ]

        def build_tree_node(pid: int, visited: Set[int]) -> Dict[str, Any]:
            if pid in visited:
                return {"pid": pid, "cycle_detected": True}
            visited.add(pid)

            proc_info = proc_by_pid.get(pid, {})
            child_pids = children_map.get(pid, [])
            return {
                "pid": pid,
                "entity_id": generate_process_entity_id(pid),
                "name": proc_info.get("name", "unknown"),
                "exe": proc_info.get("exe"),
                "username": proc_info.get("username"),
                "status": proc_info.get("status"),
                "create_time": proc_info.get("create_time"),
                "children": [build_tree_node(c_pid, visited.copy()) for c_pid in child_pids],
            }

        process_tree = [build_tree_node(r_pid, set()) for r_pid in root_pids]

        # 6. Build Correlated Forensic Chains
        # Flat list linking: Process -> Parent -> Executable -> Sockets -> Children
        correlated_chains: List[Dict[str, Any]] = []
        for p in proc_list:
            pid = p.get("pid")
            if pid is None:
                continue

            ppid = p.get("ppid")
            parent_info = None
            if ppid is not None and ppid in proc_by_pid:
                parent_proc = proc_by_pid[ppid]
                parent_info = {
                    "pid": ppid,
                    "name": parent_proc.get("name", "unknown"),
                    "entity_id": generate_process_entity_id(ppid),
                }

            exe_path = p.get("exe")
            matched_file = files_by_norm_path.get(os.path.normpath(exe_path).lower()) if exe_path else None
            sha256 = matched_file.get("sha256") if matched_file else None

            exe_info = None
            if exe_path:
                exe_info = {
                    "path": exe_path,
                    "name": os.path.basename(exe_path),
                    "sha256": sha256,
                    "entity_id": generate_file_entity_id(exe_path, sha256),
                }

            sockets = net_by_pid.get(pid, [])
            direct_children = [
                {
                    "pid": c_pid,
                    "name": proc_by_pid[c_pid].get("name", "unknown"),
                    "entity_id": generate_process_entity_id(c_pid),
                }
                for c_pid in children_map.get(pid, [])
                if c_pid in proc_by_pid
            ]

            correlated_chains.append({
                "pid": pid,
                "entity_id": generate_process_entity_id(pid),
                "process_name": p.get("name", "unknown"),
                "username": p.get("username"),
                "create_time": p.get("create_time"),
                "parent": parent_info,
                "executable": exe_info,
                "network_connections": sockets,
                "children": direct_children,
                "has_network": len(sockets) > 0,
                "has_parent": parent_info is not None,
                "has_children": len(direct_children) > 0,
            })

        return {
            "summary": {
                "total_entities": (
                    len(entities["processes"])
                    + len(entities["network"])
                    + len(entities["files"])
                    + len(entities["users"])
                ),
                "total_relationships": len(relationships),
                "process_count": len(entities["processes"]),
                "network_count": len(entities["network"]),
                "file_count": len(entities["files"]),
                "user_count": len(entities["users"]),
                "correlated_chains_count": len(correlated_chains),
                "root_process_count": len(process_tree),
            },
            "entities": entities,
            "relationships": relationships,
            "process_tree": process_tree,
            "correlated_chains": correlated_chains,
        }


def correlate_evidence(evidence_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience wrapper to correlate raw collection payloads.
    Accepts a dictionary mapping collector names or containing raw results.
    """
    correlator = ForensicCorrelator()

    # Extract process records
    procs = []
    if "processes" in evidence_data:
        p_raw = evidence_data["processes"]
        if isinstance(p_raw, dict) and "processes" in p_raw:
            procs = p_raw["processes"]
        elif isinstance(p_raw, list):
            procs = p_raw

    # Extract network records
    net = []
    if "network" in evidence_data:
        n_raw = evidence_data["network"]
        if isinstance(n_raw, dict) and "connections" in n_raw:
            net = n_raw["connections"]
        elif isinstance(n_raw, list):
            net = n_raw

    # Extract file records
    files = []
    if "files" in evidence_data:
        f_raw = evidence_data["files"]
        if isinstance(f_raw, dict):
            if "files" in f_raw:
                files.extend(f_raw["files"])
            if "process_binaries" in f_raw:
                files.extend(f_raw["process_binaries"])
        elif isinstance(f_raw, list):
            files = f_raw

    # Extract user records
    users = []
    if "users" in evidence_data:
        u_raw = evidence_data["users"]
        if isinstance(u_raw, dict):
            if "current_user" in u_raw and u_raw["current_user"]:
                users.append(u_raw["current_user"])
            if "user_profiles" in u_raw:
                users.extend(u_raw["user_profiles"])
        elif isinstance(u_raw, list):
            users = u_raw

    return correlator.correlate(
        processes=procs,
        network=net,
        files=files,
        users=users,
    )
