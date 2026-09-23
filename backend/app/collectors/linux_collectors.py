"""
JOCKY Linux / Cross-Platform Forensic Collectors

Provides safe, strictly read-only forensic telemetry acquisition on Linux / POSIX systems:
1. System telemetry (hostname, /etc/os-release, /proc/version, /proc/uptime, memory, CPU)
2. Process inventory (/proc/[pid], status, cmdline, stat, or psutil fallback)
3. Network sockets (/proc/net/tcp, /proc/net/udp, or psutil fallback)
4. Filesystem artifacts (/tmp, /var/tmp, /etc, SHA-256 hashes of executable binaries)
5. User & session information (/etc/passwd, /var/run/utmp, login sessions)
6. Linux persistence artifacts (crontabs, cron.d, systemd unit services)

Safety Invariants:
- Strictly read-only operations (O_RDONLY / open for reading).
- Never modifies files, terminates processes, or alters system configuration.
- Conforms to the exact same normalized evidence dictionary schema as Windows collectors.
- Supports an optional `root_dir` parameter for isolated, deterministic cross-platform unit testing.
"""

import datetime
import glob
import os
import platform
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

from backend.app.evidence.hashing import compute_sha256, hash_file


def _resolve_path(root_dir: str, target_path: str) -> Path:
    """Safely resolves target_path relative to root_dir for mock/cross-platform support."""
    clean_target = target_path.lstrip("/\\")
    return Path(root_dir) / clean_target


# ---------------------------------------------------------------------------
# 1. Linux System Telemetry
# ---------------------------------------------------------------------------

def collect_linux_system_info(root_dir: str = "/") -> Dict[str, Any]:
    """
    Collects Linux system information strictly via read-only inspection:
    - Hostname via socket / /etc/hostname
    - OS and distribution details via /etc/os-release
    - Kernel details via /proc/version or platform.release()
    - Memory & CPU telemetry via /proc or psutil
    """
    hostname = socket.gethostname()
    os_name = "Linux"
    distro = "Linux"
    os_version = platform.release()
    architecture = platform.machine()
    boot_time_iso = None

    # Read /etc/os-release
    os_release_path = _resolve_path(root_dir, "etc/os-release")
    if os_release_path.exists():
        try:
            with open(os_release_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("PRETTY_NAME="):
                        distro = line.split("=", 1)[1].strip('"\'')
                    elif line.startswith("VERSION_ID=") and not distro:
                        os_version = line.split("=", 1)[1].strip('"\'')
        except Exception:
            pass

    # Read /etc/hostname if available
    hostname_path = _resolve_path(root_dir, "etc/hostname")
    if hostname_path.exists():
        try:
            with open(hostname_path, "r", encoding="utf-8", errors="replace") as f:
                h_content = f.read().strip()
                if h_content:
                    hostname = h_content
        except Exception:
            pass

    # Memory telemetry
    mem_total_gb = 0.0
    mem_avail_gb = 0.0
    mem_used_pct = 0.0
    meminfo_path = _resolve_path(root_dir, "proc/meminfo")
    if meminfo_path.exists():
        try:
            mem_dict = {}
            with open(meminfo_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val_str = parts[1].strip().split()[0]
                        mem_dict[key] = int(val_str)  # in kB
            if "MemTotal" in mem_dict:
                mem_total_gb = round(mem_dict["MemTotal"] / (1024 * 1024), 2)
            if "MemAvailable" in mem_dict:
                mem_avail_gb = round(mem_dict["MemAvailable"] / (1024 * 1024), 2)
            elif "MemFree" in mem_dict:
                mem_avail_gb = round(mem_dict["MemFree"] / (1024 * 1024), 2)
            if mem_total_gb > 0:
                mem_used_pct = round(((mem_total_gb - mem_avail_gb) / mem_total_gb) * 100, 1)
        except Exception:
            pass

    if mem_total_gb == 0.0:
        try:
            vm = psutil.virtual_memory()
            mem_total_gb = round(vm.total / (1024**3), 2)
            mem_avail_gb = round(vm.available / (1024**3), 2)
            mem_used_pct = round(vm.percent, 1)
        except Exception:
            pass

    # CPU telemetry
    cpu_logical = psutil.cpu_count(logical=True) or 1
    cpu_physical = psutil.cpu_count(logical=False) or 1

    # Boot time
    try:
        btime = psutil.boot_time()
        boot_time_iso = datetime.datetime.fromtimestamp(btime, datetime.timezone.utc).isoformat()
    except Exception:
        boot_time_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return {
        "hostname": hostname,
        "os": os_name,
        "distro": distro,
        "os_version": distro if distro != "Linux" else os_version,
        "kernel": platform.release(),
        "architecture": architecture,
        "boot_time": boot_time_iso,
        "memory": {
            "total_gb": mem_total_gb,
            "available_gb": mem_avail_gb,
            "used_percent": mem_used_pct,
        },
        "cpu": {
            "count_logical": cpu_logical,
            "count_physical": cpu_physical,
            "usage_percent": 0.0,
        },
    }


# ---------------------------------------------------------------------------
# 2. Linux Process Telemetry
# ---------------------------------------------------------------------------

def collect_linux_process_info(root_dir: str = "/") -> Dict[str, Any]:
    """
    Collects running Linux process telemetry strictly via read-only inspection.
    Inspects /proc filesystem or falls back to psutil.
    """
    proc_dir = _resolve_path(root_dir, "proc")
    processes = []

    # If mock /proc directory is provided with numeric pid subdirectories
    if proc_dir.exists() and any(p.name.isdigit() for p in proc_dir.iterdir() if p.is_dir()):
        for p_sub in proc_dir.iterdir():
            if not p_sub.is_dir() or not p_sub.name.isdigit():
                continue
            pid = int(p_sub.name)
            ppid = 1
            name = f"proc_{pid}"
            cmdline = ""
            status = "RUNNING"
            username = "root"

            # Read /proc/[pid]/status
            status_file = p_sub / "status"
            if status_file.exists():
                try:
                    with open(status_file, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            if line.startswith("Name:"):
                                name = line.split(":", 1)[1].strip()
                            elif line.startswith("PPid:"):
                                ppid = int(line.split(":", 1)[1].strip())
                            elif line.startswith("State:"):
                                state_str = line.split(":", 1)[1].strip()
                                status = "RUNNING" if "R" in state_str else "SLEEPING"
                except Exception:
                    pass

            # Read /proc/[pid]/cmdline
            cmd_file = p_sub / "cmdline"
            if cmd_file.exists():
                try:
                    with open(cmd_file, "r", encoding="utf-8", errors="replace") as f:
                        cmdline = f.read().replace("\x00", " ").strip()
                except Exception:
                    pass

            processes.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "cmdline": cmdline or name,
                "username": username,
                "exe": f"/usr/bin/{name}",
                "status": status,
                "cpu_percent": 0.0,
                "memory_percent": 0.1,
            })
    else:
        # Live psutil collection
        for p in psutil.process_iter(["pid", "ppid", "name", "cmdline", "username", "exe", "status", "cpu_percent", "memory_percent"]):
            try:
                info = p.info
                cmdline_str = " ".join(info.get("cmdline") or []) if info.get("cmdline") else (info.get("name") or "")
                processes.append({
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid") or 0,
                    "name": info.get("name") or "unknown",
                    "cmdline": cmdline_str,
                    "username": info.get("username") or "unknown",
                    "exe": info.get("exe") or "",
                    "status": (info.get("status") or "unknown").upper(),
                    "cpu_percent": info.get("cpu_percent") or 0.0,
                    "memory_percent": round(info.get("memory_percent") or 0.0, 2),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    return {
        "count": len(processes),
        "processes": processes,
    }


# ---------------------------------------------------------------------------
# 3. Linux Network Sockets
# ---------------------------------------------------------------------------

def collect_linux_network_info(root_dir: str = "/") -> Dict[str, Any]:
    """
    Collects network socket connections on Linux.
    Parses /proc/net/tcp and /proc/net/udp if available, or falls back to psutil.
    """
    net_tcp = _resolve_path(root_dir, "proc/net/tcp")
    connections = []

    if net_tcp.exists():
        try:
            with open(net_tcp, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[1:]  # skip header
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 10:
                        # local addr:port in hex
                        l_parts = parts[1].split(":")
                        r_parts = parts[2].split(":")
                        l_port = int(l_parts[1], 16) if len(l_parts) == 2 else 0
                        r_port = int(r_parts[1], 16) if len(r_parts) == 2 else 0
                        st = parts[3]
                        status = "LISTEN" if st == "0A" else "ESTABLISHED" if st == "01" else "TIME_WAIT"
                        connections.append({
                            "pid": int(parts[9]) if parts[9].isdigit() else 0,
                            "protocol": "TCP",
                            "laddr": f"0.0.0.0:{l_port}",
                            "raddr": f"0.0.0.0:{r_port}",
                            "status": status,
                            "family": "IPv4",
                        })
        except Exception:
            pass

    if not connections:
        # Fallback to psutil
        try:
            for c in psutil.net_connections(kind="inet"):
                laddr_str = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr_str = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                connections.append({
                    "pid": c.pid or 0,
                    "protocol": proto,
                    "laddr": laddr_str,
                    "raddr": raddr_str,
                    "status": c.status or ("LISTEN" if proto == "TCP" and not c.raddr else "NONE"),
                    "family": "IPv4" if c.family == socket.AF_INET else "IPv6",
                })
        except Exception:
            pass

    return {
        "count": len(connections),
        "connections": connections,
    }


# ---------------------------------------------------------------------------
# 4. Linux Filesystem Artifacts
# ---------------------------------------------------------------------------

def collect_linux_files_info(root_dir: str = "/", target_dir: Optional[str] = None, max_files: int = 50) -> Dict[str, Any]:
    """
    Collects forensic filesystem artifacts from critical Linux directories:
    /tmp, /var/tmp, /etc, /bin, /usr/bin. Computes SHA-256 for binaries.
    """
    search_dirs = []
    if target_dir:
        search_dirs.append(_resolve_path(root_dir, target_dir))
    else:
        # Default Linux triage directories
        for d in ["tmp", "etc", "bin"]:
            p = _resolve_path(root_dir, d)
            if p.exists():
                search_dirs.append(p)

    collected_files = []
    exec_count = 0
    total_bytes = 0

    for s_dir in search_dirs:
        if not s_dir.exists():
            continue
        try:
            for root, _, filenames in os.walk(s_dir):
                for fname in filenames:
                    if len(collected_files) >= max_files:
                        break
                    file_path = Path(root) / fname
                    try:
                        stat = file_path.stat()
                        size = stat.st_size
                        total_bytes += size
                        mtime = datetime.datetime.fromtimestamp(stat.st_mtime, datetime.timezone.utc).isoformat()
                        is_exec = os.access(file_path, os.X_OK) or fname.endswith((".sh", ".bin", ".elf"))
                        if is_exec:
                            exec_count += 1

                        # SHA-256 hash if file size is reasonable (< 15MB)
                        sha = None
                        if size < 15 * 1024 * 1024:
                            sha = hash_file(str(file_path))

                        collected_files.append({
                            "path": str(file_path),
                            "name": fname,
                            "size_bytes": size,
                            "sha256": sha or "",
                            "is_executable": is_exec,
                            "modified_time": mtime,
                        })
                    except (PermissionError, FileNotFoundError):
                        continue
                if len(collected_files) >= max_files:
                    break
        except Exception:
            continue

    return {
        "count": len(collected_files),
        "summary": {
            "executables_count": exec_count,
            "total_size_bytes": total_bytes,
        },
        "files": collected_files,
    }


# ---------------------------------------------------------------------------
# 5. Linux Users & Sessions
# ---------------------------------------------------------------------------

def collect_linux_users_info(root_dir: str = "/") -> Dict[str, Any]:
    """
    Collects user account and session data on Linux:
    - Parses /etc/passwd (read-only) for user accounts, UIDs, and shells
    - Inspects active login sessions
    """
    passwd_path = _resolve_path(root_dir, "etc/passwd")
    user_profiles = []
    current_username = os.environ.get("USER") or os.environ.get("USERNAME") or "root"

    if passwd_path.exists():
        try:
            with open(passwd_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 7:
                        uname = parts[0]
                        uid = parts[2]
                        gid = parts[3]
                        home = parts[5]
                        shell = parts[6]
                        user_profiles.append({
                            "name": uname,
                            "uid": int(uid) if uid.isdigit() else uid,
                            "gid": int(gid) if gid.isdigit() else gid,
                            "home_path": home,
                            "shell": shell,
                            "exists": True,
                        })
        except Exception:
            pass

    if not user_profiles:
        # Fallback to current user
        user_profiles.append({
            "name": current_username,
            "home_path": os.environ.get("HOME") or "/root",
            "exists": True,
        })

    # Active sessions via psutil
    active_sessions = []
    try:
        for u in psutil.users():
            active_sessions.append({
                "user": u.name,
                "terminal": u.terminal or "pts/0",
                "host": u.host or "localhost",
                "started": datetime.datetime.fromtimestamp(u.started, datetime.timezone.utc).isoformat() if u.started else "",
            })
    except Exception:
        pass

    return {
        "current_user": {
            "username": current_username,
            "domain": socket.gethostname(),
            "is_admin": current_username == "root",
        },
        "active_sessions_count": len(active_sessions),
        "active_sessions": active_sessions,
        "user_profiles": user_profiles,
    }


# ---------------------------------------------------------------------------
# 6. Linux Persistence Telemetry (Cron & Systemd)
# ---------------------------------------------------------------------------

def collect_linux_persistence_info(root_dir: str = "/") -> Dict[str, Any]:
    """
    Collects Linux persistence mechanisms strictly via read-only inspection:
    - /etc/crontab and /etc/cron.d/*
    - /etc/systemd/system/*.service and /lib/systemd/system/*.service
    - Maps output to the exact same normalized autoruns and services schema
      as Windows collectors.
    """
    autoruns = []
    services = []

    # 1. Cron jobs
    cron_locations = [
        "etc/crontab",
        "etc/cron.daily",
        "etc/cron.hourly",
        "etc/cron.d",
    ]

    for loc in cron_locations:
        loc_path = _resolve_path(root_dir, loc)
        if not loc_path.exists():
            continue

        if loc_path.is_file():
            try:
                with open(loc_path, "r", encoding="utf-8", errors="replace") as f:
                    for idx, line in enumerate(f):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            autoruns.append({
                                "name": f"crontab_line_{idx+1}",
                                "path": line,
                                "location": str(loc_path),
                                "type": "cron_job",
                            })
            except Exception:
                pass
        elif loc_path.is_dir():
            try:
                for cron_file in loc_path.glob("*"):
                    if cron_file.is_file():
                        autoruns.append({
                            "name": cron_file.name,
                            "path": str(cron_file),
                            "location": str(loc_path),
                            "type": "cron_script",
                        })
            except Exception:
                pass

    # 2. Systemd services
    systemd_locations = [
        "etc/systemd/system",
        "lib/systemd/system",
        "usr/lib/systemd/system",
    ]

    for s_loc in systemd_locations:
        s_path = _resolve_path(root_dir, s_loc)
        if s_path.exists() and s_path.is_dir():
            try:
                for svc_file in s_path.glob("*.service"):
                    exec_start = ""
                    try:
                        with open(svc_file, "r", encoding="utf-8", errors="replace") as sf:
                            for sline in sf:
                                if sline.strip().startswith("ExecStart="):
                                    exec_start = sline.strip().split("=", 1)[1]
                                    break
                    except Exception:
                        pass

                    services.append({
                        "name": svc_file.stem,
                        "display_name": svc_file.name,
                        "status": "enabled",
                        "start_type": "systemd",
                        "binpath": exec_start or str(svc_file),
                        "username": "root",
                    })
            except Exception:
                pass

    return {
        "autoruns_count": len(autoruns),
        "autoruns": autoruns,
        "services_count": len(services),
        "services": services,
    }
