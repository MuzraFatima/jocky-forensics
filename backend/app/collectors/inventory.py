"""
Host inventory collectors: services, startup entries, drivers / kernel modules,
listening ports and DNS resolver configuration (blueprint §5.1, §5.2, §6).

All collectors are read-only. They read files, the registry and psutil
state; none of them start processes or change configuration. Each returns
the standard envelope from contract.py, and a source that does not exist on
the current platform comes back as "unsupported" with a reason.

The Linux and macOS readers take a root_dir so tests can point them at a
fixture tree instead of the real /etc and /proc.
"""

import os
import platform as host_platform
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil

from .contract import make_result, unsupported

MAX_ITEMS = 500


def _platform(platform_name: Optional[str]) -> str:
    name = platform_name or host_platform.system()
    if name in ("Darwin", "macOS"):
        return "Darwin"
    return name


def _under(root_dir: str, path: str) -> Path:
    return Path(root_dir) / path.lstrip("/\\")


def _read_text(path: Path, errors: List[str], limit: int = 256 * 1024) -> Optional[str]:
    try:
        if not _is_file(path):
            return None
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except (PermissionError, OSError) as exc:
        errors.append(f"{path}: {exc.__class__.__name__}")
        return None


def _is_dir(path: Path) -> bool:
    """Path.is_dir() that treats an unreadable parent as 'not there' instead of raising."""
    try:
        return path.is_dir()
    except OSError:
        return False


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _list_dir(path: Path, errors: Optional[List[str]] = None, pattern: Optional[str] = None) -> List[Path]:
    """
    List a directory without raising. Spool and home directories often exist
    but are unreadable to an unprivileged collector; that is recorded as an
    error (making the result "partial") instead of aborting the collection.
    """
    try:
        if not _is_dir(path):
            return []
        entries = path.glob(pattern) if pattern else path.iterdir()
        return sorted(entries)
    except (PermissionError, OSError) as exc:
        if errors is not None:
            errors.append(f"{path}: {exc.__class__.__name__}")
        return []


# ---------------------------------------------------------------------------
# Windows registry helpers (imported lazily; winreg only exists on Windows)
# ---------------------------------------------------------------------------

def _winreg_values(hive: Any, subkey: str, errors: List[str]) -> List[Tuple[str, Any]]:
    import winreg

    values: List[Tuple[str, Any]] = []
    try:
        with winreg.OpenKey(hive, subkey) as key:
            index = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                values.append((name, data))
                index += 1
    except FileNotFoundError:
        pass
    except OSError as exc:
        errors.append(f"{subkey}: {exc.__class__.__name__}")
    return values


def _winreg_subkeys(hive: Any, subkey: str, errors: List[str]) -> List[str]:
    import winreg

    names: List[str] = []
    try:
        with winreg.OpenKey(hive, subkey) as key:
            index = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, index))
                except OSError:
                    break
                index += 1
    except OSError as exc:
        errors.append(f"{subkey}: {exc.__class__.__name__}")
    return names


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

_UNIT_DIRS = ("etc/systemd/system", "lib/systemd/system", "usr/lib/systemd/system")


def _parse_unit(text: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "[")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields.setdefault(key.strip(), value.strip())
    return fields


def _enabled_units(root_dir: str) -> set:
    enabled = set()
    base = _under(root_dir, "etc/systemd/system")
    if _is_dir(base):
        for wants in _list_dir(base, pattern="*.wants"):
            for link in _list_dir(wants):
                enabled.add(link.name)
    return enabled


def _linux_services(root_dir: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    seen = set()
    enabled = _enabled_units(root_dir)
    for unit_dir in _UNIT_DIRS:
        directory = _under(root_dir, unit_dir)
        if not _is_dir(directory):
            continue
        for unit in _list_dir(directory, errors, "*.service"):
            if unit.name in seen or len(items) >= MAX_ITEMS:
                continue
            seen.add(unit.name)
            text = _read_text(unit, errors)
            if text is None:
                continue
            fields = _parse_unit(text)
            items.append(
                {
                    "name": unit.name,
                    "display_name": fields.get("Description"),
                    "binary_path": fields.get("ExecStart"),
                    "run_as": fields.get("User") or "root",
                    "start_mode": "enabled" if unit.name in enabled else "static_or_disabled",
                    "state": None,
                    "definition_path": "/" + unit_dir + "/" + unit.name,
                    "source": "systemd",
                }
            )
    return items, errors


def _windows_services() -> Tuple[List[Dict[str, Any]], List[str]]:
    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    try:
        for service in psutil.win_service_iter():
            if len(items) >= MAX_ITEMS:
                break
            try:
                info = service.as_dict()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError) as exc:
                errors.append(f"{service.name()}: {exc.__class__.__name__}")
                continue
            items.append(
                {
                    "name": info.get("name"),
                    "display_name": info.get("display_name"),
                    "binary_path": info.get("binpath"),
                    "run_as": info.get("username"),
                    "start_mode": info.get("start_type"),
                    "state": info.get("status"),
                    "pid": info.get("pid"),
                    "source": "service_control_manager",
                }
            )
    except Exception as exc:  # psutil raises a variety of OSErrors here
        errors.append(f"service_control_manager: {exc.__class__.__name__}")
    return items, errors


def _macos_launchd(root_dir: str, dirs: Tuple[str, ...], kind: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    for rel in dirs:
        directory = _under(root_dir, rel)
        if not _is_dir(directory):
            continue
        for plist in _list_dir(directory, errors, "*.plist"):
            if len(items) >= MAX_ITEMS:
                break
            items.append({"name": plist.stem, "definition_path": "/" + rel + "/" + plist.name, "source": kind})
    return items, errors


def collect_services(root_dir: str = "/", platform_name: Optional[str] = None) -> Dict[str, Any]:
    """Installed services: Windows SCM services, systemd units, or macOS LaunchDaemons."""
    plat = _platform(platform_name)
    if plat == "Windows":
        items, errors = _windows_services()
        method = "psutil_win_service_iter"
    elif plat == "Linux":
        items, errors = _linux_services(root_dir)
        method = "systemd_unit_file_scan"
    elif plat == "Darwin":
        items, errors = _macos_launchd(root_dir, ("Library/LaunchDaemons", "System/Library/LaunchDaemons"), "launchd")
        method = "launchd_plist_scan"
    else:
        return unsupported("services", plat, f"No service inventory source for {plat}")
    return make_result("services", items, method=method, platform_name=plat, errors=errors)


# ---------------------------------------------------------------------------
# Startup entries
# ---------------------------------------------------------------------------

_WINDOWS_RUN_KEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)


def _windows_startup() -> Tuple[List[Dict[str, Any]], List[str]]:
    import winreg

    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    for hive, hive_name in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
        for subkey in _WINDOWS_RUN_KEYS:
            for name, data in _winreg_values(hive, subkey, errors):
                items.append(
                    {"name": name, "command": str(data), "location": f"{hive_name}\\{subkey}", "source": "registry_run_key"}
                )
    folders = []
    if os.environ.get("APPDATA"):
        folders.append(Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup")
    if os.environ.get("PROGRAMDATA"):
        folders.append(Path(os.environ["PROGRAMDATA"]) / "Microsoft/Windows/Start Menu/Programs/StartUp")
    for folder in folders:
        if _is_dir(folder):
            for entry in _list_dir(folder, errors):
                if _is_file(entry):
                    items.append(
                        {"name": entry.name, "command": str(entry), "location": str(folder), "source": "startup_folder"}
                    )
    return items[:MAX_ITEMS], errors


def _parse_cron_line(line: str, has_user_field: bool) -> Tuple[Optional[str], Optional[str], str]:
    """Split a crontab line into (schedule, user, command). System crontabs carry a user column."""
    fields = line.split()
    when_len = 1 if fields[0].startswith("@") else 5
    user_len = 1 if has_user_field else 0
    if len(fields) <= when_len + user_len:
        return None, None, line
    schedule = " ".join(fields[:when_len])
    user = fields[when_len] if has_user_field else None
    command = " ".join(fields[when_len + user_len:])
    return schedule, user, command


def _linux_startup(root_dir: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    items: List[Dict[str, Any]] = []
    errors: List[str] = []

    # (path, has_user_field): system crontabs name the user, per-user crontabs do not
    cron_files: List[Tuple[Path, bool]] = [(_under(root_dir, "etc/crontab"), True)]
    for rel, has_user in (("etc/cron.d", True), ("var/spool/cron/crontabs", False), ("var/spool/cron", False)):
        directory = _under(root_dir, rel)
        if _is_dir(directory):
            cron_files.extend((p, has_user) for p in _list_dir(directory, errors) if _is_file(p))
    for cron, has_user in cron_files:
        text = _read_text(cron, errors)
        if not text:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or re.match(r"^[A-Za-z_]+=", stripped):
                continue
            schedule, user, command = _parse_cron_line(stripped, has_user)
            items.append(
                {
                    "name": cron.name,
                    "command": command,
                    "schedule": schedule,
                    "run_as": user,
                    "location": "/" + str(cron.relative_to(root_dir)).replace("\\", "/"),
                    "source": "cron",
                }
            )

    autostart_dirs = [_under(root_dir, "etc/xdg/autostart")]
    home = _under(root_dir, "home")
    if _is_dir(home):
        autostart_dirs.extend(user / ".config/autostart" for user in _list_dir(home, errors) if _is_dir(user))
    for directory in autostart_dirs:
        if not _is_dir(directory):
            continue
        for desktop in _list_dir(directory, errors, "*.desktop"):
            fields = _parse_unit(_read_text(desktop, errors) or "")
            items.append(
                {
                    "name": fields.get("Name") or desktop.stem,
                    "command": fields.get("Exec"),
                    "location": "/" + str(desktop.relative_to(root_dir)).replace("\\", "/"),
                    "source": "xdg_autostart",
                }
            )

    rc_local = _under(root_dir, "etc/rc.local")
    text = _read_text(rc_local, errors)
    if text:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and stripped != "exit 0":
                items.append({"name": "rc.local", "command": stripped, "location": "/etc/rc.local", "source": "rc_local"})

    return items[:MAX_ITEMS], errors


def collect_startup_entries(root_dir: str = "/", platform_name: Optional[str] = None) -> Dict[str, Any]:
    """Programs set to run at boot or logon: Run keys and Startup folders, cron and XDG autostart, LaunchAgents."""
    plat = _platform(platform_name)
    if plat == "Windows":
        items, errors = _windows_startup()
        method = "registry_run_keys_and_startup_folders"
    elif plat == "Linux":
        items, errors = _linux_startup(root_dir)
        method = "cron_xdg_autostart_rc_local_scan"
    elif plat == "Darwin":
        items, errors = _macos_launchd(root_dir, ("Library/LaunchAgents",), "launch_agent")
        method = "launch_agent_plist_scan"
    else:
        return unsupported("startup", plat, f"No startup inventory source for {plat}")
    return make_result("startup", items, method=method, platform_name=plat, errors=errors)


# ---------------------------------------------------------------------------
# Drivers / kernel modules
# ---------------------------------------------------------------------------

_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
_DRIVER_TYPES = {1: "kernel_driver", 2: "file_system_driver"}
_START_TYPES = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}


def _windows_drivers() -> Tuple[List[Dict[str, Any]], List[str]]:
    import winreg

    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    for name in _winreg_subkeys(winreg.HKEY_LOCAL_MACHINE, _SERVICES_KEY, errors):
        if len(items) >= MAX_ITEMS:
            break
        values = dict(_winreg_values(winreg.HKEY_LOCAL_MACHINE, f"{_SERVICES_KEY}\\{name}", []))
        driver_type = _DRIVER_TYPES.get(values.get("Type"))
        if not driver_type:
            continue
        items.append(
            {
                "name": name,
                "image_path": values.get("ImagePath"),
                "display_name": values.get("DisplayName"),
                "start_mode": _START_TYPES.get(values.get("Start"), values.get("Start")),
                "driver_type": driver_type,
                "source": "registry_services",
            }
        )
    return items, errors


def _linux_modules(root_dir: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    text = _read_text(_under(root_dir, "proc/modules"), errors)
    if text is None:
        errors.append("/proc/modules: not readable")
        return items, errors
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0]
        taint_text = _read_text(_under(root_dir, f"sys/module/{name}/taint"), []) or ""
        taint = taint_text.strip()
        items.append(
            {
                "name": name,
                "size_bytes": int(parts[1]) if parts[1].isdigit() else None,
                "ref_count": int(parts[2]) if parts[2].isdigit() else None,
                "used_by": [] if len(parts) < 4 or parts[3] == "-" else parts[3].strip(",").split(","),
                "state": parts[4] if len(parts) > 4 else None,
                "taint_flags": taint or None,
                # "O" = out-of-tree, "E" = unsigned, "P" = proprietary (kernel taint letters)
                "unsigned": "E" in taint,
                "out_of_tree": "O" in taint,
                "source": "proc_modules",
            }
        )
        if len(items) >= MAX_ITEMS:
            break
    return items, errors


def collect_drivers(root_dir: str = "/", platform_name: Optional[str] = None) -> Dict[str, Any]:
    """Installed kernel drivers (Windows) or loaded kernel modules (Linux)."""
    plat = _platform(platform_name)
    if plat == "Windows":
        items, errors = _windows_drivers()
        return make_result("drivers", items, method="registry_services_type_scan", platform_name=plat, errors=errors)
    if plat == "Linux":
        items, errors = _linux_modules(root_dir)
        return make_result("drivers", items, method="proc_modules_and_sys_module_taint", platform_name=plat, errors=errors)
    return unsupported(
        "drivers",
        plat,
        "Kernel extension inventory on macOS needs kmutil/kextstat, which JOCKY does not run (no process execution).",
    )


# ---------------------------------------------------------------------------
# Listening ports
# ---------------------------------------------------------------------------

def collect_listening_ports(platform_name: Optional[str] = None) -> Dict[str, Any]:
    """TCP sockets in LISTEN state and bound UDP sockets, with the owning process where visible."""
    plat = _platform(platform_name)
    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return make_result(
            "listening_ports", [], method="psutil_net_connections", platform_name=plat, status="denied",
            extra={"reason": "Socket table needs elevated privileges on this platform."},
        )
    names: Dict[int, str] = {}
    for conn in connections:
        is_tcp_listen = conn.status == psutil.CONN_LISTEN
        is_udp_bound = conn.type == 2 and conn.laddr and not conn.raddr  # SOCK_DGRAM
        if not (is_tcp_listen or is_udp_bound):
            continue
        pid = conn.pid
        if pid and pid not in names:
            try:
                names[pid] = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                names[pid] = None
        items.append(
            {
                "protocol": "TCP" if is_tcp_listen else "UDP",
                "address": conn.laddr.ip if conn.laddr else None,
                "port": conn.laddr.port if conn.laddr else None,
                "pid": pid,
                "process_name": names.get(pid) if pid else None,
                "exposed": bool(conn.laddr) and conn.laddr.ip not in ("127.0.0.1", "::1", "localhost"),
            }
        )
    items.sort(key=lambda i: (i["protocol"], i["port"] or 0))
    return make_result("listening_ports", items[:MAX_ITEMS], method="psutil_net_connections", platform_name=plat, errors=errors)


# ---------------------------------------------------------------------------
# DNS resolver configuration
# ---------------------------------------------------------------------------

def _resolv_conf(root_dir: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    text = _read_text(_under(root_dir, "etc/resolv.conf"), errors)
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("nameserver", "search", "domain"):
            for value in parts[1:]:
                items.append({"kind": parts[0], "value": value, "source": "/etc/resolv.conf"})
    hosts = _read_text(_under(root_dir, "etc/hosts"), errors)
    for line in (hosts or "").splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2:
            items.append({"kind": "hosts_entry", "value": parts[0], "names": parts[1:], "source": "/etc/hosts"})
    return items[:MAX_ITEMS], errors


def _windows_dns() -> Tuple[List[Dict[str, Any]], List[str]]:
    import winreg

    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    for iface in _winreg_subkeys(winreg.HKEY_LOCAL_MACHINE, base, errors):
        values = dict(_winreg_values(winreg.HKEY_LOCAL_MACHINE, f"{base}\\{iface}", []))
        for field in ("NameServer", "DhcpNameServer"):
            for server in re.split(r"[ ,]+", str(values.get(field) or "").strip()):
                if server:
                    items.append({"kind": "nameserver", "value": server, "interface": iface, "source": field})
    hosts_path = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32/drivers/etc/hosts"
    hosts = _read_text(hosts_path, errors)
    for line in (hosts or "").splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2:
            items.append({"kind": "hosts_entry", "value": parts[0], "names": parts[1:], "source": str(hosts_path)})
    return items[:MAX_ITEMS], errors


def collect_dns_config(root_dir: str = "/", platform_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Configured DNS resolvers and static hosts-file entries.

    This is resolver configuration, not the resolver cache: reading the
    Windows DNS client cache needs an undocumented API, so JOCKY does not
    claim to collect it.
    """
    plat = _platform(platform_name)
    if plat == "Windows":
        items, errors = _windows_dns()
        method = "registry_tcpip_interfaces_and_hosts_file"
    elif plat in ("Linux", "Darwin"):
        items, errors = _resolv_conf(root_dir)
        method = "resolv_conf_and_hosts_file"
    else:
        return unsupported("dns", plat, f"No DNS configuration source for {plat}")
    return make_result("dns", items, method=method, platform_name=plat, errors=errors)


INVENTORY_COLLECTORS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "services": collect_services,
    "startup": collect_startup_entries,
    "drivers": collect_drivers,
    "listening_ports": collect_listening_ports,
    "dns": collect_dns_config,
}
