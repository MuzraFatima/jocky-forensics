"""
Tests for Phase 7: Cross-Platform Forensics (Windows + Linux/Ubuntu) & Collector Dispatcher.

Validates:
1. Linux collectors strictly conform to normalized forensic evidence dictionary schemas.
2. Linux filesystem parser correctly parses /etc/os-release, /proc/meminfo, /etc/passwd, and crontabs.
3. Schema parity between Windows and Linux collectors (matching keys and data types).
4. Platform dispatcher cleanly routes based on detected or forced platform.
5. REST API endpoint GET /api/forensics/platform reports accurate capabilities.
"""

import os
import plistlib
import shutil
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.collectors.linux_collectors import (
    collect_linux_files_info,
    collect_linux_network_info,
    collect_linux_persistence_info,
    collect_linux_process_info,
    collect_linux_system_info,
    collect_linux_users_info,
)
from backend.app.collectors.macos_collectors import (
    collect_macos_files_info,
    collect_macos_network_info,
    collect_macos_persistence_info,
    collect_macos_process_info,
    collect_macos_system_info,
    collect_macos_users_info,
)
from backend.app.collectors.dispatcher import (
    dispatch_files_info,
    dispatch_network_info,
    dispatch_persistence_info,
    dispatch_process_info,
    dispatch_system_info,
    dispatch_users_info,
    get_current_platform,
    get_platform_collectors,
    is_windows,
    is_linux,
    is_macos,
    is_darwin,
)
from backend.app.collectors.system import collect_system_info as win_system_info
from backend.app.collectors.processes import collect_process_info as win_process_info
from backend.app.collectors.network import collect_network_info as win_network_info
from backend.app.main import app


client = TestClient(app)


@pytest.fixture
def mock_linux_root():
    """
    Creates a temporary mock Linux filesystem root containing realistic
    /etc/os-release, /etc/passwd, /proc/meminfo, /proc/1/status, /etc/crontab,
    and systemd unit files.
    """
    temp_dir = tempfile.mkdtemp(prefix="jocky_linux_mock_")
    root = Path(temp_dir)

    # 1. /etc/os-release & /etc/hostname
    etc = root / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    (etc / "os-release").write_text(
        'NAME="Ubuntu"\n'
        'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\n'
        'ID_LIKE=debian\n'
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
        'VERSION_ID="22.04"\n',
        encoding="utf-8",
    )
    (etc / "hostname").write_text("forensic-ubuntu-node01\n", encoding="utf-8")

    # 2. /etc/passwd
    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n"
        "forensic_user:x:1000:1000:Forensic Analyst,,,:/home/forensic_user:/bin/bash\n",
        encoding="utf-8",
    )

    # 3. /proc/meminfo
    proc = root / "proc"
    proc.mkdir(parents=True, exist_ok=True)
    (proc / "meminfo").write_text(
        "MemTotal:       16384000 kB\n"
        "MemFree:         4096000 kB\n"
        "MemAvailable:    8192000 kB\n",
        encoding="utf-8",
    )

    # 4. /proc/[pid] processes
    proc_1 = proc / "1"
    proc_1.mkdir(parents=True, exist_ok=True)
    (proc_1 / "status").write_text("Name:\tsystemd\nState:\tS (sleeping)\nPPid:\t0\n", encoding="utf-8")
    (proc_1 / "cmdline").write_text("/sbin/init\x00splash\x00", encoding="utf-8")

    proc_500 = proc / "500"
    proc_500.mkdir(parents=True, exist_ok=True)
    (proc_500 / "status").write_text("Name:\tsshd\nState:\tS (sleeping)\nPPid:\t1\n", encoding="utf-8")
    (proc_500 / "cmdline").write_text("/usr/sbin/sshd\x00-D\x00", encoding="utf-8")

    # 5. /proc/net/tcp
    proc_net = proc / "net"
    proc_net.mkdir(parents=True, exist_ok=True)
    (proc_net / "tcp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
        "   1: 0100007F:0050 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0\n",
        encoding="utf-8",
    )

    # 6. /etc/crontab
    (etc / "crontab").write_text(
        "# /etc/crontab\n"
        "17 * * * * root    cd / && run-parts --report /etc/cron.hourly\n"
        "25 6 * * * root    test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily\n",
        encoding="utf-8",
    )

    # 7. /etc/systemd/system/*.service
    systemd_sys = etc / "systemd" / "system"
    systemd_sys.mkdir(parents=True, exist_ok=True)
    (systemd_sys / "malicious_backdoor.service").write_text(
        "[Unit]\nDescription=Suspicious Backdoor Daemon\n[Service]\nExecStart=/tmp/backdoor.sh\n",
        encoding="utf-8",
    )

    # 8. /tmp directory with files
    tmp_dir = root / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    (tmp_dir / "backdoor.sh").write_text("#!/bin/bash\necho persistent\n", encoding="utf-8")
    (tmp_dir / "notes.txt").write_text("triage artifact\n", encoding="utf-8")

    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Linux Collector Unit Tests
# ---------------------------------------------------------------------------

def test_linux_system_info_parsing(mock_linux_root):
    sys_info = collect_linux_system_info(root_dir=mock_linux_root)
    assert sys_info["os"] == "Linux"
    assert "Ubuntu 22.04" in sys_info["distro"]
    assert sys_info["hostname"] == "forensic-ubuntu-node01"
    assert sys_info["memory"]["total_gb"] > 0
    assert "cpu" in sys_info
    assert sys_info["cpu"]["count_logical"] >= 1


def test_linux_process_info_parsing(mock_linux_root):
    proc_info = collect_linux_process_info(root_dir=mock_linux_root)
    assert proc_info["count"] >= 2
    pids = [p["pid"] for p in proc_info["processes"]]
    assert 1 in pids
    assert 500 in pids
    sshd = next(p for p in proc_info["processes"] if p["pid"] == 500)
    assert sshd["name"] == "sshd"
    assert "/usr/sbin/sshd" in sshd["cmdline"]


def test_linux_network_info_parsing(mock_linux_root):
    net_info = collect_linux_network_info(root_dir=mock_linux_root)
    assert net_info["count"] == 2
    ports = [c["laddr"] for c in net_info["connections"]]
    # port 0016 hex is 22 (SSH)
    assert any(":22" in p for p in ports)
    # port 0050 hex is 80 (HTTP)
    assert any(":80" in p for p in ports)


def test_linux_files_info_parsing(mock_linux_root):
    files_info = collect_linux_files_info(root_dir=mock_linux_root, max_files=20)
    assert files_info["count"] >= 1
    fnames = [f["name"] for f in files_info["files"]]
    assert "backdoor.sh" in fnames or "notes.txt" in fnames
    # Check SHA-256 computation
    for f in files_info["files"]:
        if f["name"] == "notes.txt":
            assert len(f["sha256"]) == 64


def test_linux_users_info_parsing(mock_linux_root):
    users_info = collect_linux_users_info(root_dir=mock_linux_root)
    assert "current_user" in users_info
    assert len(users_info["user_profiles"]) >= 4
    unames = [u["name"] for u in users_info["user_profiles"]]
    assert "root" in unames
    assert "forensic_user" in unames


def test_linux_persistence_info_parsing(mock_linux_root):
    pers_info = collect_linux_persistence_info(root_dir=mock_linux_root)
    assert pers_info["autoruns_count"] >= 2  # 2 crontab lines
    assert pers_info["services_count"] >= 1  # malicious_backdoor.service
    service_names = [s["name"] for s in pers_info["services"]]
    assert "malicious_backdoor" in service_names
    backdoor_svc = next(s for s in pers_info["services"] if s["name"] == "malicious_backdoor")
    assert "/tmp/backdoor.sh" in backdoor_svc["binpath"]


# ---------------------------------------------------------------------------
# Cross-Platform Schema Parity Tests
# ---------------------------------------------------------------------------

def test_cross_platform_schema_parity(mock_linux_root):
    """
    Ensures both Windows and Linux outputs conform to identical top-level keys
    so downstream analysis (correlation, timeline, vault) works interchangeably.
    """
    linux_sys = collect_linux_system_info(root_dir=mock_linux_root)
    win_sys = win_system_info()

    # System schema parity
    for key in ["hostname", "os", "os_version", "architecture", "boot_time", "memory", "cpu"]:
        assert key in linux_sys, f"Key '{key}' missing from Linux system info"
        assert key in win_sys, f"Key '{key}' missing from Windows system info"

    # Process schema parity
    linux_proc = collect_linux_process_info(root_dir=mock_linux_root)
    win_proc = win_process_info()
    assert "count" in linux_proc and "processes" in linux_proc
    assert "count" in win_proc and "processes" in win_proc

    if linux_proc["processes"] and win_proc["processes"]:
        lp = linux_proc["processes"][0]
        wp = win_proc["processes"][0]
        for pkey in ["pid", "ppid", "name", "cmdline", "username", "exe", "status"]:
            assert pkey in lp, f"Process key '{pkey}' missing from Linux process"
            assert pkey in wp, f"Process key '{pkey}' missing from Windows process"

    # Network schema parity
    linux_net = collect_linux_network_info(root_dir=mock_linux_root)
    win_net = win_network_info()
    assert "count" in linux_net and "connections" in linux_net
    assert "count" in win_net and "connections" in win_net


# ---------------------------------------------------------------------------
# Dispatcher Tests
# ---------------------------------------------------------------------------

def test_dispatcher_forced_platforms(mock_linux_root):
    # Test Linux dispatch
    l_sys = dispatch_system_info(root_dir=mock_linux_root, force_platform="Linux")
    assert l_sys["os"] == "Linux"

    l_proc = dispatch_process_info(root_dir=mock_linux_root, force_platform="Linux")
    assert l_proc["count"] >= 2

    l_pers = dispatch_persistence_info(root_dir=mock_linux_root, force_platform="Linux")
    assert l_pers["services_count"] >= 1

    # Test collector dictionary mapping
    linux_collectors = get_platform_collectors(force_platform="Linux")
    assert "system" in linux_collectors
    assert "persistence" in linux_collectors
    assert callable(linux_collectors["system"])


# ---------------------------------------------------------------------------
# REST API Endpoint Test
# ---------------------------------------------------------------------------

def test_api_platform_endpoint():
    res = client.get("/api/forensics/platform")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "platform" in data
    assert "capabilities" in data
    assert "windows" in data["capabilities"]
    assert "linux" in data["capabilities"]
    assert "macos" in data["capabilities"]
    assert "is_macos" in data
    assert data["read_only"] is True


# ---------------------------------------------------------------------------
# macOS / Darwin Collector Tests (Prompt 6)
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_macos_root():
    """
    Creates a temporary mock macOS filesystem root containing:
    - /System/Library/CoreServices/SystemVersion.plist
    - /etc/hostname and /etc/passwd
    - /Users user profiles (admin, analyst, Shared)
    - /Library/LaunchDaemons (*.plist) and /Library/LaunchAgents (*.plist)
    - /tmp triage files
    - /mock_proc process entries
    - /mock_net socket connection records
    """
    temp_dir = tempfile.mkdtemp(prefix="jocky_macos_mock_")
    root = Path(temp_dir)

    # 1. SystemVersion.plist
    core_services = root / "System" / "Library" / "CoreServices"
    core_services.mkdir(parents=True, exist_ok=True)
    with open(core_services / "SystemVersion.plist", "wb") as f:
        plistlib.dump({
            "ProductName": "macOS",
            "ProductVersion": "14.4.1",
            "ProductBuildVersion": "23E224",
        }, f)

    # 2. Hostname
    etc = root / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    (etc / "hostname").write_text("forensic-mac-lab01\n", encoding="utf-8")

    # 3. /etc/passwd
    (etc / "passwd").write_text(
        "nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false\n"
        "root:*:0:0:System Administrator:/var/root:/bin/sh\n"
        "admin:*:501:20:Forensic Admin:/Users/admin:/bin/zsh\n",
        encoding="utf-8",
    )

    # 4. /Users profiles
    users = root / "Users"
    users.mkdir(parents=True, exist_ok=True)
    (users / "admin").mkdir(parents=True, exist_ok=True)
    (users / "analyst").mkdir(parents=True, exist_ok=True)
    (users / "Shared").mkdir(parents=True, exist_ok=True)

    # 5. LaunchDaemons & LaunchAgents
    ld = root / "Library" / "LaunchDaemons"
    ld.mkdir(parents=True, exist_ok=True)
    with open(ld / "com.forensic.daemon.plist", "wb") as f:
        plistlib.dump({
            "Label": "com.forensic.daemon",
            "Program": "/usr/local/bin/forensic_daemon",
            "RunAtLoad": True,
        }, f)

    la = root / "Library" / "LaunchAgents"
    la.mkdir(parents=True, exist_ok=True)
    with open(la / "com.forensic.agent.plist", "wb") as f:
        plistlib.dump({
            "Label": "com.forensic.agent",
            "Program": "/usr/local/bin/agent",
            "RunAtLoad": False,
        }, f)

    # 6. /tmp with files
    tmp = root / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "sample_script.sh").write_text("#!/bin/sh\necho test\n", encoding="utf-8")
    (tmp / "notes.txt").write_text("macOS triage notes\n", encoding="utf-8")

    # 7. mock_proc
    mock_p = root / "mock_proc" / "1"
    mock_p.mkdir(parents=True, exist_ok=True)
    (mock_p / "info.txt").write_text("Name: launchd\nCmdline: /sbin/launchd\nUser: root\nPPid: 0\n", encoding="utf-8")

    mock_p2 = root / "mock_proc" / "200"
    mock_p2.mkdir(parents=True, exist_ok=True)
    (mock_p2 / "info.txt").write_text("Name: Finder\nCmdline: /System/Library/CoreServices/Finder.app\nUser: admin\nPPid: 1\n", encoding="utf-8")

    # 8. mock_net
    mock_n = root / "mock_net"
    mock_n.mkdir(parents=True, exist_ok=True)
    (mock_n / "connections.txt").write_text(
        "TCP 127.0.0.1:8080 0.0.0.0:* LISTEN 1\n"
        "TCP 192.168.1.10:49200 93.184.216.34:443 ESTABLISHED 200\n",
        encoding="utf-8",
    )

    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_macos_system_info_parsing(mock_macos_root):
    sys_info = collect_macos_system_info(root_dir=mock_macos_root)
    assert sys_info["collector"] == "system"
    assert sys_info["os"] == "macOS"
    assert "14.4.1" in sys_info["os_version"]
    assert sys_info["build_version"] == "23E224"
    assert sys_info["hostname"] == "forensic-mac-lab01"
    assert "memory" in sys_info
    assert "cpu" in sys_info


def test_macos_process_info(mock_macos_root):
    proc_info = collect_macos_process_info(root_dir=mock_macos_root)
    assert proc_info["collector"] == "processes"
    assert proc_info["count"] >= 2
    procs = proc_info["processes"]
    names = [p["name"] for p in procs]
    assert "launchd" in names
    assert "Finder" in names


def test_macos_network_info(mock_macos_root):
    net_info = collect_macos_network_info(root_dir=mock_macos_root)
    assert net_info["collector"] == "network"
    assert net_info["count"] >= 2
    protocols = [c["protocol"] for c in net_info["connections"]]
    assert "TCP" in protocols


def test_macos_files_info(mock_macos_root):
    files_info = collect_macos_files_info(root_dir=mock_macos_root)
    assert files_info["collector"] == "files"
    assert files_info["count"] >= 2
    fnames = [f["filename"] for f in files_info["files"]]
    assert "sample_script.sh" in fnames or "notes.txt" in fnames
    # Check SHA-256 hash was computed
    hashes = [f["sha256"] for f in files_info["files"] if f.get("sha256")]
    assert len(hashes) > 0
    assert len(hashes[0]) == 64


def test_macos_users_info(mock_macos_root):
    users_info = collect_macos_users_info(root_dir=mock_macos_root)
    assert users_info["collector"] == "users"
    assert len(users_info["user_accounts"]) >= 2
    u_names = [u["username"] for u in users_info["user_accounts"]]
    assert "root" in u_names
    assert "admin" in u_names
    # Check /Users profile directories
    assert "admin" in users_info["discovered_home_profiles"]
    assert "analyst" in users_info["discovered_home_profiles"]
    assert "Shared" not in users_info["discovered_home_profiles"]


def test_macos_persistence_launch_daemons(mock_macos_root):
    pers_info = collect_macos_persistence_info(root_dir=mock_macos_root)
    assert pers_info["collector"] == "persistence"
    assert len(pers_info["launch_daemons"]) >= 1
    assert pers_info["launch_daemons"][0]["label"] == "com.forensic.daemon"
    assert pers_info["launch_daemons"][0]["run_at_load"] is True
    assert len(pers_info["launch_agents"]) >= 1
    assert pers_info["launch_agents"][0]["label"] == "com.forensic.agent"
    assert pers_info["total_mechanisms"] >= 2


def test_dispatcher_macos_platform(mock_macos_root):
    # Test macOS / Darwin dispatching
    m_sys = dispatch_system_info(root_dir=mock_macos_root, force_platform="macOS")
    assert m_sys["os"] == "macOS"

    m_proc = dispatch_process_info(root_dir=mock_macos_root, force_platform="Darwin")
    assert m_proc["count"] >= 2

    m_pers = dispatch_persistence_info(root_dir=mock_macos_root, force_platform="macOS")
    assert m_pers["total_mechanisms"] >= 2

    # Test collector dictionary mapping for macOS
    mac_collectors = get_platform_collectors(force_platform="macOS")
    assert "system" in mac_collectors
    assert "persistence" in mac_collectors
    assert "launch_daemons" in mac_collectors
    assert callable(mac_collectors["system"])


def test_platform_detection_helpers():
    # Verify platform detection helper invariants
    assert isinstance(is_windows(), bool)
    assert isinstance(is_linux(), bool)
    assert isinstance(is_macos(), bool)
    assert isinstance(is_darwin(), bool)
    assert is_macos() == is_darwin()

