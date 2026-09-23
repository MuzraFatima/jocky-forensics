"""
Unit tests for JOCKY System, Process, and Network Forensic Collectors.
"""

import json
from unittest.mock import MagicMock, patch
import psutil

from backend.app.collectors import (
    collect_files_info,
    collect_network_info,
    collect_process_info,
    collect_registry_info,
    collect_system_info,
    collect_users_info,
    collect_windows_metadata,
    get_collectors,
)


# =====================================================================
# System Collector Tests
# =====================================================================

def test_system_collector_returns_dict():
    """1. Verify system collector returns a dictionary."""
    data = collect_system_info()
    assert isinstance(data, dict)


def test_system_collector_required_fields():
    """2. Verify all required forensic system fields exist and are populated."""
    data = collect_system_info()

    required_fields = [
        "collector",
        "read_only",
        "hostname",
        "os",
        "os_version",
        "architecture",
        "username",
        "cpu",
        "memory",
        "boot_time",
    ]

    for field in required_fields:
        assert field in data, f"Missing required field '{field}'"
        assert data[field] is not None, f"Field '{field}' cannot be None"

    assert data["collector"] == "system"
    assert isinstance(data["hostname"], str) and len(data["hostname"]) > 0
    assert isinstance(data["os"], str) and len(data["os"]) > 0
    assert isinstance(data["os_version"], str) and len(data["os_version"]) > 0
    assert isinstance(data["architecture"], str) and len(data["architecture"]) > 0
    assert isinstance(data["username"], str) and len(data["username"]) > 0
    assert isinstance(data["cpu"], dict)
    assert isinstance(data["memory"], dict)
    assert isinstance(data["boot_time"], str) and len(data["boot_time"]) > 0

    # Verify CPU nested fields
    assert "count_logical" in data["cpu"]
    assert "count_physical" in data["cpu"]

    # Verify Memory nested fields
    assert "total_bytes" in data["memory"]
    assert "available_bytes" in data["memory"]
    assert data["memory"]["total_bytes"] > 0
    assert data["memory"]["available_bytes"] > 0


def test_system_collector_json_serializable():
    """3. Verify collector output is strictly JSON serializable."""
    data = collect_system_info()
    serialized = json.dumps(data)
    assert isinstance(serialized, str)
    deserialized = json.loads(serialized)
    assert deserialized == data


def test_system_collector_is_read_only():
    """4. Verify system collector is explicitly flagged as read-only."""
    data = collect_system_info()
    assert data["read_only"] is True


# =====================================================================
# Process Collector Tests
# =====================================================================

def test_process_collector_returns_dict():
    """1. Verify process collector returns a dictionary."""
    data = collect_process_info()
    assert isinstance(data, dict)


def test_process_collector_metadata():
    """2 & 3. Verify collector identity and read-only flag."""
    data = collect_process_info()
    assert data["collector"] == "processes"
    assert data["read_only"] is True
    assert "timestamp_utc" in data
    assert isinstance(data["timestamp_utc"], str)


def test_process_collector_list_and_count():
    """4 & 5. Verify processes is a list and count matches length."""
    data = collect_process_info()
    assert isinstance(data["processes"], list)
    assert data["count"] == len(data["processes"])
    assert data["count"] > 0  # A live system has running processes


def test_process_collector_json_serializable():
    """6. Verify all process records are JSON serializable."""
    data = collect_process_info()
    serialized = json.dumps(data)
    assert isinstance(serialized, str)
    deserialized = json.loads(serialized)
    assert deserialized["count"] == data["count"]
    assert deserialized["collector"] == "processes"
    assert deserialized["read_only"] is True


def test_process_collector_expected_fields():
    """7. Verify expected process record fields exist."""
    data = collect_process_info()
    expected_fields = {
        "pid",
        "name",
        "username",
        "exe",
        "cpu_percent",
        "memory_percent",
        "status",
        "create_time",
    }

    assert len(data["processes"]) > 0
    for proc in data["processes"][:20]:
        for field in expected_fields:
            assert field in proc, f"Process record missing expected field '{field}'"
        assert isinstance(proc["pid"], int) or proc["pid"] is None
        assert isinstance(proc["name"], str)


def test_process_collector_inaccessible_processes_handling():
    """8. Verify that NoSuchProcess, AccessDenied, and ZombieProcess do not terminate collection."""
    mock_p1 = MagicMock()
    mock_p1.info = {
        "pid": 101,
        "name": "explorer.exe",
        "username": "User",
        "exe": "C:\\Windows\\explorer.exe",
        "cpu_percent": 0.5,
        "memory_percent": 1.2,
        "status": "running",
        "create_time": 1700000000.0,
    }

    mock_p2 = MagicMock()
    mock_p2_prop = MagicMock(side_effect=psutil.NoSuchProcess(pid=102))
    type(mock_p2).info = mock_p2_prop

    mock_p3 = MagicMock()
    mock_p3_prop = MagicMock(side_effect=psutil.AccessDenied(pid=103))
    type(mock_p3).info = mock_p3_prop

    mock_p4 = MagicMock()
    mock_p4_prop = MagicMock(side_effect=psutil.ZombieProcess(pid=104))
    type(mock_p4).info = mock_p4_prop

    mock_p5 = MagicMock()
    mock_p5.info = {
        "pid": 105,
        "name": "cmd.exe",
        "username": "User",
        "exe": "C:\\Windows\\System32\\cmd.exe",
        "cpu_percent": 0.0,
        "memory_percent": 0.3,
        "status": "running",
        "create_time": 1700000010.0,
    }

    mock_process_list = [mock_p1, mock_p2, mock_p3, mock_p4, mock_p5]

    with patch("psutil.process_iter", return_value=mock_process_list):
        data = collect_process_info()

    assert data["collector"] == "processes"
    assert data["count"] == 2
    assert len(data["processes"]) == 2
    assert data["processes"][0]["pid"] == 101
    assert data["processes"][1]["pid"] == 105


# =====================================================================
# Network Collector Tests
# =====================================================================

def test_network_collector_returns_dict():
    """1. Verify network collector returns a dictionary."""
    data = collect_network_info()
    assert isinstance(data, dict)


def test_network_collector_metadata():
    """2. Verify collector name, read_only flag, and timestamp."""
    data = collect_network_info()
    assert data["collector"] == "network"
    assert data["read_only"] is True
    assert "timestamp_utc" in data
    assert isinstance(data["timestamp_utc"], str)


def test_network_collector_list_and_count():
    """3. Verify connections is a list and count matches length."""
    data = collect_network_info()
    assert isinstance(data["connections"], list)
    assert data["count"] == len(data["connections"])


def test_network_collector_json_serializable():
    """4. Verify network collector output is strictly JSON serializable."""
    data = collect_network_info()
    serialized = json.dumps(data)
    assert isinstance(serialized, str)
    deserialized = json.loads(serialized)
    assert deserialized["count"] == data["count"]
    assert deserialized["collector"] == "network"
    assert deserialized["read_only"] is True


def test_network_collector_expected_fields():
    """5. Verify expected socket endpoint fields exist in connection records."""
    data = collect_network_info()
    expected_fields = {
        "local_address",
        "local_port",
        "remote_address",
        "remote_port",
        "status",
        "pid",
        "protocol",
    }

    for conn in data["connections"]:
        for field in expected_fields:
            assert field in conn, f"Connection record missing field '{field}'"
        assert conn["protocol"] in ("TCP", "UDP", "UNKNOWN")


def test_network_collector_graceful_error_handling():
    """6. Verify that AccessDenied is handled gracefully without crashing."""
    with patch("psutil.net_connections", side_effect=psutil.AccessDenied()):
        with patch("psutil.process_iter", return_value=[]):
            data = collect_network_info()

    assert data["collector"] == "network"
    assert data["read_only"] is True
    assert isinstance(data["connections"], list)
    assert data["count"] == 0


# =====================================================================
# Registry Tests
# =====================================================================

def test_get_collectors_registry():
    """7. Verify collector registry exposes all Phase 3 active collectors."""
    collectors = get_collectors()
    assert "system" in collectors
    assert "processes" in collectors
    assert "network" in collectors
    assert "files" in collectors
    assert "users" in collectors
    assert "windows_metadata" in collectors
    assert "registry" in collectors
    assert callable(collectors["system"])
    assert callable(collectors["processes"])
    assert callable(collectors["network"])
    assert callable(collectors["files"])
    assert callable(collectors["users"])
    assert callable(collectors["windows_metadata"])
    assert callable(collectors["registry"])


# =====================================================================
# Phase 3: Files Collector Tests
# =====================================================================

def test_files_collector_returns_dict(tmp_path):
    """1. Verify files collector returns a dictionary with target path."""
    # Create test files
    sample_file = tmp_path / "test_artifact.txt"
    sample_file.write_text("forensic evidence content", encoding="utf-8")

    data = collect_files_info(target_path=str(tmp_path))
    assert isinstance(data, dict)
    assert data["collector"] == "files"
    assert data["read_only"] is True
    assert "provenance" in data
    assert data["provenance"]["read_only"] is True
    assert "evidence_id" in data
    assert data["evidence_id"].startswith("EVID-")
    assert isinstance(data["files"], list)
    assert data["count"] >= 1


def test_files_collector_file_metadata_and_hash(tmp_path):
    """2. Verify file metadata fields and SHA-256 hash computation."""
    payload = "critical forensic payload for hashing test"
    sample_file = tmp_path / "suspect.bin"
    sample_file.write_text(payload, encoding="utf-8")

    import hashlib
    expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    data = collect_files_info(target_path=str(tmp_path))
    matching = [f for f in data["files"] if f["filename"] == "suspect.bin"]
    assert len(matching) == 1
    f_meta = matching[0]

    required_fields = [
        "path", "filename", "extension", "size_bytes",
        "created_time", "modified_time", "accessed_time",
        "is_hidden", "is_executable", "sha256", "permissions"
    ]
    for field in required_fields:
        assert field in f_meta, f"Missing file field {field}"

    assert f_meta["size_bytes"] == len(payload.encode("utf-8"))
    assert f_meta["sha256"] == expected_hash
    assert f_meta["extension"] == ".bin"


def test_files_collector_json_serializable(tmp_path):
    """3. Verify files collector output is strictly JSON serializable."""
    sample_file = tmp_path / "sample.log"
    sample_file.write_text("log line 1\nlog line 2\n", encoding="utf-8")

    data = collect_files_info(target_path=str(tmp_path))
    serialized = json.dumps(data)
    assert isinstance(serialized, str)
    deserialized = json.loads(serialized)
    assert deserialized["collector"] == "files"
    assert deserialized["count"] == data["count"]


def test_files_collector_process_binaries():
    """4. Verify process binaries inspection returns a list of unique executables."""
    data = collect_files_info()
    assert "process_binaries" in data
    assert isinstance(data["process_binaries"], list)
    assert isinstance(data["process_binaries_count"], int)


# =====================================================================
# Phase 3: Users Collector Tests
# =====================================================================

def test_users_collector_returns_dict():
    """1. Verify users collector returns a valid dictionary."""
    data = collect_users_info()
    assert isinstance(data, dict)
    assert data["collector"] == "users"
    assert data["read_only"] is True
    assert "evidence_id" in data
    assert data["evidence_id"].startswith("EVID-")
    assert "provenance" in data
    assert data["provenance"]["read_only"] is True


def test_users_collector_current_user_structure():
    """2. Verify current user context fields exist and are well-formed."""
    data = collect_users_info()
    cu = data["current_user"]
    assert isinstance(cu, dict)
    assert "username" in cu and len(cu["username"]) > 0
    assert "is_admin" in cu and isinstance(cu["is_admin"], bool)
    assert "domain" in cu
    assert "session_name" in cu


def test_users_collector_json_serializable():
    """3. Verify users collector output is strictly JSON serializable."""
    data = collect_users_info()
    serialized = json.dumps(data)
    assert isinstance(serialized, str)
    deserialized = json.loads(serialized)
    assert deserialized["collector"] == "users"
    assert deserialized["read_only"] is True


def test_users_collector_resilience():
    """4. Verify users collector handles psutil.users exception gracefully."""
    with patch("psutil.users", side_effect=Exception("Simulated session query error")):
        data = collect_users_info()
        assert data["collector"] == "users"
        assert data["active_sessions"] == []
        assert "current_user" in data


# =====================================================================
# Phase 3: Windows Metadata & Registry Collector Tests
# =====================================================================

def test_windows_metadata_returns_dict():
    """1. Verify windows metadata collector returns expected envelope."""
    data = collect_windows_metadata()
    assert isinstance(data, dict)
    assert data["collector"] == "windows_metadata"
    assert data["read_only"] is True
    assert "evidence_id" in data
    assert "provenance" in data
    assert "autoruns" in data
    assert "services" in data
    assert "os_metadata" in data
    assert "environment" in data
    assert isinstance(data["count"], int)


def test_windows_metadata_json_serializable():
    """2. Verify windows metadata output is strictly JSON serializable."""
    data = collect_windows_metadata()
    serialized = json.dumps(data)
    assert isinstance(serialized, str)
    deserialized = json.loads(serialized)
    assert deserialized["collector"] == "windows_metadata"
    assert deserialized["read_only"] is True


def test_registry_collector_alias():
    """3. Verify registry convenience alias returns valid payload."""
    data = collect_registry_info()
    assert isinstance(data, dict)
    assert data["collector"] == "registry"
    assert data["read_only"] is True
    assert "autoruns" in data
    assert isinstance(data["autoruns"], list)

