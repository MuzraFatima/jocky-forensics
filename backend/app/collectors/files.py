"""
JOCKY Safe Files & Process Metadata Forensic Collector

Authorized read-only digital forensic collector for file system metadata,
timestamp auditing (MAC times), size metrics, cryptographic file hashing (SHA-256),
and process binary verification.

Safety Invariants:
- Strictly read-only: does not create, modify, truncate, move, or delete any file.
- Bounded traversal: depth-limited and item-limited to prevent runaway disk I/O.
- Safe hashing: size-bounded SHA-256 hashing (skips excessive multi-gigabyte files).
- Gracefully handles AccessDenied, PermissionError, and FileNotFoundError.
"""

import datetime
import hashlib
import os
from pathlib import Path
import stat
from typing import Any, Dict, List, Optional, Set
import psutil

from .provenance import create_provenance, generate_collector_evidence_id

# Executable and script extensions of forensic interest
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".wsf", ".scr", ".pif", ".cpl", ".msi", ".jar", ".py", ".sh"
}

# Maximum file size for inline SHA-256 hashing (20 MB)
MAX_HASH_SIZE_BYTES = 20 * 1024 * 1024


def _safe_format_ts(epoch_ts: Optional[float]) -> Optional[str]:
    """Safely format an epoch timestamp to ISO 8601 UTC string."""
    if not epoch_ts or epoch_ts <= 0:
        return None
    try:
        return datetime.datetime.fromtimestamp(epoch_ts, tz=datetime.timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return None


def _compute_file_sha256(file_path: Path, max_bytes: int = MAX_HASH_SIZE_BYTES) -> Optional[str]:
    """
    Safely computes SHA-256 digest of a file in chunks.
    Returns None if file exceeds max_bytes or if unreadable.
    """
    try:
        if file_path.stat().st_size > max_bytes:
            return "SKIPPED_EXCEEDS_SIZE_LIMIT"
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _is_file_hidden(file_path: Path, st: os.stat_result) -> bool:
    """Check if file is marked hidden."""
    if file_path.name.startswith("."):
        return True
    if hasattr(stat, "FILE_ATTRIBUTE_HIDDEN"):
        return bool(st.st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
    return False


def _inspect_file(file_path: Path, compute_hash: bool = True) -> Optional[Dict[str, Any]]:
    """Gathers normalized read-only forensic metadata for a single file path."""
    try:
        st = file_path.stat()
        ext = file_path.suffix.lower()
        is_exec = ext in EXECUTABLE_EXTENSIONS or bool(st.st_mode & 0o111)
        is_hidden = _is_file_hidden(file_path, st)

        sha256_hash = _compute_file_sha256(file_path) if compute_hash else None

        # Determine permissions summary
        perms = "read-only" if not (st.st_mode & stat.S_IWUSR) else "read-write"

        return {
            "path": str(file_path.resolve()),
            "filename": file_path.name,
            "extension": ext or "none",
            "size_bytes": st.st_size,
            "created_time": _safe_format_ts(getattr(st, "st_ctime", None)),
            "modified_time": _safe_format_ts(st.st_mtime),
            "accessed_time": _safe_format_ts(st.st_atime),
            "is_hidden": is_hidden,
            "is_executable": is_exec,
            "sha256": sha256_hash,
            "permissions": perms,
        }
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _collect_process_binary_metadata(max_binaries: int = 40) -> List[Dict[str, Any]]:
    """Collects file metadata for accessible unique running process executables."""
    records: List[Dict[str, Any]] = []
    seen_paths: Set[str] = set()

    try:
        for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
            if len(records) >= max_binaries:
                break
            try:
                exe = proc.info.get("exe")
                if exe and exe not in seen_paths and os.path.exists(exe):
                    seen_paths.add(exe)
                    meta = _inspect_file(Path(exe), compute_hash=True)
                    if meta:
                        meta["associated_process_name"] = proc.info.get("name")
                        meta["associated_pid"] = proc.info.get("pid")
                        records.append(meta)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue
    except Exception:
        pass

    return records


def collect_files_info(
    target_path: Optional[str] = None,
    max_files: int = 50,
) -> Dict[str, Any]:
    """
    Safely enumerates files and collects read-only forensic metadata and hashes.

    If target_path is specified, scans that directory up to max_files.
    Otherwise, inspects default forensic interest locations (e.g. Temp directory,
    Startup directory, and running process binaries).

    Returns:
        Structured JSON-serializable dictionary adhering to JOCKY collector standards.
    """
    file_records: List[Dict[str, Any]] = []
    scan_errors: List[str] = []
    scanned_locations: List[str] = []

    # 1. Determine targets to scan
    dirs_to_scan: List[Path] = []
    if target_path:
        p = Path(target_path)
        if p.exists() and p.is_dir():
            dirs_to_scan.append(p)
        elif p.exists() and p.is_file():
            single_record = _inspect_file(p, compute_hash=True)
            if single_record:
                file_records.append(single_record)
    else:
        # Default forensic scan locations
        # A. Windows / System Temp directory
        temp_dir = os.environ.get("TEMP") or os.environ.get("TMP") or "/tmp"
        if temp_dir and os.path.exists(temp_dir):
            dirs_to_scan.append(Path(temp_dir))

        # B. User Startup directory (Windows)
        appdata = os.environ.get("APPDATA")
        if appdata:
            startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if startup_dir.exists():
                dirs_to_scan.append(startup_dir)

    # 2. Perform bounded read-only scan of target directories
    for d in dirs_to_scan:
        scanned_locations.append(str(d))
        try:
            with os.scandir(d) as it:
                for entry in it:
                    if len(file_records) >= max_files:
                        break
                    try:
                        if entry.is_file(follow_symlinks=False):
                            meta = _inspect_file(Path(entry.path), compute_hash=True)
                            if meta:
                                file_records.append(meta)
                    except (PermissionError, OSError) as err:
                        scan_errors.append(f"{entry.path}: {err}")
        except (PermissionError, OSError) as err:
            scan_errors.append(f"{d}: {err}")

    # 3. Gather running process binary metadata
    process_binaries = _collect_process_binary_metadata(max_binaries=30)

    # 4. Compute summaries
    total_bytes = sum(f["size_bytes"] for f in file_records if isinstance(f.get("size_bytes"), int))
    executables_count = sum(1 for f in file_records if f.get("is_executable"))
    hidden_count = sum(1 for f in file_records if f.get("is_hidden"))

    provenance = create_provenance(
        collector_name="files",
        method="filesystem_stat_and_sha256_bounded_scan",
    )

    return {
        "collector": "files",
        "collector_version": "1.0.0",
        "read_only": True,
        "evidence_id": generate_collector_evidence_id("files"),
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "provenance": provenance,
        "scanned_locations": scanned_locations,
        "files": file_records,
        "count": len(file_records),
        "process_binaries": process_binaries,
        "process_binaries_count": len(process_binaries),
        "summary": {
            "total_files": len(file_records),
            "total_bytes": total_bytes,
            "executables_count": executables_count,
            "hidden_count": hidden_count,
        },
        "errors": scan_errors[:10],
    }
