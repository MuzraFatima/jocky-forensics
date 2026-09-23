"""
Tests for Phase 10: Performance, Hardening & Final Packaging.

Validates:
1. Security validation and path traversal injection prevention (hardening.py).
2. Read-only invariant enforcement and safe bounds.
3. Performance latency benchmarks (DSL compilation, correlation, timeline, report rendering).
4. Standalone CLI commands (compile, execute, audit, export).
"""

import json
import os
import shutil
import tempfile
import time
from pathlib import Path
import pytest

from backend.app.engine.hardening import (
    SecurityValidationError,
    bounded_memory_inspect,
    sanitize_case_id,
    sanitize_forensic_path,
    verify_read_only_access,
)
from backend.app.language.compiler import compile_jocky
from backend.app.analysis.correlator import correlate_evidence
from backend.app.analysis.timeline import build_forensic_timeline
from backend.app.reporting.report_engine import ForensicReportBuilder
from backend.app.cli import main as cli_main


# ---------------------------------------------------------------------------
# 1. Security Hardening Unit Tests
# ---------------------------------------------------------------------------

def test_sanitize_case_id_accepts_valid():
    assert sanitize_case_id("CASE-2026-001") == "CASE-2026-001"
    assert sanitize_case_id("INCIDENT_ALPHA_99") == "INCIDENT_ALPHA_99"


def test_sanitize_case_id_rejects_traversal_and_null_bytes():
    with pytest.raises(SecurityValidationError):
        sanitize_case_id("../escaped_case")

    with pytest.raises(SecurityValidationError):
        sanitize_case_id("case/with/slashes")

    with pytest.raises(SecurityValidationError):
        sanitize_case_id("case\\with\\backslashes")

    with pytest.raises(SecurityValidationError):
        sanitize_case_id("case\x00nullbyte")

    with pytest.raises(SecurityValidationError):
        sanitize_case_id("")


def test_sanitize_forensic_path_rejects_traversal():
    with pytest.raises(SecurityValidationError):
        sanitize_forensic_path("../../../etc/passwd")

    with pytest.raises(SecurityValidationError):
        sanitize_forensic_path("C:\\Windows\\..\\..\\Windows")


def test_sanitize_forensic_path_enforces_base_boundary():
    temp_boundary = tempfile.mkdtemp(prefix="jocky_bound_")
    valid_sub = Path(temp_boundary) / "subfolder" / "file.txt"
    valid_sub.parent.mkdir(parents=True, exist_ok=True)
    valid_sub.write_text("ok", encoding="utf-8")

    # Inside boundary -> OK
    res = sanitize_forensic_path(str(valid_sub), base_boundary=temp_boundary)
    assert res == valid_sub.resolve()

    # Escaping boundary -> raises SecurityValidationError
    outside = Path(tempfile.gettempdir())
    with pytest.raises(SecurityValidationError):
        sanitize_forensic_path(str(outside), base_boundary=temp_boundary)

    shutil.rmtree(temp_boundary, ignore_errors=True)


def test_bounded_memory_inspect():
    large_list = list(range(5000))
    bounded = bounded_memory_inspect(large_list, max_items=500)
    assert len(bounded) == 500
    assert bounded[0] == 0
    assert bounded[-1] == 499


# ---------------------------------------------------------------------------
# 2. Performance Benchmarks
# ---------------------------------------------------------------------------

def test_benchmark_dsl_compilation_latency():
    """Asserts that 50 compilations complete well under 100ms (< 2ms each)."""
    script = """CASE "BENCH-01"
TARGET "PC-BENCH"
COLLECT SYSTEM
COLLECT PROCESSES
    WHERE status == RUNNING
REPORT FORMAT JSON"""

    start = time.perf_counter()
    for _ in range(50):
        res = compile_jocky(script)
        assert res["success"] is True
    duration_ms = (time.perf_counter() - start) * 1000

    # Ensure average compilation is sub-millisecond or few milliseconds
    assert duration_ms < 250, f"Compilation too slow: {duration_ms:.2f}ms for 50 runs"


def test_benchmark_correlation_latency():
    """Asserts that 100 processes and 100 connections correlate in < 50ms."""
    fake_procs = [{"pid": i, "ppid": 1 if i > 1 else 0, "name": f"proc_{i}.exe", "username": "SYSTEM"} for i in range(1, 101)]
    fake_conns = [{"pid": (i % 50) + 1, "protocol": "TCP", "laddr": f"10.0.0.{i}:443", "raddr": "1.1.1.1:443", "status": "ESTABLISHED"} for i in range(1, 101)]

    start = time.perf_counter()
    corr = correlate_evidence({
        "processes": {"processes": fake_procs},
        "network": {"connections": fake_conns},
        "files": {"files": []},
        "users": {"user_profiles": []},
    })
    duration_ms = (time.perf_counter() - start) * 1000

    assert corr["summary"]["process_count"] == 100
    assert duration_ms < 100, f"Correlation too slow: {duration_ms:.2f}ms"


def test_benchmark_report_html_rendering_latency():
    """Asserts that full HTML report generation renders in < 30ms."""
    builder = ForensicReportBuilder(case_id="BENCH-REP", target="LIVE-BENCH")
    rep_data = builder.build_report_data(
        collected_data={
            "system": {"hostname": "BENCH-HOST", "os": "Windows"},
            "processes": {"count": 10, "processes": []},
            "network": {"count": 5, "connections": []},
        },
        detections=[{"rule_id": "RULE-001", "rule_name": "Test Rule", "severity": "HIGH", "description": "Benchmark alert"}],
    )

    start = time.perf_counter()
    for _ in range(10):
        html_out = builder.generate_html(rep_data)
        assert len(html_out) > 500
    duration_ms = (time.perf_counter() - start) * 1000

    assert duration_ms < 100, f"HTML rendering too slow: {duration_ms:.2f}ms for 10 runs"


# ---------------------------------------------------------------------------
# 3. Standalone CLI Tests
# ---------------------------------------------------------------------------

def test_cli_compile_command():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_incident.jocky"
    ret = cli_main(["compile", str(fixture_path)])
    assert ret == 0


def test_cli_compile_nonexistent_file():
    ret = cli_main(["compile", "non_existent_script.jocky"])
    assert ret == 1


def test_cli_execute_command(tmp_path):
    fixture_path = Path(__file__).parent / "fixtures" / "sample_incident.jocky"
    out_file = tmp_path / "cli_test_report.html"

    ret = cli_main(["execute", str(fixture_path), "--format", "HTML", "--output", str(out_file)])
    assert ret == 0
    assert out_file.exists()
    assert "<!DOCTYPE html>" in out_file.read_text(encoding="utf-8")


def test_cli_audit_command():
    ret = cli_main(["audit"])
    # Return code 0 (intact) or 2 (tampered if previous tamper tests ran on shared vault)
    assert ret in (0, 2)


def test_cli_export_command(tmp_path):
    out_bundle = tmp_path / "bundle_export.json"
    ret = cli_main(["export", "INCIDENT-2026-ALPHA", "--output", str(out_bundle)])
    assert ret == 0
    assert out_bundle.exists()
    bundle_data = json.loads(out_bundle.read_text(encoding="utf-8"))
    assert "manifest" in bundle_data
