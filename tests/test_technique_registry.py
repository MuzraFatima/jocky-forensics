"""
Tests for Phase 2: Advanced Technique Registry.

Validates:
1. Complete registration of advanced forensic and threat detection techniques.
2. Presence and validity of all required fields (technique_id, name, category, indicators, evidence, collector, status, demo).
3. Filtering by category, analysis status, MITRE mapping, and demo availability.
4. Lookup by internal technique ID, detection rule ID, and MITRE ATT&CK ID.
5. Summary aggregation accuracy.
6. REST API endpoints (/api/forensics/techniques, /api/forensics/techniques/{id}, /api/forensics/techniques/stats/summary).
7. Defensive safety invariant: zero offensive/evasion/malware techniques.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.analysis.registry import (
    AnalysisStatus,
    TechniqueCategory,
    TechniqueEntry,
    TechniqueRegistry,
    get_technique_registry,
)

client = TestClient(app)


@pytest.fixture
def registry():
    """Provides a fresh or singleton TechniqueRegistry instance."""
    return get_technique_registry()


def test_registry_initialization_and_count(registry):
    """Verify registry loads all canonical techniques from catalog."""
    summary = registry.get_summary()
    assert summary["total_techniques"] >= 16
    assert summary["mitre_mapped_count"] >= 10
    assert summary["demo_available_count"] >= 10


def test_all_techniques_have_required_fields(registry):
    """Verify every entry has complete, non-empty metadata fields."""
    techniques = registry.list_techniques()
    assert len(techniques) >= 16

    for t in techniques:
        # technique_id
        assert t.technique_id.startswith("TECH-")
        assert len(t.technique_id) >= 6

        # technique_name
        assert t.technique_name and len(t.technique_name.strip()) > 3

        # category
        assert isinstance(t.category, TechniqueCategory)

        # observable_indicators
        assert isinstance(t.observable_indicators, list)
        assert len(t.observable_indicators) >= 1
        for ind in t.observable_indicators:
            assert isinstance(ind, str) and len(ind.strip()) > 0

        # required_evidence
        assert isinstance(t.required_evidence, list)
        assert len(t.required_evidence) >= 1

        # relevant_collector
        assert isinstance(t.relevant_collector, str)
        assert len(t.relevant_collector) > 0

        # analysis_status
        assert isinstance(t.analysis_status, AnalysisStatus)

        # demo_availability
        assert isinstance(t.demo_availability, bool)

        # description
        assert isinstance(t.description, str) and len(t.description.strip()) > 10


def test_implemented_techniques_match_forensic_rules(registry):
    """Verify that implemented detection techniques correctly map to existing RULE IDs."""
    implemented = registry.list_techniques(status=AnalysisStatus.IMPLEMENTED)
    rule_mapped = [t for t in implemented if t.detection_rule_id]
    rule_ids = {t.detection_rule_id for t in rule_mapped}

    # Must cover RULE-001 through RULE-005
    assert "RULE-001" in rule_ids
    assert "RULE-002" in rule_ids
    assert "RULE-003" in rule_ids
    assert "RULE-004" in rule_ids
    assert "RULE-005" in rule_ids


def test_filter_by_status(registry):
    """Verify filtering techniques by analysis status."""
    implemented = registry.list_techniques(status=AnalysisStatus.IMPLEMENTED)
    assert len(implemented) >= 7
    for t in implemented:
        assert t.analysis_status == AnalysisStatus.IMPLEMENTED

    detectable = registry.list_techniques(status=AnalysisStatus.DETECTABLE)
    assert len(detectable) >= 5
    for t in detectable:
        assert t.analysis_status == AnalysisStatus.DETECTABLE

    partially = registry.list_techniques(status=AnalysisStatus.PARTIALLY_IMPLEMENTED)
    assert len(partially) >= 1
    for t in partially:
        assert t.analysis_status == AnalysisStatus.PARTIALLY_IMPLEMENTED

    planned = registry.list_techniques(status=AnalysisStatus.PLANNED)
    assert len(planned) >= 1
    for t in planned:
        assert t.analysis_status == AnalysisStatus.PLANNED


def test_filter_by_category(registry):
    """Verify filtering techniques by category."""
    persistence = registry.list_techniques(category=TechniqueCategory.PERSISTENCE_MECHANISMS)
    assert len(persistence) >= 3
    for t in persistence:
        assert t.category == TechniqueCategory.PERSISTENCE_MECHANISMS

    injection = registry.list_techniques(category=TechniqueCategory.PROCESS_HIERARCHY_INJECTION)
    assert len(injection) >= 2
    for t in injection:
        assert t.category == TechniqueCategory.PROCESS_HIERARCHY_INJECTION


def test_lookup_by_id_and_mitre(registry):
    """Verify technique retrieval by ID, Rule ID, and MITRE ID."""
    # Lookup by ID
    tmp_exec = registry.get("TECH-TMP-EXEC")
    assert tmp_exec is not None
    assert tmp_exec.technique_name == "Execution from Temporary Directories"
    assert tmp_exec.detection_rule_id == "RULE-001"

    # Lookup by Rule ID
    rule_2 = registry.get_by_rule_id("RULE-002")
    assert rule_2 is not None
    assert rule_2.technique_id == "TECH-PROC-SPAWN"

    # Lookup by MITRE ID
    mitre_t1571 = registry.get_by_mitre("T1571")
    assert mitre_t1571 is not None
    assert mitre_t1571.technique_id == "TECH-NET-BACKDOOR"
    assert mitre_t1571.mitre_mapping.tactic == "Command and Control"

    # Nonexistent lookup
    assert registry.get("TECH-NONEXISTENT") is None
    assert registry.get_by_mitre("T9999.999") is None


def test_lookup_by_collector(registry):
    """Verify grouping techniques by collector module."""
    proc_techs = registry.get_by_collector("processes")
    assert len(proc_techs) >= 4
    for t in proc_techs:
        assert t.relevant_collector.lower() == "processes"

    net_techs = registry.get_by_collector("network")
    assert len(net_techs) >= 2


def test_defensive_safety_invariants(registry):
    """Ensure no offensive, exploit generation, or malware evasion capabilities are registered."""
    prohibited_offensive_actions = [
        "exploit generation",
        "weaponized payload",
        "kernel rootkit",
        "bootkit deployment",
        "disable edr",
        "disable antivirus",
        "unhook ntdll",
        "process hollowing execution",
        "evasion tool",
    ]
    for t in registry.list_techniques():
        desc_lower = t.description.lower()
        name_lower = t.technique_name.lower()
        for kw in prohibited_offensive_actions:
            assert kw not in desc_lower, f"Prohibited offensive capability '{kw}' found in {t.technique_id}"
            assert kw not in name_lower, f"Prohibited offensive capability '{kw}' found in {t.technique_id}"


# ── REST API Integration Tests ────────────────────────────────────────────────

def test_api_techniques_summary_endpoint():
    """Verify GET /api/forensics/techniques/stats/summary returns aggregate statistics."""
    resp = client.get("/api/forensics/techniques/stats/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    summary = data["summary"]
    assert summary["total_techniques"] >= 16
    assert summary["status_breakdown"]["implemented"] >= 7
    assert summary["status_breakdown"]["detectable"] >= 5
    assert summary["status_breakdown"]["partially_implemented"] >= 1
    assert summary["status_breakdown"]["planned"] >= 1


def test_api_list_techniques_endpoint():
    """Verify GET /api/forensics/techniques returns all techniques with filter queries."""
    # 1. Unfiltered list
    all_resp = client.get("/api/forensics/techniques")
    assert all_resp.status_code == 200
    all_data = all_resp.json()
    assert all_data["success"] is True
    assert all_data["count"] >= 16

    # 2. Filter by status
    impl_resp = client.get("/api/forensics/techniques?status=implemented")
    assert impl_resp.status_code == 200
    impl_data = impl_resp.json()
    assert impl_data["count"] >= 7
    for item in impl_data["techniques"]:
        assert item["analysis_status"] == "implemented"

    # 3. Filter by MITRE only
    mitre_resp = client.get("/api/forensics/techniques?mitre_only=true")
    assert mitre_resp.status_code == 200
    mitre_data = mitre_resp.json()
    for item in mitre_data["techniques"]:
        assert item["mitre_mapping"] is not None

    # 4. Filter by Demo only
    demo_resp = client.get("/api/forensics/techniques?demo_only=true")
    assert demo_resp.status_code == 200
    demo_data = demo_resp.json()
    for item in demo_data["techniques"]:
        assert item["demo_availability"] is True


def test_api_get_technique_by_id_endpoint():
    """Verify GET /api/forensics/techniques/{technique_id} retrieves individual records."""
    # 1. Direct ID lookup
    resp = client.get("/api/forensics/techniques/TECH-TMP-EXEC")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    tech = data["technique"]
    assert tech["technique_id"] == "TECH-TMP-EXEC"
    assert tech["mitre_mapping"]["id"] == "T1036.005"
    assert tech["detection_rule_id"] == "RULE-001"

    # 2. MITRE ID fallback lookup
    mitre_resp = client.get("/api/forensics/techniques/T1055")
    assert mitre_resp.status_code == 200
    m_data = mitre_resp.json()
    assert m_data["technique"]["technique_id"] == "TECH-PROC-HOLLOW"

    # 3. Not found returns 404
    nf_resp = client.get("/api/forensics/techniques/NONEXISTENT-TECH-99")
    assert nf_resp.status_code == 404
    assert nf_resp.json()["success"] is False
