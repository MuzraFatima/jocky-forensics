"""Declarative detection rules: each rule fires on its scenario, stays quiet on benign data, and explains itself."""

import copy

import pytest

from backend.app.collectors.inventory import executable_of
from backend.app.detection import DetectionEngine, RuleError, correlate, load_rules, validate_rule


def _evidence(source, records):
    key = {"processes": "processes"}.get(source, "items")
    return {source: {key: records}}


SUSPICIOUS = {
    "JKY-DET-001": ("services", {"name": "upd.service", "executable": "/tmp/.x/run.sh", "binary_path": "/tmp/.x/run.sh"}),
    "JKY-DET-002": ("startup", {"name": "Updater", "command": "powershell -enc SQBFAFgA"}),
    "JKY-DET-003": ("drivers", {"name": "diamorphine", "unsigned": True, "out_of_tree": True}),
    "JKY-DET-004": ("drivers", {"name": "gdrv", "driver_type": "kernel_driver", "image_path": r"C:\Users\Public\gdrv.sys"}),
    "JKY-DET-005": ("listening_ports", {"protocol": "TCP", "port": 4444, "address": "0.0.0.0"}),
    "JKY-DET-006": ("dns", {"kind": "hosts_entry", "value": "203.0.113.7", "names": ["update.microsoft.com"]}),
    "JKY-DET-007": ("processes", {"pid": 10, "ppid": 1, "name": "inv.exe", "exe": r"C:\Users\bob\AppData\Local\Temp\inv.exe"}),
}

BENIGN = {
    "JKY-DET-001": ("services", {"name": "ssh.service", "executable": "/usr/sbin/sshd", "binary_path": "/usr/sbin/sshd -D"}),
    "JKY-DET-002": ("startup", {"name": "SecurityHealth", "command": r"%windir%\system32\SecurityHealthSystray.exe"}),
    "JKY-DET-003": ("drivers", {"name": "e1000", "unsigned": False, "out_of_tree": False}),
    "JKY-DET-004": ("drivers", {"name": "disk", "driver_type": "kernel_driver", "image_path": r"System32\drivers\disk.sys"}),
    "JKY-DET-005": ("listening_ports", {"protocol": "TCP", "port": 443, "address": "0.0.0.0"}),
    "JKY-DET-006": ("dns", {"kind": "hosts_entry", "value": "0.0.0.0", "names": ["telemetry.microsoft.com"]}),
    "JKY-DET-007": ("processes", {"pid": 11, "ppid": 1, "name": "code.exe", "exe": r"C:\Program Files\VS Code\code.exe"}),
}


@pytest.fixture(scope="module")
def engine():
    return DetectionEngine()


def test_at_least_five_rules_ship_and_validate():
    rules = load_rules()
    assert len(rules) >= 5
    for rule in rules:
        assert rule["attack"] and rule["benign_explanations"]


@pytest.mark.parametrize("rule_id", sorted(SUSPICIOUS))
def test_rule_fires_on_its_scenario(engine, rule_id):
    source, record = SUSPICIOUS[rule_id]
    result = engine.evaluate(_evidence(source, [record]), evidence_ids={source: "EVID-1"})
    hits = [f for f in result["findings"] if f["rule_id"] == rule_id]
    assert len(hits) == 1
    finding = hits[0]
    assert finding["matched_because"], "a finding must say why it matched"
    assert finding["evidence_id"] == "EVID-1"
    assert finding["record"].items() >= record.items()


@pytest.mark.parametrize("rule_id", sorted(BENIGN))
def test_rule_stays_quiet_on_benign_record(engine, rule_id):
    source, record = BENIGN[rule_id]
    result = engine.evaluate(_evidence(source, [record]))
    assert not [f for f in result["findings"] if f["rule_id"] == rule_id]


def test_parent_child_rule_uses_the_process_tree(engine):
    procs = [
        {"pid": 100, "ppid": 1, "name": "WINWORD.EXE"},
        {"pid": 101, "ppid": 100, "name": "powershell.exe"},
        {"pid": 200, "ppid": 1, "name": "explorer.exe"},
        {"pid": 201, "ppid": 200, "name": "cmd.exe"},
    ]
    result = engine.evaluate({"processes": {"processes": procs}})
    hits = [f for f in result["findings"] if f["rule_id"] == "JKY-DET-008"]
    assert [h["record"]["pid"] for h in hits] == [101]


def test_rules_without_their_source_are_reported_as_skipped(engine):
    result = engine.evaluate(_evidence("dns", []))
    assert "JKY-DET-001" in result["skipped_rules"]
    assert result["sources_seen"] == ["dns"]


def test_correlation_ranks_independent_sources_higher_but_never_says_compromised(engine):
    evidence = {}
    for rule_id in ("JKY-DET-001", "JKY-DET-005", "JKY-DET-006"):
        source, record = SUSPICIOUS[rule_id]
        evidence[source] = _evidence(source, [record])[source]
    result = engine.evaluate(evidence, endpoint="lab-ubuntu")
    corr = result["correlation"]
    assert corr["independent_sources"] == 3
    assert corr["priority"] == "critical"
    assert corr["verdict"] == "analyst review recommended"
    assert "compromised" not in corr["summary"].lower()
    assert {"T1543", "T1571"} <= {t["id"] for t in corr["techniques"]}
    assert corr["benign_explanations"]


def test_single_source_keeps_rule_severity():
    finding = {"source": "dns", "severity": "medium", "attack": [{"id": "T1562", "name": "x"}],
               "benign_explanations": ["b"]}
    assert correlate([finding])["priority"] == "medium"
    assert correlate([])["verdict"] == "no findings"


def test_malformed_rules_are_rejected():
    good = copy.deepcopy(load_rules()[0])
    validate_rule(good)
    for broken in (
        {**good, "source": "registry_hives"},
        {**good, "severity": "apocalyptic"},
        {**good, "attack": [{"id": "1543"}]},
        {**good, "benign_explanations": []},
        {**good, "condition": {"field": "x", "op": "teleport"}},
        {**good, "condition": {"all": []}},
    ):
        with pytest.raises(RuleError):
            validate_rule(broken)


def test_executable_is_split_from_arguments():
    assert executable_of('"C:\\Program Files\\Zoom\\CptService.exe" -user_path C:\\Users\\x\\AppData\\Roaming') == (
        "C:\\Program Files\\Zoom\\CptService.exe"
    )
    assert executable_of("-/usr/bin/foo --flag") == "/usr/bin/foo"
    assert executable_of(None) is None
