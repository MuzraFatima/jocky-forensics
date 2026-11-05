"""
JOCKY declarative detection engine (blueprint §7).

Rules live as JSON files in detection/rules/. Each rule names the evidence
source it reads, a condition over record fields, a severity, a confidence,
ATT&CK techniques and the benign explanations an analyst should rule out.
The engine is deterministic and read-only: it evaluates collected evidence
and never touches the host.

Findings are explainable: every finding lists the record that matched and
which field satisfied which condition. Correlation (§7.4) then looks for
independent signals from different sources on the same endpoint and
explains why the combination merits review. It never declares a host
compromised.

Rule schema:
    {
      "id": "JKY-DET-001",
      "title": "...",
      "description": "...",
      "source": "services",
      "condition": {"all": [<clause>, ...]} | {"any": [...]} | <clause>,
      "severity": "low" | "medium" | "high" | "critical",
      "confidence": "low" | "medium" | "high",
      "attack": [{"id": "T1543.002", "name": "..."}],
      "benign_explanations": ["..."]
    }

A clause is {"field": "binary_path", "op": "<op>", "value"|"values": ...}
or {"not": <clause>}. Ops: equals, in, contains_any, not_contains_any,
startswith_any, regex, is_true, present, gte. String comparisons are
case-insensitive, and path separators are normalised to "/" so one rule
covers Windows and Linux paths.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

RULES_DIR = Path(__file__).resolve().parent / "rules"

# Where each collector keeps its records
RECORD_KEYS: Dict[str, str] = {
    "processes": "processes",
    "network": "connections",
    "files": "files",
    "services": "items",
    "startup": "items",
    "drivers": "items",
    "listening_ports": "items",
    "dns": "items",
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
VALID_OPS = {"equals", "in", "contains_any", "not_contains_any", "startswith_any", "regex", "is_true", "present", "gte"}
REQUIRED_KEYS = {"id", "title", "description", "source", "condition", "severity", "confidence", "attack",
                 "benign_explanations"}


class RuleError(ValueError):
    """A rule file is malformed."""


# ---------------------------------------------------------------------------
# Rule loading and validation
# ---------------------------------------------------------------------------

def _validate_clause(clause: Any, rule_id: str) -> None:
    if not isinstance(clause, dict):
        raise RuleError(f"{rule_id}: condition clauses must be objects")
    if "all" in clause or "any" in clause:
        key = "all" if "all" in clause else "any"
        if not isinstance(clause[key], list) or not clause[key]:
            raise RuleError(f"{rule_id}: '{key}' needs a non-empty list")
        for sub in clause[key]:
            _validate_clause(sub, rule_id)
        return
    if "not" in clause:
        _validate_clause(clause["not"], rule_id)
        return
    if "field" not in clause or clause.get("op") not in VALID_OPS:
        raise RuleError(f"{rule_id}: clause needs a field and one of {sorted(VALID_OPS)}")


def validate_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    missing = REQUIRED_KEYS - set(rule)
    rule_id = rule.get("id", "<no id>")
    if missing:
        raise RuleError(f"{rule_id}: missing {sorted(missing)}")
    if rule["source"] not in RECORD_KEYS:
        raise RuleError(f"{rule_id}: unknown source '{rule['source']}'")
    if rule["severity"] not in SEVERITY_ORDER:
        raise RuleError(f"{rule_id}: unknown severity '{rule['severity']}'")
    if rule["confidence"] not in ("low", "medium", "high"):
        raise RuleError(f"{rule_id}: unknown confidence '{rule['confidence']}'")
    if not rule["attack"] or not all(re.fullmatch(r"T\d{4}(\.\d{3})?", t.get("id", "")) for t in rule["attack"]):
        raise RuleError(f"{rule_id}: attack needs ATT&CK ids like T1543 or T1543.002")
    if not rule["benign_explanations"]:
        raise RuleError(f"{rule_id}: list at least one benign explanation")
    _validate_clause(rule["condition"], rule_id)
    return rule


def load_rules(directory: Path = RULES_DIR) -> List[Dict[str, Any]]:
    rules = []
    for path in sorted(directory.glob("*.json")):
        with open(path, encoding="utf-8") as handle:
            rules.append(validate_rule(json.load(handle)))
    ids = [r["id"] for r in rules]
    if len(ids) != len(set(ids)):
        raise RuleError("duplicate rule ids")
    return rules


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _norm(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        value = " ".join(str(v) for v in value)
    return str(value).replace("\\", "/").lower()


def _get(record: Dict[str, Any], dotted: str) -> Any:
    current: Any = record
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _values(clause: Dict[str, Any]) -> List[Any]:
    if "values" in clause:
        return list(clause["values"])
    return [clause.get("value")]


def _clause_matches(clause: Dict[str, Any], record: Dict[str, Any], why: List[str]) -> bool:
    if "all" in clause:
        trail: List[str] = []
        if all(_clause_matches(sub, record, trail) for sub in clause["all"]):
            why.extend(trail)
            return True
        return False
    if "any" in clause:
        for sub in clause["any"]:
            trail = []
            if _clause_matches(sub, record, trail):
                why.extend(trail)
                return True
        return False
    if "not" in clause:
        return not _clause_matches(clause["not"], record, [])

    field, op = clause["field"], clause["op"]
    raw = _get(record, field)
    if op == "present":
        hit = raw not in (None, "", [])
        detail = f"{field} is present"
    elif op == "is_true":
        hit = raw is True
        detail = f"{field} is true"
    elif raw is None:
        return False
    elif op == "gte":
        hit = isinstance(raw, (int, float)) and raw >= clause["value"]
        detail = f"{field}={raw} >= {clause['value']}"
    elif op in ("equals", "in"):
        wanted = {_norm(v) for v in _values(clause)}
        hit = _norm(raw) in wanted or (not isinstance(raw, str) and raw in _values(clause))
        detail = f"{field}={raw!r} is on the rule's watch list"
    elif op in ("contains_any", "not_contains_any"):
        text = _norm(raw)
        found = [v for v in _values(clause) if _norm(v) in text]
        hit = bool(found) if op == "contains_any" else not found
        detail = (f"{field}={raw!r} contains {found[0]!r}" if found
                  else f"{field}={raw!r} contains none of the expected locations")
    elif op == "startswith_any":
        text = _norm(raw)
        found = [v for v in _values(clause) if text.startswith(_norm(v))]
        hit = bool(found)
        detail = f"{field}={raw!r} starts with {found[0]!r}" if found else ""
    elif op == "regex":
        hit = re.search(clause["value"], str(raw), re.IGNORECASE) is not None
        detail = f"{field}={raw!r} matches /{clause['value']}/"
    else:  # pragma: no cover - validate_rule rejects unknown ops
        return False
    if hit:
        why.append(detail)
    return hit


def _records(source: str, result: Any) -> List[Dict[str, Any]]:
    if not isinstance(result, dict):
        return []
    records = result.get(RECORD_KEYS[source]) or []
    return [r for r in records if isinstance(r, dict)]


def _enrich_processes(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Give each process its parent's name so rules can match parent/child pairs."""
    names = {r.get("pid"): r.get("name") for r in records}
    return [{**r, "parent_name": names.get(r.get("ppid"))} for r in records]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None):
        self.rules = rules if rules is not None else load_rules()

    def evaluate(
        self,
        evidence: Dict[str, Any],
        evidence_ids: Optional[Dict[str, str]] = None,
        endpoint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run every rule whose source is present in the evidence."""
        evidence_ids = evidence_ids or {}
        findings: List[Dict[str, Any]] = []
        prepared: Dict[str, List[Dict[str, Any]]] = {}
        for source in evidence:
            if source in RECORD_KEYS:
                recs = _records(source, evidence[source])
                prepared[source] = _enrich_processes(recs) if source == "processes" else recs

        evaluated = [r for r in self.rules if r["source"] in prepared]
        for rule in evaluated:
            for index, record in enumerate(prepared[rule["source"]]):
                why: List[str] = []
                if _clause_matches(rule["condition"], record, why):
                    findings.append(self._finding(rule, record, index, why, evidence_ids.get(rule["source"])))

        findings.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
        return {
            "engine": "jocky-detection",
            "rules_loaded": len(self.rules),
            "rules_evaluated": len(evaluated),
            "sources_seen": sorted(prepared),
            "skipped_rules": sorted(r["id"] for r in self.rules if r["source"] not in prepared),
            "finding_count": len(findings),
            "findings": findings,
            "correlation": correlate(findings, endpoint),
        }

    @staticmethod
    def _finding(rule: Dict[str, Any], record: Dict[str, Any], index: int, why: List[str],
                 evidence_id: Optional[str]) -> Dict[str, Any]:
        return {
            "rule_id": rule["id"],
            "title": rule["title"],
            "description": rule["description"],
            "source": rule["source"],
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "attack": rule["attack"],
            "matched_because": why,
            "record_index": index,
            "record": record,
            "evidence_id": evidence_id,
            "benign_explanations": rule["benign_explanations"],
        }


def correlate(findings: Iterable[Dict[str, Any]], endpoint: Optional[str] = None) -> Dict[str, Any]:
    """
    Combine findings from independent sources (§7.4). One source on its own
    stays at its rule severity; signals from two or more different sources
    raise the combined priority, because coincidence becomes less likely.
    """
    findings = list(findings)
    by_source: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        by_source.setdefault(f["source"], []).append(f)
    if not findings:
        return {"endpoint": endpoint, "priority": "none", "independent_sources": 0, "summary": "No rule matched.",
                "techniques": [], "benign_explanations": [], "verdict": "no findings"}

    top = max(SEVERITY_ORDER.index(f["severity"]) for f in findings)
    sources = len(by_source)
    bump = 1 if sources >= 2 else 0
    bump += 1 if sources >= 3 else 0
    priority = SEVERITY_ORDER[min(top + bump, len(SEVERITY_ORDER) - 1)]
    techniques: List[Tuple[str, str]] = sorted({(t["id"], t["name"]) for f in findings for t in f["attack"]})
    benign = sorted({b for f in findings for b in f["benign_explanations"]})
    parts = [f"{len(v)} {k}" for k, v in sorted(by_source.items())]
    summary = (
        f"{len(findings)} finding(s) across {sources} independent source(s): {', '.join(parts)}."
        + (" Independent signals from different sources make coincidence less likely, so the combination"
           " is ranked higher than any single finding." if sources >= 2 else "")
    )
    return {
        "endpoint": endpoint,
        "priority": priority,
        "independent_sources": sources,
        "summary": summary,
        "techniques": [{"id": t, "name": n} for t, n in techniques],
        "benign_explanations": benign,
        # Blueprint §7.4: never label the endpoint compromised automatically
        "verdict": "analyst review recommended",
    }
