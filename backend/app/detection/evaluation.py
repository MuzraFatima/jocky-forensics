"""
Experiment E4: detection effectiveness (blueprint §13).

Each labelled record is evaluated on its own. A record counts as a true
positive when it is malicious and at least one of its expected rules fires,
a false positive when it is benign and any rule fires, a false negative
when it is malicious and none of its expected rules fires, and a true
negative otherwise. Per-rule figures use the record's expected_rules.

    precision = TP / (TP + FP)
    recall    = TP / (TP + FN)
    F1        = 2PR / (P + R)
    FPR       = FP / (FP + TN)
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .engine import RECORD_KEYS, DetectionEngine


def _ratio(num: int, den: int) -> Optional[float]:
    return round(num / den, 3) if den else None


def _metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, Any]:
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 3) if precision and recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate": _ratio(fp, fp + tn)}


def _outcome(malicious: bool, fired: set, expected: set) -> str:
    if malicious:
        return "tp" if fired & expected else "fn"
    return "fp" if fired else "tn"


def evaluate_dataset(records: List[Dict[str, Any]], engine: Optional[DetectionEngine] = None) -> Dict[str, Any]:
    engine = engine or DetectionEngine()
    overall = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    per_rule: Dict[str, Dict[str, int]] = {r["id"]: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for r in engine.rules}
    misses: List[Dict[str, Any]] = []

    # Evaluate each source's records together, as a real collection would be,
    # so relational rules (parent/child processes) see the whole snapshot.
    by_source: Dict[str, List[Dict[str, Any]]] = {}
    for item in records:
        by_source.setdefault(item["source"], []).append(item)

    for source, items in by_source.items():
        evidence = {source: {RECORD_KEYS[source]: [item["record"] for item in items]}}
        fired_by_index: Dict[int, set] = {}
        for finding in engine.evaluate(evidence)["findings"]:
            fired_by_index.setdefault(finding["record_index"], set()).add(finding["rule_id"])

        for index, item in enumerate(items):
            fired = fired_by_index.get(index, set())
            expected = set(item.get("expected_rules", []))
            malicious = bool(item["malicious"])
            outcome = _outcome(malicious, fired, expected)
            overall[outcome] += 1
            if outcome in ("fp", "fn"):
                misses.append({"outcome": outcome.upper(), "source": source, "note": item.get("note"),
                               "fired": sorted(fired), "expected": sorted(expected)})

            for rule in engine.rules:
                if rule["source"] != source:
                    continue
                rid = rule["id"]
                should = malicious and rid in expected
                did = rid in fired
                key = "tp" if should and did else "fn" if should else "fp" if did else "tn"
                per_rule[rid][key] += 1

    return {
        "records": len(records),
        "malicious": sum(1 for r in records if r["malicious"]),
        "overall": _metrics(**overall),
        "per_rule": {rid: _metrics(**counts) for rid, counts in sorted(per_rule.items())},
        "errors": misses,
    }


def load_dataset(path: Path) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)["records"]
