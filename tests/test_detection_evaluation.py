"""Experiment E4 harness: metric arithmetic and a regression floor on the labelled dataset."""

from pathlib import Path

from backend.app.detection.evaluation import _metrics, evaluate_dataset, load_dataset

DATASET = Path(__file__).resolve().parent / "fixtures" / "detection" / "labelled_records.json"


def test_metric_formulas():
    m = _metrics(tp=8, fp=2, fn=2, tn=8)
    assert m["precision"] == 0.8
    assert m["recall"] == 0.8
    assert m["f1"] == 0.8
    assert m["false_positive_rate"] == 0.2
    empty = _metrics(tp=0, fp=0, fn=0, tn=5)
    assert empty["precision"] is None and empty["f1"] == 0.0


def test_dataset_is_balanced_enough_to_mean_something():
    records = load_dataset(DATASET)
    malicious = [r for r in records if r["malicious"]]
    assert len(records) >= 50
    assert 0.3 <= len(malicious) / len(records) <= 0.6
    for rule_id in {rid for r in malicious for rid in r["expected_rules"]}:
        assert sum(rule_id in r["expected_rules"] for r in malicious) >= 1


def test_every_error_is_reported_with_its_note():
    result = evaluate_dataset(load_dataset(DATASET))
    o = result["overall"]
    assert o["tp"] + o["fp"] + o["fn"] + o["tn"] == result["records"]
    assert len(result["errors"]) == o["fp"] + o["fn"]
    assert all(e["note"] for e in result["errors"])


def test_detection_quality_does_not_regress():
    """Floors sit just under the measured values; raising a rule's noise or losing coverage fails here."""
    overall = evaluate_dataset(load_dataset(DATASET))["overall"]
    assert overall["recall"] >= 0.8
    assert overall["precision"] >= 0.7
    assert overall["false_positive_rate"] <= 0.25
