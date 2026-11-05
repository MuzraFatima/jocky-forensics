"""Declarative, explainable detection rules and correlation (blueprint §7)."""

from .engine import DetectionEngine, RuleError, correlate, load_rules, validate_rule

__all__ = ["DetectionEngine", "RuleError", "correlate", "load_rules", "validate_rule"]
