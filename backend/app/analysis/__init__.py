"""
JOCKY Forensic Analysis, Correlation & Timeline Module

Provides:
- ForensicCorrelator: Graph-based correlation between processes, sockets, files, and parents
- Entity ID generators (Process, Network, File, User)
- correlate_evidence: High-level correlation orchestration
- ForensicTimeline & build_forensic_timeline: Normalized chronological event reconstruction
- ForensicRuleEngine & evaluate_forensic_rules: Deterministic heuristic indicators
"""

from .correlator import (
    ForensicCorrelator,
    correlate_evidence,
    generate_file_entity_id,
    generate_network_entity_id,
    generate_process_entity_id,
    generate_user_entity_id,
)
from .rules import (
    ForensicRuleEngine,
    evaluate_forensic_rules,
)
from .timeline import (
    ForensicTimeline,
    build_forensic_timeline,
)

__all__ = [
    "ForensicCorrelator",
    "correlate_evidence",
    "generate_process_entity_id",
    "generate_file_entity_id",
    "generate_network_entity_id",
    "generate_user_entity_id",
    "ForensicTimeline",
    "build_forensic_timeline",
    "ForensicRuleEngine",
    "evaluate_forensic_rules",
]
