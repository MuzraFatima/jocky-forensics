"""
JOCKY Forensic Analysis, Correlation & Timeline Module

Provides:
- ForensicCorrelator: Graph-based correlation between processes, sockets, files, and parents
- Entity ID generators (Process, Network, File, User)
- correlate_evidence: High-level correlation orchestration
- ForensicTimeline & build_forensic_timeline: Normalized chronological event reconstruction
- ForensicRuleEngine & evaluate_forensic_rules: Deterministic heuristic indicators
"""

from .analyzers import (
    AdvancedAnalysisPipeline,
    ExecutionAnalyzer,
    MemoryAnalyzer,
    NetworkAnalyzer,
    PersistenceAnalyzer,
    ProcessAnalyzer,
)
from .correlator import (
    ForensicCorrelator,
    correlate_evidence,
    generate_file_entity_id,
    generate_network_entity_id,
    generate_process_entity_id,
    generate_user_entity_id,
)
from .registry import (
    AnalysisStatus,
    MitreMapping,
    TechniqueCategory,
    TechniqueEntry,
    TechniqueRegistry,
    get_technique_registry,
)
from .mapping import (
    EvidenceTechniqueMapper,
    ForensicContext,
    ObservableIndicator,
    TechniqueFinding,
    analyze_evidence_techniques,
)
from .rules import (
    ForensicRuleEngine,
    evaluate_forensic_rules,
)
from .mitre import (
    build_mitre_analysis,
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
    "AnalysisStatus",
    "MitreMapping",
    "TechniqueCategory",
    "TechniqueEntry",
    "TechniqueRegistry",
    "get_technique_registry",
    "EvidenceTechniqueMapper",
    "ForensicContext",
    "ObservableIndicator",
    "TechniqueFinding",
    "analyze_evidence_techniques",
    "ProcessAnalyzer",
    "NetworkAnalyzer",
    "ExecutionAnalyzer",
    "PersistenceAnalyzer",
    "MemoryAnalyzer",
    "AdvancedAnalysisPipeline",
    "build_mitre_analysis",
]
