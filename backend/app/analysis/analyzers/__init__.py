"""
JOCKY Modular Advanced Analysis Subsystem (Phase 4)

Provides safe, passive forensic analyzers:
- ProcessAnalyzer: Process ancestry, parent-child shell spawning, orphaned processes
- NetworkAnalyzer: Outbound C2 backdoor sockets, high-fanout lateral scanning
- ExecutionAnalyzer: Volatile temporary path execution, Living-off-the-Land (LOLBins) arguments
- PersistenceAnalyzer: Windows registry autoruns, Linux cron/systemd, macOS launchd, timestomping
- MemoryAnalyzer: Unmapped binary images, anomalous resident set size, privilege context disparities

Integrates with EvidenceTechniqueMapper to emit unified findings.
"""

from typing import Any, Dict, List, Optional
from backend.app.analysis.mapping import (
    EvidenceTechniqueMapper,
    ForensicContext,
    ObservableIndicator,
    TechniqueFinding,
)
from backend.app.analysis.registry import get_technique_registry

from .process_analyzer import ProcessAnalyzer
from .network_analyzer import NetworkAnalyzer
from .execution_analyzer import ExecutionAnalyzer
from .persistence_analyzer import PersistenceAnalyzer
from .memory_analyzer import MemoryAnalyzer


class AdvancedAnalysisPipeline:
    """
    Coordinates all modular analyzers to extract indicators and emit structured findings.
    """

    def __init__(self, registry=None):
        self.registry = registry or get_technique_registry()
        self.process_analyzer = ProcessAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.execution_analyzer = ExecutionAnalyzer()
        self.persistence_analyzer = PersistenceAnalyzer()
        self.memory_analyzer = MemoryAnalyzer()
        self.mapper = EvidenceTechniqueMapper(registry=self.registry)

    def extract_all_indicators(self, evidence_data: Dict[str, Any], context: ForensicContext) -> List[ObservableIndicator]:
        """
        Runs all modular analyzers against collected evidence and aggregates observable indicators.
        """
        all_indicators: List[ObservableIndicator] = []

        # Run process analyzer
        all_indicators.extend(self.process_analyzer.analyze(evidence_data, context))

        # Run network analyzer
        all_indicators.extend(self.network_analyzer.analyze(evidence_data, context))

        # Run execution analyzer
        all_indicators.extend(self.execution_analyzer.analyze(evidence_data, context))

        # Run persistence analyzer
        all_indicators.extend(self.persistence_analyzer.analyze(evidence_data, context))

        # Run memory analyzer
        all_indicators.extend(self.memory_analyzer.analyze(evidence_data, context))

        return all_indicators

    def analyze(self, evidence_data: Dict[str, Any], context: Optional[ForensicContext] = None) -> List[TechniqueFinding]:
        """
        Orchestrates full modular analysis and synthesizes findings:
        Evidence → Modular Analyzers → Observable Indicators → Technique → Finding
        """
        ctx = self.mapper._extract_context(evidence_data, context)
        indicators = self.extract_all_indicators(evidence_data, ctx)
        findings = self.mapper.map_indicators_to_findings(indicators, ctx)
        return findings


__all__ = [
    "ProcessAnalyzer",
    "NetworkAnalyzer",
    "ExecutionAnalyzer",
    "PersistenceAnalyzer",
    "MemoryAnalyzer",
    "AdvancedAnalysisPipeline",
]
