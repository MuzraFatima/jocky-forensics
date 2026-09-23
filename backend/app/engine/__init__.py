"""
JOCKY Forensic Execution Engine & Policy Layer

Enforces authorization, boundaries, and non-destructive invariants on execution plans,
and orchestrates read-only collection readiness.

Phase 2: adds IR-aware policy evaluation and IR execution.
"""

from typing import Any, Dict
from .policy import PolicyEngine
from .executor import ForensicExecutor
from .ir_policy import evaluate_ir_policy
from .ir_executor import IRExecutor


def evaluate_policy(execution_plan: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience helper to evaluate an execution plan against the policy engine."""
    engine = PolicyEngine()
    return engine.evaluate(execution_plan)


def execute_plan(execution_plan: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience helper to orchestrate an execution plan through policy and executor."""
    executor = ForensicExecutor()
    return executor.execute(execution_plan)


def execute_jocky_ir(ir: Dict[str, Any]) -> Dict[str, Any]:
    """Phase-2 convenience helper: run a JOCKY IR through the IR execution engine."""
    executor = IRExecutor()
    return executor.execute_jocky_ir(ir)


__all__ = [
    # Phase 1 / legacy
    "PolicyEngine",
    "ForensicExecutor",
    "evaluate_policy",
    "execute_plan",
    # Phase 2
    "evaluate_ir_policy",
    "IRExecutor",
    "execute_jocky_ir",
]
