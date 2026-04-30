"""Analysis Passes for AST-based security detection.

This package contains composable analysis passes that operate on Fact stores.
Each pass is a pure function that takes a list of Facts (or a FactStore) and
produces derived facts,中间 results, or findings.

Phase 3 Passes:
- call_graph: Function-level call graph + entrypoint → sink reachability
- finding_builder: ReachabilityResult + SinkFact → FindingFact
"""

from __future__ import annotations

from analysis.passes.call_graph import (
    CallChainLink,
    CallGraph,
    ReachabilityResult,
    build_call_graph,
    find_reachable_sinks,
)
from analysis.passes.finding_builder import (
    FindingFactsBuilder,
    build_finding_facts,
)
from analysis.passes.taint_lite import build_taint_lite_dataflows

__all__ = [
    "CallChainLink",
    "CallGraph",
    "ReachabilityResult",
    "build_call_graph",
    "build_finding_facts",
    "build_taint_lite_dataflows",
    "find_reachable_sinks",
    "FindingFactsBuilder",
]
