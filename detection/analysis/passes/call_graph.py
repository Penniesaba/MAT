"""Call Graph + Entrypoint → Sink Reachability Analysis Pass.

This module provides function-level call graph construction and reachability
analysis for the AST-based security detection framework.

Phase 3 of the AST implementation checklist focuses on:
- Building a function-level call graph from CallFact entries and local function symbols
- Finding sinks reachable from EntryPointFact.function_id
- Returning call chain evidence for FindingFact generation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from analysis.facts.schema import CallFact, EntryPointFact, Fact, FunctionFact, SinkFact

# ----------------------------------------------------------------------
# Output Structures
# ----------------------------------------------------------------------


@dataclass(slots=True)
class CallChainLink:
    """A single step in a call chain from entrypoint to sink.

    Attributes:
        call_id: ID of the CallFact representing this call.
        caller_func_id: function_id of the caller (the function making the call).
        callee_func_id: function_id of the callee (the function being called).
            Will be None when the callee is not a tracked function.
        snippet: Source code snippet of the call.
        line: Source line where the call occurs.
    """

    call_id: str
    caller_func_id: str
    callee_func_id: str | None
    snippet: str
    line: int


@dataclass
class ReachabilityResult:
    """Result of reachability analysis from an entrypoint to one or more sinks.

    Attributes:
        entrypoint_id: ID of the EntryPointFact used as the starting point.
        entrypoint_function_id: function_id of the entrypoint function.
        sink_id: ID of the SinkFact that was reached.
        call_chain: Ordered list of CallChainLink objects forming the path
            from entrypoint to sink. Empty if the sink is directly called
            by the entrypoint function.
        is_reachable: Always True when a ReachabilityResult is returned;
            kept for API symmetry with the single-hop case.
    """

    entrypoint_id: str
    entrypoint_function_id: str
    sink_id: str
    call_chain: list[CallChainLink] = field(default_factory=list)
    is_reachable: bool = True


@dataclass
class CallGraph:
    """Function-level call graph built from CallFact entries.

    Attributes:
        calls_by_caller: Maps function_id -> list of CallFact made by that function.
        call_by_id: Maps CallFact.id -> CallFact for O(1) lookup.
        function_by_id: Maps function_id -> list of CallFact where the callee
            matches that function_id (i.e., inverse index for callee resolution).
        callee_by_call_id: Maps CallFact.id -> resolved callee function_id,
            or None if the callee could not be resolved to a tracked function.
    """

    calls_by_caller: dict[str, list[CallFact]] = field(default_factory=dict)
    call_by_id: dict[str, CallFact] = field(default_factory=dict)
    function_by_id: dict[str, list[CallFact]] = field(default_factory=dict)
    callee_by_call_id: dict[str, str | None] = field(default_factory=dict)


# ----------------------------------------------------------------------
# Core API
# ----------------------------------------------------------------------


def _is_call_fact(fact: Fact) -> Literal[True]:
    """Type guard: narrow Fact to CallFact."""
    return fact.type == "call"


def _is_function_fact(fact: Fact) -> Literal[True]:
    """Type guard: narrow Fact to FunctionFact."""
    return fact.type == "function"


def _iter_calls(facts: list[Fact]) -> tuple[CallFact, ...]:
    """Yield CallFact entries from a fact list (type-narrowed iterator)."""
    return tuple(fact for fact in facts if _is_call_fact(fact))


def _iter_functions(facts: list[Fact]) -> tuple[FunctionFact, ...]:
    """Yield FunctionFact entries from a fact list (type-narrowed iterator)."""
    return tuple(fact for fact in facts if _is_function_fact(fact))


def _resolve_callee_function_id(
    call: CallFact,
    symbol_table: dict[tuple[str, str], str],
) -> str | None:
    """Resolve a call's callee to a full function_id using the local symbol table.

    If CallFact.normalized_callee is already a known function_id (has a ":" prefix),
    it is returned as-is. Otherwise the bare callee name is looked up in the
    symbol table keyed by (caller_file, bare_name). This resolves local calls
    like `helper_func` → `python:src/server.py:helper_func`.

    Returns None when the callee cannot be resolved to any tracked function.
    """
    # If normalized_callee is already a qualified function_id, use it
    if call.normalized_callee:
        if ":" in call.normalized_callee:
            return call.normalized_callee
        # It's a bare name that the extractor did not qualify; try symbol lookup
        # Look up by (caller_file, bare_name)
        caller_file = call.file
        key = (caller_file, call.normalized_callee)
        resolved = symbol_table.get(key)
        if resolved:
            return resolved

    # Fall back to the raw callee name (module-qualified names won't be in the
    # symbol table; this just passes them through as-is for external deps)
    if call.callee:
        if ":" in call.callee:
            return call.callee
        key = (call.file, call.callee)
        resolved = symbol_table.get(key)
        if resolved:
            return resolved

    return None


def build_call_graph(facts: list[Fact]) -> CallGraph:
    """Build a function-level call graph from a list of facts.

    Args:
        facts: List of Fact objects (typically from a FactStore).
            Should contain at least CallFact and (optionally) FunctionFact entries.

    Returns:
        CallGraph containing:
        - calls_by_caller: {function_id: [CallFact, ...]}
        - call_by_id: {call_id: CallFact}
        - function_by_id: {function_id: [CallFact, ...]}  (calls whose callee is that function)
    """
    # ------------------------------------------------------------------
    # Pass 1 – build local symbol table from FunctionFact entries
    # Maps (file, bare_name) -> function_id for same-file resolution
    # Also tracks the set of all known function_ids.
    # ------------------------------------------------------------------
    symbol_table: dict[tuple[str, str], str] = {}
    known_function_ids: set[str] = set()

    for func in _iter_functions(facts):
        known_function_ids.add(func.id)
        # Index by (file, name) so that a bare call like "helper_func" resolves
        # to the same file's FunctionFact entry.
        symbol_table[(func.file, func.name)] = func.id

    # ------------------------------------------------------------------
    # Pass 2 – index CallFact entries into the three lookup structures
    # ------------------------------------------------------------------
    calls_by_caller: dict[str, list[CallFact]] = {}
    call_by_id: dict[str, CallFact] = {}
    function_by_id: dict[str, list[CallFact]] = {}
    callee_by_call_id: dict[str, str | None] = {}

    for call in _iter_calls(facts):
        call_by_id[call.id] = call

        # Index by caller (who is making the call)
        caller_func_id = call.caller
        if caller_func_id not in calls_by_caller:
            calls_by_caller[caller_func_id] = []
        calls_by_caller[caller_func_id].append(call)

        # Resolve the callee to a full function_id (or None if unresolved)
        callee_func_id = _resolve_callee_function_id(call, symbol_table)
        callee_by_call_id[call.id] = callee_func_id

        # Index by resolved callee function_id so BFS can traverse into it
        if callee_func_id is not None:
            if callee_func_id not in function_by_id:
                function_by_id[callee_func_id] = []
            function_by_id[callee_func_id].append(call)

    return CallGraph(
        calls_by_caller=calls_by_caller,
        call_by_id=call_by_id,
        function_by_id=function_by_id,
        callee_by_call_id=callee_by_call_id,
    )


def find_reachable_sinks(
    entrypoints: list[EntryPointFact],
    sinks: list[SinkFact],
    graph: CallGraph,
) -> list[ReachabilityResult]:
    """Find sinks reachable from entrypoint functions via call chains.

    Performs a BFS from each entrypoint's function_id through the call graph,
    tracking call chains. A sink is reachable when there exists a path of
    CallFact edges from the entrypoint function to the CallFact referenced
    by SinkFact.call_id.

    Args:
        entrypoints: List of EntryPointFact to use as starting points.
        sinks: List of SinkFact to check for reachability.
        graph: CallGraph built from the same fact set.

    Returns:
        List of ReachabilityResult, one per reachable sink.
        Each result contains the call_chain (ordered call_id links) from
        entrypoint to sink.
    """
    results: list[ReachabilityResult] = []
    sink_to_calls: dict[str, list[SinkFact]] = {}

    # Build inverse index: call_id -> list of SinkFact (there can be multiple rules per call)
    for sink in sinks:
        if sink.call_id not in sink_to_calls:
            sink_to_calls[sink.call_id] = []
        sink_to_calls[sink.call_id].append(sink)

    for ep in entrypoints:
        ep_func_id = ep.function_id
        path = _bfs_find_sinks(ep_func_id, graph, sink_to_calls)
        for sink, chain_links in path:
            results.append(
                ReachabilityResult(
                    entrypoint_id=ep.id,
                    entrypoint_function_id=ep_func_id,
                    sink_id=sink.id,
                    call_chain=chain_links,
                    is_reachable=True,
                )
            )

    return results


# ----------------------------------------------------------------------
# Internal Helpers
# ----------------------------------------------------------------------


def _bfs_find_sinks(
    start_func_id: str,
    graph: CallGraph,
    sink_to_calls: dict[str, list[SinkFact]],
) -> list[tuple[SinkFact, list[CallChainLink]]]:
    """BFS from start_func_id to find any reachable sinks.

    Returns a list of (sink, call_chain) tuples found via any path from start.
    Multi-hop paths are supported via recursive/resursive callee traversal.
    """
    results: list[tuple[SinkFact, list[CallChainLink]]] = []

    # frontier: list of (current_function_id, chain_so_far)
    # chain_so_far is a list of CallChainLink from entrypoint to current
    frontier: list[tuple[str, list[CallChainLink]]] = [(start_func_id, [])]
    visited: set[str] = {start_func_id}

    while frontier:
        current_func_id, chain_so_far = frontier.pop(0)

        # Get all calls made by this function
        calls_made = graph.calls_by_caller.get(current_func_id, [])

        for call in calls_made:
            link = CallChainLink(
                call_id=call.id,
                caller_func_id=call.caller,
                callee_func_id=graph.callee_by_call_id.get(call.id),
                snippet=call.snippet,
                line=call.line,
            )
            new_chain = chain_so_far + [link]

            # Check if this call is a sink
            if call.id in sink_to_calls:
                for sink in sink_to_calls[call.id]:
                    results.append((sink, new_chain))

            # Continue BFS to callee if not yet visited
            callee_func_id = graph.callee_by_call_id.get(call.id)
            if callee_func_id and callee_func_id not in visited:
                visited.add(callee_func_id)
                frontier.append((callee_func_id, new_chain))

    return results
