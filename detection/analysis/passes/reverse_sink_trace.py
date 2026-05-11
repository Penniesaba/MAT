"""Reverse Sink Trace — Generic sink root finding without MCP entrypoints.

This pass reverses the analysis direction: instead of starting from MCP entrypoints
and following call chains to sinks (forward reachability), it starts from each
SinkFact and walks backwards through the call graph to find the root function
that ultimately triggered the sink.

This detects dangerous code paths in packages that do NOT expose MCP interfaces
(e.g. poisoned dependencies, utility libraries with RCE vectors).

Algorithm:
1. For each SinkFact, find the CallFact via sink.call_id
2. The call's caller is the direct function containing the sink invocation
3. Build a reverse index: callee_func_id -> list of CallFact where this callee was called
4. BFS upwards from the sink's caller:
   - Query the reverse index to find who called the current function
   - If no one calls it (or only <module> calls it), it is the root
   - Continue until root or max depth (10) is reached
5. Build a forward call_chain from root to sink for evidence
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from analysis.facts.schema import (
        CallFact,
        Fact,
        FindingFact,
        SinkFact,
    )
    from analysis.passes.call_graph import CallChainLink, CallGraph

from analysis.facts.ids import make_finding_id
from analysis.facts.schema import Confidence, FindingFact, FindingStatus, Severity

from .call_graph import CallChainLink


# ---------------------------------------------------------------------------
# Output Structure
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SinkRootResult:
    """Result of reverse-tracing from a sink to its triggering root function.

    Attributes:
        sink_id: ID of the SinkFact.
        sink_name: Human-readable sink name (e.g. "eval", "execSync").
        sink_category: Category string (e.g. "rce", "ssrf").
        sink_severity: Severity value as string (e.g. "high", "critical").
        root_function_id: function_id of the root function that ultimately
            calls the sink. For module-level code with no containing function,
            this will be "<module>".
        root_function_name: Name part extracted from root_function_id (last
            segment after ":"), or "<module>" for module-level code.
        root_is_module_level: True when the root is module-level code (no
            function wrapper), False when it's a named function.
        call_chain: Ordered list of CallChainLink from root to sink (inclusive
            of both endpoints). Length = distance + 1.
        distance: Number of intermediate hops from root to sink.
            0 = root directly calls sink, 1 = one intermediate function, etc.
    """

    sink_id: str
    sink_name: str
    sink_category: str
    sink_severity: str
    root_function_id: str
    root_function_name: str
    root_is_module_level: bool
    call_chain: list[CallChainLink] = field(default_factory=list)
    distance: int = 0
    sink_args: list[dict[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Reverse Trace Algorithm
# ---------------------------------------------------------------------------


def find_sink_root_chains(facts: list[Fact], graph: CallGraph) -> list[SinkRootResult]:
    """Trace every SinkFact back to its root function via reverse BFS.

    Args:
        facts: Full fact list (used to look up function metadata).
        graph: CallGraph built from the same fact list.

    Returns:
        List of SinkRootResult, one per SinkFact. If a sink's call_id is not
        found in the graph, it is skipped silently.
    """
    # Filter to sink facts
    sinks = [f for f in facts if f.type == "sink"]
    if not sinks:
        return []

    results: list[SinkRootResult] = []
    MAX_DEPTH = 10

    for sink in sinks:  # type: ignore[union-attr]
        call = graph.call_by_id.get(sink.call_id)  # type: ignore[arg-type]
        if call is None:
            # Sink's call_id not in graph — skip silently
            continue

        # Direct caller of the sink (the function containing the sink invocation)
        current_func_id: str = call.caller

        # BFS upward to find root
        visited: set[str] = {current_func_id}
        chain_from_sink_to_root: list[str] = [current_func_id]  # sink's caller first
        depth = 0

        while depth < MAX_DEPTH:
            callers = graph.function_by_id.get(current_func_id, [])
            # Filter out module-level callers
            non_module_callers = [
                c.caller for c in callers if c.caller and c.caller != "<module>"
            ]

            if not non_module_callers:
                # No function callers — current_func_id may be the root OR may only
                # be called by <module>. Check if <module> is a caller and continue.
                module_callers = [c.caller for c in callers if c.caller == "<module>"]
                if module_callers and "<module>" not in visited:
                    # Current function is called by module-level code — <module> is the root.
                    # Add <module> to the chain and treat it as the ultimate root.
                    visited.add("<module>")
                    chain_from_sink_to_root.insert(0, "<module>")
                    current_func_id = "<module>"
                    depth += 1
                # Always stop here — either no module callers, or we just added <module>
                break

            # Pick the first non-module caller as the parent
            # (In practice there should rarely be multiple distinct callers)
            next_func_id = non_module_callers[0]
            if next_func_id in visited:
                break
            visited.add(next_func_id)
            chain_from_sink_to_root.insert(0, next_func_id)
            current_func_id = next_func_id
            depth += 1

        # Build forward call_chain from root to sink
        call_chain = _build_forward_chain(
            chain_from_sink_to_root,  # root → ... → sink's caller
            sink.call_id,  # type: ignore[arg-type]
            graph,
        )

        # Determine if root is module-level
        root_is_module = current_func_id == "<module>" or not current_func_id

        # Extract root function name
        if root_is_module:
            root_function_name = "<module>"
        else:
            # function_id format: "language:path:name" — extract name part
            root_function_name = current_func_id.rsplit(":", 1)[-1]

        # Get sink severity as string
        sink_severity_str = str(sink.severity_base.value) if sink.severity_base else "medium"  # type: ignore[union-attr]

        results.append(
            SinkRootResult(
                sink_id=sink.id,  # type: ignore[attr-defined]
                sink_name=sink.sink_name,  # type: ignore[attr-defined]
                sink_category=sink.category,  # type: ignore[attr-defined]
                sink_severity=sink_severity_str,
                root_function_id=current_func_id,
                root_function_name=root_function_name,
                root_is_module_level=root_is_module,
                call_chain=call_chain,
                distance=depth,
                sink_args=[
                    {"index": str(a.index), "expr": a.expr, "kind": a.kind}
                    for a in call.args
                ] if call.args else [],
            )
        )

    return results


def _build_forward_chain(
    func_ids: list[str],
    sink_call_id: str,
    graph: CallGraph,
) -> list[CallChainLink]:
    """Build an ordered CallChainLink list from root function_ids to the sink.

    Args:
        func_ids: List of function_ids from root to sink's caller (inclusive).
            Last element is the function that directly calls the sink.
        sink_call_id: The call_id of the SinkFact.
        graph: The call graph.

    Returns:
        List of CallChainLink from root to sink. The chain includes both
        the intermediate function calls AND the final sink call.
    """
    if not func_ids:
        return []

    chain: list[CallChainLink] = []

    # Build links for each consecutive pair of functions
    for i in range(len(func_ids) - 1):
        caller_func_id = func_ids[i]
        callee_func_id = func_ids[i + 1]
        # Find the CallFact that connects these two functions
        calls_made = graph.calls_by_caller.get(caller_func_id, [])
        for call in calls_made:
            resolved_callee = graph.callee_by_call_id.get(call.id)
            if resolved_callee == callee_func_id:
                chain.append(
                    CallChainLink(
                        call_id=call.id,
                        caller_func_id=caller_func_id,
                        callee_func_id=callee_func_id,
                        snippet=call.snippet,
                        line=call.line,
                    )
                )
                break

    # Add the final sink call
    sink_call = graph.call_by_id.get(sink_call_id)
    if sink_call:
        # The last func in func_ids is the caller of the sink
        last_func_id = func_ids[-1] if func_ids else "<module>"
        chain.append(
            CallChainLink(
                call_id=sink_call.id,
                caller_func_id=last_func_id,
                callee_func_id=graph.callee_by_call_id.get(sink_call_id),
                snippet=sink_call.snippet,
                line=sink_call.line,
            )
        )

    return chain


# ---------------------------------------------------------------------------
# FindingFact Builder
# ---------------------------------------------------------------------------


def build_sink_root_findings(
    root_chains: list[SinkRootResult],
    facts: list[Fact],
) -> list[FindingFact]:
    """Convert SinkRootResult list into FindingFact records.

    Args:
        root_chains: List of SinkRootResult from find_sink_root_chains.
        facts: Full fact list (used for sink metadata lookups).

    Returns:
        List of FindingFact with Confidence.MEDIUM and FindingStatus.POTENTIAL.
        entrypoint_id field is set to root_function_id to mark the root.
    """
    # Build sink lookup
    sink_by_id: dict[str, SinkFact] = {}
    for f in facts:
        if f.type == "sink":
            sink_by_id[f.id] = f  # type: ignore[index]

    findings: list[FindingFact] = []

    for result in root_chains:
        sink = sink_by_id.get(result.sink_id)
        if sink is None:
            continue

        # Build finding name: root-based instead of entrypoint-based
        category = result.sink_category
        name = f"root_{result.root_function_name}_sink_{result.sink_name}".replace(
            " ", "_"
        ).replace("-", "_")

        finding_id = make_finding_id(category, name)

        severity = sink.severity_base if sink.severity_base is not None else Severity.MEDIUM

        evidence = _build_evidence(result, sink)

        call_chain_serialized = []
        for i, link in enumerate(result.call_chain):
            entry = {
                "call_id": link.call_id,
                "caller_func_id": link.caller_func_id,
                "callee_func_id": link.callee_func_id,
                "snippet": link.snippet,
                "line": link.line,
            }
            if i == len(result.call_chain) - 1 and result.sink_args:
                entry["args"] = result.sink_args
            call_chain_serialized.append(entry)

        findings.append(
            FindingFact(
                type="finding",
                id=finding_id,
                file=sink.file,
                line=sink.line,
                title=f"Potential {category} in {result.root_function_name} via {result.sink_name}",
                category=category,
                severity=severity,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.POTENTIAL,
                entrypoint_id=result.root_function_id,  # Mark the root function
                sink_id=result.sink_id,
                call_chain=call_chain_serialized,
                evidence=evidence,
            )
        )

    return findings


def _build_evidence(result: SinkRootResult, sink: SinkFact) -> list[str]:
    """Build evidence list for a sink root finding.

    Format mirrors finding_builder.py _build_evidence for consistency.
    """
    evidence: list[str] = []

    root_label = result.root_function_name
    evidence.append(
        f"Root function: {root_label} "
        f"(function_id={result.root_function_id}, module_level={result.root_is_module_level})"
    )

    evidence.append(
        f"Sink: {result.sink_name} "
        f"(category={result.sink_category}, rule={sink.rule_id}, reason={sink.reason})"
    )

    if result.sink_args:
        args_str = ", ".join(f"{a['expr']}" for a in result.sink_args)
        evidence.append(f"Sink arguments: ({args_str})")

    if result.call_chain:
        first_link = result.call_chain[0]
        last_link = result.call_chain[-1]
        evidence.append(
            f"Call chain: {len(result.call_chain)} hops  "
            f"first={first_link.snippet!r}  last={last_link.snippet!r}"
        )
    else:
        evidence.append("Call chain: direct call (no intermediate hops)")

    evidence.append(f"Distance: {result.distance} intermediate function(s) from root to sink")

    return evidence