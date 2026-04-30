"""Taint-lite Data Flow Analysis Pass.

Phase 5 of the AST implementation checklist:
- Generates minimal DataFlowFact records from existing SourceFact/CallFact/SinkFact/FunctionFact entries
- Supports same-function propagation: param -> assign -> sink_arg
- Supports one-hop cross-function propagation: caller_param -> callee_param -> sink_arg

This pass is intentionally limited ("lite") to avoid false positives from complex
multi-hop, context-sensitive, alias-sensitive, or path-sensitive analysis.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from analysis.facts.schema import (
        AssignFact,
        CallFact,
        DataFlowFact,
        Fact,
        FunctionFact,
        SinkFact,
        SourceFact,
    )
    from analysis.passes.call_graph import ReachabilityResult

__all__ = ["build_taint_lite_dataflows"]

# ---------------------------------------------------------------------------
# Type Guards
# ---------------------------------------------------------------------------


def _is_source_fact(fact: Fact) -> Literal[True]:
    """Narrow Fact to SourceFact."""
    return fact.type == "source"


def _is_call_fact(fact: Fact) -> Literal[True]:
    """Narrow Fact to CallFact."""
    return fact.type == "call"


def _is_sink_fact(fact: Fact) -> Literal[True]:
    """Narrow Fact to SinkFact."""
    return fact.type == "sink"


def _is_function_fact(fact: Fact) -> Literal[True]:
    """Narrow Fact to FunctionFact."""
    return fact.type == "function"


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------


def build_taint_lite_dataflows(
    facts: list[Fact],
    reachability_results: list[ReachabilityResult],
) -> list[DataFlowFact]:
    """Build minimal DataFlowFact records from facts and reachability results.

    This pass implements a "taint-lite" analysis that can prove data flow
    for a subset of cases without full Datalog/pointer analysis:

    1. Same-function direct param: source_param -> sink_arg  (same function)
    2. Same-function assign:       source_param -> x -> sink(x)  (same function)
    3. One-hop cross-function:     caller_param -> callee_param -> sink_arg

    Args:
        facts: Full fact list containing SourceFact, CallFact, SinkFact,
            FunctionFact entries.
        reachability_results: List of ReachabilityResult from
            ``find_reachable_sinks()``, indicating which sinks are reachable
            from which entrypoints.

    Returns:
        List of DataFlowFact records for provable source-to-sink flows.
        Returns empty list when no flow can be proven — never raises.
    """
    # Build indices for O(1) lookups
    source_by_id: dict[str, SourceFact] = {
        f.id: f for f in facts if _is_source_fact(f)
    }
    sources_in_func: dict[str, list[SourceFact]] = {}
    for src in source_by_id.values():
        func_id = src.function_id
        if func_id not in sources_in_func:
            sources_in_func[func_id] = []
        sources_in_func[func_id].append(src)

    func_by_id: dict[str, FunctionFact] = {
        f.id: f for f in facts if _is_function_fact(f)
    }

    call_by_id: dict[str, CallFact] = {
        f.id: f for f in facts if _is_call_fact(f)
    }
    calls_by_func: dict[str, list[CallFact]] = {}
    for call in call_by_id.values():
        caller = call.caller
        if caller not in calls_by_func:
            calls_by_func[caller] = []
        calls_by_func[caller].append(call)

    sink_by_id: dict[str, SinkFact] = {
        f.id: f for f in facts if _is_sink_fact(f)
    }

    # Collect AssignFact records for assign propagation
    assign_facts: list[AssignFact] = [f for f in facts if f.type == "assign"]

    # Generate flows for each reachable (entrypoint, sink) pair
    flows: list[DataFlowFact] = []

    for result in reachability_results:
        entrypoint_func_id = result.entrypoint_function_id
        sink_id = result.sink_id

        sink_fact = sink_by_id.get(sink_id)
        if sink_fact is None:
            continue

        sink_call = call_by_id.get(sink_fact.call_id)
        if sink_call is None:
            continue

        # Find entrypoint function
        ep_func = func_by_id.get(entrypoint_func_id)
        if ep_func is None:
            continue

        # Sources in the entrypoint function
        sources = sources_in_func.get(entrypoint_func_id, [])

        for source in sources:
            source_name = source.name
            ep_func_id = ep_func.id

            same_func_flows = _try_same_function_flow(
                source=source,
                source_name=source_name,
                ep_func=ep_func,
                sink_call=sink_call,
                sink_fact=sink_fact,
                source_id=source.id,
                sink_id=sink_id,
                call_by_id=call_by_id,
                func_by_id=func_by_id,
                calls_by_func=calls_by_func,
                assign_facts=assign_facts,
            )
            if same_func_flows:
                flows.extend(same_func_flows)
            else:
                one_hop_flows = _try_one_hop_cross_function_flow(
                    source=source,
                    source_name=source_name,
                    entrypoint_func_id=entrypoint_func_id,
                    sink_call=sink_call,
                    sink_fact=sink_fact,
                    result=result,
                    source_id=source.id,
                    sink_id=sink_id,
                    call_by_id=call_by_id,
                    func_by_id=func_by_id,
                    calls_by_func=calls_by_func,
                )
                if one_hop_flows:
                    flows.extend(one_hop_flows)

    return flows


# ---------------------------------------------------------------------------
# Same-function Flow Detection
# ---------------------------------------------------------------------------


def _try_same_function_flow(
    source: SourceFact,
    source_name: str,
    ep_func: FunctionFact,
    sink_call: CallFact,
    sink_fact: SinkFact,
    source_id: str,
    sink_id: str,
    call_by_id: dict[str, CallFact],
    func_by_id: dict[str, FunctionFact],
    calls_by_func: dict[str, list[CallFact]],
    assign_facts: list[AssignFact] | None = None,
) -> list[DataFlowFact]:
    """Try to prove same-function param -> sink propagation.

    Case A: source_param directly passed to sink(arg)
    Case B: source_param -> var -> sink(var) via assignment

    Returns a list containing DataFlowFact(s) if proven, empty list if not.
    """
    sink_func_id = sink_call.caller

    # Same function: entrypoint == sink caller
    if sink_func_id != ep_func.id:
        return []

    sink_args = sink_call.args

    # Case A: direct param -> sink_arg
    if _direct_param_to_sink(source_name, sink_args):
        path = [
            {
                "kind": "param",
                "line": sink_call.line,
                "name": source_name,
                "function": ep_func.qualified_name or ep_func.name,
            },
            {
                "kind": "call_arg",
                "line": sink_call.line,
                "call_id": sink_call.id,
                "arg_index": _find_arg_index(sink_args, source_name),
                "snippet": sink_call.snippet,
            },
        ]
        return [_build_dataflow(source_id, sink_id, path, sink_fact)]

    # Case B: param -> var -> sink(var) via assignment
    assign_path = _trace_assign_to_sink(source_name, sink_args, ep_func, calls_by_func, assign_facts)
    if assign_path is not None:
        var_name, assign_line = assign_path
        path = [
            {
                "kind": "param",
                "line": sink_call.line,
                "name": source_name,
                "function": ep_func.qualified_name or ep_func.name,
            },
            {
                "kind": "assign",
                "line": assign_line,
                "from_": source_name,
                "to": var_name,
                "snippet": f"{var_name} = {source_name}",
            },
            {
                "kind": "call_arg",
                "line": sink_call.line,
                "call_id": sink_call.id,
                "arg_index": _find_arg_index(sink_args, var_name),
                "snippet": sink_call.snippet,
            },
        ]
        return [_build_dataflow(source_id, sink_id, path, sink_fact)]

    return []


def _direct_param_to_sink(source_name: str, sink_args: tuple) -> bool:
    """Check if source_name is directly passed as a sink argument."""
    for arg in sink_args:
        if arg.kind == "name" and arg.expr == source_name:
            return True
    return False


def _find_arg_index(sink_args: tuple, var_name: str) -> int | None:
    """Find the argument index for var_name."""
    for arg in sink_args:
        if arg.kind == "name" and arg.expr == var_name:
            return arg.index
    return None


def _trace_assign_to_sink(
    source_name: str,
    sink_args: tuple,
    func: FunctionFact,
    calls_by_func: dict[str, list[CallFact]],
    assign_facts: list[AssignFact] | None = None,
) -> tuple[str, int] | None:
    """Trace source -> var assignment chain using real AssignFact records.

    Looks for assignments like `var = source_name` where var is later
    passed to the sink.

    Returns (var_name, assign_line) if found, None otherwise.
    """
    if not assign_facts:
        return None

    # Get sink arg names
    sink_arg_names: set[str] = set()
    for arg in sink_args:
        if arg.kind == "name":
            sink_arg_names.add(arg.expr)

    if not sink_arg_names:
        return None

    # Find assignments in this function where:
    # - value == source_name
    # - target is used as a sink argument
    for assign in assign_facts:
        if assign.function_id != func.id:
            continue
        if assign.value == source_name and assign.target in sink_arg_names:
            return (assign.target, assign.line)

    return None


# ---------------------------------------------------------------------------
# One-hop Cross-function Flow Detection
# ---------------------------------------------------------------------------


def _try_one_hop_cross_function_flow(
    source: SourceFact,
    source_name: str,
    entrypoint_func_id: str,
    sink_call: CallFact,
    sink_fact: SinkFact,
    result: ReachabilityResult,
    source_id: str,
    sink_id: str,
    call_by_id: dict[str, CallFact],
    func_by_id: dict[str, FunctionFact],
    calls_by_func: dict[str, list[CallFact]],
) -> list[DataFlowFact]:
    """Try to prove one-hop cross-function param propagation.

    Pattern: caller_param -> intermediate_call_arg -> intermediate_param -> sink_arg

    where intermediate is one hop away in the call chain.

    Returns a list containing DataFlowFact(s) if proven, empty list if not.
    """
    sink_func_id = sink_call.caller

    # Skip if sink is in the entrypoint itself (handled by same-function case)
    if sink_func_id == entrypoint_func_id:
        return []

    call_chain = result.call_chain
    if not call_chain:
        return []

    # For one-hop: first call in chain should pass source to the helper
    first_link = call_chain[0]
    first_call = call_by_id.get(first_link.call_id)
    if first_call is None:
        return []

    # Check if entrypoint passes source as argument to the first helper
    arg_index = _find_arg_index(first_call.args, source_name)
    if arg_index is None:
        # Source param not directly passed; check if any arg references it
        for arg in first_call.args:
            if arg.kind == "name" and arg.expr == source_name:
                arg_index = arg.index
                break
        if arg_index is None:
            return []

    helper_func_id = first_link.callee_func_id
    if helper_func_id is None:
        return []

    helper_func = func_by_id.get(helper_func_id)
    if helper_func is None:
        return []

    # Find the parameter in helper that receives the source
    if arg_index >= len(helper_func.params):
        return []

    helper_param = helper_func.params[arg_index]
    helper_param_name = helper_param.name

    # Now check if helper's param flows to sink
    # Two cases: sink is directly in helper (1-hop), or sink is deeper
    if sink_func_id == helper_func_id:
        # Direct sink in helper
        if _direct_param_to_sink(helper_param_name, sink_call.args):
            path = [
                {
                    "kind": "param",
                    "line": first_call.line,
                    "name": source_name,
                    "function": func_by_id.get(entrypoint_func_id).qualified_name
                    if func_by_id.get(entrypoint_func_id)
                    else entrypoint_func_id,
                },
                {
                    "kind": "call_arg",
                    "line": first_call.line,
                    "call_id": first_call.id,
                    "arg_index": arg_index,
                    "snippet": first_call.snippet,
                },
                {
                    "kind": "param",
                    "line": sink_call.line,
                    "name": helper_param_name,
                    "function": helper_func.qualified_name or helper_func.name,
                },
                {
                    "kind": "call_arg",
                    "line": sink_call.line,
                    "call_id": sink_call.id,
                    "arg_index": _find_arg_index(sink_call.args, helper_param_name),
                    "snippet": sink_call.snippet,
                },
            ]
            return [_build_dataflow(source_id, sink_id, path, sink_fact)]

    # Multi-hop: sink is deeper in call chain
    # Check if helper_param flows through subsequent calls in the chain
    remaining_links = call_chain[1:]
    for link in remaining_links:
        next_call = call_by_id.get(link.call_id)
        if next_call is None:
            continue

        next_arg_index = _find_arg_index(next_call.args, helper_param_name)
        if next_arg_index is not None:
            # Found flow to next function
            next_func_id = link.callee_func_id
            if next_func_id is None:
                continue

            next_func = func_by_id.get(next_func_id)
            if next_func is None:
                continue

            if next_arg_index >= len(next_func.params):
                continue

            next_param_name = next_func.params[next_arg_index].name

            if next_func_id == sink_func_id:
                # Reached the sink function
                if _direct_param_to_sink(next_param_name, sink_call.args):
                    path = [
                        {
                            "kind": "param",
                            "line": first_call.line,
                            "name": source_name,
                            "function": func_by_id.get(entrypoint_func_id).qualified_name
                            if func_by_id.get(entrypoint_func_id)
                            else entrypoint_func_id,
                        },
                        {
                            "kind": "call_arg",
                            "line": first_call.line,
                            "call_id": first_call.id,
                            "arg_index": arg_index,
                            "snippet": first_call.snippet,
                        },
                        {
                            "kind": "param",
                            "line": sink_call.line,
                            "name": next_param_name,
                            "function": next_func.qualified_name or next_func.name,
                        },
                        {
                            "kind": "call_arg",
                            "line": sink_call.line,
                            "call_id": sink_call.id,
                            "arg_index": _find_arg_index(sink_call.args, next_param_name),
                            "snippet": sink_call.snippet,
                        },
                    ]
                    return [_build_dataflow(source_id, sink_id, path, sink_fact)]

            # Update for next iteration
            helper_param_name = next_param_name

    return []


# ---------------------------------------------------------------------------
# DataFlowFact Builder
# ---------------------------------------------------------------------------


def _build_dataflow(
    source_id: str,
    sink_id: str,
    path: list[dict],
    sink_fact: SinkFact,
) -> DataFlowFact:
    """Build a DataFlowFact from path steps.

    Args:
        source_id: ID of the source SourceFact.
        sink_id: ID of the sink SinkFact.
        path: List of path step dicts with kind, line, and optional fields.
        sink_fact: The sink fact (used for file/line defaults and confidence).

    Returns:
        A DataFlowFact with proper path and metadata.
    """
    from analysis.facts.ids import make_dataflow_id
    from analysis.facts.schema import Confidence, DataFlowFact, PathStep, PathStepKind

    # Build PathStep objects from dicts
    path_steps: list[PathStep] = []
    for step in path:
        kind_str = step["kind"]
        kind = PathStepKind(kind_str)

        path_step = PathStep(
            kind=kind,
            line=step["line"],
            name=step.get("name"),
            function=step.get("function"),
            from_=step.get("from_"),
            to=step.get("to"),
            snippet=step.get("snippet"),
            call_id=step.get("call_id"),
            arg_index=step.get("arg_index"),
        )
        path_steps.append(path_step)

    # Generate a descriptive ID
    source_name = path_steps[0].name if path_steps else "unknown"
    sink_name = sink_fact.sink_name if sink_fact else "unknown"
    dataflow_id = make_dataflow_id(source_name, sink_name)

    return DataFlowFact(
        type="dataflow",
        id=dataflow_id,
        file=sink_fact.file if sink_fact else "",
        line=sink_fact.line if sink_fact else 0,
        source_id=source_id,
        sink_id=sink_id,
        path=path_steps,
        confidence=sink_fact.confidence if sink_fact else Confidence.MEDIUM,
    )