"""Unit tests for the taint-lite data flow analysis pass.

Phase 5 of the AST implementation checklist.

Covers:
1. Same-function direct param: source_param -> sink_arg (same function)
2. Same-function assign propagation: source_param -> var -> sink(var)
3. One-hop cross-function propagation: caller_param -> callee_param -> sink_arg
4. No matching flow → empty list (graceful, no exception)
5. Empty inputs → empty list
"""

from __future__ import annotations

from analysis.facts.ids import make_dataflow_id
from analysis.facts.schema import (
    AssignFact,
    CallArg,
    CallFact,
    Confidence,
    DataFlowFact,
    EntryPointFact,
    Fact,
    FunctionFact,
    ParamInfo,
    PathStepKind,
    Severity,
    SinkFact,
    SourceFact,
)
from analysis.passes.call_graph import (
    CallChainLink,
    ReachabilityResult,
    build_call_graph,
    find_reachable_sinks,
)
from analysis.passes.taint_lite import build_taint_lite_dataflows


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_function(
    func_id: str,
    name: str = "test_func",
    params: list[str] | None = None,
) -> FunctionFact:
    return FunctionFact(
        type="function",
        id=func_id,
        language="python",
        name=name,
        qualified_name=name,
        file="src/test.py",
        line=1,
        extractor="test",
        params=[ParamInfo(name=p, annotation=None, default=None) for p in (params or [])],
    )


def _make_call(
    call_id: str,
    caller: str,
    callee: str,
    snippet: str,
    line: int,
    args: list[CallArg] | None = None,
    normalized_callee: str | None = None,
) -> CallFact:
    return CallFact(
        type="call",
        id=call_id,
        caller=caller,
        callee=callee,
        normalized_callee=normalized_callee or callee,
        snippet=snippet,
        line=line,
        file="src/test.py",
        extractor="test",
        args=args or [],
    )


def _make_entrypoint(
    ep_id: str,
    name: str,
    func_id: str,
) -> EntryPointFact:
    return EntryPointFact(
        type="entrypoint",
        id=ep_id,
        name=name,
        function_id=func_id,
        kind="mcp_tool",
        file="src/test.py",
        line=1,
        extractor="test",
    )


def _make_sink(
    sink_id: str,
    call_id: str,
    category: str,
    sink_name: str,
    rule_id: str = "R001",
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    reason: str = "dangerous call",
) -> SinkFact:
    return SinkFact(
        type="sink",
        id=sink_id,
        call_id=call_id,
        category=category,
        rule_id=rule_id,
        sink_name=sink_name,
        severity_base=severity,
        confidence=confidence,
        reason=reason,
        file="src/test.py",
        line=10,
        extractor="test",
    )


def _make_source(
    source_id: str,
    function_id: str,
    name: str,
    kind: str = "user_input",
) -> SourceFact:
    return SourceFact(
        type="source",
        id=source_id,
        function_id=function_id,
        name=name,
        kind=kind,
        confidence=Confidence.HIGH,
        file="src/test.py",
        line=2,
        extractor="test",
    )


def _make_assign(
    assign_id: str,
    function_id: str,
    target: str,
    value: str,
    line: int,
) -> AssignFact:
    return AssignFact(
        type="assign",
        id=assign_id,
        function_id=function_id,
        target=target,
        value=value,
        snippet=f"{target} = {value}",
        file="src/test.py",
        line=line,
        extractor="test",
    )


def _arg(name: str, index: int) -> CallArg:
    return CallArg(index=index, expr=name, kind="name")


# ---------------------------------------------------------------------------
# Test: Same-function direct param -> sink_arg
# ---------------------------------------------------------------------------


class TestSameFunctionDirectParam:
    """source_param directly passed to sink_arg in the same function."""

    def test_direct_param_to_sink_returns_dataflow(self) -> None:
        # Arrange: entrypoint func_a(param=cmd) -> call(helper, cmd) -> sink eval
        func_a_id = "python:src/test.py:func_a"
        funcs = [
            _make_function(func_a_id, "func_a", params=["cmd"]),
        ]
        call_id = "call1"
        calls = [
            _make_call(
                call_id,
                func_a_id,
                "eval",
                "eval(cmd)",
                line=10,
                args=[_arg("cmd", 0)],
                normalized_callee="eval",
            ),
        ]
        eps = [
            _make_entrypoint("ep1", "run_tool", func_a_id),
        ]
        sinks = [
            _make_sink("sink1", call_id, "rce", "eval"),
        ]
        sources = [
            _make_source("src1", func_a_id, "cmd"),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks, *sources]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        # Act
        dataflows = build_taint_lite_dataflows(all_facts, reachability)

        # Assert
        assert len(dataflows) == 1
        df = dataflows[0]
        assert df.type == "dataflow"
        assert df.source_id == "src1"
        assert df.sink_id == "sink1"
        assert len(df.path) == 2
        assert df.path[0].kind == PathStepKind.PARAM
        assert df.path[0].name == "cmd"
        assert df.path[1].kind == PathStepKind.CALL_ARG


# ---------------------------------------------------------------------------
# Test: Same-function assign propagation
# ---------------------------------------------------------------------------


class TestSameFunctionAssignPropagation:
    """source_param -> var via assign -> sink(var) in the same function."""

    def test_assign_propagation_returns_dataflow_with_assign_fact(self) -> None:
        """With real AssignFact, assign propagation produces DataFlowFact with ASSIGN step."""
        # Arrange: func_a(cmd) -> x = cmd -> subprocess.run(x)
        func_a_id = "python:src/test.py:func_a"
        funcs = [
            _make_function(func_a_id, "func_a", params=["cmd"]),
        ]
        call_id = "call1"
        calls = [
            _make_call(
                call_id,
                func_a_id,
                "subprocess.run",
                "subprocess.run(x)",
                line=10,
                args=[_arg("x", 0)],
                normalized_callee="subprocess.run",
            ),
        ]
        eps = [
            _make_entrypoint("ep1", "run_tool", func_a_id),
        ]
        sinks = [
            _make_sink("sink1", call_id, "rce", "subprocess.run"),
        ]
        sources = [
            _make_source("src1", func_a_id, "cmd"),
        ]
        assigns = [
            _make_assign("assign1", func_a_id, "x", "cmd", line=5),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks, *sources, *assigns]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        # Act
        dataflows = build_taint_lite_dataflows(all_facts, reachability)

        # Assert
        assert len(dataflows) == 1
        df = dataflows[0]
        assert df.source_id == "src1"
        assert df.sink_id == "sink1"
        assert len(df.path) == 3
        assert df.path[0].kind == PathStepKind.PARAM
        assert df.path[0].name == "cmd"
        assert df.path[1].kind == PathStepKind.ASSIGN
        assert df.path[1].from_ == "cmd"
        assert df.path[1].to == "x"
        assert df.path[2].kind == PathStepKind.CALL_ARG

    def test_assign_propagation_no_flow_when_no_matching_assign(self) -> None:
        """Without matching AssignFact (different value), no dataflow is produced."""
        # Arrange: func_a(user) -> safe_input = "literal" -> sink(safe_input)
        # The AssignFact has value="literal", not "user", so no flow
        func_a_id = "python:src/test.py:func_a"
        funcs = [
            _make_function(func_a_id, "func_a", params=["user", "safe_input"]),
        ]
        call_id = "call1"
        calls = [
            _make_call(
                call_id,
                func_a_id,
                "execute",
                "execute(safe_input)",
                line=10,
                args=[_arg("safe_input", 0)],
                normalized_callee="execute",
            ),
        ]
        eps = [
            _make_entrypoint("ep1", "process_user", func_a_id),
        ]
        sinks = [
            _make_sink("sink1", call_id, "sql", "execute"),
        ]
        sources = [
            _make_source("src1", func_a_id, "user"),
        ]
        # AssignFact has value="literal" (not "user"), so no propagation
        assigns = [
            _make_assign("assign1", func_a_id, "safe_input", "literal", line=5),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks, *sources, *assigns]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        # Act
        dataflows = build_taint_lite_dataflows(all_facts, reachability)

        # Assert: AssignFact value doesn't match source name → no dataflow
        assert dataflows == []


# ---------------------------------------------------------------------------
# Test: One-hop cross-function propagation
# ---------------------------------------------------------------------------


class TestOneHopCrossFunction:
    """caller_param -> intermediate_param -> sink in one-hop helper function."""

    def test_one_hop_propagation_returns_dataflow(self) -> None:
        # Arrange:
        #   ep func_a(cmd) -> call helper(helper, cmd) -> call eval(eval, cmd)
        #   helper receives cmd as param_0, passes it to eval
        func_a_id = "python:src/test.py:func_a"
        helper_id = "python:src/test.py:helper"
        funcs = [
            _make_function(func_a_id, "func_a", params=["cmd"]),
            _make_function(helper_id, "helper", params=["cmd_arg"]),
        ]
        call1_id = "call1"
        call2_id = "call2"
        calls = [
            _make_call(
                call1_id,
                func_a_id,
                "helper",
                "helper(cmd)",
                line=5,
                args=[_arg("cmd", 0)],
                normalized_callee=helper_id,
            ),
            _make_call(
                call2_id,
                helper_id,
                "eval",
                "eval(cmd_arg)",
                line=15,
                args=[_arg("cmd_arg", 0)],
                normalized_callee="eval",
            ),
        ]
        eps = [
            _make_entrypoint("ep1", "run_tool", func_a_id),
        ]
        sinks = [
            _make_sink("sink1", call2_id, "rce", "eval"),
        ]
        sources = [
            _make_source("src1", func_a_id, "cmd"),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks, *sources]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        # Act
        dataflows = build_taint_lite_dataflows(all_facts, reachability)

        # Assert
        assert len(dataflows) >= 1
        df = dataflows[0]
        assert df.source_id == "src1"
        assert df.sink_id == "sink1"
        # Path: param(cmd) -> call_arg(cmd) -> param(cmd_arg) -> call_arg(cmd_arg)
        assert len(df.path) == 4


# ---------------------------------------------------------------------------
# Test: No matching flow → empty list
# ---------------------------------------------------------------------------


class TestNoMatchingFlow:
    """Source param name does not match any sink arg → empty list, no exception."""

    def test_no_source_name_match_returns_empty(self) -> None:
        # Arrange: func_a has source "cmd", but sink receives "other" (not cmd)
        func_a_id = "python:src/test.py:func_a"
        funcs = [
            _make_function(func_a_id, "func_a", params=["cmd"]),
        ]
        call_id = "call1"
        calls = [
            _make_call(
                call_id,
                func_a_id,
                "eval",
                "eval(other)",
                line=10,
                args=[_arg("other", 0)],
                normalized_callee="eval",
            ),
        ]
        eps = [
            _make_entrypoint("ep1", "run_tool", func_a_id),
        ]
        sinks = [
            _make_sink("sink1", call_id, "rce", "eval"),
        ]
        sources = [
            _make_source("src1", func_a_id, "cmd"),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks, *sources]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        # Act
        dataflows = build_taint_lite_dataflows(all_facts, reachability)

        # Assert
        assert dataflows == []


# ---------------------------------------------------------------------------
# Test: Empty inputs → empty list
# ---------------------------------------------------------------------------


class TestEmptyInputs:
    """Empty reachability_results or empty fact list → empty list, no exception."""

    def test_empty_reachability_returns_empty(self) -> None:
        dataflows = build_taint_lite_dataflows([], [])
        assert dataflows == []

    def test_no_sources_returns_empty(self) -> None:
        func_a_id = "python:src/test.py:func_a"
        funcs = [_make_function(func_a_id, "func_a", params=["cmd"])]
        call_id = "call1"
        calls = [
            _make_call(
                call_id,
                func_a_id,
                "eval",
                "eval(cmd)",
                line=10,
                args=[_arg("cmd", 0)],
                normalized_callee="eval",
            ),
        ]
        eps = [_make_entrypoint("ep1", "run_tool", func_a_id)]
        sinks = [_make_sink("sink1", call_id, "rce", "eval")]
        # NO sources

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        dataflows = build_taint_lite_dataflows(all_facts, reachability)
        assert dataflows == []


# ---------------------------------------------------------------------------
# Test: DataFlowFact structure is correct
# ---------------------------------------------------------------------------


class TestDataFlowFactStructure:
    """Generated DataFlowFact has all required fields populated."""

    def test_dataflow_has_required_fields(self) -> None:
        func_a_id = "python:src/test.py:func_a"
        funcs = [
            _make_function(func_a_id, "func_a", params=["cmd"]),
        ]
        call_id = "call1"
        calls = [
            _make_call(
                call_id,
                func_a_id,
                "eval",
                "eval(cmd)",
                line=10,
                args=[_arg("cmd", 0)],
                normalized_callee="eval",
            ),
        ]
        eps = [
            _make_entrypoint("ep1", "run_tool", func_a_id),
        ]
        sinks = [
            _make_sink("sink1", call_id, "rce", "eval"),
        ]
        sources = [
            _make_source("src1", func_a_id, "cmd"),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks, *sources]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)
        dataflows = build_taint_lite_dataflows(all_facts, reachability)

        assert len(dataflows) == 1
        df = dataflows[0]
        assert df.type == "dataflow"
        assert df.id.startswith("flow:")
        assert df.source_id == "src1"
        assert df.sink_id == "sink1"
        assert df.file == "src/test.py"
        assert df.line == 10
        assert df.confidence == Confidence.HIGH
        assert all(step.kind in PathStepKind for step in df.path)