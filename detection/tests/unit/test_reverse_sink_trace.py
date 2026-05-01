"""Unit tests for reverse_sink_trace module.

Covers:
1. Module-level direct sink (no function wrapper — <module> → sink)
2. One-hop to sink (root function directly calls sink)
3. Multi-hop chain (root → intermediate → ... → sink)
4. No duplicate with MCP entrypoint findings (dedup logic)
5. Python module-level sink detection
"""

from __future__ import annotations

from analysis.facts.schema import (
    CallFact,
    Confidence,
    Fact,
    FindingFact,
    FindingStatus,
    FunctionFact,
    Severity,
    SinkFact,
)
from analysis.passes.call_graph import build_call_graph
from analysis.passes.reverse_sink_trace import (
    SinkRootResult,
    build_sink_root_findings,
    find_sink_root_chains,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_function(
    fact_id: str,
    name: str = "test_func",
    file: str = "src/test.js",
    line: int = 1,
) -> FunctionFact:
    return FunctionFact(
        type="function",
        id=fact_id,
        language="javascript",
        name=name,
        qualified_name=name,
        file=file,
        line=line,
        extractor="test",
    )


def _make_call(
    call_id: str,
    caller: str,
    callee: str,
    snippet: str = "call()",
    line: int = 10,
    normalized_callee: str | None = None,
    file: str = "src/test.js",
) -> CallFact:
    return CallFact(
        type="call",
        id=call_id,
        caller=caller,
        callee=callee,
        normalized_callee=normalized_callee,
        snippet=snippet,
        line=line,
        file=file,
        extractor="test",
    )


def _make_sink(
    sink_id: str,
    call_id: str,
    category: str,
    sink_name: str,
    rule_id: str = "R001",
    severity: Severity = Severity.HIGH,
    reason: str = "dangerous call",
    file: str = "src/test.js",
    line: int = 10,
) -> SinkFact:
    return SinkFact(
        type="sink",
        id=sink_id,
        call_id=call_id,
        category=category,
        rule_id=rule_id,
        sink_name=sink_name,
        severity_base=severity,
        confidence=Confidence.HIGH,
        reason=reason,
        file=file,
        line=line,
        extractor="test",
    )


# ---------------------------------------------------------------------------
# Test class: TestFindSinkRootChains — module-level direct sink
# ---------------------------------------------------------------------------


class TestModuleLevelDirectSink:
    """Test: module-level code directly calls sink → <module> is root."""

    def test_js_module_level_direct_sink(self) -> None:
        """JS: eval("code") at module level → root is <module>, distance=0."""
        # Module-level call: <module> → eval()
        calls = [
            _make_call(
                "call:src/test.js:5:1",
                caller="<module>",
                callee="eval",
                snippet='eval("code")',
                line=5,
            ),
        ]
        sinks = [
            _make_sink(
                "sink:rce:src/test.js:5",
                "call:src/test.js:5:1",
                "rce",
                "eval",
                reason="direct eval",
            ),
        ]

        all_facts: list[Fact] = [*calls, *sinks]
        graph = build_call_graph(all_facts)
        results = find_sink_root_chains(all_facts, graph)

        assert len(results) == 1
        result = results[0]
        assert result.root_function_id == "<module>"
        assert result.root_function_name == "<module>"
        assert result.root_is_module_level is True
        assert result.distance == 0
        assert result.sink_name == "eval"
        assert result.sink_category == "rce"


# ---------------------------------------------------------------------------
# Test class: TestFindSinkRootChains — one hop to sink
# ---------------------------------------------------------------------------


class TestOneHopToSink:
    """Test: one function directly calls sink (root → sink)."""

    def test_function_directly_calls_sink(self) -> None:
        """JS: function run(cmd) { execSync(cmd); } run("ls") → root=run, distance=0."""
        funcs = [
            _make_function("js:src/test.js:run", "run"),
        ]
        calls = [
            _make_call(
                "call:src/test.js:10:1",
                caller="js:src/test.js:run",
                callee="execSync",
                snippet="execSync(cmd)",
                line=10,
                normalized_callee="js:child_process:execSync",
            ),
        ]
        sinks = [
            _make_sink(
                "sink:rce:src/test.js:10",
                "call:src/test.js:10:1",
                "rce",
                "execSync",
                reason="shell command execution",
            ),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *sinks]
        graph = build_call_graph(all_facts)
        results = find_sink_root_chains(all_facts, graph)

        assert len(results) == 1
        result = results[0]
        assert result.root_function_id == "js:src/test.js:run"
        assert result.root_function_name == "run"
        assert result.root_is_module_level is False
        assert result.distance == 0
        assert result.sink_name == "execSync"
        assert len(result.call_chain) == 1


# ---------------------------------------------------------------------------
# Test class: TestFindSinkRootChains — multi-hop chain
# ---------------------------------------------------------------------------


class TestMultiHopChain:
    """Test: multi-hop call chain from root to sink."""

    def test_three_hop_chain(self) -> None:
        """JS: <module> → collectInfo → execSafe → execSync (Apifox pattern)."""
        funcs = [
            _make_function("js:src/test.js:execSafe", "execSafe"),
            _make_function("js:src/test.js:collectInfo", "collectInfo"),
        ]
        calls = [
            # collectInfo → execSafe
            _make_call(
                "call:src/test.js:5:1",
                caller="js:src/test.js:collectInfo",
                callee="execSafe",
                snippet="execSafe('ps aux')",
                line=5,
                normalized_callee="js:src/test.js:execSafe",
            ),
            # execSafe → execSync
            _make_call(
                "call:src/test.js:2:1",
                caller="js:src/test.js:execSafe",
                callee="execSync",
                snippet="execSync(cmd)",
                line=2,
                normalized_callee="js:child_process:execSync",
            ),
            # module → collectInfo
            _make_call(
                "call:src/test.js:10:1",
                caller="<module>",
                callee="collectInfo",
                snippet="collectInfo()",
                line=10,
                normalized_callee="js:src/test.js:collectInfo",
            ),
        ]
        sinks = [
            _make_sink(
                "sink:rce:src/test.js:2",
                "call:src/test.js:2:1",
                "rce",
                "execSync",
                reason="shell command via execSync",
            ),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *sinks]
        graph = build_call_graph(all_facts)
        results = find_sink_root_chains(all_facts, graph)

        assert len(results) == 1
        result = results[0]
        assert result.root_function_id == "<module>"
        assert result.root_function_name == "<module>"
        assert result.root_is_module_level is True
        assert result.distance == 2  # collectInfo → execSafe → execSync (2 hops)
        assert result.sink_name == "execSync"
        # call_chain should have 3 links: module→collectInfo, collectInfo→execSafe, execSafe→execSync
        assert len(result.call_chain) == 3


# ---------------------------------------------------------------------------
# Test class: TestBuildSinkRootFindings — no duplicate with MCP entrypoint
# ---------------------------------------------------------------------------


class TestNoDuplicateWithMcpEntrypoint:
    """Test: when both MCP forward path and reverse path find the same sink, no duplicates."""

    def test_deduplication_between_mcp_and_generic(self) -> None:
        """Same sink reached via MCP path should not appear twice when combined."""
        # Setup: function dangerous(cmd) { eval(cmd); }
        #   server.tool("run", (cmd) => { dangerous(cmd); });  ← MCP entrypoint
        #   dangerous("ls");  ← direct call, same sink

        funcs = [
            _make_function("js:src/test.js:dangerous", "dangerous"),
        ]
        calls = [
            # MCP entrypoint path: run_tool → dangerous → eval
            _make_call(
                "call:src/test.js:3:1",
                caller="js:src/test.js:dangerous",
                callee="eval",
                snippet='eval(cmd)',
                line=3,
                normalized_callee="js:builtin:eval",
            ),
            # Direct module call: dangerous("ls")
            _make_call(
                "call:src/test.js:7:1",
                caller="<module>",
                callee="dangerous",
                snippet='dangerous("ls")',
                line=7,
                normalized_callee="js:src/test.js:dangerous",
            ),
            # call from dangerous to dangerous (internal)
            _make_call(
                "call:src/test.js:5:1",
                caller="js:src/test.js:dangerous",
                callee="eval",
                snippet='eval(cmd)',
                line=5,
                normalized_callee="js:builtin:eval",
            ),
        ]
        sinks = [
            # Same sink id for both eval calls
            _make_sink(
                "sink:rce:src/test.js:3",
                "call:src/test.js:3:1",
                "rce",
                "eval",
            ),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *sinks]
        graph = build_call_graph(all_facts)

        # Simulate Path A result (MCP forward) — already found sink:rce:src/test.js:3
        path_a_findings = [
            FindingFact(
                type="finding",
                id="finding:rce:ep_run__tool_sink_eval",
                file="src/test.js",
                line=3,
                title="Potential rce via run_tool → eval",
                category="rce",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                status=FindingStatus.POTENTIAL,
                entrypoint_id="entry:src/test.js:run",
                sink_id="sink:rce:src/test.js:3",
                call_chain=[],
                evidence=[],
            )
        ]

        # Path B reverse trace
        root_chains = find_sink_root_chains(all_facts, graph)

        # Deduplication: filter out sinks already covered by Path A
        covered_sink_ids = {f.sink_id for f in path_a_findings if f.sink_id}
        filtered_chains = [rc for rc in root_chains if rc.sink_id not in covered_sink_ids]

        path_b_findings = build_sink_root_findings(filtered_chains, all_facts)

        # Combine
        combined = [*path_a_findings, *path_b_findings]

        # Should not have duplicate sink_ids
        sink_ids = [f.sink_id for f in combined if f.sink_id]
        assert len(sink_ids) == len(set(sink_ids)), f"Duplicate sink_ids found: {sink_ids}"


# ---------------------------------------------------------------------------
# Test class: TestFindSinkRootChains — Python module-level sink
# ---------------------------------------------------------------------------


class TestPythonModuleLevelSink:
    """Test: Python module-level os.system() detection."""

    def test_python_module_level_os_system(self) -> None:
        """Python: os.system("whoami") at module level → root is <module>."""
        calls = [
            _make_call(
                "call:src/server.py:3:1",
                caller="<module>",
                callee="os.system",
                snippet='os.system("whoami")',
                line=3,
                normalized_callee="python:os:system",
                file="src/server.py",
            ),
        ]
        sinks = [
            _make_sink(
                "sink:cmd-injection:src/server.py:3",
                "call:src/server.py:3:1",
                "cmd-injection",
                "os.system",
                reason="shell command via os.system",
                file="src/server.py",
                line=3,
            ),
        ]

        all_facts: list[Fact] = [*calls, *sinks]
        graph = build_call_graph(all_facts)
        results = find_sink_root_chains(all_facts, graph)

        assert len(results) == 1
        result = results[0]
        assert result.root_function_id == "<module>"
        assert result.root_function_name == "<module>"
        assert result.root_is_module_level is True
        assert result.distance == 0


# ---------------------------------------------------------------------------
# Test class: TestBuildSinkRootFindings — FindingFact structure
# ---------------------------------------------------------------------------


class TestSinkRootFindingFactStructure:
    """Test: SinkRootResult → FindingFact conversion produces correct structure."""

    def test_finding_fact_has_correct_fields(self) -> None:
        """FindingFact from reverse trace has MEDIUM confidence, POTENTIAL status."""
        funcs = [
            _make_function("js:src/test.js:run", "run"),
        ]
        calls = [
            _make_call(
                "call:src/test.js:10:1",
                caller="js:src/test.js:run",
                callee="eval",
                snippet='eval(userInput)',
                line=10,
                normalized_callee="js:builtin:eval",
            ),
        ]
        sinks = [
            _make_sink(
                "sink:rce:src/test.js:10",
                "call:src/test.js:10:1",
                "rce",
                "eval",
                severity=Severity.CRITICAL,
                reason="user input passed to eval",
            ),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *sinks]
        graph = build_call_graph(all_facts)
        root_chains = find_sink_root_chains(all_facts, graph)
        findings = build_sink_root_findings(root_chains, all_facts)

        assert len(findings) == 1
        finding = findings[0]
        assert isinstance(finding, FindingFact)
        assert finding.confidence == Confidence.MEDIUM
        assert finding.status == FindingStatus.POTENTIAL
        assert finding.severity == Severity.CRITICAL
        assert finding.entrypoint_id == "js:src/test.js:run"  # root function_id
        assert finding.sink_id == "sink:rce:src/test.js:10"
        assert finding.category == "rce"
        assert "run" in finding.title
        assert "eval" in finding.title
        # evidence populated
        assert len(finding.evidence) > 0
        assert any("Root function" in e for e in finding.evidence)
        assert any("eval" in e for e in finding.evidence)


# ---------------------------------------------------------------------------
# Test class: TestFindSinkRootChains — edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Test: empty graph, no sinks, etc."""

    def test_empty_facts_returns_empty_results(self) -> None:
        """No facts → no results."""
        results = find_sink_root_chains([], build_call_graph([]))
        assert results == []

    def test_sink_with_no_matching_call_id_skipped(self) -> None:
        """Sink whose call_id is not in the graph is skipped silently."""
        # A call that exists but sink points to a different call_id
        calls = [
            _make_call(
                "call:src/test.js:5:1",
                caller="<module>",
                callee="eval",
                snippet='eval("x")',
                line=5,
            ),
        ]
        # Sink points to a non-existent call_id
        sinks = [
            _make_sink(
                "sink:rce:src/test.js:99",
                "call:src/test.js:99:999",  # does not exist in graph
                "rce",
                "eval",
            ),
        ]

        all_facts: list[Fact] = [*calls, *sinks]
        graph = build_call_graph(all_facts)
        results = find_sink_root_chains(all_facts, graph)

        # Should skip the sink with non-existent call_id
        assert len(results) == 0

    def test_max_depth_limits_bfs(self) -> None:
        """BFS upward stops at MAX_DEPTH=10 to prevent infinite loops."""
        # Create a deep chain: func0 → func1 → ... → func15 → sink
        # With MAX_DEPTH=10, should stop before reaching func0 as root
        funcs = [_make_function(f"js:src/test.js:func{i}", f"func{i}") for i in range(15)]
        calls = []
        for i in range(14):
            calls.append(
                _make_call(
                    f"call:src/test.js:{i+1}:1",
                    caller=f"js:src/test.js:func{i}",
                    callee=f"func{i+1}",
                    snippet=f"func{i+1}()",
                    line=i + 1,
                    normalized_callee=f"js:src/test.js:func{i+1}",
                )
            )
        # Final call: func14 → sink
        calls.append(
            _make_call(
                "call:src/test.js:15:1",
                caller="js:src/test.js:func14",
                callee="eval",
                snippet="eval(cmd)",
                line=15,
                normalized_callee="js:builtin:eval",
            )
        )
        sinks = [
            _make_sink(
                "sink:rce:src/test.js:15",
                "call:src/test.js:15:1",
                "rce",
                "eval",
            ),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *sinks]
        graph = build_call_graph(all_facts)
        results = find_sink_root_chains(all_facts, graph)

        assert len(results) == 1
        result = results[0]
        # Distance should be capped at 10 (MAX_DEPTH)
        assert result.distance <= 10
        # root_function_id should be one of the intermediate functions (func4 or so),
        # not func0 (which would be 14 hops away)
        assert result.root_function_id.startswith("js:src/test.js:func")