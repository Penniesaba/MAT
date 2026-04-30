"""Unit tests for Call Graph + Reachability Analysis Pass.

Covers:
- build_call_graph: building call graph from facts
- find_reachable_sinks: entrypoint → sink reachability
- Single-hop and multi-hop scenarios
- Unreachable sinks are not returned
- Graceful handling of dirty data (missing call_id references)
"""

from __future__ import annotations

from analysis.facts.schema import (
    CallFact,
    EntryPointFact,
    FunctionFact,
    SinkFact,
)
from analysis.facts.store import FactStore
from analysis.passes.call_graph import (
    CallChainLink,
    CallGraph,
    ReachabilityResult,
    build_call_graph,
    find_reachable_sinks,
)


# ---------------------------------------------------------------------------
# Test class: TestBuildCallGraph
# ---------------------------------------------------------------------------


class TestBuildCallGraph:
    """Test call graph construction from fact lists."""

    def _make_function_fact(self, fact_id: str) -> FunctionFact:
        return FunctionFact(
            type="function",
            id=fact_id,
            language="python",
            name="test_func",
            qualified_name="test_func",
            file="src/test.py",
            line=1,
            extractor="test",
        )

    def _make_call_fact(
        self,
        call_id: str,
        caller: str,
        callee: str,
        normalized_callee: str | None = None,
    ) -> CallFact:
        return CallFact(
            type="call",
            id=call_id,
            caller=caller,
            callee=callee,
            normalized_callee=normalized_callee,
            file="src/test.py",
            line=10,
            snippet=f"{callee}()",
            extractor="test",
        )

    def test_empty_facts_returns_empty_graph(self) -> None:
        """No facts produces an empty call graph."""
        graph = build_call_graph([])

        assert graph.calls_by_caller == {}
        assert graph.call_by_id == {}
        assert graph.function_by_id == {}

    def test_call_facts_indexed_by_caller(self) -> None:
        """CallFact entries are indexed by caller function_id."""
        facts = [
            self._make_function_fact("python:src/server.py:run_cmd"),
            self._make_call_fact(
                "call:src/server.py:10:1",
                caller="python:src/server.py:run_cmd",
                callee="subprocess.run",
                normalized_callee="python:subprocess.run",
            ),
        ]
        graph = build_call_graph(facts)

        assert "python:src/server.py:run_cmd" in graph.calls_by_caller
        assert len(graph.calls_by_caller["python:src/server.py:run_cmd"]) == 1
        assert (
            graph.calls_by_caller["python:src/server.py:run_cmd"][0].id
            == "call:src/server.py:10:1"
        )

    def test_call_facts_indexed_by_id(self) -> None:
        """CallFact entries are indexed by their own ID."""
        facts = [
            self._make_call_fact(
                "call:src/server.py:10:1",
                caller="python:src/server.py:run_cmd",
                callee="subprocess.run",
            ),
        ]
        graph = build_call_graph(facts)

        assert "call:src/server.py:10:1" in graph.call_by_id
        assert graph.call_by_id["call:src/server.py:10:1"].callee == "subprocess.run"

    def test_call_facts_indexed_by_callee(self) -> None:
        """CallFact entries are indexed by normalized_callee (function_id)."""
        facts = [
            self._make_call_fact(
                "call:src/server.py:10:1",
                caller="python:src/server.py:run_cmd",
                callee="subprocess.run",
                normalized_callee="python:subprocess.run",
            ),
        ]
        graph = build_call_graph(facts)

        assert "python:subprocess.run" in graph.function_by_id
        assert (
            graph.function_by_id["python:subprocess.run"][0].id
            == "call:src/server.py:10:1"
        )

    def test_multiple_calls_from_same_function(self) -> None:
        """A function can have multiple outgoing calls."""
        facts = [
            self._make_function_fact("python:src/server.py:run_cmd"),
            self._make_call_fact(
                "call:src/server.py:10:1",
                caller="python:src/server.py:run_cmd",
                callee="subprocess.run",
                normalized_callee="python:subprocess.run",
            ),
            self._make_call_fact(
                "call:src/server.py:11:1",
                caller="python:src/server.py:run_cmd",
                callee="os.system",
                normalized_callee="python:os.system",
            ),
        ]
        graph = build_call_graph(facts)

        calls = graph.calls_by_caller["python:src/server.py:run_cmd"]
        assert len(calls) == 2
        call_ids = {c.id for c in calls}
        assert call_ids == {"call:src/server.py:10:1", "call:src/server.py:11:1"}

    def test_non_call_facts_ignored(self) -> None:
        """Only CallFact entries are included in the graph."""
        func = self._make_function_fact("python:src/server.py:run_cmd")
        entry = EntryPointFact(
            type="entrypoint",
            id="entry:src/server.py:run_cmd",
            name="run_cmd",
            function_id="python:src/server.py:run_cmd",
            file="src/server.py",
            line=1,
            extractor="test",
        )
        sink = SinkFact(
            type="sink",
            id="sink:rce:src/server.py:10",
            call_id="call:src/server.py:10:1",
            category="rce",
            rule_id="test",
            sink_name="subprocess.run",
            file="src/server.py",
            line=10,
            extractor="test",
        )

        graph = build_call_graph([func, entry, sink])

        assert graph.call_by_id == {}
        assert graph.calls_by_caller == {}

    def test_facts_from_store(self) -> None:
        """build_call_graph works with facts from a FactStore."""
        store = FactStore()
        func = self._make_function_fact("python:src/server.py:run_cmd")
        call = self._make_call_fact(
            "call:src/server.py:10:1",
            caller="python:src/server.py:run_cmd",
            callee="subprocess.run",
            normalized_callee="python:subprocess.run",
        )
        store.add_all([func, call])

        graph = build_call_graph(store.all_facts())

        assert "call:src/server.py:10:1" in graph.call_by_id


# ---------------------------------------------------------------------------
# Test class: TestFindReachableSinks
# ---------------------------------------------------------------------------


class TestFindReachableSinks:
    """Test entrypoint → sink reachability analysis."""

    def _make_ep(self, ep_id: str, func_id: str) -> EntryPointFact:
        return EntryPointFact(
            type="entrypoint",
            id=ep_id,
            name="test",
            function_id=func_id,
            file="src/test.py",
            line=1,
            extractor="test",
        )

    def _make_call(
        self,
        call_id: str,
        caller: str,
        callee: str,
        normalized_callee: str | None = None,
        snippet: str = "...",
        line: int = 10,
    ) -> CallFact:
        return CallFact(
            type="call",
            id=call_id,
            caller=caller,
            callee=callee,
            normalized_callee=normalized_callee,
            file="src/test.py",
            line=line,
            snippet=snippet,
            extractor="test",
        )

    def _make_sink(
        self,
        sink_id: str,
        call_id: str,
        category: str = "rce",
    ) -> SinkFact:
        return SinkFact(
            type="sink",
            id=sink_id,
            call_id=call_id,
            category=category,
            rule_id="test",
            sink_name="test",
            file="src/test.py",
            line=10,
            extractor="test",
        )

    # ------------------------------------------------------------------
    # Single-hop: entrypoint directly calls sink
    # ------------------------------------------------------------------

    def test_single_hop_reachable_sink(self) -> None:
        """EntryPoint → directly called sink is reported as reachable."""
        entrypoint = self._make_ep("entry:src/server.py:run_cmd", "python:src/server.py:run_cmd")
        call = self._make_call(
            "call:src/server.py:10:1",
            caller="python:src/server.py:run_cmd",
            callee="subprocess.run",
            normalized_callee="python:subprocess.run",
            snippet="subprocess.run(cmd, shell=True)",
            line=10,
        )
        sink = self._make_sink("sink:rce:src/server.py:10", "call:src/server.py:10:1")

        graph = build_call_graph([call])
        results = find_reachable_sinks([entrypoint], [sink], graph)

        assert len(results) == 1
        result = results[0]
        assert result.entrypoint_id == "entry:src/server.py:run_cmd"
        assert result.entrypoint_function_id == "python:src/server.py:run_cmd"
        assert result.sink_id == "sink:rce:src/server.py:10"
        assert result.is_reachable is True
        assert len(result.call_chain) == 1
        assert result.call_chain[0].call_id == "call:src/server.py:10:1"
        assert result.call_chain[0].snippet == "subprocess.run(cmd, shell=True)"

    # ------------------------------------------------------------------
    # Multi-hop: entrypoint → helper → sink
    # ------------------------------------------------------------------

    def test_multi_hop_reachable_sink(self) -> None:
        """EntryPoint → helper function → sink is reported as reachable."""
        entrypoint = self._make_ep("entry:src/server.py:run_cmd", "python:src/server.py:run_cmd")
        call_to_helper = self._make_call(
            "call:src/server.py:5:1",
            caller="python:src/server.py:run_cmd",
            callee="helper_func",
            normalized_callee="python:src/server.py:helper_func",
            snippet="helper_func(cmd)",
            line=5,
        )
        call_to_sink = self._make_call(
            "call:src/server.py:20:1",
            caller="python:src/server.py:helper_func",
            callee="subprocess.run",
            normalized_callee="python:subprocess.run",
            snippet="subprocess.run(cmd, shell=True)",
            line=20,
        )
        sink = self._make_sink("sink:rce:src/server.py:20", "call:src/server.py:20:1")

        graph = build_call_graph([call_to_helper, call_to_sink])
        results = find_reachable_sinks([entrypoint], [sink], graph)

        assert len(results) == 1
        result = results[0]
        assert result.sink_id == "sink:rce:src/server.py:20"
        assert len(result.call_chain) == 2
        assert result.call_chain[0].call_id == "call:src/server.py:5:1"
        assert result.call_chain[1].call_id == "call:src/server.py:20:1"

    # ------------------------------------------------------------------
    # Unreachable sinks should not be returned
    # ------------------------------------------------------------------

    def test_unreachable_sink_not_returned(self) -> None:
        """Sink not connected to entrypoint via any call path is not returned."""
        entrypoint = self._make_ep("entry:src/server.py:run_cmd", "python:src/server.py:run_cmd")
        # A sink in a completely unrelated function
        unrelated_call = self._make_call(
            "call:src/utils.py:10:1",
            caller="python:src/utils.py:other_func",
            callee="subprocess.run",
            normalized_callee="python:subprocess.run",
            line=10,
        )
        sink = self._make_sink("sink:rce:src/utils.py:10", "call:src/utils.py:10:1")

        graph = build_call_graph([unrelated_call])
        results = find_reachable_sinks([entrypoint], [sink], graph)

        assert len(results) == 0

    def test_sink_without_matching_call_not_returned(self) -> None:
        """Sink whose call_id does not exist in the call graph is not returned."""
        entrypoint = self._make_ep("entry:src/server.py:run_cmd", "python:src/server.py:run_cmd")
        sink = self._make_sink("sink:rce:src/server.py:99", "call:src/server.py:99:999")

        graph = build_call_graph([])  # no calls at all
        results = find_reachable_sinks([entrypoint], [sink], graph)

        assert len(results) == 0

    # ------------------------------------------------------------------
    # Graceful handling of dirty data
    # ------------------------------------------------------------------

    def test_sink_with_missing_call_id_still_succeeds(self) -> None:
        """Sink referencing a non-existent call_id does not crash."""
        entrypoint = self._make_ep("entry:src/server.py:run_cmd", "python:src/server.py:run_cmd")
        # call exists but sink points to a different non-existent call_id
        call = self._make_call(
            "call:src/server.py:10:1",
            caller="python:src/server.py:run_cmd",
            callee="subprocess.run",
            normalized_callee="python:subprocess.run",
            line=10,
        )
        # Valid call_id in sink but not reachable from entrypoint
        valid_sink = self._make_sink("sink:rce:src/server.py:10", "call:src/server.py:10:1")
        invalid_sink = self._make_sink(
            "sink:rce:src/server.py:99", "call:src/server.py:does_not_exist"
        )

        graph = build_call_graph([call])
        # Should not raise
        results = find_reachable_sinks([entrypoint], [valid_sink, invalid_sink], graph)

        # Only the valid sink should appear
        assert len(results) == 1
        assert results[0].sink_id == "sink:rce:src/server.py:10"

    def test_entrypoint_with_no_outgoing_calls(self) -> None:
        """EntryPoint whose function makes no calls returns empty results."""
        entrypoint = self._make_ep("entry:src/server.py:naked_func", "python:src/server.py:naked_func")
        sink = self._make_sink("sink:rce:src/server.py:10", "call:src/server.py:10:1")

        graph = build_call_graph([])  # no calls in the codebase
        results = find_reachable_sinks([entrypoint], [sink], graph)

        assert len(results) == 0

    def test_multiple_entrypoints_same_sink(self) -> None:
        """Multiple entrypoints can reach the same sink; each gets its own result."""
        ep1 = self._make_ep("entry:src/server.py:func_a", "python:src/server.py:func_a")
        ep2 = self._make_ep("entry:src/server.py:func_b", "python:src/server.py:func_b")
        call = self._make_call(
            "call:src/server.py:10:1",
            caller="python:src/server.py:func_a",
            callee="subprocess.run",
            normalized_callee="python:subprocess.run",
            line=10,
        )
        sink = self._make_sink("sink:rce:src/server.py:10", "call:src/server.py:10:1")

        graph = build_call_graph([call])
        results = find_reachable_sinks([ep1, ep2], [sink], graph)

        assert len(results) == 1  # only ep1 can reach it
        assert results[0].entrypoint_id == "entry:src/server.py:func_a"

    def test_call_chain_links_contain_call_id_ordered_path(self) -> None:
        """Call chain preserves call_id ordering for evidence reconstruction."""
        entrypoint = self._make_ep("entry:src/server.py:run_cmd", "python:src/server.py:run_cmd")
        call1 = self._make_call(
            "call:src/server.py:5:1",
            caller="python:src/server.py:run_cmd",
            callee="validate",
            normalized_callee="python:src/server.py:validate",
            snippet="validate(cmd)",
            line=5,
        )
        call2 = self._make_call(
            "call:src/server.py:10:1",
            caller="python:src/server.py:validate",
            callee="exec",
            normalized_callee="python:src/server.py:exec",
            snippet="exec(cmd)",
            line=10,
        )
        call3 = self._make_call(
            "call:src/server.py:15:1",
            caller="python:src/server.py:exec",
            callee="subprocess.run",
            normalized_callee="python:subprocess.run",
            snippet="subprocess.run(cmd, shell=True)",
            line=15,
        )
        sink = self._make_sink("sink:rce:src/server.py:15", "call:src/server.py:15:1")

        graph = build_call_graph([call1, call2, call3])
        results = find_reachable_sinks([entrypoint], [sink], graph)

        assert len(results) == 1
        chain = results[0].call_chain
        assert len(chain) == 3
        call_ids = [link.call_id for link in chain]
        assert call_ids == ["call:src/server.py:5:1", "call:src/server.py:10:1", "call:src/server.py:15:1"]

        # Verify each link has correct metadata for reconstruction
        assert chain[0].caller_func_id == "python:src/server.py:run_cmd"
        assert chain[0].callee_func_id == "python:src/server.py:validate"
        assert chain[2].snippet == "subprocess.run(cmd, shell=True)"

    def test_multi_hop_via_bare_local_function_name_resolves_via_symbol_table(self) -> None:
        """Local bare-name call (e.g. callee='helper_func') resolves via FunctionFact symbol table.

        This tests the scenario where an extractor outputs CallFact with only a bare
        callee name (no language: prefix) and no normalized_callee, but a FunctionFact
        with matching (file, name) exists in the fact set. The call graph must use that
        FunctionFact to resolve the callee function_id, enabling multi-hop traversal.
        """
        # Entry point
        ep = self._make_ep("entry:src/server.py:run_cmd", "python:src/server.py:run_cmd")

        # The helper function definition (provides the symbol table entry)
        helper_func = FunctionFact(
            type="function",
            id="python:src/server.py:helper_func",
            language="python",
            name="helper_func",
            qualified_name="server.helper_func",
            file="src/server.py",
            line=20,
            extractor="python_ast",
        )

        # Call from run_cmd -> helper_func (bare name, no normalized_callee)
        call_to_helper = CallFact(
            type="call",
            id="call:src/server.py:5:1",
            caller="python:src/server.py:run_cmd",
            callee="helper_func",
            normalized_callee=None,  # bare name from extractor
            file="src/server.py",
            line=5,
            snippet="helper_func(cmd)",
            extractor="python_ast",
        )

        # Call from helper_func -> subprocess.run (full normalized_callee)
        call_to_sink = CallFact(
            type="call",
            id="call:src/server.py:21:4",
            caller="python:src/server.py:helper_func",
            callee="subprocess.run",
            normalized_callee="python:subprocess.run",
            file="src/server.py",
            line=21,
            snippet="subprocess.run(cmd, shell=True)",
            extractor="python_ast",
        )

        # Sink matched on the second call
        sink = self._make_sink("sink:rce:src/server.py:21", "call:src/server.py:21:4")

        graph = build_call_graph([helper_func, call_to_helper, call_to_sink])
        results = find_reachable_sinks([ep], [sink], graph)

        assert len(results) == 1
        chain = results[0].call_chain
        assert len(chain) == 2
        call_ids = [link.call_id for link in chain]
        assert call_ids == ["call:src/server.py:5:1", "call:src/server.py:21:4"]
        # Verify the first link's callee_func_id was resolved via symbol table
        assert chain[0].callee_func_id == "python:src/server.py:helper_func"
        # Verify BFS could follow the resolved callee into the next function
        assert chain[1].caller_func_id == "python:src/server.py:helper_func"


# ---------------------------------------------------------------------------
# Test class: TestCallChainLinkDataclass
# ---------------------------------------------------------------------------


class TestCallChainLinkDataclass:
    """Test CallChainLink structure for evidence traceability."""

    def test_call_chain_link_fields(self) -> None:
        """CallChainLink stores all fields needed to reconstruct call evidence."""
        link = CallChainLink(
            call_id="call:src/server.py:10:4",
            caller_func_id="python:src/server.py:run_cmd",
            callee_func_id="python:subprocess.run",
            snippet="subprocess.run(cmd, shell=True)",
            line=10,
        )
        assert link.call_id == "call:src/server.py:10:4"
        assert link.caller_func_id == "python:src/server.py:run_cmd"
        assert link.callee_func_id == "python:subprocess.run"
        assert link.snippet == "subprocess.run(cmd, shell=True)"
        assert link.line == 10

    def test_call_chain_link_callee_can_be_none(self) -> None:
        """CallChainLink.callee_func_id may be None when callee is not a tracked function."""
        link = CallChainLink(
            call_id="call:src/server.py:10:4",
            caller_func_id="python:src/server.py:run_cmd",
            callee_func_id=None,
            snippet="os.system(cmd)",
            line=10,
        )
        assert link.callee_func_id is None
