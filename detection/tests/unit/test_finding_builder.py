"""Unit tests for FindingFactsBuilder.

Covers:
1. Single reachable sink → exactly 1 FindingFact
2. Multiple reachable results → multiple Findings with stable unique IDs
3. call_chain order preservation
4. Missing sink_id → skipped (graceful handling, no crash)
5. Default severity/confidence when SinkFact field is absent
6. FindingStatus is always POTENTIAL
7. evidence contains entrypoint and sink descriptions
"""

from __future__ import annotations

from analysis.facts.schema import (
    CallFact,
    Confidence,
    EntryPointFact,
    Fact,
    FindingFact,
    FindingStatus,
    FunctionFact,
    Severity,
    SinkFact,
)
from analysis.passes.call_graph import (
    CallChainLink,
    ReachabilityResult,
    build_call_graph,
    find_reachable_sinks,
)
from analysis.passes.finding_builder import (
    FindingFactsBuilder,
    build_finding_facts,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_function(id: str, name: str = "test_func") -> FunctionFact:
    return FunctionFact(
        type="function",
        id=id,
        language="python",
        name=name,
        qualified_name=name,
        file="src/test.py",
        line=1,
        extractor="test",
    )


def _make_call(
    call_id: str,
    caller: str,
    callee: str,
    snippet: str = "call()",
    line: int = 10,
    normalized_callee: str | None = None,
) -> CallFact:
    return CallFact(
        type="call",
        id=call_id,
        caller=caller,
        callee=callee,
        normalized_callee=normalized_callee,
        snippet=snippet,
        line=line,
        file="src/test.py",
        extractor="test",
    )


def _make_entrypoint(
    ep_id: str,
    name: str,
    func_id: str,
    kind: str = "mcp_tool",
) -> EntryPointFact:
    return EntryPointFact(
        type="entrypoint",
        id=ep_id,
        name=name,
        function_id=func_id,
        kind=kind,
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


# ---------------------------------------------------------------------------
# Test class: TestBuildFindingFacts - single reachable sink
# ---------------------------------------------------------------------------


class TestSingleReachableSink:
    """Test: one entrypoint reaches one sink → one FindingFact."""

    def test_one_reachable_sink_produces_one_finding(self) -> None:
        # Arrange: ep func_a → call1 → sink1
        funcs = [
            _make_function("python:src/test.py:func_a", "func_a"),
            _make_function("python:src/test.py:helper", "helper"),
        ]
        calls = [
            _make_call("call1", "python:src/test.py:func_a", "helper", "helper()", 5),
        ]
        eps = [
            _make_entrypoint("ep1", "run_tool", "python:src/test.py:func_a"),
        ]
        sinks = [
            _make_sink("sink1", "call1", "rce", "eval", "R001"),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        # Act
        findings = build_finding_facts(reachability, all_facts)

        # Assert
        assert len(findings) == 1
        finding = findings[0]
        assert isinstance(finding, FindingFact)
        assert finding.entrypoint_id == "ep1"
        assert finding.sink_id == "sink1"
        assert finding.status == FindingStatus.POTENTIAL
        assert finding.category == "rce"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.HIGH
        assert finding.id.startswith("finding:rce:")
        # evidence is populated
        assert len(finding.evidence) > 0
        assert any("run_tool" in e for e in finding.evidence)
        assert any("eval" in e for e in finding.evidence)


# ---------------------------------------------------------------------------
# Test class: TestBuildFindingFacts - multiple reachable sinks
# ---------------------------------------------------------------------------


class TestMultipleReachableSinks:
    """Test: multiple reachable sinks → multiple Findings, IDs stable & unique."""

    def test_multiple_reachable_results_unique_finding_ids(self) -> None:
        # Arrange: ep func_a → call1 → sink1 AND ep func_a → call2 → sink2
        funcs = [
            _make_function("python:src/test.py:func_a"),
            _make_function("python:src/test.py:helper1"),
            _make_function("python:src/test.py:helper2"),
        ]
        calls = [
            _make_call("call1", "python:src/test.py:func_a", "helper1", "helper1()", 5),
            _make_call("call2", "python:src/test.py:func_a", "helper2", "helper2()", 10),
        ]
        eps = [
            _make_entrypoint("ep1", "run_tool", "python:src/test.py:func_a"),
        ]
        sinks = [
            _make_sink("sink1", "call1", "rce", "eval", "R001"),
            _make_sink("sink2", "call2", "data exfiltration", "exfil", "R002"),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        # Act
        findings = build_finding_facts(reachability, all_facts)

        # Assert
        assert len(findings) == 2
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids)), "Finding IDs must be unique"
        # IDs should be deterministic (stable across runs)
        # Note: underscores in names are doubled, so "run_tool" → "run__tool"
        assert ids[0] == "finding:rce:ep_run__tool_sink_eval"
        assert ids[1] == "finding:data exfiltration:ep_run__tool_sink_exfil"

    def test_same_sink_reachable_from_two_entrypoints_produces_two_findings(self) -> None:
        """Same sink reached from two entrypoints → two FindingFacts with different IDs."""
        funcs = [
            _make_function("python:src/test.py:tool_a"),
            _make_function("python:src/test.py:tool_b"),
            _make_function("python:src/test.py:helper"),
        ]
        calls = [
            _make_call("call1", "python:src/test.py:tool_a", "helper", "helper()", 5),
            _make_call("call2", "python:src/test.py:tool_b", "helper", "helper()", 20),
        ]
        eps = [
            _make_entrypoint("ep1", "tool_a", "python:src/test.py:tool_a"),
            _make_entrypoint("ep2", "tool_b", "python:src/test.py:tool_b"),
        ]
        sinks = [
            _make_sink("sink1", "call1", "rce", "dangerous", "R001"),
            # sink2 points to the same call as sink1 (multi-rule per call)
            _make_sink("sink2", "call2", "rce", "dangerous", "R003"),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        # Act
        findings = build_finding_facts(reachability, all_facts)

        # Assert: should have one finding per ReachabilityResult
        assert len(findings) == 2
        ids = sorted([f.id for f in findings])
        assert ids[0] != ids[1]


# ---------------------------------------------------------------------------
# Test class: TestCallChainOrder
# ---------------------------------------------------------------------------


class TestCallChainOrder:
    """Test: call_chain order is preserved (first-to-last hop order)."""

    def test_multihop_call_chain_order_preserved(self) -> None:
        # Arrange: ep func_a → call1 → func_b → call2 → sink1
        funcs = [
            _make_function("python:src/test.py:func_a"),
            _make_function("python:src/test.py:func_b"),
            _make_function("python:src/test.py:func_c"),
        ]
        calls = [
            _make_call("call1", "python:src/test.py:func_a", "func_b", "func_b()", 5, "python:src/test.py:func_b"),
            _make_call("call2", "python:src/test.py:func_b", "func_c", "func_c()", 10, "python:src/test.py:func_c"),
            _make_call("call3", "python:src/test.py:func_c", "external", "run_cmd()", 15, "python:external:run_cmd"),
        ]
        eps = [
            _make_entrypoint("ep1", "run_tool", "python:src/test.py:func_a"),
        ]
        sinks = [
            _make_sink("sink1", "call3", "rce", "run_cmd", "R001"),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        # Act
        findings = build_finding_facts(reachability, all_facts)

        # Assert
        assert len(findings) == 1
        chain = findings[0].call_chain
        assert len(chain) == 3
        assert chain[0]["call_id"] == "call1"
        assert chain[1]["call_id"] == "call2"
        assert chain[2]["call_id"] == "call3"
        # Verify order is caller→callee (first=func_a, last=func_c)
        assert chain[0]["caller_func_id"] == "python:src/test.py:func_a"
        assert chain[1]["caller_func_id"] == "python:src/test.py:func_b"


# ---------------------------------------------------------------------------
# Test class: TestMissingSinkHandling
# ---------------------------------------------------------------------------


class TestMissingSinkHandling:
    """Test: reachability result referencing unknown sink_id is gracefully skipped."""

    def test_missing_sink_skipped_without_crash(self) -> None:
        # Arrange: a ReachabilityResult whose sink_id has no matching SinkFact
        reachability = [
            ReachabilityResult(
                entrypoint_id="ep1",
                entrypoint_function_id="python:src/test.py:func_a",
                sink_id="nonexistent_sink",
                call_chain=[],
            )
        ]
        # Empty fact list (no SinkFact at all)
        facts: list[Fact] = []

        # Act & Assert: should NOT raise, just return empty list
        findings = build_finding_facts(reachability, facts, skip_missing_sinks=True)
        assert findings == []

    def test_missing_sink_raises_when_skip_disabled(self) -> None:
        # Arrange
        reachability = [
            ReachabilityResult(
                entrypoint_id="ep1",
                entrypoint_function_id="python:src/test.py:func_a",
                sink_id="nonexistent_sink",
                call_chain=[],
            )
        ]
        facts: list[Fact] = []

        # Act & Assert
        import pytest
        with pytest.raises(ValueError, match="nonexistent_sink"):
            build_finding_facts(reachability, facts, skip_missing_sinks=False)


# ---------------------------------------------------------------------------
# Test class: TestDefaultSeverityConfidence
# ---------------------------------------------------------------------------


class TestDefaultSeverityConfidence:
    """Test: missing severity_base/confidence on SinkFact → safe defaults."""

    def test_missing_severity_base_defaults_to_medium(self) -> None:
        # Arrange: SinkFact with severity_base = Severity.MEDIUM
        reachability = [
            ReachabilityResult(
                entrypoint_id="ep1",
                entrypoint_function_id="python:src/test.py:func_a",
                sink_id="sink1",
                call_chain=[],
            )
        ]
        # SinkFact with no explicit severity_base (defaults to MEDIUM per schema)
        sink = SinkFact(
            type="sink",
            id="sink1",
            call_id="call1",
            category="rce",
            rule_id="R001",
            sink_name="eval",
            severity_base=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            file="src/test.py",
            line=10,
            extractor="test",
        )
        facts: list[Fact] = [sink]

        # Act
        findings = build_finding_facts(reachability, facts)

        # Assert
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_missing_confidence_defaults_to_medium(self) -> None:
        # Arrange: SinkFact with missing confidence
        reachability = [
            ReachabilityResult(
                entrypoint_id="ep1",
                entrypoint_function_id="python:src/test.py:func_a",
                sink_id="sink1",
                call_chain=[],
            )
        ]
        sink = SinkFact(
            type="sink",
            id="sink1",
            call_id="call1",
            category="rce",
            rule_id="R001",
            sink_name="eval",
            severity_base=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            file="src/test.py",
            line=10,
            extractor="test",
        )
        facts: list[Fact] = [sink]

        # Act
        findings = build_finding_facts(reachability, facts)

        # Assert
        assert len(findings) == 1
        assert findings[0].confidence == Confidence.MEDIUM


# ---------------------------------------------------------------------------
# Test class: TestEvidenceContents
# ---------------------------------------------------------------------------


class TestEvidenceContents:
    """Test: evidence field contains entrypoint + sink human-readable descriptions."""

    def test_evidence_contains_entrypoint_and_sink_descriptions(self) -> None:
        # Arrange
        funcs = [
            _make_function("python:src/test.py:func_a"),
        ]
        calls = [
            _make_call("call1", "python:src/test.py:func_a", "dangerous", "eval(user_input)", 5),
        ]
        eps = [
            _make_entrypoint("ep1", "run_tool", "python:src/test.py:func_a"),
        ]
        sinks = [
            _make_sink("sink1", "call1", "rce", "eval", "R001", reason="remote code execution"),
        ]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        # Act
        findings = build_finding_facts(reachability, all_facts)

        # Assert
        assert len(findings) == 1
        evidence = findings[0].evidence
        assert any("run_tool" in e for e in evidence), f"entrypoint not in evidence: {evidence}"
        assert any("eval" in e for e in evidence), f"sink not in evidence: {evidence}"
        assert any("rce" in e or "reason" in e for e in evidence)


# ---------------------------------------------------------------------------
# Test class: TestFindingStatusAlwaysPotential
# ---------------------------------------------------------------------------


class TestFindingStatusAlwaysPotential:
    """Test: status is always FindingStatus.POTENTIAL regardless of input."""

    def test_status_is_always_potential(self) -> None:
        reachability = [
            ReachabilityResult(
                entrypoint_id="ep1",
                entrypoint_function_id="python:src/test.py:func_a",
                sink_id="sink1",
                call_chain=[],
            )
        ]
        sink = SinkFact(
            type="sink",
            id="sink1",
            call_id="call1",
            category="rce",
            rule_id="R001",
            sink_name="eval",
            severity_base=Severity.HIGH,
            confidence=Confidence.HIGH,
            file="src/test.py",
            line=10,
            extractor="test",
        )
        facts: list[Fact] = [sink]

        findings = build_finding_facts(reachability, facts)
        assert len(findings) == 1
        assert findings[0].status == FindingStatus.POTENTIAL


# ---------------------------------------------------------------------------
# Test class: TestBuilderAPI
# ---------------------------------------------------------------------------


class TestBuilderAPI:
    """Test the FinderFactsBuilder class API directly."""

    def test_builder_produces_same_result_as_function_api(self) -> None:
        funcs = [_make_function("python:src/test.py:func_a")]
        calls = [_make_call("call1", "python:src/test.py:func_a", "helper", "helper()", 5)]
        eps = [_make_entrypoint("ep1", "run_tool", "python:src/test.py:func_a")]
        sinks = [_make_sink("sink1", "call1", "rce", "eval", "R001")]

        all_facts: list[Fact] = [*funcs, *calls, *eps, *sinks]
        graph = build_call_graph(all_facts)
        reachability = find_reachable_sinks(eps, sinks, graph)

        findings_fn = build_finding_facts(reachability, all_facts)
        builder = FindingFactsBuilder(all_facts)
        findings_builder = builder.build(reachability)

        assert len(findings_fn) == len(findings_builder) == 1
        assert findings_fn[0].id == findings_builder[0].id
        assert findings_fn[0].category == findings_builder[0].category
