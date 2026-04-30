"""Unit tests for the Dynamic Correlation pass.

Phase 6 of the analysis pipeline.

Covers:
1. POTENTIAL finding + matching RuntimeEventFact → CONFIRMED, dynamic_evidence includes event.id
2. POTENTIAL finding + no matching RuntimeEventFact → stays POTENTIAL
3. RuntimeEventFact with no matching FindingFact → new RUNTIME_ONLY finding
4. Empty findings + runtime events → all become RUNTIME_ONLY
5. Findings + empty runtime events → all stay POTENTIAL
6. Both empty → empty list
7. Already CONFIRMED finding + matching event → unchanged (no re-processing)
8. rce category + PROCESS_EXEC match
9. file category + FILE_ACCESS match
10. network category + NETWORK_CONNECT match
11. CONFIRMED finding's confidence upgraded to HIGH
12. Original input lists not modified (function returns new list)
"""

from __future__ import annotations

from analysis.facts.ids import make_finding_id, make_runtime_event_id
from analysis.facts.schema import (
    Confidence,
    FindingFact,
    FindingStatus,
    RuntimeEventFact,
    RuntimeEventKind,
    Severity,
)
from analysis.passes.dynamic_correlation import correlate_dynamic


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_runtime_event(
    event_id: str = "",
    kind: RuntimeEventKind = RuntimeEventKind.PROCESS_EXEC,
    syscall: str | None = None,
    command: str | None = None,
    pid: int | None = None,
    timestamp: str | None = None,
) -> RuntimeEventFact:
    """Create a RuntimeEventFact for testing."""
    return RuntimeEventFact(
        type="runtime",
        id=event_id or make_runtime_event_id(syscall or "execve", pid or 1),
        file="dynamic",
        line=0,
        extractor="test",
        kind=kind,
        syscall=syscall,
        command=command,
        pid=pid,
        container_id=None,
        timestamp=timestamp,
        correlated_entrypoint=None,
        correlated_sink=None,
        confidence=None,
    )


def _make_finding(
    finding_id: str = "",
    category: str = "rce",
    status: FindingStatus = FindingStatus.POTENTIAL,
    confidence: Confidence = Confidence.MEDIUM,
    severity: Severity = Severity.HIGH,
    dynamic_evidence: list[str] | None = None,
    evidence: list[str] | None = None,
) -> FindingFact:
    """Create a FindingFact for testing."""
    return FindingFact(
        type="finding",
        id=finding_id or make_finding_id(category, "test_finding"),
        file="src/test.py",
        line=10,
        title="Test Finding",
        category=category,
        severity=severity,
        confidence=confidence,
        status=status,
        entrypoint_id=None,
        sink_id=None,
        call_chain=[],
        dataflows=[],
        dynamic_evidence=dynamic_evidence or [],
        evidence=evidence or [],
    )


# ---------------------------------------------------------------------------
# Test: POTENTIAL finding + matching event → CONFIRMED
# ---------------------------------------------------------------------------


class TestPotentialFindingMatchedByEvent:
    """POTENTIAL finding correlated with matching runtime event becomes CONFIRMED."""

    def test_potential_rce_with_process_exec_becomes_confirmed(self) -> None:
        """RCE finding matched by PROCESS_EXEC runtime event → status=CONFIRMED."""
        finding = _make_finding(
            finding_id="finding:rce:test1",
            category="rce",
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.MEDIUM,
        )
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
            command="/bin/sh -c whoami",
        )

        result = correlate_dynamic([finding], [event])

        assert len(result) == 1
        upgraded = result[0]
        assert upgraded.status == FindingStatus.CONFIRMED
        assert upgraded.confidence == Confidence.HIGH
        assert "runtime:bash:12345" in upgraded.dynamic_evidence

    def test_potential_file_with_file_access_becomes_confirmed(self) -> None:
        """file finding matched by FILE_ACCESS runtime event → status=CONFIRMED."""
        finding = _make_finding(
            finding_id="finding:file:test1",
            category="file",
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.MEDIUM,
        )
        event = _make_runtime_event(
            event_id="runtime:cat:12346",
            kind=RuntimeEventKind.FILE_ACCESS,
            syscall="cat",
            pid=12346,
            command="/etc/passwd",
        )

        result = correlate_dynamic([finding], [event])

        assert len(result) == 1
        upgraded = result[0]
        assert upgraded.status == FindingStatus.CONFIRMED
        assert upgraded.confidence == Confidence.HIGH

    def test_potential_network_with_network_connect_becomes_confirmed(self) -> None:
        """network finding matched by NETWORK_CONNECT event → status=CONFIRMED."""
        finding = _make_finding(
            finding_id="finding:network:test1",
            category="network",
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.MEDIUM,
        )
        event = _make_runtime_event(
            event_id="runtime:curl:12347",
            kind=RuntimeEventKind.NETWORK_CONNECT,
            syscall="curl",
            pid=12347,
        )

        result = correlate_dynamic([finding], [event])

        assert len(result) == 1
        upgraded = result[0]
        assert upgraded.status == FindingStatus.CONFIRMED
        assert upgraded.confidence == Confidence.HIGH


# ---------------------------------------------------------------------------
# Test: POTENTIAL finding + no matching event → stays POTENTIAL
# ---------------------------------------------------------------------------


class TestPotentialFindingNoMatch:
    """POTENTIAL finding without a matching runtime event stays POTENTIAL."""

    def test_potential_rce_no_matching_event_stays_potential(self) -> None:
        """RCE finding without PROCESS_EXEC event → stays POTENTIAL."""
        finding = _make_finding(
            finding_id="finding:rce:test1",
            category="rce",
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.MEDIUM,
        )
        # Network event does not match rce category, but still becomes RUNTIME_ONLY
        event = _make_runtime_event(
            event_id="runtime:curl:12347",
            kind=RuntimeEventKind.NETWORK_CONNECT,
            syscall="curl",
            pid=12347,
        )

        result = correlate_dynamic([finding], [event])

        # Result has 2: original RCE finding (stays POTENTIAL) + network event (RUNTIME_ONLY)
        assert len(result) == 2
        rce_finding = next(f for f in result if f.category == "rce")
        assert rce_finding.status == FindingStatus.POTENTIAL
        assert rce_finding.confidence == Confidence.MEDIUM

    def test_potential_file_no_matching_event_stays_potential(self) -> None:
        """file finding without FILE_ACCESS event → stays POTENTIAL."""
        finding = _make_finding(
            finding_id="finding:file:test1",
            category="file",
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.MEDIUM,
        )
        # Process exec event does not match file category, but still becomes RUNTIME_ONLY
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
        )

        result = correlate_dynamic([finding], [event])

        # Result has 2: original file finding (stays POTENTIAL) + process exec event (RUNTIME_ONLY)
        assert len(result) == 2
        file_finding = next(f for f in result if f.category == "file")
        assert file_finding.status == FindingStatus.POTENTIAL


# ---------------------------------------------------------------------------
# Test: Runtime-only events → RUNTIME_ONLY finding
# ---------------------------------------------------------------------------


class TestRuntimeOnlyEvents:
    """RuntimeEventFact with no matching FindingFact becomes RUNTIME_ONLY finding."""

    def test_unmatched_process_exec_becomes_runtime_only(self) -> None:
        """PROCESS_EXEC event with no matching finding → RUNTIME_ONLY finding."""
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
            command="/bin/sh",
        )

        result = correlate_dynamic([], [event])

        assert len(result) == 1
        finding = result[0]
        assert finding.status == FindingStatus.RUNTIME_ONLY
        assert finding.category == "rce"
        assert finding.confidence == Confidence.MEDIUM
        assert "runtime:bash:12345" in finding.dynamic_evidence

    def test_unmatched_file_access_becomes_runtime_only(self) -> None:
        """FILE_ACCESS event with no matching finding → RUNTIME_ONLY finding."""
        event = _make_runtime_event(
            event_id="runtime:cat:12346",
            kind=RuntimeEventKind.FILE_ACCESS,
            syscall="cat",
            pid=12346,
            command="/etc/passwd",
        )

        result = correlate_dynamic([], [event])

        assert len(result) == 1
        finding = result[0]
        assert finding.status == FindingStatus.RUNTIME_ONLY
        assert finding.category == "file"

    def test_unmatched_network_connect_becomes_runtime_only(self) -> None:
        """NETWORK_CONNECT event with no matching finding → RUNTIME_ONLY finding."""
        event = _make_runtime_event(
            event_id="runtime:curl:12347",
            kind=RuntimeEventKind.NETWORK_CONNECT,
            syscall="curl",
            pid=12347,
        )

        result = correlate_dynamic([], [event])

        assert len(result) == 1
        finding = result[0]
        assert finding.status == FindingStatus.RUNTIME_ONLY
        assert finding.category == "network"

    def test_multiple_unmatched_events_create_multiple_runtime_only_findings(
        self,
    ) -> None:
        """Multiple unmatched events produce multiple RUNTIME_ONLY findings."""
        events = [
            _make_runtime_event(
                event_id="runtime:bash:1",
                kind=RuntimeEventKind.PROCESS_EXEC,
                syscall="bash",
                pid=1,
            ),
            _make_runtime_event(
                event_id="runtime:cat:2",
                kind=RuntimeEventKind.FILE_ACCESS,
                syscall="cat",
                pid=2,
            ),
            _make_runtime_event(
                event_id="runtime:curl:3",
                kind=RuntimeEventKind.NETWORK_CONNECT,
                syscall="curl",
                pid=3,
            ),
        ]

        result = correlate_dynamic([], events)

        assert len(result) == 3
        categories = {f.category for f in result}
        assert categories == {"rce", "file", "network"}


# ---------------------------------------------------------------------------
# Test: Empty inputs
# ---------------------------------------------------------------------------


class TestEmptyInputs:
    """Empty or null inputs are handled gracefully."""

    def test_empty_findings_and_empty_events_returns_empty(self) -> None:
        """Both empty → empty list."""
        result = correlate_dynamic([], [])
        assert result == []

    def test_empty_findings_with_runtime_events_returns_runtime_only(self) -> None:
        """Empty findings + runtime events → all become RUNTIME_ONLY."""
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
        )

        result = correlate_dynamic([], [event])

        assert len(result) == 1
        assert result[0].status == FindingStatus.RUNTIME_ONLY

    def test_findings_with_empty_runtime_events_keeps_potential(self) -> None:
        """Findings + empty runtime events → all findings stay POTENTIAL."""
        finding = _make_finding(
            finding_id="finding:rce:test1",
            category="rce",
            status=FindingStatus.POTENTIAL,
        )

        result = correlate_dynamic([finding], [])

        assert len(result) == 1
        assert result[0].status == FindingStatus.POTENTIAL


# ---------------------------------------------------------------------------
# Test: Already CONFIRMED finding unchanged
# ---------------------------------------------------------------------------


class TestConfirmedFindingUnchanged:
    """Already CONFIRMED findings are returned as-is."""

    def test_confirmed_rce_with_matching_event_stays_confirmed(self) -> None:
        """Already CONFIRMED finding + matching event → stays CONFIRMED, no re-processing."""
        finding = _make_finding(
            finding_id="finding:rce:test1",
            category="rce",
            status=FindingStatus.CONFIRMED,
            confidence=Confidence.HIGH,
            dynamic_evidence=["old-event-id"],
        )
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
        )

        result = correlate_dynamic([finding], [event])

        # CONFIRMED finding is returned unchanged; event was matched so no RUNTIME_ONLY created
        confirmed = next(f for f in result if f.id == "finding:rce:test1")
        assert confirmed.status == FindingStatus.CONFIRMED
        # Should not be upgraded again or have duplicate evidence
        assert len(confirmed.dynamic_evidence) == 1
        assert "old-event-id" in confirmed.dynamic_evidence

    def test_confirmed_finding_matching_event_no_runtime_only(self) -> None:
        """A CONFIRMED finding that matches an event should not produce a duplicate RUNTIME_ONLY."""
        event = _make_runtime_event(
            kind=RuntimeEventKind.PROCESS_EXEC, command="ls", pid=100,
        )
        confirmed_finding = _make_finding(
            category="rce", status=FindingStatus.CONFIRMED,
            confidence=Confidence.HIGH,
        )
        result = correlate_dynamic([confirmed_finding], [event])
        # Only the original confirmed finding, no RUNTIME_ONLY
        assert len(result) == 1
        assert result[0].status == FindingStatus.CONFIRMED
        assert result[0].id == confirmed_finding.id

    def test_confirmed_rce_without_matching_event_stays_confirmed(self) -> None:
        """CONFIRMED finding with non-matching event → stays CONFIRMED; event becomes RUNTIME_ONLY."""
        finding = _make_finding(
            finding_id="finding:rce:test1",
            category="rce",
            status=FindingStatus.CONFIRMED,
            confidence=Confidence.HIGH,
        )
        # Network event does not match rce, but still becomes RUNTIME_ONLY
        event = _make_runtime_event(
            event_id="runtime:curl:12347",
            kind=RuntimeEventKind.NETWORK_CONNECT,
            syscall="curl",
            pid=12347,
        )

        result = correlate_dynamic([finding], [event])

        # CONFIRMED stays, network event becomes RUNTIME_ONLY
        confirmed = next(f for f in result if f.id == "finding:rce:test1")
        assert confirmed.status == FindingStatus.CONFIRMED
        runtime_only = next(f for f in result if f.status == FindingStatus.RUNTIME_ONLY)
        assert runtime_only.category == "network"


# ---------------------------------------------------------------------------
# Test: Mixed confirmed and potential findings
# ---------------------------------------------------------------------------


class TestMixedFindingStatuses:
    """Mixture of CONFIRMED and POTENTIAL findings are handled correctly."""

    def test_confirmed_stays_confirmed_potential_gets_upgraded(self) -> None:
        """CONFIRMED stays, POTENTIAL matched by event becomes CONFIRMED."""
        confirmed_finding = _make_finding(
            finding_id="finding:rce:confirmed1",
            category="rce",
            status=FindingStatus.CONFIRMED,
            confidence=Confidence.HIGH,
        )
        potential_finding = _make_finding(
            finding_id="finding:rce:potential1",
            category="rce",
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.MEDIUM,
        )
        events = [
            _make_runtime_event(
                event_id="runtime:bash:12345",
                kind=RuntimeEventKind.PROCESS_EXEC,
                syscall="bash",
                pid=12345,
            ),
        ]

        result = correlate_dynamic([confirmed_finding, potential_finding], events)

        # confirmed stays, potential gets upgraded
        confirmed = next(f for f in result if f.id == "finding:rce:confirmed1")
        potential = next(f for f in result if f.id == "finding:rce:potential1")
        assert confirmed.status == FindingStatus.CONFIRMED
        assert potential.status == FindingStatus.CONFIRMED

    def test_multiple_potential_findings_only_first_matched(self) -> None:
        """When multiple POTENTIAL findings match same event, only first is upgraded."""
        finding_a = _make_finding(
            finding_id="finding:rce:findA",
            category="rce",
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.MEDIUM,
        )
        finding_b = _make_finding(
            finding_id="finding:rce:findB",
            category="rce",
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.MEDIUM,
        )
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
        )

        result = correlate_dynamic([finding_a, finding_b], [event])

        # Only one finding upgraded (first match wins), the other stays POTENTIAL
        upgraded_count = sum(1 for f in result if f.status == FindingStatus.CONFIRMED)
        assert upgraded_count == 1
        potential_count = sum(1 for f in result if f.status == FindingStatus.POTENTIAL)
        assert potential_count == 1


# ---------------------------------------------------------------------------
# Test: Confidence upgrade to HIGH
# ---------------------------------------------------------------------------


class TestConfidenceUpgrade:
    """Matched POTENTIAL findings have their confidence upgraded to HIGH."""

    def test_confirmed_finding_has_confidence_high(self) -> None:
        """Upgraded finding has confidence=HIGH."""
        finding = _make_finding(
            finding_id="finding:rce:test1",
            category="rce",
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.LOW,
        )
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
        )

        result = correlate_dynamic([finding], [event])

        assert len(result) == 1
        assert result[0].confidence == Confidence.HIGH

    def test_confirmed_finding_evidence_includes_runtime_event_id(self) -> None:
        """Upgraded finding's evidence list includes the runtime event confirmation."""
        finding = _make_finding(
            finding_id="finding:rce:test1",
            category="rce",
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.MEDIUM,
            evidence=["original evidence"],
        )
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
        )

        result = correlate_dynamic([finding], [event])

        evidence_texts = result[0].evidence
        assert any("runtime:bash:12345" in e for e in evidence_texts)


# ---------------------------------------------------------------------------
# Test: Input not modified (immutability)
# ---------------------------------------------------------------------------


class TestInputImmutability:
    """correlate_dynamic returns a new list and does not modify inputs."""

    def test_returns_new_list_not_input(self) -> None:
        """Return value is a new list, not the input findings list."""
        findings = [
            _make_finding(
                finding_id="finding:rce:test1",
                category="rce",
                status=FindingStatus.POTENTIAL,
            ),
        ]
        events = [
            _make_runtime_event(
                event_id="runtime:bash:12345",
                kind=RuntimeEventKind.PROCESS_EXEC,
                syscall="bash",
                pid=12345,
            ),
        ]

        result = correlate_dynamic(findings, events)

        assert result is not findings
        assert result is not events

    def test_original_finding_not_modified(self) -> None:
        """Original FindingFact objects are not modified."""
        finding = _make_finding(
            finding_id="finding:rce:test1",
            category="rce",
            status=FindingStatus.POTENTIAL,
            confidence=Confidence.MEDIUM,
            dynamic_evidence=[],
        )
        original_status = finding.status
        original_confidence = finding.confidence
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
        )

        correlate_dynamic([finding], [event])

        # Original finding should be unchanged
        assert finding.status == original_status
        assert finding.confidence == original_confidence

    def test_original_runtime_events_not_modified(self) -> None:
        """Original RuntimeEventFact objects are not modified."""
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
        )

        correlate_dynamic([], [event])

        # Event should be unchanged
        assert event.id == "runtime:bash:12345"
        assert event.kind == RuntimeEventKind.PROCESS_EXEC


# ---------------------------------------------------------------------------
# Test: RUNTIME_ONLY finding structure
# ---------------------------------------------------------------------------


class TestRuntimeOnlyFindingStructure:
    """RUNTIME_ONLY findings have correct structure and metadata."""

    def test_runtime_only_finding_has_title(self) -> None:
        """RUNTIME_ONLY finding has a title starting with 'Runtime-only:'."""
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
        )

        result = correlate_dynamic([], [event])

        assert len(result) == 1
        assert result[0].title.startswith("Runtime-only:")

    def test_runtime_only_finding_has_dynamic_evidence(self) -> None:
        """RUNTIME_ONLY finding's dynamic_evidence includes the event id."""
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
        )

        result = correlate_dynamic([], [event])

        assert "runtime:bash:12345" in result[0].dynamic_evidence

    def test_runtime_only_finding_evidence_contains_command(self) -> None:
        """RUNTIME_ONLY finding's evidence contains the observed command."""
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
            command="/bin/sh -c whoami",
        )

        result = correlate_dynamic([], [event])

        evidence_text = " ".join(result[0].evidence)
        assert "/bin/sh -c whoami" in evidence_text


# ---------------------------------------------------------------------------
# Test: Category to event kind mapping
# ---------------------------------------------------------------------------


class TestCategoryEventKindMapping:
    """The _CATEGORY_TO_EVENT_KIND mapping is correctly applied."""

    def test_rce_category_matches_process_exec(self) -> None:
        """rce category finding is matched by PROCESS_EXEC event."""
        finding = _make_finding(
            finding_id="finding:rce:test1",
            category="rce",
            status=FindingStatus.POTENTIAL,
        )
        event = _make_runtime_event(
            event_id="runtime:execve:99999",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="execve",
            pid=99999,
        )

        result = correlate_dynamic([finding], [event])

        assert len(result) == 1
        assert result[0].status == FindingStatus.CONFIRMED

    def test_file_category_matches_file_access(self) -> None:
        """file category finding is matched by FILE_ACCESS event."""
        finding = _make_finding(
            finding_id="finding:file:test1",
            category="file",
            status=FindingStatus.POTENTIAL,
        )
        event = _make_runtime_event(
            event_id="runtime:open:99999",
            kind=RuntimeEventKind.FILE_ACCESS,
            syscall="open",
            pid=99999,
            command="/etc/shadow",
        )

        result = correlate_dynamic([finding], [event])

        assert len(result) == 1
        assert result[0].status == FindingStatus.CONFIRMED

    def test_network_category_matches_network_connect(self) -> None:
        """network category finding is matched by NETWORK_CONNECT event."""
        finding = _make_finding(
            finding_id="finding:network:test1",
            category="network",
            status=FindingStatus.POTENTIAL,
        )
        event = _make_runtime_event(
            event_id="runtime:connect:99999",
            kind=RuntimeEventKind.NETWORK_CONNECT,
            syscall="connect",
            pid=99999,
        )

        result = correlate_dynamic([finding], [event])

        assert len(result) == 1
        assert result[0].status == FindingStatus.CONFIRMED

    def test_unmatched_category_no_cross_matching(self) -> None:
        """file category finding is NOT matched by PROCESS_EXEC event; both appear in result."""
        finding = _make_finding(
            finding_id="finding:file:test1",
            category="file",
            status=FindingStatus.POTENTIAL,
        )
        event = _make_runtime_event(
            event_id="runtime:bash:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="bash",
            pid=12345,
        )

        result = correlate_dynamic([finding], [event])

        # file finding stays POTENTIAL; process_exec event becomes RUNTIME_ONLY
        assert len(result) == 2
        file_finding = next(f for f in result if f.category == "file")
        assert file_finding.status == FindingStatus.POTENTIAL
        runtime_only = next(f for f in result if f.status == FindingStatus.RUNTIME_ONLY)
        assert runtime_only.category == "rce"