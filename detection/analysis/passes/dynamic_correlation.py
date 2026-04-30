"""Dynamic Correlation Pass — correlate static findings with runtime events.

Phase 4 of the analysis pipeline:
- Consumes FindingFact records (POTENTIAL / CONFIRMED status)
- Correlates with RuntimeEventFact records from dynamic analysis
- Upgrades finding status and confidence based on runtime evidence
- Promotes unmatched runtime events to RUNTIME_ONLY findings
"""

from __future__ import annotations

from dataclasses import replace

from analysis.facts.ids import make_finding_id
from analysis.facts.schema import (
    Confidence,
    Fact,
    FindingFact,
    FindingStatus,
    RuntimeEventFact,
    RuntimeEventKind,
    Severity,
)

__all__ = ["correlate_dynamic"]

# ---------------------------------------------------------------------------
# Category → RuntimeEventKind mapping
# ---------------------------------------------------------------------------

_CATEGORY_TO_EVENT_KIND: dict[str, RuntimeEventKind] = {
    "rce": RuntimeEventKind.PROCESS_EXEC,
    "file": RuntimeEventKind.FILE_ACCESS,
    "network": RuntimeEventKind.NETWORK_CONNECT,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _category_from_event(event: RuntimeEventFact) -> str:
    """Map a RuntimeEventKind back to a sink category string."""
    for cat, kind in _CATEGORY_TO_EVENT_KIND.items():
        if kind == event.kind:
            return cat
    return event.kind.value


def _make_runtime_only_finding(event: RuntimeEventFact) -> FindingFact:
    """Create a RUNTIME_ONLY FindingFact from an unmatched RuntimeEventFact."""
    name = f"{event.kind.value}_{event.pid}" if event.pid is not None else event.kind.value
    finding_id = make_finding_id("dynamic", name)

    evidence_text = "Observed in sandbox: "
    if event.command:
        evidence_text += event.command
    elif event.syscall:
        evidence_text += event.syscall
    else:
        evidence_text += event.kind.value

    return FindingFact(
        type="finding",
        id=finding_id,
        file="",
        line=0,
        title=f"Runtime-only: {event.kind.value}",
        category=_category_from_event(event),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        status=FindingStatus.RUNTIME_ONLY,
        entrypoint_id=None,
        sink_id=None,
        call_chain=[],
        dataflows=[],
        dynamic_evidence=[event.id],
        evidence=[evidence_text],
    )


def _build_matched_finding(
    finding: FindingFact,
    event: RuntimeEventFact,
) -> FindingFact:
    """Upgrade a POTENTIAL finding to CONFIRMED with runtime evidence."""
    updated_evidence = list(finding.evidence)
    updated_evidence.append(f"Confirmed by runtime event {event.id}")

    return replace(
        finding,
        status=FindingStatus.CONFIRMED,
        confidence=Confidence.HIGH,
        dynamic_evidence=list(finding.dynamic_evidence) + [event.id],
        evidence=updated_evidence,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def correlate_dynamic(
    findings: list[FindingFact],
    runtime_events: list[RuntimeEventFact],
) -> list[FindingFact]:
    """Correlate static FindingFact records with RuntimeEventFact records.

    Upgrade rules:
        - POTENTIAL finding + matching RuntimeEventFact → CONFIRMED, confidence HIGH
        - RuntimeEventFact with no matching FindingFact → new RUNTIME_ONLY FindingFact

    Unchanged:
        - CONFIRMED findings are returned as-is (already correlated)
        - POTENTIAL findings with no matching runtime event are returned as-is

    Args:
        findings: List of FindingFact records from static analysis.
        runtime_events: List of RuntimeEventFact records from sandbox execution.

    Returns:
        New list of FindingFact with upgraded findings and RUNTIME_ONLY additions.
        The input lists are not modified.
    """
    if not findings and not runtime_events:
        return []

    # Index findings by category for O(n) matching
    findings_by_category: dict[str, list[FindingFact]] = {}
    for f in findings:
        cat = f.category
        if cat not in findings_by_category:
            findings_by_category[cat] = []
        findings_by_category[cat].append(f)

    # Track which runtime events have been matched to avoid duplicate processing
    matched_event_ids: set[str] = set()
    # Track which findings have been upgraded
    upgraded_finding_ids: set[str] = set()

    result: list[FindingFact] = []

    # First pass: upgrade POTENTIAL findings that have matching runtime events
    for event in runtime_events:
        event_kind = event.kind

        # Find the category that maps to this event kind
        matched_category: str | None = None
        for cat, kind in _CATEGORY_TO_EVENT_KIND.items():
            if kind == event_kind:
                matched_category = cat
                break

        if matched_category is None:
            continue

        candidates = findings_by_category.get(matched_category, [])
        for finding in candidates:
            # Skip if already confirmed or already upgraded
            if finding.id in upgraded_finding_ids:
                continue
            if finding.status == FindingStatus.CONFIRMED:
                matched_event_ids.add(event.id)
                continue
            # Only upgrade POTENTIAL findings
            if finding.status != FindingStatus.POTENTIAL:
                continue

            upgraded = _build_matched_finding(finding, event)
            result.append(upgraded)
            upgraded_finding_ids.add(finding.id)
            matched_event_ids.add(event.id)
            break  # One event matches one finding (first match wins)

    # Collect all original findings that were NOT upgraded
    for finding in findings:
        if finding.id not in upgraded_finding_ids:
            result.append(finding)

    # Second pass: promote unmatched runtime events to RUNTIME_ONLY findings
    for event in runtime_events:
        if event.id in matched_event_ids:
            continue

        runtime_only_finding = _make_runtime_only_finding(event)
        result.append(runtime_only_finding)

    return result