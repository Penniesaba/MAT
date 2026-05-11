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


def _extract_sink_filename(finding: FindingFact) -> str | None:
    """Extract the filename portion from a finding's file path.

    Used for ustack归因: checks if the sink filename appears in a runtime event's ustack.
    """
    if not finding.file:
        return None
    import os

    return os.path.basename(finding.file)


def _target_path_overlaps(finding: FindingFact, event: RuntimeEventFact) -> bool:
    """Check if event.target_path overlaps with any sink_args.expr in the finding's call_chain.

    Returns True if there's any overlap between the target path and the call chain's
    sink argument expressions.
    """
    if not event.target_path:
        return False

    target = event.target_path.lower()

    for link in finding.call_chain:
        if not isinstance(link, dict):
            continue
        # Look for sink_args in the call chain link
        sink_args = link.get("sink_args")
        if not sink_args:
            continue
        if not isinstance(sink_args, list):
            continue
        for arg in sink_args:
            if isinstance(arg, dict) and "expr" in arg:
                expr = str(arg["expr"]).lower()
                if expr and expr in target:
                    return True
    return False


def _match_precision(finding: FindingFact, event: RuntimeEventFact) -> str:
    """Determine match precision between a finding and a runtime event.

    Returns:
        "exact"  - ustack归因 or target_path match (high confidence)
        "category" - only category match (medium confidence)

    Level 1 (exact): category + ustack归因 or target_path match
        - ustack归因: event.ustack contains the sink filename from finding.file
        - target_path: event.target_path overlaps with sink_args in finding's call_chain

    Level 2 (category): only category matches
    """
    # Check exact match criteria
    sink_filename = _extract_sink_filename(finding)

    # ustack归因: event.ustack contains sink filename
    if event.ustack and sink_filename:
        for frame in event.ustack:
            if sink_filename in frame:
                return "exact"

    # target_path matching
    if _target_path_overlaps(finding, event):
        return "exact"

    # Fall back to category-only match
    return "category"


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
    match_level: str,
) -> FindingFact:
    """Upgrade a POTENTIAL finding to CONFIRMED with runtime evidence.

    Args:
        finding: The original finding to upgrade.
        event: The runtime event that confirmed this finding.
        match_level: "exact" or "category" — determines confidence level.
    """
    updated_evidence = list(finding.evidence)

    # Add match level info
    match_label = "exact" if match_level == "exact" else "category"
    updated_evidence.append(f"Matched by runtime event {event.id} (level={match_label})")

    # Add ustack归因 info if available
    if event.ustack and match_level == "exact":
        sink_filename = _extract_sink_filename(finding)
        if sink_filename:
            for frame in event.ustack:
                if sink_filename in frame:
                    updated_evidence.append(f"ustack归因: {frame}")
                    break

    # Add target_path info if available
    if event.target_path and match_level == "exact":
        updated_evidence.append(f"target_path: {event.target_path}")

    # Add command_args if available
    if event.command_args:
        args_str = " ".join(str(a) for a in event.command_args)
        updated_evidence.append(f"command_args: {args_str}")

    # Determine confidence based on match level
    # "exact" match gets HIGH; "category" match also gets HIGH for backward compat
    # but exact matches have richer evidence for human review
    confidence = Confidence.HIGH

    return replace(
        finding,
        status=FindingStatus.CONFIRMED,
        confidence=confidence,
        dynamic_evidence=list(finding.dynamic_evidence) + [event.id],
        evidence=updated_evidence,
    )


# ---------------------------------------------------------------------------
# Severity escalation for behavior combinations
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _escalate_severity(severity: Severity) -> Severity:
    """Escalate severity by one level if possible."""
    try:
        idx = _SEVERITY_ORDER.index(severity)
        if idx < len(_SEVERITY_ORDER) - 1:
            return _SEVERITY_ORDER[idx + 1]
    except ValueError:
        pass
    return severity


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def correlate_dynamic(
    findings: list[FindingFact],
    runtime_events: list[RuntimeEventFact],
) -> list[FindingFact]:
    """Correlate static FindingFact records with RuntimeEventFact records.

    Upgrade rules:
        - POTENTIAL finding + exact match (ustack归因 or target_path) → CONFIRMED, confidence HIGH
        - POTENTIAL finding + category match only → CONFIRMED, confidence MEDIUM
        - RuntimeEventFact with no matching FindingFact → new RUNTIME_ONLY FindingFact
        - Finding with ≥2 different event categories → severity escalation

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
    # Track which findings have been upgraded and their matched event categories
    upgraded_finding_info: dict[str, tuple[FindingFact, set[str]]] = {}  # finding_id -> (upgraded_finding, matched_categories)

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
            # Skip if already confirmed (from input) or already upgraded
            prev_upgraded = upgraded_finding_info.get(finding.id)
            if prev_upgraded is not None:
                # Already upgraded in this pass — add this event's category
                existing_finding, existing_cats = prev_upgraded
                if event_kind.value not in existing_cats:
                    new_cats = existing_cats | {event_kind.value}
                    upgraded_finding_info[finding.id] = (existing_finding, new_cats)
                matched_event_ids.add(event.id)
                continue
            if finding.status == FindingStatus.CONFIRMED:
                matched_event_ids.add(event.id)
                continue
            # Only upgrade POTENTIAL findings
            if finding.status != FindingStatus.POTENTIAL:
                continue

            # Determine match precision
            match_level = _match_precision(finding, event)

            upgraded = _build_matched_finding(finding, event, match_level)
            matched_categories = {event_kind.value}
            upgraded_finding_info[finding.id] = (upgraded, matched_categories)
            matched_event_ids.add(event.id)
            break  # One event matches one finding (first match wins)

    # Collect all original findings that were NOT upgraded
    for finding in findings:
        if finding.id not in upgraded_finding_info:
            result.append(finding)

    # Second pass: promote unmatched runtime events to RUNTIME_ONLY findings
    for event in runtime_events:
        if event.id in matched_event_ids:
            continue

        runtime_only_finding = _make_runtime_only_finding(event)
        result.append(runtime_only_finding)

    # Third pass: apply severity escalation for behavior combinations
    # If a finding was correlated with ≥2 different event categories, escalate severity
    for finding_id, (upgraded_finding, matched_categories) in upgraded_finding_info.items():
        if len(matched_categories) >= 2:
            escalated_severity = _escalate_severity(upgraded_finding.severity)
            if escalated_severity != upgraded_finding.severity:
                # Update evidence with severity escalation note
                updated_evidence = list(upgraded_finding.evidence)
                updated_evidence.append(
                    f"severity_escalation: {len(matched_categories)} behavior types "
                    f"({', '.join(sorted(matched_categories))}) → {upgraded_finding.severity.value}→{escalated_severity.value}"
                )
                escalated_finding = replace(
                    upgraded_finding,
                    severity=escalated_severity,
                    evidence=updated_evidence,
                )
                # Replace in result
                for i, f in enumerate(result):
                    if f.id == finding_id:
                        result[i] = escalated_finding
                        break
        else:
            # Add the upgraded finding to result
            result.append(upgraded_finding)

    return result