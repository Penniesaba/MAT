"""Adapter for converting FindingFact to CapabilityFinding."""

from __future__ import annotations

from detection.core.models import CapabilityFinding, EvidenceSource
from analysis.facts.schema import Confidence, FindingFact, FindingStatus, Severity

# ----------------------------------------------------------------------
# Mapping Constants
# ----------------------------------------------------------------------

SEVERITY_SCORE_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
}

CONFIDENCE_SCORES: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.6,
    Confidence.LOW: 0.3,
}

DEFAULT_SOURCES: list[EvidenceSource] = [EvidenceSource.STATIC]


# ----------------------------------------------------------------------
# Core Adapter
# ----------------------------------------------------------------------


def finding_to_capability(finding: FindingFact) -> CapabilityFinding:
    """Convert a FindingFact to a CapabilityFinding for reporting.

    Args:
        finding: The FindingFact to convert.

    Returns:
        A CapabilityFinding with mapped fields and preserved evidence.
    """
    score_weight = SEVERITY_SCORE_WEIGHTS.get(finding.severity, 0.5)
    confidence = CONFIDENCE_SCORES.get(finding.confidence, 0.6)

    name = _derive_name(finding)
    description = _derive_description(finding)

    metadata = _build_metadata(finding)

    return CapabilityFinding(
        name=name,
        description=description,
        score_weight=score_weight,
        confidence=confidence,
        sources=DEFAULT_SOURCES.copy(),
        evidence=finding.evidence.copy(),
        metadata=metadata,
    )


def adapt_findings(findings: list[FindingFact]) -> list[CapabilityFinding]:
    """Convert a list of FindingFacts to CapabilityFindings.

    Args:
        findings: List of FindingFacts to convert.

    Returns:
        List of CapabilityFindings.
    """
    return [finding_to_capability(f) for f in findings]


# ----------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------


def _derive_name(finding: FindingFact) -> str:
    """Derive a readable name from the FindingFact."""
    if finding.title:
        return finding.title

    category = finding.category or "unknown"
    return f"{category.capitalize()} Finding"


def _derive_description(finding: FindingFact) -> str:
    """Derive a readable description from the FindingFact."""
    parts: list[str] = []

    if finding.category:
        parts.append(f"Category: {finding.category}")

    if finding.recommendation:
        parts.append(f"Recommendation: {finding.recommendation}")

    if not parts:
        return f"Security finding in {finding.file} at line {finding.line}"

    return " | ".join(parts)


def _build_metadata(finding: FindingFact) -> dict[str, str]:
    """Build metadata dict from FindingFact fields."""
    metadata: dict[str, str] = {
        "finding_id": finding.id,
        "status": finding.status.value,
        "category": finding.category or "",
    }

    if finding.entrypoint_id:
        metadata["entrypoint_id"] = finding.entrypoint_id

    if finding.sink_id:
        metadata["sink_id"] = finding.sink_id

    return metadata