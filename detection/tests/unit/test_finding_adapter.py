"""Unit tests for finding_adapter module."""

from __future__ import annotations

import pytest

from analysis.adapters.finding_adapter import (
    adapt_findings,
    finding_to_capability,
    SEVERITY_SCORE_WEIGHTS,
    CONFIDENCE_SCORES,
)
from detection.core.models import CapabilityFinding, EvidenceSource
from analysis.facts.schema import (
    Confidence,
    FindingFact,
    FindingStatus,
    Severity,
)


class TestFindingToCapability:
    """Tests for finding_to_capability function."""

    def test_basic_conversion(self) -> None:
        """Test basic FindingFact to CapabilityFinding conversion."""
        finding = FindingFact(
            type="test",
            id="finding-001",
            file="test.py",
            line=42,
            title="SQL Injection",
            category="injection",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            evidence=["line 42: query.execute(user_input)"],
        )

        result = finding_to_capability(finding)

        assert isinstance(result, CapabilityFinding)
        assert result.name == "SQL Injection"
        assert "injection" in result.description
        assert result.score_weight == SEVERITY_SCORE_WEIGHTS[Severity.HIGH]
        assert result.confidence == CONFIDENCE_SCORES[Confidence.HIGH]
        assert EvidenceSource.STATIC in result.sources

    def test_severity_mapping_critical(self) -> None:
        """Test CRITICAL severity maps to correct score_weight."""
        finding = self._make_finding(severity=Severity.CRITICAL)
        result = finding_to_capability(finding)
        assert result.score_weight == 1.0

    def test_severity_mapping_high(self) -> None:
        """Test HIGH severity maps to correct score_weight."""
        finding = self._make_finding(severity=Severity.HIGH)
        result = finding_to_capability(finding)
        assert result.score_weight == 0.75

    def test_severity_mapping_medium(self) -> None:
        """Test MEDIUM severity maps to correct score_weight."""
        finding = self._make_finding(severity=Severity.MEDIUM)
        result = finding_to_capability(finding)
        assert result.score_weight == 0.5

    def test_severity_mapping_low(self) -> None:
        """Test LOW severity maps to correct score_weight."""
        finding = self._make_finding(severity=Severity.LOW)
        result = finding_to_capability(finding)
        assert result.score_weight == 0.25

    def test_confidence_mapping_high(self) -> None:
        """Test HIGH confidence maps to correct float value."""
        finding = self._make_finding(confidence=Confidence.HIGH)
        result = finding_to_capability(finding)
        assert result.confidence == 1.0

    def test_confidence_mapping_medium(self) -> None:
        """Test MEDIUM confidence maps to correct float value."""
        finding = self._make_finding(confidence=Confidence.MEDIUM)
        result = finding_to_capability(finding)
        assert result.confidence == 0.6

    def test_confidence_mapping_low(self) -> None:
        """Test LOW confidence maps to correct float value."""
        finding = self._make_finding(confidence=Confidence.LOW)
        result = finding_to_capability(finding)
        assert result.confidence == 0.3

    def test_sources_include_static(self) -> None:
        """Test that sources includes EvidenceSource.STATIC."""
        finding = self._make_finding()
        result = finding_to_capability(finding)
        assert EvidenceSource.STATIC in result.sources

    def test_evidence_preserved(self) -> None:
        """Test that evidence from FindingFact is preserved."""
        evidence = ["line 10: dangerous_call()", "line 20: another_call()"]
        finding = self._make_finding(evidence=evidence)
        result = finding_to_capability(finding)
        assert result.evidence == evidence
        assert len(result.evidence) == 2

    def test_metadata_finding_id(self) -> None:
        """Test that metadata contains finding_id."""
        finding = self._make_finding(id="finding-123")
        result = finding_to_capability(finding)
        assert result.metadata["finding_id"] == "finding-123"

    def test_metadata_entrypoint_id(self) -> None:
        """Test that metadata contains entrypoint_id when present."""
        finding = self._make_finding(entrypoint_id="ep-456")
        result = finding_to_capability(finding)
        assert result.metadata["entrypoint_id"] == "ep-456"

    def test_metadata_sink_id(self) -> None:
        """Test that metadata contains sink_id when present."""
        finding = self._make_finding(sink_id="sink-789")
        result = finding_to_capability(finding)
        assert result.metadata["sink_id"] == "sink-789"

    def test_metadata_status(self) -> None:
        """Test that metadata contains status value."""
        finding = self._make_finding(status=FindingStatus.POTENTIAL)
        result = finding_to_capability(finding)
        assert result.metadata["status"] == "potential"

    def test_metadata_category(self) -> None:
        """Test that metadata contains category."""
        finding = self._make_finding(category="command injection")
        result = finding_to_capability(finding)
        assert result.metadata["category"] == "command injection"

    def test_metadata_complete(self) -> None:
        """Test that all required metadata fields are present."""
        finding = FindingFact(
            type="test",
            id="finding-full",
            file="app.py",
            line=100,
            title="Full Test",
            category="test-category",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            status=FindingStatus.CONFIRMED,
            entrypoint_id="ep-test",
            sink_id="sink-test",
            evidence=["test evidence"],
        )
        result = finding_to_capability(finding)

        required_keys = {"finding_id", "entrypoint_id", "sink_id", "status", "category"}
        assert required_keys.issubset(result.metadata.keys())

    def test_name_has_semantic_content(self) -> None:
        """Test that name is not empty and has semantic meaning."""
        finding = self._make_finding(title="Command Injection Detected")
        result = finding_to_capability(finding)
        assert result.name
        assert len(result.name) > 0

    def test_description_has_semantic_content(self) -> None:
        """Test that description is not empty and has semantic meaning."""
        finding = self._make_finding(title="Test", category="injection")
        result = finding_to_capability(finding)
        assert result.description
        assert len(result.description) > 0

    def test_name_fallback_when_no_title(self) -> None:
        """Test that name is derived from category when title is empty."""
        finding = self._make_finding(title="", category="sql injection")
        result = finding_to_capability(finding)
        assert result.name == "Sql injection Finding"

    def _make_finding(
        self,
        id: str = "test-finding",
        severity: Severity = Severity.MEDIUM,
        confidence: Confidence = Confidence.HIGH,
        status: FindingStatus = FindingStatus.POTENTIAL,
        evidence: list[str] | None = None,
        entrypoint_id: str | None = None,
        sink_id: str | None = None,
        title: str = "Test Finding",
        category: str = "test",
    ) -> FindingFact:
        """Helper to create a FindingFact for testing."""
        return FindingFact(
            type="test",
            id=id,
            file="test.py",
            line=1,
            title=title,
            category=category,
            severity=severity,
            confidence=confidence,
            status=status,
            entrypoint_id=entrypoint_id,
            sink_id=sink_id,
            evidence=evidence or ["test evidence"],
        )


class TestAdaptFindings:
    """Tests for adapt_findings function."""

    def test_empty_list(self) -> None:
        """Test that empty list returns empty list."""
        result = adapt_findings([])
        assert result == []

    def test_single_finding(self) -> None:
        """Test adapting a single finding."""
        finding = FindingFact(
            type="test",
            id="single",
            file="test.py",
            line=1,
            title="Single",
            category="test",
        )
        result = adapt_findings([finding])
        assert len(result) == 1
        assert isinstance(result[0], CapabilityFinding)

    def test_multiple_findings(self) -> None:
        """Test adapting multiple findings."""
        findings = [
            FindingFact(
                type="test",
                id=f"finding-{i}",
                file="test.py",
                line=i,
                title=f"Finding {i}",
                category="test",
            )
            for i in range(3)
        ]
        result = adapt_findings(findings)
        assert len(result) == 3
        assert all(isinstance(f, CapabilityFinding) for f in result)
        assert result[0].name == "Finding 0"
        assert result[1].name == "Finding 1"
        assert result[2].name == "Finding 2"