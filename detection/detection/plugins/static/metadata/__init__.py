"""Metadata static analysis plugin for tool descriptions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from detection.core.models import CapabilityFinding, EvidenceSource
from detection.core.registry import DetectorRegistry
from detection.core.session import DetectionSession
from detection.rules import CapabilityRule, IndicatorRule, RuleBook


def register(registry: DetectorRegistry, rulebook: RuleBook) -> None:
    """Register metadata detectors using the shared rulebook."""

    detector = _MetadataRuleDetector(rulebook)
    registry.register_detector("static", detector)


@dataclass
class _MetadataRuleDetector:
    rulebook: RuleBook

    def __post_init__(self) -> None:
        self._rules: Dict[str, CapabilityRule] = self.rulebook.for_language("metadata")

    def __call__(self, session: DetectionSession) -> List[CapabilityFinding]:
        findings: List[CapabilityFinding] = []
        if not self._rules:
            return findings

        records = list(_iter_metadata_records(session.target_path))
        if not records:
            return findings

        for capability in self._rules.values():
            evidence: List[str] = []
            files_with_hits: set[str] = set()
            indicator_boost = 0.0
            used_indicators: set[IndicatorRule] = set()

            for path, content in records:
                for indicator in capability.indicators:
                    if "metadata" not in indicator.languages:
                        continue
                    matches = _match_indicator(content, indicator)
                    if not matches:
                        continue

                    files_with_hits.add(str(path))
                    if indicator not in used_indicators:
                        indicator_boost += indicator.confidence_boost
                        used_indicators.add(indicator)
                    for match in matches:
                        evidence.append(f"{path}:{match}")

            if not evidence:
                continue

            confidence = _compute_confidence(
                base=capability.base_confidence,
                files=len(files_with_hits),
                hits=len(evidence),
                boost=indicator_boost,
            )

            findings.append(
                CapabilityFinding(
                    name=capability.name,
                    description=capability.description,
                    score_weight=capability.weight,
                    confidence=confidence,
                    sources=[EvidenceSource.STATIC],
                    evidence=evidence,
                    metadata={"files": sorted(files_with_hits)},
                )
            )

        return findings


def _iter_metadata_records(root: Path) -> Iterable[Tuple[Path, str]]:
    for path in root.rglob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        content = data.get("tool_content")
        if isinstance(content, str) and content.strip():
            yield path, content


def _match_indicator(text: str, indicator: IndicatorRule) -> List[str]:
    matches: List[str] = []
    if indicator.type == "keyword":
        haystack = text if indicator.case_sensitive else text.lower()
        for pattern in indicator.patterns:
            needle = pattern if indicator.case_sensitive else pattern.lower()
            if needle in haystack:
                matches.append(pattern.strip())
    elif indicator.type == "regex" and indicator.pattern:
        import re

        flags = 0 if indicator.case_sensitive else re.IGNORECASE
        compiled = re.compile(indicator.pattern, flags)
        for match in compiled.finditer(text):
            snippet = match.group(0)
            matches.append(snippet.strip())
    return matches


def _compute_confidence(*, base: float, files: int, hits: int, boost: float) -> float:
    confidence = base + 0.1 * files + 0.05 * max(0, hits - files) + boost
    return min(confidence, 0.99)
