"""Python static analysis plugin based on configuration-driven indicators."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from detection.core.models import CapabilityFinding, EvidenceSource
from detection.core.registry import DetectorRegistry
from detection.core.session import DetectionSession
from detection.rules import CapabilityRule, IndicatorRule, RuleBook


def register(registry: DetectorRegistry, rulebook: RuleBook) -> None:
    """Register Python static detectors with the shared registry."""

    detector = _PythonRuleDetector(rulebook)
    registry.register_detector("static", detector)


@dataclass
class _PythonRuleDetector:
    rulebook: RuleBook

    def __post_init__(self) -> None:
        self._rules: Dict[str, CapabilityRule] = self.rulebook.for_language("python")

    def __call__(self, session: DetectionSession) -> List[CapabilityFinding]:
        findings: List[CapabilityFinding] = []
        if not self._rules:
            return findings

        file_texts = {
            path: text
            for path in _iter_python_files(session.target_path)
            if (text := _safe_read(path)) is not None
        }

        if not file_texts:
            return findings

        for capability in self._rules.values():
            evidence: List[str] = []
            files_with_hits: set[str] = set()
            indicator_boost = 0.0
            used_indicators: set[IndicatorRule] = set()

            for path, text in file_texts.items():
                for indicator in capability.indicators:
                    if "python" not in indicator.languages:
                        continue
                    matches = _match_indicator(text, indicator)
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


def _iter_python_files(root: Path):
    return root.rglob("*.py")


def _safe_read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _match_indicator(text: str, indicator: IndicatorRule) -> List[str]:
    matches: List[str] = []
    if indicator.type == "keyword":
        haystack = text if indicator.case_sensitive else text.lower()
        for pattern in indicator.patterns:
            needle = pattern if indicator.case_sensitive else pattern.lower()
            if needle in haystack:
                matches.append(pattern.strip())
    elif indicator.type == "regex" and indicator.pattern:
        flags = 0 if indicator.case_sensitive else re.IGNORECASE
        compiled = re.compile(indicator.pattern, flags)
        for match in compiled.finditer(text):
            snippet = match.group(0)
            matches.append(snippet.strip())
    return matches


def _compute_confidence(*, base: float, files: int, hits: int, boost: float) -> float:
    confidence = base + 0.1 * files + 0.05 * max(0, hits - files) + boost
    return min(confidence, 0.99)
