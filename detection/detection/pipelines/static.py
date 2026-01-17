"""Static analysis pipeline connecting detectors, scoring, and mitigation."""

from __future__ import annotations

from pathlib import Path
from typing import List

from detection.core.models import CapabilityFinding, DetectionResult, EvidenceSource
from detection.core.registry import DetectorRegistry
from detection.core.session import DetectionSession
from detection.mitigation import MitigationEngine


def run_static_pipeline(
    target_path: Path,
    registry: DetectorRegistry,
    policy_dir: Path,
) -> DetectionResult:
    """Execute registered static detectors and compile a detection result."""

    session = DetectionSession(target_path=target_path, config={"pipeline": "static"})
    findings: List[CapabilityFinding] = []
    for detector in registry.detectors_for("static"):
        detector_findings = detector(session)
        for finding in detector_findings:
            if EvidenceSource.STATIC not in finding.sources:
                finding.sources.append(EvidenceSource.STATIC)
        session.add_findings(detector_findings)
        findings.extend(detector_findings)

    score = sum(f.score_weight * f.confidence for f in findings)
    risk_level = _score_to_risk_level(score)
    engine = MitigationEngine(policy_dir=policy_dir)
    mitigations = engine.recommendations(findings)

    return DetectionResult(
        server_name=target_path.name,
        findings=findings,
        total_score=score,
        risk_level=risk_level,
        mitigations=mitigations,
    )


def _score_to_risk_level(score: float) -> str:
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"
