"""Knowledge-assisted pipeline entry point."""

from __future__ import annotations

from pathlib import Path

from detection.core.models import DetectionResult
from detection.core.registry import DetectorRegistry


def run_rag_pipeline(
    target_path: Path,
    registry: DetectorRegistry,
) -> DetectionResult:
    """Placeholder RAG pipeline reserved for Phase 3."""

    raise NotImplementedError("RAG pipeline not yet implemented.")
