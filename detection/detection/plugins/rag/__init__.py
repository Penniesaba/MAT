"""Knowledge-driven enrichment plugins."""

from __future__ import annotations

from detection.core.registry import DetectorRegistry


def register(registry: DetectorRegistry) -> None:
    """Register RAG enrichers during Phase 3."""

    # Implementation will reuse the knowledge service once available.
    pass
