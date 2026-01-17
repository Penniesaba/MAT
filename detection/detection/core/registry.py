"""Registry that keeps track of available detector plugins."""

from __future__ import annotations

from collections import defaultdict
from typing import Callable, Dict, List, Protocol

from .models import CapabilityFinding, DetectionResult
from .session import DetectionSession


class Detector(Protocol):
    """Protocol each detector implementation must satisfy."""

    def __call__(self, session: DetectionSession) -> List[CapabilityFinding]:
        """Execute the detector and return normalized capability findings."""


class ReportRenderer(Protocol):
    """Protocol for rendering finished detection results."""

    def __call__(self, result: DetectionResult) -> str:
        """Render a detection result into a string."""


class DetectorRegistry:
    """Simple registry for detectors, renderers, and other plugin hooks."""

    def __init__(self) -> None:
        self._detectors: Dict[str, List[Detector]] = defaultdict(list)
        self._renderers: Dict[str, ReportRenderer] = {}

    def register_detector(self, category: str, detector: Detector) -> None:
        """Register a detector under a capability category."""

        self._detectors[category].append(detector)

    def detectors_for(self, category: str) -> List[Detector]:
        """Return all detectors belonging to a category."""

        return list(self._detectors.get(category, []))

    def register_renderer(self, name: str, renderer: ReportRenderer) -> None:
        """Register a renderer by name."""

        self._renderers[name] = renderer

    def renderer(self, name: str) -> ReportRenderer:
        """Retrieve a previously registered renderer."""

        return self._renderers[name]
