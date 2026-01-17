"""Shared session context passed to detectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .models import CapabilityFinding


@dataclass(slots=True)
class DetectionSession:
    """Context object storing configuration and intermediate results."""

    target_path: Path
    config: Dict[str, object] = field(default_factory=dict)
    findings: List[CapabilityFinding] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)

    def add_findings(self, findings: List[CapabilityFinding]) -> None:
        """Append new findings and keep a global record."""

        self.findings.extend(findings)

    def get(self, key: str, default: Optional[object] = None) -> Optional[object]:
        """Retrieve a configuration or metadata value."""

        if key in self.config:
            return self.config[key]
        return self.metadata.get(key, default)
