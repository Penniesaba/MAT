"""Shared data structures describing capabilities and detection results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Mapping, Optional


class EvidenceSource(str, Enum):
    """Different evidence origins used throughout the detection workflow."""

    STATIC = "static"
    DYNAMIC = "dynamic"
    KNOWLEDGE = "knowledge"
    MANUAL = "manual"


@dataclass(slots=True)
class CapabilityFinding:
    """Normalized finding describing a capability observed in a server."""

    name: str
    description: str
    score_weight: float
    confidence: float
    sources: List[EvidenceSource] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class DetectionResult:
    """Aggregated detection output used for reporting and mitigation."""

    server_name: str
    findings: List[CapabilityFinding]
    total_score: float
    risk_level: str
    mitigations: List[str] = field(default_factory=list)
    notes: Optional[str] = None
