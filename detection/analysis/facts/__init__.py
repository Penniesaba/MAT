"""Security Fact Schema definitions."""

from .schema import (
    CallArg,
    CallKwarg,
    CallResolution,
    Confidence,
    DataFlowFact,
    EntryPointEvidence,
    EntryPointFact,
    EntryPointKind,
    Fact,
    FindingFact,
    FindingStatus,
    FunctionFact,
    ImportFact,
    ImportKind,
    ParamInfo,
    PathStep,
    PathStepKind,
    RuntimeEventFact,
    RuntimeEventKind,
    SCHEMA_VERSION,
    Severity,
    SinkFact,
    SourceFact,
)

__all__ = [
    "SCHEMA_VERSION",
    # Base class
    "Fact",
    # Concrete fact types
    "FunctionFact",
    "ImportFact",
    "EntryPointFact",
    "CallFact",
    "SinkFact",
    "SourceFact",
    "DataFlowFact",
    "RuntimeEventFact",
    "FindingFact",
    # Enums
    "ImportKind",
    "Confidence",
    "Severity",
    "FindingStatus",
    "EntryPointKind",
    "PathStepKind",
    "RuntimeEventKind",
    # Nested structures
    "ParamInfo",
    "CallArg",
    "CallKwarg",
    "CallResolution",
    "EntryPointEvidence",
    "PathStep",
]
