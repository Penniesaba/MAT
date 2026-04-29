"""Security Fact Schema for AST-based detection framework.

This module defines all dataclass models for security facts extracted from
source code, AST analysis, and runtime instrumentation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


SCHEMA_VERSION = "1.0.0"


class ImportKind(str, Enum):
    """Kind of import statement."""

    IMPORT = "import"
    IMPORT_AS = "import_as"
    FROM_IMPORT = "from_import"
    FROM_IMPORT_AS = "from_import_as"
    REQUIRE = "require"
    REQUIRE_DESTRUCTURE = "require_destructure"
    ESM_IMPORT = "esm_import"
    ESM_IMPORT_AS = "esm_import_as"
    ESM_NAMED_IMPORT = "esm_named_import"


class Confidence(str, Enum):
    """Confidence level for facts."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(str, Enum):
    """Severity level for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, Enum):
    """Status of a finding."""

    POTENTIAL = "potential"
    CONFIRMED = "confirmed"
    RUNTIME_ONLY = "runtime_only"


class EntryPointKind(str, Enum):
    """Kind of MCP entry point."""

    MCP_TOOL = "mcp_tool"
    MCP_RESOURCE = "mcp_resource"
    MCP_PROMPT = "mcp_prompt"


class PathStepKind(str, Enum):
    """Kind of data flow path step."""

    PARAM = "param"
    ASSIGN = "assign"
    RETURN = "return"
    CALL_ARG = "call_arg"
    FIELD_ACCESS = "field_access"


class RuntimeEventKind(str, Enum):
    """Kind of runtime event observed during dynamic analysis."""

    PROCESS_EXEC = "process_exec"
    FILE_ACCESS = "file_access"
    NETWORK_CONNECT = "network_connect"


# ----------------------------------------------------------------------
# Nested Supporting Structures
# ----------------------------------------------------------------------


@dataclass(slots=True)
class ParamInfo:
    """Information about a function parameter."""

    name: str
    annotation: str | None = None
    default: str | None = None


@dataclass(slots=True)
class CallArg:
    """A positional argument in a function call."""

    index: int
    expr: str
    kind: str  # "name", "literal", "attribute", etc.


@dataclass(slots=True)
class CallKwarg:
    """A keyword argument in a function call."""

    expr: str
    value: Any  # Python literal: bool, str, int, None, etc.


@dataclass(slots=True)
class CallResolution:
    """Resolution information for a called function."""

    import_alias: str | None = None
    confidence: Confidence = Confidence.HIGH


@dataclass(slots=True)
class EntryPointEvidence:
    """Evidence of an entry point definition."""

    kind: str  # "decorator", "call_registration"
    text: str


@dataclass(slots=True)
class PathStep:
    """A single step in a data flow path."""

    kind: PathStepKind
    line: int
    name: str | None = None  # for param
    function: str | None = None  # for param
    from_: str | None = None  # for assign (using from_ to avoid Python keyword)
    to: str | None = None  # for assign
    snippet: str | None = None  # for assign
    call_id: str | None = None  # for call_arg
    arg_index: int | None = None  # for call_arg


# ----------------------------------------------------------------------
# Base Fact
# ----------------------------------------------------------------------


@dataclass(slots=True)
class Fact:
    """Base class for all security facts."""

    type: str
    id: str
    file: str
    line: int
    extractor: str = ""


# ----------------------------------------------------------------------
# Concrete Fact Types
# ----------------------------------------------------------------------


@dataclass(slots=True)
class FunctionFact(Fact):
    """Represents a callable unit: function, method, or anonymous handler."""

    language: str = ""
    name: str = ""
    qualified_name: str = ""
    end_line: int = 0
    params: list[ParamInfo] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    docstring: str | None = None
    enclosing_class: str | None = None


@dataclass(slots=True)
class ImportFact(Fact):
    """Represents an import relationship, used for symbol resolution."""

    language: str = ""
    module: str = ""
    imported_name: str | None = None
    alias: str | None = None
    kind: ImportKind = ImportKind.IMPORT


@dataclass(slots=True)
class EntryPointFact(Fact):
    """Represents an MCP exposed entry point."""

    kind: EntryPointKind = EntryPointKind.MCP_TOOL
    name: str = ""
    function_id: str = ""
    evidence: EntryPointEvidence | None = None
    params: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.HIGH


@dataclass(slots=True)
class CallFact(Fact):
    """Represents a function call with evidence about the invocation."""

    caller: str = ""
    callee: str = ""
    normalized_callee: str | None = None
    column: int | None = None
    end_line: int | None = None
    snippet: str = ""
    args: list[CallArg] = field(default_factory=list)
    kwargs: Mapping[str, CallKwarg] = field(default_factory=dict)
    resolution: CallResolution | None = None


@dataclass(slots=True)
class SinkFact(Fact):
    """Represents a sensitive or dangerous function matched by a rule."""

    call_id: str = ""
    category: str = ""
    rule_id: str = ""
    sink_name: str = ""
    severity_base: Severity = Severity.MEDIUM
    reason: str = ""
    conditions: Mapping[str, Any] = field(default_factory=dict)
    confidence: Confidence = Confidence.HIGH


@dataclass(slots=True)
class SourceFact(Fact):
    """Represents an untrusted input source."""

    kind: str = ""
    function_id: str = ""
    name: str = ""
    confidence: Confidence = Confidence.HIGH


@dataclass(slots=True)
class DataFlowFact(Fact):
    """Represents a data flow path from source to sink."""

    source_id: str = ""
    sink_id: str = ""
    path: list[PathStep] = field(default_factory=list)
    confidence: Confidence = Confidence.HIGH


@dataclass(slots=True)
class RuntimeEventFact(Fact):
    """Represents evidence from dynamic testing."""

    kind: RuntimeEventKind = RuntimeEventKind.PROCESS_EXEC
    syscall: str | None = None
    command: str | None = None
    pid: int | None = None
    container_id: str | None = None
    timestamp: str | None = None
    correlated_entrypoint: str | None = None
    correlated_sink: str | None = None
    confidence: Confidence | None = None


@dataclass(slots=True)
class FindingFact(Fact):
    """Represents a final risk conclusion with correlated evidence."""

    title: str = ""
    category: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.HIGH
    status: FindingStatus = FindingStatus.POTENTIAL
    entrypoint_id: str | None = None
    sink_id: str | None = None
    call_chain: list[Mapping[str, Any]] = field(default_factory=list)
    dataflows: list[str] = field(default_factory=list)
    dynamic_evidence: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommendation: str | None = None
