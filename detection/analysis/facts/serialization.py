"""Serialization for AST Security Analysis Facts.

Supports JSON and JSONL format with full roundtrip preservation.
"""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import Any, get_origin

from .schema import (
    SCHEMA_VERSION,
    Fact,
    FunctionFact,
    ImportFact,
    EntryPointFact,
    CallFact,
    SinkFact,
    SourceFact,
    DataFlowFact,
    RuntimeEventFact,
    FindingFact,
    ParamInfo,
    CallArg,
    CallKwarg,
    CallResolution,
    EntryPointEvidence,
    PathStep,
    ImportKind,
    Confidence,
    Severity,
    FindingStatus,
    EntryPointKind,
    PathStepKind,
    RuntimeEventKind,
)


# Type dispatch map for deserialization
_FACT_TYPES: dict[str, type[Fact]] = {
    "function": FunctionFact,
    "import": ImportFact,
    "entrypoint": EntryPointFact,
    "call": CallFact,
    "sink": SinkFact,
    "source": SourceFact,
    "dataflow": DataFlowFact,
    "runtime_event": RuntimeEventFact,
    "finding": FindingFact,
}

# Nested dataclass types that need reconstruction
_NESTED_TYPES: dict[str, type] = {
    "ParamInfo": ParamInfo,
    "CallArg": CallArg,
    "CallKwarg": CallKwarg,
    "CallResolution": CallResolution,
    "EntryPointEvidence": EntryPointEvidence,
    "PathStep": PathStep,
}

# Enum types for reconstruction
_ENUM_TYPES: dict[str, type[Enum]] = {
    "ImportKind": ImportKind,
    "Confidence": Confidence,
    "Severity": Severity,
    "FindingStatus": FindingStatus,
    "EntryPointKind": EntryPointKind,
    "PathStepKind": PathStepKind,
    "RuntimeEventKind": RuntimeEventKind,
}

# Map of field names that differ between Python and JSON
_FIELD_NAME_MAP: dict[str, str] = {
    "from_": "from",
}

# Explicit mapping of (FactClass, field_name) → enum type for reconstruction
# This bypasses PEP 563 string annotation issue with fields(cls).type
_FACT_ENUM_FIELDS: dict[tuple[str, str], type[Enum]] = {
    # ImportFact
    ("ImportFact", "kind"): ImportKind,
    # EntryPointFact
    ("EntryPointFact", "kind"): EntryPointKind,
    ("EntryPointFact", "confidence"): Confidence,
    # CallResolution (nested in CallFact)
    ("CallResolution", "confidence"): Confidence,
    # SinkFact
    ("SinkFact", "severity_base"): Severity,
    ("SinkFact", "confidence"): Confidence,
    # SourceFact
    ("SourceFact", "confidence"): Confidence,
    # DataFlowFact
    ("DataFlowFact", "confidence"): Confidence,
    # PathStep (nested inside DataFlowFact.path)
    ("PathStep", "kind"): PathStepKind,
    # RuntimeEventFact
    ("RuntimeEventFact", "kind"): RuntimeEventKind,
    ("RuntimeEventFact", "confidence"): Confidence,
    # FindingFact
    ("FindingFact", "severity"): Severity,
    ("FindingFact", "confidence"): Confidence,
    ("FindingFact", "status"): FindingStatus,
}

# Explicit mapping of (FactClass, field_name) → nested class name for reconstruction
# This bypasses PEP 563 string annotation issue where fields(cls).type returns strings
_FACT_NESTED_FIELDS: dict[tuple[str, str], str | None] = {
    # FunctionFact
    ("FunctionFact", "params"): "ParamInfo",
    # EntryPointFact
    ("EntryPointFact", "evidence"): "EntryPointEvidence",
    # CallFact
    ("CallFact", "args"): "CallArg",
    ("CallFact", "kwargs"): "CallKwarg",
    ("CallFact", "resolution"): "CallResolution",
    # SinkFact
    ("SinkFact", "conditions"): None,  # Mapping[str, Any] - no reconstruction needed
    # DataFlowFact
    ("DataFlowFact", "path"): "PathStep",
}


def _get_enum_type_for_field(class_name: str, field_name: str) -> type[Enum] | None:
    """Get enum type for a field using explicit mapping.

    This works around PEP 563 where fields(cls).type returns strings.
    """
    return _FACT_ENUM_FIELDS.get((class_name, field_name))


def _get_nested_class_for_field(class_name: str, field_name: str) -> str | None:
    """Get nested class name for a field using explicit mapping.

    This works around PEP 563 where fields(cls).type returns strings.
    """
    return _FACT_NESTED_FIELDS.get((class_name, field_name))


def _convert_value(value: Any) -> Any:
    """Convert a value for JSON serialization.

    - Enum values become their .value string
    - Dataclasses become dicts (recursive)
    - Lists of nested types get converted
    - Mapping[str, CallKwarg] become dict[str, dict]
    - None stays None
    """
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _dataclass_to_dict(value)
    if isinstance(value, dict):
        return {k: _convert_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        result = []
        for item in value:
            if is_dataclass(item):
                result.append(_dataclass_to_dict(item))
            else:
                result.append(_convert_value(item))
        return result
    return value


def _dataclass_to_dict(obj: Any) -> dict[str, Any]:
    """Convert a dataclass instance to a dict with proper field name mapping."""
    result: dict[str, Any] = {}
    for f in fields(obj):
        value = getattr(obj, f.name)
        # Apply field name mapping (e.g., from_ -> from)
        json_name = _FIELD_NAME_MAP.get(f.name, f.name)
        result[json_name] = _convert_value(value)
    return result


def _dict_to_dataclass(class_name: str, data: dict[str, Any]) -> Any:
    """Reconstruct a nested dataclass from a dict."""
    if class_name not in _NESTED_TYPES:
        return data

    cls = _NESTED_TYPES[class_name]

    kwargs: dict[str, Any] = {}
    for f in fields(cls):
        json_name = _FIELD_NAME_MAP.get(f.name, f.name)
        if json_name in data:
            value = data[json_name]

            if isinstance(value, str):
                enum_type = _get_enum_type_for_field(class_name, f.name)
                if enum_type:
                    try:
                        value = enum_type(value)
                    except (ValueError, KeyError):
                        pass
            kwargs[f.name] = value

    return cls(**kwargs)


def fact_to_dict(fact: Fact) -> dict[str, Any]:
    """Convert a Fact instance to a JSON-serializable dict.

    Args:
        fact: A Fact subclass instance

    Returns:
        dict ready for JSON serialization with schema_version included
    """
    result = _dataclass_to_dict(fact)
    result["schema_version"] = SCHEMA_VERSION
    return result


def dict_to_fact(data: dict[str, Any]) -> Fact:
    """Reconstruct a Fact from a dict (reverse of fact_to_dict).

    Args:
        data: A dict previously produced by fact_to_dict

    Returns:
        The reconstructed Fact subclass instance

    Raises:
        KeyError: If 'type' field is missing
        ValueError: If 'type' is unknown
    """
    fact_type = data.get("type")
    if not fact_type:
        raise KeyError("Missing 'type' field in fact data")

    if fact_type not in _FACT_TYPES:
        raise ValueError(f"Unknown fact type: {fact_type}")

    cls = _FACT_TYPES[fact_type]

    # Build kwargs, skipping schema_version
    kwargs: dict[str, Any] = {}
    for f in fields(cls):
        json_name = _FIELD_NAME_MAP.get(f.name, f.name)
        if json_name in data:
            value = data[json_name]

            # Reconstruct enum values using explicit mapping (bypasses PEP 563)
            if isinstance(value, str):
                enum_type = _get_enum_type_for_field(cls.__name__, f.name)
                if enum_type:
                    try:
                        value = enum_type(value)
                    except (ValueError, KeyError):
                        pass
            else:
                # Reconstruct nested dataclasses and collections using explicit mapping
                nested_class = _get_nested_class_for_field(cls.__name__, f.name)
                if nested_class and nested_class in _NESTED_TYPES:
                    from collections.abc import Mapping as MappingABC
                    origin = get_origin(f.type) if hasattr(f.type, '__origin__') else None
                    is_mapping = origin is MappingABC or (
                        isinstance(f.type, str) and f.type.startswith('Mapping')
                    )
                    if is_mapping:
                        value = {
                            k: _dict_to_dataclass(nested_class, v)
                            for k, v in value.items()
                        }
                    elif isinstance(value, dict):
                        value = _dict_to_dataclass(nested_class, value)
                    elif isinstance(value, list):
                        value = [_dict_to_dataclass(nested_class, item) for item in value]

            kwargs[f.name] = value

    return cls(**kwargs)


def serialize_facts(facts: list[Fact], format: str) -> str:
    """Serialize a list of Facts to a string.

    Args:
        facts: List of Fact instances
        format: Either "json" (pretty-printed) or "jsonl" (line-delimited)

    Returns:
        Serialized string

    Raises:
        ValueError: If format is not "json" or "jsonl"
    """
    dicts = [fact_to_dict(f) for f in facts]

    if format == "json":
        return json.dumps(dicts, indent=2, ensure_ascii=False)
    if format == "jsonl":
        return "\n".join(json.dumps(d, ensure_ascii=False) for d in dicts)

    raise ValueError(f"Unknown format: {format}. Expected 'json' or 'jsonl'")


def deserialize_facts(text: str, format: str) -> list[Fact]:
    """Deserialize a string to a list of Facts.

    Args:
        text: Serialized string from serialize_facts
        format: Either "json" or "jsonl"

    Returns:
        List of Fact instances

    Raises:
        ValueError: If format is not "json" or "jsonl"
        json.JSONDecodeError: If text is not valid JSON for the format
    """
    if format == "json":
        data = json.loads(text)
        return [dict_to_fact(d) for d in data]

    if format == "jsonl":
        facts: list[Fact] = []
        for line in text.split("\n"):
            line = line.strip()
            if line:
                d = json.loads(line)
                facts.append(dict_to_fact(d))
        return facts

    raise ValueError(f"Unknown format: {format}. Expected 'json' or 'jsonl'")