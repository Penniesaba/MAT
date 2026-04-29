"""Deterministic Fact ID generation for AST-based detection framework.

This module provides functions for generating consistent, unique IDs for
all fact types. IDs follow the format:

    <type>:<project_relative_path>:<qualifier>

All paths are converted to POSIX style (forward slashes) for cross-platform
consistency.
"""

from __future__ import annotations

from pathlib import Path


def make_fact_id(type_prefix: str, root: Path, file: Path, qualifier: str) -> str:
    """Generate a deterministic fact ID.

    Format: <type>:<project_relative_path>:<qualifier>

    Args:
        type_prefix: The fact type prefix (e.g., "python", "js", "entry").
        root: The project root directory.
        file: The file path (must be relative to root).
        qualifier: A unique qualifier for this fact within the file.

    Returns:
        A deterministic fact ID string.

    Example:
        >>> root = Path("/project")
        >>> file = Path("/project/src/server.py")
        >>> make_fact_id("python", root, file, "run_cmd")
        'python:src/server.py:run_cmd'
    """
    rel = file.relative_to(root)
    rel_posix = str(rel).replace("\\", "/")
    return f"{type_prefix}:{rel_posix}:{qualifier}"


def make_function_id(language: str, root: Path, file: Path, name: str) -> str:
    """Generate a FunctionFact ID.

    Format: <language>:<relative_path>:<name>

    Example:
        >>> root = Path("/project")
        >>> file = Path("/project/src/server.py")
        >>> make_function_id("python", root, file, "run_cmd")
        'python:src/server.py:run_cmd'
    """
    return make_fact_id(language, root, file, name)


def make_import_id(root: Path, file: Path, line: int, imported: str) -> str:
    """Generate an ImportFact ID.

    Format: import:<relative_path>:<line>:<imported_name>

    Example:
        >>> root = Path("/project")
        >>> file = Path("/project/src/server.py")
        >>> make_import_id(root, file, 1, "subprocess")
        'import:src/server.py:1:subprocess'
    """
    rel = file.relative_to(root)
    rel_posix = str(rel).replace("\\", "/")
    return f"import:{rel_posix}:{line}:{imported}"


def make_entrypoint_id(root: Path, file: Path, name: str) -> str:
    """Generate an EntryPointFact ID.

    Format: entry:<relative_path>:<name>

    Example:
        >>> root = Path("/project")
        >>> file = Path("/project/src/server.py")
        >>> make_entrypoint_id(root, file, "run_cmd")
        'entry:src/server.py:run_cmd'
    """
    return make_fact_id("entry", root, file, name)


def make_call_id(root: Path, file: Path, line: int, column: int) -> str:
    """Generate a CallFact ID.

    Format: call:<relative_path>:<line>:<column>

    Example:
        >>> root = Path("/project")
        >>> file = Path("/project/src/server.py")
        >>> make_call_id(root, file, 15, 4)
        'call:src/server.py:15:4'
    """
    rel = file.relative_to(root)
    rel_posix = str(rel).replace("\\", "/")
    return f"call:{rel_posix}:{line}:{column}"


def make_sink_id(category: str, root: Path, file: Path, line: int) -> str:
    """Generate a SinkFact ID.

    Format: sink:<category>:<relative_path>:<line>

    Example:
        >>> root = Path("/project")
        >>> file = Path("/project/src/server.py")
        >>> make_sink_id("rce", root, file, 15)
        'sink:rce:src/server.py:15'
    """
    rel = file.relative_to(root)
    rel_posix = str(rel).replace("\\", "/")
    return f"sink:{category}:{rel_posix}:{line}"


def make_source_id(
    root: Path, file: Path, function_name: str, param_name: str
) -> str:
    """Generate a SourceFact ID.

    Format: source:<relative_path>:<function_name>:<param_name>

    Example:
        >>> root = Path("/project")
        >>> file = Path("/project/src/server.py")
        >>> make_source_id(root, file, "run_cmd", "cmd")
        'source:src/server.py:run_cmd:cmd'
    """
    rel = file.relative_to(root)
    rel_posix = str(rel).replace("\\", "/")
    return f"source:{rel_posix}:{function_name}:{param_name}"


def make_dataflow_id(source_name: str, sink_name: str) -> str:
    """Generate a DataFlowFact ID.

    Format: flow:<source_name>-to-<sink_name>

    Example:
        >>> make_dataflow_id("cmd", "subprocess")
        'flow:cmd-to-subprocess'
    """
    return f"flow:{source_name}-to-{sink_name}"


def make_runtime_event_id(syscall: str, pid: int) -> str:
    """Generate a RuntimeEventFact ID.

    Format: runtime:<syscall>:<pid>

    Example:
        >>> make_runtime_event_id("execve", 12345)
        'runtime:execve:12345'
    """
    return f"runtime:{syscall}:{pid}"


def make_finding_id(category: str, name: str) -> str:
    """Generate a FindingFact ID.

    Format: finding:<category>:<name>

    Example:
        >>> make_finding_id("rce", "run_cmd")
        'finding:rce:run_cmd'
    """
    return f"finding:{category}:{name}"
