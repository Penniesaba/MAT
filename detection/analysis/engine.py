"""AST Analysis Engine — entry point for shadow-mode static pipeline.

Phase 3 of the AST implementation checklist:
- Runs in parallel with the legacy detector registry
- Produces CapabilityFinding output via the adapter layer
- Does not replace or remove existing detector behavior
"""

from __future__ import annotations

import logging
from pathlib import Path

from detection.core.models import CapabilityFinding

from .adapters.finding_adapter import adapt_findings
from .extractors.python_ast import extract_python_facts
from .facts.schema import (
    EntryPointFact,
    Fact,
    FindingFact,
    SinkFact,
)
from .passes.call_graph import build_call_graph, find_reachable_sinks
from .passes.finding_builder import build_finding_facts

__all__ = ["run_ast_analysis"]

_log = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Type guards — narrow list[Fact] to concrete fact subtypes
# ----------------------------------------------------------------------


def _filter_entrypoints(facts: list[Fact]) -> list[EntryPointFact]:
    """Narrow a Fact list to EntryPointFact entries (type-safe)."""
    return [f for f in facts if f.type == "entrypoint"]


def _filter_sinks(facts: list[Fact]) -> list[SinkFact]:
    """Narrow a Fact list to SinkFact entries (type-safe)."""
    return [f for f in facts if f.type == "sink"]


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------


def run_ast_analysis(target_path: Path) -> list[CapabilityFinding]:
    """Run the AST-based security analysis on a Python project.

    This function performs a full pipeline:
    1. Extract security facts (FunctionFact, ImportFact, CallFact,
       EntryPointFact, SinkFact, SourceFact) from all Python files
    2. Build a call graph and find entrypoint-to-sink reachability
    3. Convert FindingFact results to CapabilityFinding via the adapter

    Args:
        target_path: Path to a Python file or a directory containing Python
            source files. Directory targets are scanned recursively.

    Returns:
        List of CapabilityFinding objects representing security findings.
        Returns an empty list if no findings are produced or if the target
        cannot be processed.

    Graceful handling:
        - Individual files that fail to parse are logged and skipped
        - The function never raises an exception for a single bad file
        - If the entire target is inaccessible, an empty list is returned
    """
    root, files = _resolve_files(target_path)
    if not files:
        _log.warning("No Python files found in %s", target_path)
        return []

    all_facts: list[Fact] = []
    for file_path in files:
        facts, errors = _extract_facts(root, file_path)
        for err in errors:
            _log.debug("Extraction warning in %s:%d — %s", err.file, err.line, err.message)
        all_facts.extend(facts)

    if not all_facts:
        return []

    findings = _analyze_facts(all_facts)
    return adapt_findings(findings)


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------


def _resolve_files(target_path: Path) -> tuple[Path, list[Path]]:
    """Resolve target to (root, list_of_python_files).

    If target is a single .py file, root is its parent directory.
    If target is a directory, root is that directory.
    """
    if target_path.is_file():
        return target_path.parent, [target_path]
    # Directory — recursively collect all .py files
    files = sorted(target_path.rglob("*.py"))
    return target_path, files


def _extract_facts(root: Path, file_path: Path) -> tuple[list[Fact], list[object]]:
    """Extract facts from one Python file with graceful failure.

    Returns (facts, errors) where errors are non-fatal ExtractionError tuples.
    """
    try:
        source = file_path.read_text(encoding="utf-8")
    except OSError as e:
        _log.debug("Could not read %s: %s", file_path, e)
        return [], []

    try:
        facts, errors = extract_python_facts(root, file_path, source)
        return facts, errors
    except Exception as e:
        _log.debug("Unexpected error extracting %s: %s", file_path, e)
        return [], []


def _analyze_facts(facts: list[Fact]) -> list[FindingFact]:
    """Run the full analysis pipeline on a fact list.

    Pipeline: call graph → reachability → finding facts
    """
    graph = build_call_graph(facts)

    entrypoints = _filter_entrypoints(facts)
    sinks = _filter_sinks(facts)

    if not entrypoints or not sinks:
        return []

    reachability_results = find_reachable_sinks(
        entrypoints=entrypoints,
        sinks=sinks,
        graph=graph,
    )

    return build_finding_facts(reachability_results, facts)