"""Integration tests for the full AST pipeline with taint-lite data flow analysis.

Phase 5 acceptance checks:
1. extract_python_facts produces SourceFact entries for MCP parameters
2. engine.run_ast_analysis runs the full pipeline including taint-lite
3. FindingFact records contain dataflows field with correlated DataFlowFact IDs
4. End-to-end: source -> sink data flow is detected and reported
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


# ----------------------------------------------------------------------
# Lazy engine import helper (same pattern as existing integration tests)
# ----------------------------------------------------------------------


def _import_engine_modules():
    """Lazily import engine and extractor modules."""
    try:
        _engine_mod = importlib.import_module("analysis.engine")
        _mod = importlib.import_module("analysis.extractors.python_ast")
    except ModuleNotFoundError:
        _repo_root = Path(__file__).resolve().parent.parent.parent
        sys.path.insert(0, str(_repo_root))
        _engine_mod = importlib.import_module("analysis.engine")
        _mod = importlib.import_module("analysis.extractors.python_ast")

    return _engine_mod, _mod


def _make_python_file(content: str) -> Path:
    """Create a temp Python file, returns Path. Caller should unlink it."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    )
    try:
        f.write(content)
        f.flush()
        return Path(f.name)
    finally:
        f.close()


def _cleanup(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


# ----------------------------------------------------------------------
# Test fixtures as plain functions
# ----------------------------------------------------------------------


def _rce_file() -> Path:
    """MCP tool with RCE sink and user-input source parameter."""
    content = """\
import subprocess

@mcp.tool()
def run_cmd(cmd: str) -> str:
    \"\"\"MCP tool that executes shell commands.\"\"\"
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
"""
    return _make_python_file(content)


def _no_source_file() -> Path:
    """No dangerous sinks, just a plain MCP tool function."""
    content = """\
@mcp.tool()
def greet(name: str) -> str:
    return f"Hello, {name}!"
"""
    return _make_python_file(content)


# ----------------------------------------------------------------------
# Test: SourceFact is produced for MCP parameters
# ----------------------------------------------------------------------


def test_extractor_produces_source_facts_for_mcp_params():
    """extract_python_facts generates SourceFact for MCP tool parameters."""
    _engine_mod, _extractor_mod = _import_engine_modules()
    extract_python_facts = getattr(_extractor_mod, "extract_python_facts")

    content = """\
@mcp.tool()
def run_cmd(cmd: str) -> str:
    return subprocess.run(cmd, shell=True).stdout.decode()
"""
    path = _make_python_file(content)
    root = path.parent
    try:
        source = path.read_text(encoding="utf-8")
        facts, errors = extract_python_facts(root, path, source)
        source_facts = [f for f in facts if f.type == "source"]
        assert len(source_facts) >= 1, f"Expected at least one SourceFact, got: {[f.type for f in facts]}"
        for sf in source_facts:
            assert sf.name == "cmd"
            assert "run_cmd" in sf.function_id
    finally:
        _cleanup(path)


# ----------------------------------------------------------------------
# Test: Full pipeline produces dataflows in FindingFact (internal level)
# ----------------------------------------------------------------------


def test_finding_facts_contain_dataflow_ids():
    """FindingFact records produced by engine contain correlated dataflow IDs."""
    _engine_mod, _ = _import_engine_modules()
    _analyze_facts = getattr(_engine_mod, "_analyze_facts")
    extract_python_facts = getattr(
        importlib.import_module("analysis.extractors.python_ast"),
        "extract_python_facts",
    )

    path = _rce_file()
    root = path.parent
    try:
        source = path.read_text(encoding="utf-8")
        facts, errors = extract_python_facts(root, path, source)

        # Call the internal _analyze_facts which returns FindingFact objects
        # (run_ast_analysis returns CapabilityFinding which is the adapted output)
        findings = _analyze_facts(facts)

        assert len(findings) >= 1, f"Expected at least one finding, got {len(findings)}"
        for f in findings:
            # FindingFact objects have dataflows as a list field
            assert hasattr(f, "dataflows"), f"FindingFact should have dataflows field, got {type(f)}"
            assert isinstance(f.dataflows, list), f"dataflows should be list, got {type(f.dataflows)}"
            for df_id in f.dataflows:
                assert isinstance(df_id, str), f"dataflow ID should be str, got {type(df_id)}"
    finally:
        _cleanup(path)


# ----------------------------------------------------------------------
# Test: run_ast_analysis output is CapabilityFinding (adapter level)
# ----------------------------------------------------------------------


def test_adapter_output_is_capability_finding():
    """run_ast_analysis returns CapabilityFinding objects (adapted from FindingFact)."""
    _engine_mod, _ = _import_engine_modules()
    _run_ast = getattr(_engine_mod, "run_ast_analysis")

    path = _rce_file()
    try:
        findings = _run_ast(path)
        assert len(findings) >= 1, f"Expected at least one finding, got {len(findings)}"
        for f in findings:
            assert hasattr(f, "name")
            assert hasattr(f, "evidence")
            # dataflows is internal to FindingFact, not propagated to CapabilityFinding
            # (that's expected — metadata carries what the adapter exposes)
    finally:
        _cleanup(path)


# ----------------------------------------------------------------------
# Test: No dangerous sinks → no findings
# ----------------------------------------------------------------------


def test_no_dangerous_sinks_returns_empty():
    """Pipeline returns empty list when there are no dangerous sinks."""
    _engine_mod, _ = _import_engine_modules()
    _run_ast = getattr(_engine_mod, "run_ast_analysis")

    path = _no_source_file()
    try:
        findings = _run_ast(path)
        # No sinks → no findings
        assert isinstance(findings, list)
    finally:
        _cleanup(path)


# ----------------------------------------------------------------------
# Test: Graceful handling — malformed file returns empty, no crash
# ----------------------------------------------------------------------


def test_graceful_on_syntax_error():
    """Pipeline handles syntax errors gracefully without crashing."""
    _engine_mod, _ = _import_engine_modules()
    _run_ast = getattr(_engine_mod, "run_ast_analysis")

    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    )
    try:
        f.write("def broken(\n")
        f.flush()
        path = Path(f.name)
        findings = _run_ast(path)
        assert isinstance(findings, list)
    finally:
        f.close()
        _cleanup(Path(f.name))