"""Integration tests for AST adapter + static pipeline shadow mode.

Phase 3 acceptance checks:
1. In isolation (no registry detectors), AST path produces at least one finding
2. DetectionResult fields are complete (score / risk / findings)
3. ReportBuilder(format_="markdown"|"json") renders without error
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path

from detection.core.models import CapabilityFinding, DetectionResult, EvidenceSource
from detection.core.registry import DetectorRegistry
from detection.reporting.report_builder import ReportBuilder


# ----------------------------------------------------------------------
# Import run_static_pipeline without triggering detection.pipelines.__init__
# (which eagerly imports dynamic.py that depends on unavailable sandbox deps)
# ----------------------------------------------------------------------
_spec = importlib.util.spec_from_file_location(
    "_static_pipeline",
    Path(__file__).resolve().parents[2]   # → detection/tests/../..
    / "detection" / "pipelines" / "static.py",
)
_static_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_static_mod)
run_static_pipeline = _static_mod.run_static_pipeline
# ----------------------------------------------------------------------
# Module-level lazy import helper — resolves 'analysis' in all contexts
# ----------------------------------------------------------------------


def _import_engine():
    """Lazily import run_ast_analysis from analysis.engine.

    Tries the usual import path first.  On ModuleNotFoundError resolves
    the repository root (parent of the 'detection' package directory) and
    prepends it to sys.path before retrying.  Any residual failure propagates.
    """
    try:
        _engine_mod = importlib.import_module("analysis.engine")
    except ModuleNotFoundError:
        _repo_root = Path(__file__).resolve().parent.parent.parent
        sys.path.insert(0, str(_repo_root))
        _engine_mod = importlib.import_module("analysis.engine")

    _run_ast = getattr(_engine_mod, "run_ast_analysis")
    return _run_ast


# ----------------------------------------------------------------------
# Helper: create a temp Python file and clean up after
# ----------------------------------------------------------------------


def _make_python_file(content: str) -> Path:
    """Create a Python fixture in its own temp project directory."""
    temp_dir = Path(tempfile.mkdtemp(prefix="ast-py-fixture-"))
    path = temp_dir / "server.py"
    path.write_text(content, encoding="utf-8")
    return path


def _cleanup(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass
    if path.parent.name.startswith("ast-py-fixture-"):
        shutil.rmtree(path.parent, ignore_errors=True)


# ----------------------------------------------------------------------
# Fixtures as plain functions
# ----------------------------------------------------------------------


def _malicious_python_file() -> Path:
    """A Python file with an MCP tool that calls a dangerous sink."""
    content = """\
import subprocess

@mcp.tool()
def run_cmd(cmd: str) -> str:
    \"\"\"MCP tool that executes shell commands.\"\"\"
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
"""
    return _make_python_file(content)


def _benign_python_file() -> Path:
    """A harmless Python file with no dangerous patterns."""
    content = """
def hello(name: str) -> str:
    '''Simple greeting function.'''
    return f"Hello, {name}!"

class Greeter:
    def greet(self, name: str) -> str:
        return hello(name)
"""
    return _make_python_file(content)


# ----------------------------------------------------------------------
# Acceptance Test 1 — AST path alone produces findings
# ----------------------------------------------------------------------


def test_ast_engine_finds_rce_in_malicious_file():
    """Engine detects RCE sink reachable from MCP entrypoint."""
    run_ast_analysis = _import_engine()

    path = _malicious_python_file()
    try:
        findings = run_ast_analysis(path)
        assert len(findings) >= 1, "Expected at least one finding from AST engine"

        rce_findings = [f for f in findings if "rce" in f.name.lower() or "shell" in f.name.lower()]
        assert len(rce_findings) >= 1, f"Expected RCE finding, got: {[f.name for f in findings]}"
    finally:
        _cleanup(path)


def test_ast_engine_handles_directory_target():
    """Engine works when target is a directory."""
    run_ast_analysis = _import_engine()

    path = _malicious_python_file()
    try:
        parent = path.parent
        findings = run_ast_analysis(parent)
        assert len(findings) >= 1, "Expected findings from directory scan"
    finally:
        _cleanup(path)


def test_ast_engine_graceful_on_benign_file():
    """Engine returns empty list on benign code, no exceptions raised."""
    run_ast_analysis = _import_engine()

    path = _benign_python_file()
    try:
        findings = run_ast_analysis(path)
        assert isinstance(findings, list)
    finally:
        _cleanup(path)


# ----------------------------------------------------------------------
# Acceptance Test 2 — DetectionResult fields are complete
# ----------------------------------------------------------------------


def test_result_has_score_and_risk_level():
    """DetectionResult contains total_score and risk_level."""
    path = _malicious_python_file()
    try:
        registry = DetectorRegistry()
        result = run_static_pipeline(
            target_path=path,
            registry=registry,
            policy_dir=Path("detection/mitigation/templates"),
        )

        assert hasattr(result, "total_score")
        assert hasattr(result, "risk_level")
        assert result.risk_level in ("low", "medium", "high", "critical")
    finally:
        _cleanup(path)


def test_result_has_findings_list():
    """DetectionResult contains a list of CapabilityFinding."""
    path = _malicious_python_file()
    try:
        registry = DetectorRegistry()
        result = run_static_pipeline(
            target_path=path,
            registry=registry,
            policy_dir=Path("detection/mitigation/templates"),
        )

        assert isinstance(result.findings, list)
        for f in result.findings:
            assert isinstance(f, CapabilityFinding)
    finally:
        _cleanup(path)


def test_result_has_server_name():
    """DetectionResult.server_name is populated."""
    path = _malicious_python_file()
    try:
        registry = DetectorRegistry()
        result = run_static_pipeline(
            target_path=path,
            registry=registry,
            policy_dir=Path("detection/mitigation/templates"),
        )

        assert isinstance(result.server_name, str)
        assert len(result.server_name) > 0
    finally:
        _cleanup(path)


def test_ast_finding_sources_include_static():
    """AST-derived CapabilityFinding has EvidenceSource.STATIC."""
    path = _malicious_python_file()
    try:
        registry = DetectorRegistry()
        result = run_static_pipeline(
            target_path=path,
            registry=registry,
            policy_dir=Path("detection/mitigation/templates"),
        )

        ast_findings = [
            f for f in result.findings
            if EvidenceSource.STATIC in f.sources
        ]
        assert len(ast_findings) >= 1, (
            f"Expected at least one AST finding with EvidenceSource.STATIC; "
            f"got {len(result.findings)} total findings"
        )
    finally:
        _cleanup(path)


# ----------------------------------------------------------------------
# Acceptance Test 3 — ReportBuilder renders without error
# ----------------------------------------------------------------------


def test_render_markdown():
    """ReportBuilder(format_='markdown') produces output without raising."""
    path = _malicious_python_file()
    try:
        registry = DetectorRegistry()
        result = run_static_pipeline(
            target_path=path,
            registry=registry,
            policy_dir=Path("detection/mitigation/templates"),
        )

        builder = ReportBuilder(format_="markdown")
        output = builder.render(result)

        assert isinstance(output, str)
        assert len(output) > 0
        assert "Detection Summary" in output or "Risk Level" in output
    finally:
        _cleanup(path)


def test_render_json():
    """ReportBuilder(format_='json') produces valid JSON without raising."""
    path = _malicious_python_file()
    try:
        registry = DetectorRegistry()
        result = run_static_pipeline(
            target_path=path,
            registry=registry,
            policy_dir=Path("detection/mitigation/templates"),
        )

        builder = ReportBuilder(format_="json")
        output = builder.render(result)

        assert isinstance(output, str)
        parsed = json.loads(output)
        assert "server" in parsed or "findings" in parsed
    finally:
        _cleanup(path)


def test_empty_result_renders_markdown():
    """ReportBuilder handles a result with zero findings gracefully."""
    path = _benign_python_file()
    try:
        registry = DetectorRegistry()
        result = run_static_pipeline(
            target_path=path,
            registry=registry,
            policy_dir=Path("detection/mitigation/templates"),
        )

        builder = ReportBuilder(format_="markdown")
        output = builder.render(result)

        assert isinstance(output, str)
        assert "Detection Summary" in output or "Risk Level" in output
    finally:
        _cleanup(path)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])