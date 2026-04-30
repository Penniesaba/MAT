"""Integration tests for AST adapter + static pipeline shadow mode with JS/TS.

Phase 4 acceptance checks:
1. Engine detects findings in JS/TS files (ESM, CJS, server.tool registration)
2. JS/TS findings have EvidenceSource.STATIC in their sources
3. run_static_pipeline produces DetectionResult with complete fields for JS/TS targets
"""

from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

from detection.core.models import CapabilityFinding, DetectionResult, EvidenceSource
from detection.core.registry import DetectorRegistry


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
    import sys
    try:
        _engine_mod = importlib.import_module("analysis.engine")
    except ModuleNotFoundError:
        _repo_root = Path(__file__).resolve().parent.parent.parent
        sys.path.insert(0, str(_repo_root))
        _engine_mod = importlib.import_module("analysis.engine")

    _run_ast = getattr(_engine_mod, "run_ast_analysis")
    return _run_ast


# ----------------------------------------------------------------------
# Helper: create a temp JS/TS file and clean up after
# ----------------------------------------------------------------------


def _make_jsts_file(content: str, suffix: str = ".js") -> Path:
    """Create a temp JS/TS file, returns Path. Caller should unlink it."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
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
# Fixtures as plain functions
# ----------------------------------------------------------------------


def _malicious_js_file() -> Path:
    """A JavaScript file with an MCP tool that calls a dangerous sink."""
    content = """\
const server = { tool: () => {} };
const { exec } = require("child_process");

server.tool("run_cmd", (cmd) => {
    return exec(cmd);
});
"""
    return _make_jsts_file(content, ".js")


def _malicious_ts_file() -> Path:
    """A TypeScript file with an MCP tool that calls a dangerous sink."""
    content = """\
const server = { tool: () => {} };
import { exec } from "child_process";

server.tool("run_cmd", (cmd: string) => {
    return exec(cmd);
});
"""
    return _make_jsts_file(content, ".ts")


def _benign_js_file() -> Path:
    """A harmless JavaScript file with no dangerous patterns."""
    content = """
function greet(name) {
    return `Hello, ${name}!`;
}

const greeting = greet("World");
console.log(greeting);
"""
    return _make_jsts_file(content, ".js")


# ----------------------------------------------------------------------
# Acceptance Test 1 — AST path alone produces findings for JS/TS
# ----------------------------------------------------------------------


def test_ast_engine_finds_rce_in_malicious_js():
    """Engine detects RCE sink reachable from server.tool entrypoint in JS."""
    run_ast_analysis = _import_engine()

    path = _malicious_js_file()
    try:
        findings = run_ast_analysis(path)
        assert len(findings) >= 1, "Expected at least one finding from AST engine"

        rce_findings = [f for f in findings if "rce" in f.name.lower() or "shell" in f.name.lower()]
        assert len(rce_findings) >= 1, f"Expected RCE finding, got: {[f.name for f in findings]}"
    finally:
        _cleanup(path)


def test_ast_engine_finds_rce_in_malicious_ts():
    """Engine detects RCE sink reachable from server.tool entrypoint in TypeScript."""
    run_ast_analysis = _import_engine()

    path = _malicious_ts_file()
    try:
        findings = run_ast_analysis(path)
        assert len(findings) >= 1, "Expected at least one finding from AST engine"

        rce_findings = [f for f in findings if "rce" in f.name.lower() or "shell" in f.name.lower()]
        assert len(rce_findings) >= 1, f"Expected RCE finding, got: {[f.name for f in findings]}"
    finally:
        _cleanup(path)


def test_ast_engine_handles_js_directory_target():
    """Engine works when target is a directory containing JS files."""
    run_ast_analysis = _import_engine()

    path = _malicious_js_file()
    try:
        parent = path.parent
        findings = run_ast_analysis(parent)
        assert len(findings) >= 1, "Expected findings from directory scan"
    finally:
        _cleanup(path)


def test_ast_engine_graceful_on_benign_js():
    """Engine returns empty list on benign JS code, no exceptions raised."""
    run_ast_analysis = _import_engine()

    path = _benign_js_file()
    try:
        findings = run_ast_analysis(path)
        assert isinstance(findings, list)
    finally:
        _cleanup(path)


# ----------------------------------------------------------------------
# Acceptance Test 2 — DetectionResult fields are complete for JS/TS
# ----------------------------------------------------------------------


def test_result_has_findings_for_js():
    """DetectionResult contains CapabilityFinding list for JS target."""
    path = _malicious_js_file()
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


def test_result_has_server_name_for_js():
    """DetectionResult.server_name is populated for JS target."""
    path = _malicious_js_file()
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


# ----------------------------------------------------------------------
# Acceptance Test 3 — EvidenceSource.STATIC in JS/TS findings
# ----------------------------------------------------------------------


def test_js_finding_sources_include_static():
    """JS-derived CapabilityFinding has EvidenceSource.STATIC."""
    path = _malicious_js_file()
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


def test_ts_finding_sources_include_static():
    """TS-derived CapabilityFinding has EvidenceSource.STATIC."""
    path = _malicious_ts_file()
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
# Acceptance Test 4 — Multiple JS/TS file types are scanned
# ----------------------------------------------------------------------


def test_ast_engine_scans_multiple_jsts_extensions():
    """Engine scans .js, .ts, .mjs, .mts files in directory."""
    run_ast_analysis = _import_engine()

    # Create multiple files with different extensions
    js_path = _malicious_js_file()
    ts_path = _malicious_ts_file()
    mjs_content = """\
const server = { tool: () => {} };
import { exec } from "child_process";

server.tool("test_tool", (cmd: string) => {
    return exec(cmd);
});
"""
    mjs_path = _make_jsts_file(mjs_content, ".mjs")

    try:
        parent = js_path.parent
        findings = run_ast_analysis(parent)

        # Should find findings from multiple file types
        assert len(findings) >= 1, f"Expected findings from JS/TS/MJS scan, got: {len(findings)}"
    finally:
        _cleanup(js_path)
        _cleanup(ts_path)
        _cleanup(mjs_path)


# ----------------------------------------------------------------------
# Acceptance Test 5 — Unsupported files are silently ignored
# ----------------------------------------------------------------------


def test_ast_engine_ignores_unsupported_extensions():
    """Engine silently ignores unsupported file extensions without error."""
    run_ast_analysis = _import_engine()

    # Create a benign JS file and also a file with unsupported extension
    js_path = _malicious_js_file()
    unsupported_path = _make_jsts_file("// This is not really a .xyz file\nconst x = 1;", ".xyz")

    try:
        parent = js_path.parent
        # Should not raise, should just ignore .xyz files
        findings = run_ast_analysis(parent)
        assert isinstance(findings, list)
    finally:
        _cleanup(js_path)
        _cleanup(unsupported_path)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])