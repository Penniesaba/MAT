"""Unit tests for Phase 2 Python AST Extractor.

Tests cover:
- FunctionFact: function definitions with params, decorators, qualified names
- ImportFact: import statements with alias support
- CallFact: function calls with alias resolution
- EntryPointFact: MCP decorator detection
- SourceFact: MCP tool parameter sources
- SinkFact: RCE/file/network sink detection
- Graceful fail: SyntaxError and unsupported structures
"""

from __future__ import annotations

from pathlib import Path

import pytest

from analysis.extractors import extract_python_facts
from analysis.extractors.python_ast import ExtractionError


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def root() -> Path:
    """Project root for ID generation."""
    return Path("/project")


@pytest.fixture
def file(root: Path) -> Path:
    """File path relative to project root."""
    return Path("/project/src/server.py")


# ---------------------------------------------------------------------------
# Test class: TestPythonAstExtractorSupported
# ---------------------------------------------------------------------------


class TestPythonAstExtractorSupported:
    """Tests for supported Python constructs with complete fact extraction."""

    def test_extracts_all_six_fact_types(self, root: Path, file: Path) -> None:
        """Extractor produces at least one of each: function, import, call, entrypoint, source, sink."""
        source = """
import subprocess
from os import system as cmd_runner

@mcp.tool
def run_cmd(cmd: str) -> str:
    subprocess.run([cmd])
    return "done"
"""
        facts, errors = extract_python_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        fact_types = {f.type for f in facts}

        assert "function" in fact_types, "Missing FunctionFact"
        assert "import" in fact_types, "Missing ImportFact"
        assert "call" in fact_types, "Missing CallFact"
        assert "entrypoint" in fact_types, "Missing EntryPointFact"
        assert "source" in fact_types, "Missing SourceFact"
        assert "sink" in fact_types, "Missing SinkFact"

    def test_function_fact_contains_params_and_decorators(self, root: Path, file: Path) -> None:
        """FunctionFact has correct params, decorators, and qualified name."""
        source = """
@mcp.tool
def run_cmd(cmd: str, timeout: int = 30) -> str:
    return cmd
"""
        facts, errors = extract_python_facts(root, file, source)

        func_facts = [f for f in facts if f.type == "function"]
        assert len(func_facts) == 1

        func = func_facts[0]
        assert func.name == "run_cmd"
        assert func.qualified_name == "run_cmd"
        assert "mcp.tool" in func.decorators
        assert len(func.params) == 2
        assert func.params[0].name == "cmd"
        assert func.params[0].annotation == "str"
        assert func.params[1].name == "timeout"
        assert func.params[1].annotation == "int"
        assert func.params[1].default == "30"

    def test_import_alias_affects_normalized_callee(self, root: Path, file: Path) -> None:
        """Import alias causes normalized_callee to differ from callee."""
        source = """
from os import system as my_alias

def test():
    my_alias("ls")
"""
        facts, errors = extract_python_facts(root, file, source)

        call_facts = [f for f in facts if f.type == "call"]
        assert len(call_facts) == 1

        call = call_facts[0]
        assert call.callee == "my_alias"
        assert call.normalized_callee == "os.system"

    def test_assignment_alias_affects_normalized_callee(self, root: Path, file: Path) -> None:
        """Assignment alias (x = y) causes normalized_callee to differ from callee."""
        source = """
import subprocess

sp = subprocess

def test():
    sp.run(["ls"])
"""
        facts, errors = extract_python_facts(root, file, source)

        call_facts = [f for f in facts if f.type == "call"]
        assert len(call_facts) == 1

        call = call_facts[0]
        assert call.callee == "sp.run"
        assert call.normalized_callee == "subprocess.run"

    def test_assignment_alias_module_attribute(self, root: Path, file: Path) -> None:
        """Assignment alias (x = module.func) causes normalized_callee to differ from callee."""
        source = """
import subprocess

sp_run = subprocess.run

def test():
    sp_run(["ls"])
"""
        facts, errors = extract_python_facts(root, file, source)

        call_facts = [f for f in facts if f.type == "call"]
        assert len(call_facts) == 1

        call = call_facts[0]
        assert call.callee == "sp_run"
        assert call.normalized_callee == "subprocess.run"

    def test_alias_chain_import_to_assignment(self, root: Path, file: Path) -> None:
        """Chained alias: from os import system as s; x = s; x() resolves to os.system."""
        source = """
from os import system as s
x = s

def test():
    x()
"""
        facts, errors = extract_python_facts(root, file, source)

        call_facts = [f for f in facts if f.type == "call"]
        assert len(call_facts) == 1

        call = call_facts[0]
        # x -> s -> os.system
        assert call.callee == "x"
        assert call.normalized_callee == "os.system"

    def test_alias_chain_resolution_produces_call_resolution(
        self, root: Path, file: Path
    ) -> None:
        """Alias chain produces valid CallResolution with import_alias set."""
        source = """
from os import system as s
x = s

def test():
    x()
"""
        facts, errors = extract_python_facts(root, file, source)

        call_facts = [f for f in facts if f.type == "call"]
        assert len(call_facts) == 1

        call = call_facts[0]
        # The original import alias 's' should be captured
        assert call.resolution is not None
        assert call.resolution.import_alias == "s"
        assert call.resolution.confidence.value == "high"

    def test_direct_import_alias_resolution(self, root: Path, file: Path) -> None:
        """Direct import alias produces CallResolution with correct import_alias."""
        source = """
from os import system as cmd

def test():
    cmd()
"""
        facts, errors = extract_python_facts(root, file, source)

        call_facts = [f for f in facts if f.type == "call"]
        assert len(call_facts) == 1

        call = call_facts[0]
        assert call.normalized_callee == "os.system"
        assert call.resolution is not None
        assert call.resolution.import_alias == "cmd"

    def test_mcp_decorator_exact_match(self, root: Path, file: Path) -> None:
        """MCP decorator patterns with dots match exact qualified names."""
        source = """
@mcp.tool
def my_tool():
    pass
"""
        facts, errors = extract_python_facts(root, file, source)

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) == 1
        assert ep_facts[0].name == "my_tool"

    def test_bare_tool_decorator_no_false_positive(self, root: Path, file: Path) -> None:
        """Bare @tool decorator does NOT produce EntryPointFact."""
        source = """
def tool():
    pass

@tool
def my_func():
    pass
"""
        facts, errors = extract_python_facts(root, file, source)

        # @tool (function reference) should not be treated as MCP entry point
        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) == 0, "Bare @tool decorator should not produce EntryPointFact"

    def test_my_tool_decorator_no_false_positive(self, root: Path, file: Path) -> None:
        """@my_tool decorator does NOT produce EntryPointFact."""
        source = """
@my_tool
def my_func():
    pass
"""
        facts, errors = extract_python_facts(root, file, source)

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) == 0, "@my_tool should not produce EntryPointFact"

    def test_resource_decorator_no_false_positive(self, root: Path, file: Path) -> None:
        """@resource_handler or bare @resource does NOT produce EntryPointFact."""
        source = """
@resource
def my_func():
    pass
"""
        facts, errors = extract_python_facts(root, file, source)

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) == 0, "@resource should not produce EntryPointFact"

    def test_mcp_tools_underscore_pattern(self, root: Path, file: Path) -> None:
        """@mcp_tools pattern (underscore) should match exact or as suffix."""
        source = """
@mcp_tools
def my_func():
    pass
"""
        facts, errors = extract_python_facts(root, file, source)

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        # mcp_tools is in the pattern list, should match exact
        assert len(ep_facts) == 1

    def test_nested_alias_chain(self, root: Path, file: Path) -> None:
        """Multiple chained assignments resolve correctly."""
        source = """
import subprocess

sp = subprocess
sp_run = sp.run

def test():
    sp_run(["ls"])
"""
        facts, errors = extract_python_facts(root, file, source)

        call_facts = [f for f in facts if f.type == "call"]
        assert len(call_facts) == 1

        call = call_facts[0]
        # sp_run -> sp.run -> subprocess.run
        assert call.normalized_callee == "subprocess.run"

    def test_entry_point_fact_from_decorator(self, root: Path, file: Path) -> None:
        """MCP decorator produces EntryPointFact."""
        source = """
@mcp.tool
def my_tool(arg: str) -> str:
    return arg
"""
        facts, errors = extract_python_facts(root, file, source)

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) == 1

        ep = ep_facts[0]
        assert ep.name == "my_tool"
        assert ep.kind.value == "mcp_tool"
        assert "mcp.tool" in ep.evidence.text

    def test_entry_point_produces_source_facts_for_params(self, root: Path, file: Path) -> None:
        """MCP tool parameters produce SourceFact instances."""
        source = """
@mcp.tool
def my_tool(cmd: str, timeout: int = 10) -> str:
    return cmd
"""
        facts, errors = extract_python_facts(root, file, source)

        source_facts = [f for f in facts if f.type == "source"]
        assert len(source_facts) == 2  # cmd and timeout, not *args

        param_names = {s.name for s in source_facts}
        assert "cmd" in param_names
        assert "timeout" in param_names

        for s in source_facts:
            assert s.kind == "mcp_tool_parameter"

    def test_sink_detection_rce_subprocess(self, root: Path, file: Path) -> None:
        """subprocess.run is detected as RCE sink."""
        source = """
import subprocess

def test():
    subprocess.run(["ls"])
"""
        facts, errors = extract_python_facts(root, file, source)

        sink_facts = [f for f in facts if f.type == "sink"]
        assert len(sink_facts) >= 1

        rce_sinks = [s for s in sink_facts if s.category == "rce"]
        assert len(rce_sinks) >= 1
        assert any("subprocess" in s.sink_name for s in rce_sinks)

    def test_sink_detection_rce_os_system(self, root: Path, file: Path) -> None:
        """os.system is detected as RCE sink."""
        source = """
import os

def test():
    os.system("ls")
"""
        facts, errors = extract_python_facts(root, file, source)

        sink_facts = [f for f in facts if f.type == "sink"]
        assert len(sink_facts) >= 1

        rce_sinks = [s for s in sink_facts if s.category == "rce"]
        assert len(rce_sinks) >= 1

    def test_sink_detection_network_requests(self, root: Path, file: Path) -> None:
        """requests.get is detected as network sink."""
        source = """
import requests

def test():
    requests.get("http://example.com")
"""
        facts, errors = extract_python_facts(root, file, source)

        sink_facts = [f for f in facts if f.type == "sink"]
        assert len(sink_facts) >= 1

        network_sinks = [s for s in sink_facts if s.category == "network"]
        assert len(network_sinks) >= 1
        assert any("requests" in s.sink_name for s in network_sinks)

    def test_sink_detection_file_open(self, root: Path, file: Path) -> None:
        """builtins.open or io.open is detected as file sink."""
        source = """
import builtins

def test():
    builtins.open("/etc/passwd")
"""
        facts, errors = extract_python_facts(root, file, source)

        sink_facts = [f for f in facts if f.type == "sink"]
        assert len(sink_facts) >= 1

        file_sinks = [s for s in sink_facts if s.category == "file"]
        assert len(file_sinks) >= 1

    def test_fact_type_uses_lowercase_keys(self, root: Path, file: Path) -> None:
        """All facts use lowercase type keys matching serialization protocol."""
        source = """
import subprocess

def test():
    subprocess.run(["ls"])
"""
        facts, errors = extract_python_facts(root, file, source)

        valid_types = {"function", "import", "call", "entrypoint", "source", "sink"}
        for f in facts:
            assert f.type in valid_types, f"Fact type '{f.type}' not in {valid_types}"

    def test_call_fact_caller_is_function_id(self, root: Path, file: Path) -> None:
        """CallFact.caller uses function ID format (python:<path>:<qualname>)."""
        source = """
def my_func():
    pass
"""
        facts, errors = extract_python_facts(root, file, source)

        # No calls in this source, so add one
        source2 = """
def my_func():
    import os
    os.system("ls")
"""
        facts2, _ = extract_python_facts(root, file, source2)

        call_facts = [f for f in facts2 if f.type == "call"]
        assert len(call_facts) >= 1

        for call in call_facts:
            assert call.caller.startswith("python:"), f"Caller should start with 'python:', got: {call.caller}"

    def test_file_field_is_project_relative(self, root: Path, file: Path) -> None:
        """Facts have project-relative file paths."""
        source = """
import os
"""
        facts, errors = extract_python_facts(root, file, source)

        for f in facts:
            assert f.file == "src/server.py", f"Expected 'src/server.py', got: {f.file}"


# ---------------------------------------------------------------------------
# Test class: TestPythonAstExtractorGracefulFail
# ---------------------------------------------------------------------------


class TestPythonAstExtractorGracefulFail:
    """Tests for graceful failure handling with SyntaxError or unsupported structures."""

    def test_syntax_error_returns_empty_facts_with_error(
        self, root: Path, file: Path
    ) -> None:
        """SyntaxError produces empty facts list but does not raise exception."""
        source = """
def broken(
    x =
"""
        # This should NOT raise an exception
        facts, errors = extract_python_facts(root, file, source)

        assert len(facts) == 0, "Expected no facts on syntax error"
        assert len(errors) == 1, "Expected one error on syntax error"

        error = errors[0]
        assert error.exception_type == "SyntaxError"
        assert error.line == 2

    def test_syntax_error_unclosed_paren(self, root: Path, file: Path) -> None:
        """Unclosed parenthesis produces ExtractionError without raising."""
        source = """
def func(x: str
    return x
"""
        facts, errors = extract_python_facts(root, file, source)

        assert len(facts) == 0
        assert len(errors) >= 1
        assert any(e.exception_type == "SyntaxError" for e in errors)

    def test_non_fatal_errors_listed(self, root: Path, file: Path) -> None:
        """ExtractionError list contains structured error information."""
        source = """
def bad(
"""
        facts, errors = extract_python_facts(root, file, source)

        assert len(errors) >= 1
        error = errors[0]
        assert hasattr(error, "file")
        assert hasattr(error, "line")
        assert hasattr(error, "message")
        assert hasattr(error, "exception_type")
        assert isinstance(error.message, str)
        assert isinstance(error.exception_type, str)
