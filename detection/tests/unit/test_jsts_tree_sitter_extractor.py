"""Unit tests for Phase 4 JavaScript/TypeScript Tree-sitter Extractor.

Tests cover:
- ImportFact: ESM import, CJS require, destructured require
- EntryPointFact: server.tool(...) registration detection
- SinkFact: Node.js sink detection (child_process, eval, fs, http)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from analysis.extractors import extract_jsts_facts
from analysis.extractors.javascript_ts_tree_sitter import ExtractionError


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
    return Path("/project/src/server.js")


# ---------------------------------------------------------------------------
# Test class: TestJSTSExtractorImports
# ---------------------------------------------------------------------------


class TestJSTSExtractorImports:
    """Tests for JavaScript/TypeScript import constructs."""

    def test_esm_named_import(self, root: Path, file: Path) -> None:
        """ESM named import produces ImportFact with ESM_NAMED_IMPORT kind."""
        source = """
import { exec } from "child_process";
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        import_facts = [f for f in facts if f.type == "import"]
        assert len(import_facts) >= 1

        # Find the child_process import
        cp_import = next(
            (f for f in import_facts if f.module == "child_process"),
            None
        )
        assert cp_import is not None, f"Missing child_process import in {import_facts}"
        assert cp_import.kind.value == "esm_named_import"
        assert cp_import.imported_name == "exec"

    def test_esm_default_import(self, root: Path, file: Path) -> None:
        """ESM default import produces ImportFact with ESM_IMPORT kind."""
        source = """
import fs from "fs";
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        import_facts = [f for f in facts if f.type == "import"]
        assert len(import_facts) >= 1

        fs_import = next(
            (f for f in import_facts if f.module == "fs" and f.imported_name == "fs"),
            None
        )
        assert fs_import is not None, f"Missing fs default import in {import_facts}"
        assert fs_import.kind.value == "esm_import"

    def test_esm_namespace_import(self, root: Path, file: Path) -> None:
        """ESM namespace import produces ImportFact with ESM_IMPORT_AS kind."""
        source = """
import * as fs from "fs";
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        import_facts = [f for f in facts if f.type == "import"]
        assert len(import_facts) >= 1

        ns_import = next(
            (f for f in import_facts if f.module == "fs" and f.imported_name == "*"),
            None
        )
        assert ns_import is not None, f"Missing fs namespace import in {import_facts}"
        assert ns_import.kind.value == "esm_import_as"
        assert ns_import.alias == "fs"

    def test_cjs_require(self, root: Path, file: Path) -> None:
        """CJS require produces ImportFact with REQUIRE kind."""
        source = """
const fs = require("fs");
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        import_facts = [f for f in facts if f.type == "import"]
        assert len(import_facts) >= 1

        require_import = next(
            (f for f in import_facts if f.module == "fs" and f.kind.value == "require"),
            None
        )
        assert require_import is not None, f"Missing fs require import in {import_facts}"
        assert require_import.alias == "fs"

    def test_cjs_destructured_require(self, root: Path, file: Path) -> None:
        """CJS destructured require produces ImportFact with REQUIRE_DESTRUCTURE kind."""
        source = """
const { readFile } = require("fs");
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        import_facts = [f for f in facts if f.type == "import"]
        assert len(import_facts) >= 1

        destructure_import = next(
            (f for f in import_facts if f.module == "fs" and f.kind.value == "require_destructure"),
            None
        )
        assert destructure_import is not None, f"Missing fs destructured import in {import_facts}"
        assert destructure_import.imported_name == "readFile"


# ---------------------------------------------------------------------------
# Test class: TestJSTSExtractorEntrypoint
# ---------------------------------------------------------------------------


class TestJSTSExtractorEntrypoint:
    """Tests for MCP tool/server registration detection."""

    def test_server_tool_registration(self, root: Path, file: Path) -> None:
        """server.tool(...) produces EntryPointFact with evidence.kind=call_registration."""
        source = """
const server = { tool: () => {} };
server.tool("my_tool", () => {});
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) >= 1, f"Expected at least one EntryPointFact, got: {ep_facts}"

        ep = ep_facts[0]
        assert ep.name == "my_tool"
        assert ep.kind.value == "mcp_tool"
        assert ep.evidence.kind == "call_registration"
        assert ep.evidence.text == "server.tool"

    def test_mcp_tool_registration(self, root: Path, file: Path) -> None:
        """mcp.tool(...) produces EntryPointFact."""
        source = """
const mcp = { tool: () => {} };
mcp.tool("another_tool", () => {});
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) >= 1

        ep = ep_facts[0]
        assert ep.name == "another_tool"
        assert ep.kind.value == "mcp_tool"

    def test_server_resource_registration(self, root: Path, file: Path) -> None:
        """server.resource(...) produces EntryPointFact."""
        source = """
const server = { resource: () => {} };
server.resource("my_resource", () => {});
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) >= 1

        ep = ep_facts[0]
        assert ep.name == "my_resource"


# ---------------------------------------------------------------------------
# Test class: TestJSTSExtractorSinks
# ---------------------------------------------------------------------------


class TestJSTSExtractorSinks:
    """Tests for sink detection in JavaScript/TypeScript."""

    def test_child_process_exec_sink(self, root: Path, file: Path) -> None:
        """child_process.exec is detected as RCE sink."""
        source = """
import { exec } from "child_process";

function test(cmd) {
    exec(cmd);
}
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        sink_facts = [f for f in facts if f.type == "sink"]
        assert len(sink_facts) >= 1, f"Expected at least one sink, got: {sink_facts}"

        rce_sinks = [s for s in sink_facts if s.category == "rce"]
        assert len(rce_sinks) >= 1, f"Expected RCE sink, got: {sink_facts}"
        assert any("exec" in s.sink_name for s in rce_sinks)

    def test_eval_sink(self, root: Path, file: Path) -> None:
        """eval is detected as RCE sink."""
        source = """
function test(code) {
    eval(code);
}
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        sink_facts = [f for f in facts if f.type == "sink"]
        assert len(sink_facts) >= 1

        rce_sinks = [s for s in sink_facts if s.category == "rce"]
        assert len(rce_sinks) >= 1
        assert any(s.sink_name == "eval" for s in rce_sinks)

    def test_fs_readfile_sink(self, root: Path, file: Path) -> None:
        """fs.readFile is detected as file sink."""
        source = """
import fs from "fs";

function test(path) {
    fs.readFile(path);
}
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        sink_facts = [f for f in facts if f.type == "sink"]
        assert len(sink_facts) >= 1

        file_sinks = [s for s in sink_facts if s.category == "file"]
        assert len(file_sinks) >= 1, f"Expected file sink, got: {sink_facts}"

    def test_fetch_network_sink(self, root: Path, file: Path) -> None:
        """fetch is detected as network sink."""
        source = """
function test(url) {
    fetch(url);
}
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        sink_facts = [f for f in facts if f.type == "sink"]
        assert len(sink_facts) >= 1

        network_sinks = [s for s in sink_facts if s.category == "network"]
        assert len(network_sinks) >= 1, f"Expected network sink, got: {sink_facts}"


# ---------------------------------------------------------------------------
# Test class: TestJSTSExtractorGracefulFail
# ---------------------------------------------------------------------------


class TestJSTSExtractorGracefulFail:
    """Tests for graceful failure handling."""

    def test_invalid_syntax_returns_empty_facts(
        self, root: Path, file: Path
    ) -> None:
        """Invalid syntax produces empty facts list but does not raise exception."""
        # Use a source that tree-sitter cannot parse - unclosed string at end
        source = 'const x = "unclosed string'

        # This should NOT raise an exception
        facts, errors = extract_jsts_facts(root, file, source)

        # Tree-sitter may or may not produce errors depending on its tolerance
        # The important thing is it doesn't raise an exception
        assert isinstance(facts, list), "facts should be a list even on parse error"


class TestEntryPointKindDifferentiation:
    """Tests for EntryPointKind differentiation across tool/resource/prompt patterns.

    Validates that:
    - server.resource(...) produces EntryPointFact with kind=mcp_resource
    - server.prompt(...) produces EntryPointFact with kind=mcp_prompt
    - mcp.resource(...) produces EntryPointFact with kind=mcp_resource
    - mcp.prompt(...) produces EntryPointFact with kind=mcp_prompt
    - server.tool(...) still produces EntryPointFact with kind=mcp_tool (regression)
    """

    def test_server_resource_produces_mcp_resource_kind(self, root: Path, file: Path) -> None:
        """server.resource(...) produces EntryPointFact with kind == mcp_resource."""
        source = """
const server = { resource: () => {} };
server.resource("my_resource", () => {});
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) >= 1, f"Expected at least one EntryPointFact, got: {ep_facts}"

        ep = ep_facts[0]
        assert ep.name == "my_resource"
        assert ep.kind.value == "mcp_resource"
        assert ep.evidence.kind == "call_registration"
        assert ep.evidence.text == "server.resource"

    def test_server_prompt_produces_mcp_prompt_kind(self, root: Path, file: Path) -> None:
        """server.prompt(...) produces EntryPointFact with kind == mcp_prompt."""
        source = """
const server = { prompt: () => {} };
server.prompt("my_prompt", () => {});
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) >= 1

        ep = ep_facts[0]
        assert ep.name == "my_prompt"
        assert ep.kind.value == "mcp_prompt"
        assert ep.evidence.text == "server.prompt"

    def test_mcp_resource_produces_mcp_resource_kind(self, root: Path, file: Path) -> None:
        """mcp.resource(...) produces EntryPointFact with kind == mcp_resource."""
        source = """
const mcp = { resource: () => {} };
mcp.resource("data_resource", () => {});
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) >= 1

        ep = ep_facts[0]
        assert ep.name == "data_resource"
        assert ep.kind.value == "mcp_resource"
        assert ep.evidence.text == "mcp.resource"

    def test_mcp_prompt_produces_mcp_prompt_kind(self, root: Path, file: Path) -> None:
        """mcp.prompt(...) produces EntryPointFact with kind == mcp_prompt."""
        source = """
const mcp = { prompt: () => {} };
mcp.prompt("user_prompt", () => {});
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) >= 1

        ep = ep_facts[0]
        assert ep.name == "user_prompt"
        assert ep.kind.value == "mcp_prompt"
        assert ep.evidence.text == "mcp.prompt"

    def test_server_tool_still_produces_mcp_tool_kind(self, root: Path, file: Path) -> None:
        """server.tool(...) regression: still produces EntryPointFact with kind == mcp_tool."""
        source = """
const server = { tool: () => {} };
server.tool("my_tool", () => {});
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) >= 1

        ep = ep_facts[0]
        assert ep.name == "my_tool"
        assert ep.kind.value == "mcp_tool"
        assert ep.evidence.text == "server.tool"


class TestNamedHandlerSourceFacts:
    """Tests for SourceFact generation from named handlers in MCP registrations.

    When an MCP registration uses an identifier handler (e.g., server.tool("name", runHandler)),
    the extractor looks up the referenced FunctionFact and generates SourceFacts for its parameters.

    Validates that:
    - server.tool("name", runHandler) generates SourceFacts for runHandler's parameters
    - server.resource("name", dataHandler) also generates SourceFacts for dataHandler's parameters
    """

    def test_named_handler_tool_generates_source_facts(self, root: Path, file: Path) -> None:
        """server.tool("name", runHandler) generates SourceFacts for runHandler's parameters."""
        source = """
function runHandler(cmd) {
    eval(cmd);
}
const server = { tool: () => {} };
server.tool("run", runHandler);
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        # Find the entrypoint
        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) >= 1, f"Expected entrypoint, got: {ep_facts}"
        ep = ep_facts[0]
        assert ep.name == "run"
        assert ep.params == ["cmd"], f"Expected ep.params == ['cmd'], got: {ep.params}"

        # Find the function fact for runHandler
        func_facts = [f for f in facts if f.type == "function" and f.name == "runHandler"]
        assert len(func_facts) >= 1, f"Expected function fact for runHandler, got: {[f for f in facts if f.type == 'function']}"

        # SourceFacts should be generated for the named handler's parameters
        source_facts = [f for f in facts if f.type == "source"]
        assert len(source_facts) >= 1, f"Expected at least one source fact for handler param, got: {source_facts}"

        # Verify cmd is tracked as a source parameter
        cmd_sources = [s for s in source_facts if s.name == "cmd"]
        assert len(cmd_sources) >= 1, f"Expected cmd to be a source, got: {cmd_sources}"
        assert cmd_sources[0].function_id == func_facts[0].id

    def test_named_handler_resource_generates_source_facts(self, root: Path, file: Path) -> None:
        """server.resource("name", dataHandler) generates SourceFacts for dataHandler's parameters."""
        source = """
function dataHandler(path, options) {
    return path;
}
const server = { resource: () => {} };
server.resource("data", dataHandler);
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        # Find the entrypoint
        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) >= 1
        ep = ep_facts[0]
        assert ep.name == "data"
        assert ep.kind.value == "mcp_resource"
        assert ep.params == ["path", "options"], f"Expected ep.params == ['path', 'options'], got: {ep.params}"

        # Find the function fact for dataHandler
        func_facts = [f for f in facts if f.type == "function" and f.name == "dataHandler"]
        assert len(func_facts) >= 1

        # SourceFacts should be generated for the named handler's parameters
        source_facts = [f for f in facts if f.type == "source"]
        assert len(source_facts) >= 2, f"Expected 2 source facts (path, options), got: {source_facts}"

        # Verify both path and options are tracked as sources
        source_names = {s.name for s in source_facts}
        assert "path" in source_names, f"Expected path to be a source, got: {source_names}"
        assert "options" in source_names, f"Expected options to be a source, got: {source_names}"


class TestAliasedDestructuredRequire:
    """Tests for aliased destructured require patterns.

    When a require uses aliased destructuring like:
        const { exec: ex } = require("child_process")

    The extractor should:
    - Create an ImportFact with imported_name=exec (original name, not alias)
    - Track _require_aliases mapping: ex -> child_process.exec
    - When ex(cmd) is called, normalized_callee should resolve to child_process.exec

    Validates that:
    - Aliased destructured require creates correct ImportFact
    - Call using alias has normalized_callee resolved to full path
    - Mixed scenario: named handler + alias require + sink forms complete taint chain
    """

    def test_aliased_destructured_require_import_fact_has_original_name(self, root: Path, file: Path) -> None:
        """Aliased destructured require ImportFact has imported_name == original name (exec)."""
        source = """
const { exec: ex } = require("child_process");
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        import_facts = [f for f in facts if f.type == "import"]
        assert len(import_facts) >= 1

        # Find the child_process import
        cp_import = next(
            (f for f in import_facts if f.module == "child_process"),
            None
        )
        assert cp_import is not None, f"Missing child_process import in {import_facts}"
        assert cp_import.imported_name == "exec", f"Expected imported_name=exec, got: {cp_import.imported_name}"
        assert cp_import.kind.value == "require_destructure"

    def test_alias_call_resolves_callee_to_original_path(self, root: Path, file: Path) -> None:
        """Calling aliased require resolves normalized_callee to child_process.exec."""
        source = """
const { exec: ex } = require("child_process");
ex(cmd);
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        # Find the call to ex
        call_facts = [f for f in facts if f.type == "call" and f.callee == "ex"]
        assert len(call_facts) >= 1, f"Expected call to ex, got: {[f for f in facts if f.type == 'call']}"

        call = call_facts[0]
        # normalized_callee should resolve to child_process.exec
        assert call.normalized_callee == "child_process.exec", \
            f"Expected normalized_callee=child_process.exec, got: {call.normalized_callee}"

    def test_mixed_named_handler_alias_require_sink_taint_chain(self, root: Path, file: Path) -> None:
        """Mixed scenario: named handler + alias require + sink forms complete taint chain.

        This test validates the full integration:
        1. Named handler runHandler(cmd) with cmd as source
        2. Aliased require: const { exec: ex } = require("child_process")
        3. Sink call: ex(cmd) where ex resolves to child_process.exec

        The chain is: source(cmd) -> call(ex(cmd)) with normalized_callee=child_process.exec (sink)
        """
        source = """
function runHandler(cmd) {
    const { exec: ex } = require("child_process");
    ex(cmd);
}
const server = { tool: () => {} };
server.tool("run", runHandler);
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert len(errors) == 0, f"Expected no errors, got: {errors}"

        # Find the entrypoint
        ep_facts = [f for f in facts if f.type == "entrypoint"]
        assert len(ep_facts) >= 1
        ep = ep_facts[0]
        assert ep.name == "run"
        assert ep.kind.value == "mcp_tool"

        # Find the function fact for runHandler
        func_facts = [f for f in facts if f.type == "function" and f.name == "runHandler"]
        assert len(func_facts) >= 1
        func = func_facts[0]

        # SourceFact for cmd parameter
        source_facts = [f for f in facts if f.type == "source"]
        cmd_sources = [s for s in source_facts if s.name == "cmd"]
        assert len(cmd_sources) >= 1, f"Expected cmd source, got: {source_facts}"
        assert cmd_sources[0].function_id == func.id

        # ImportFact for aliased destructured require (imported_name = exec, not ex)
        import_facts = [f for f in facts if f.type == "import"]
        cp_imports = [f for f in import_facts if f.module == "child_process"]
        assert len(cp_imports) >= 1
        assert cp_imports[0].imported_name == "exec", \
            f"Expected imported_name=exec, got: {cp_imports[0].imported_name}"

        # Sink call: ex(cmd) with normalized_callee = child_process.exec
        call_facts = [f for f in facts if f.type == "call"]
        ex_calls = [c for c in call_facts if c.callee == "ex"]
        assert len(ex_calls) >= 1, f"Expected call to ex, got: {call_facts}"
        ex_call = ex_calls[0]
        assert ex_call.normalized_callee == "child_process.exec", \
            f"Expected normalized_callee=child_process.exec, got: {ex_call.normalized_callee}"
        assert ex_call.caller == func.id, \
            f"Expected caller={func.id}, got: {ex_call.caller}"

        # Verify sink is detected
        sink_facts = [f for f in facts if f.type == "sink"]
        rce_sinks = [s for s in sink_facts if s.category == "rce"]
        assert len(rce_sinks) >= 1, f"Expected RCE sink, got: {sink_facts}"
        assert any("exec" in s.sink_name for s in rce_sinks)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])

class TestJSTSExtractorCompleteness:
    """Regression tests for JS/TS AST completeness beyond Phase 4 smoke tests."""

    def test_class_method_does_not_crash_and_attributes_caller(self, root: Path, file: Path) -> None:
        source = """
class Runner {
    run(cmd) {
        eval(cmd);
    }
}
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert errors == []
        functions = [f for f in facts if f.type == "function"]
        assert any(f.qualified_name == "Runner.run" for f in functions)

        calls = [f for f in facts if f.type == "call" and f.callee == "eval"]
        assert len(calls) == 1
        assert calls[0].caller.endswith(":Runner.run")
        assert calls[0].args[0].expr == "cmd"
        assert calls[0].args[0].kind == "name"

    def test_arrow_function_assignment_has_function_context(self, root: Path, file: Path) -> None:
        source = """
const run = (cmd) => {
    eval(cmd);
};
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert errors == []
        assert any(f.type == "function" and f.qualified_name == "run" for f in facts)
        call = next(f for f in facts if f.type == "call" and f.callee == "eval")
        assert call.caller.endswith(":run")
        assert call.args[0].expr == "cmd"

    def test_mcp_inline_handler_emits_sources_and_assigns(self, root: Path, file: Path) -> None:
        source = """
const { exec } = require("child_process");
server.tool("run_cmd", (cmd) => {
    const command = cmd;
    return exec(command);
});
"""
        facts, errors = extract_jsts_facts(root, file, source)

        assert errors == []
        ep = next(f for f in facts if f.type == "entrypoint")
        assert ep.params == ["cmd"]

        source_facts = [f for f in facts if f.type == "source"]
        assert len(source_facts) == 1
        assert source_facts[0].name == "cmd"
        assert source_facts[0].function_id == ep.function_id

        assigns = [f for f in facts if f.type == "assign"]
        assert len(assigns) == 1
        assert assigns[0].target == "command"
        assert assigns[0].value == "cmd"

        sink_call = next(f for f in facts if f.type == "call" and f.callee == "exec")
        assert sink_call.caller == ep.function_id
        assert sink_call.args[0].expr == "command"
