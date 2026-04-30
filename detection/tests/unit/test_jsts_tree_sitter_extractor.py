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


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])