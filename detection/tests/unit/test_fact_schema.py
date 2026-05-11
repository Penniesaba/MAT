"""Unit tests for AST Security Analysis Framework - Phase 1 Fact Schema.

Tests cover:
- Schema: All 9 Fact types and 7 Enum classes
- IDs: Deterministic ID generation for all fact types
- Store: FactStore CRUD operations and error handling
- Serialization: JSON/JSONL roundtrip with nested dataclasses
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from analysis.facts import ids
from analysis.facts.schema import (
    CallArg,
    CallFact,
    CallKwarg,
    CallResolution,
    Confidence,
    DataFlowFact,
    EntryPointEvidence,
    EntryPointFact,
    EntryPointKind,
    Fact,
    FindingFact,
    FindingStatus,
    FunctionFact,
    ImportFact,
    ImportKind,
    ParamInfo,
    PathStep,
    PathStepKind,
    RuntimeEventFact,
    RuntimeEventKind,
    SCHEMA_VERSION,
    Severity,
    SinkFact,
    SourceFact,
)
from analysis.facts.serialization import (
    deserialize_facts,
    fact_to_dict,
    serialize_facts,
)
from analysis.facts.store import DuplicateFactError, FactStore


# ---------------------------------------------------------------------------
# Test class: TestSchema
# ---------------------------------------------------------------------------


class TestSchema:
    """Test Fact type definitions and schema constants."""

    def test_schema_version_constant(self) -> None:
        """SCHEMA_VERSION is defined as '1.0.0'."""
        assert SCHEMA_VERSION == "1.0.0"

    def test_function_fact_fields(self) -> None:
        """FunctionFact has all required fields and can be instantiated."""
        fact = FunctionFact(
            type="function",
            id="python:src/server.py:run_cmd",
            language="python",
            name="run_cmd",
            qualified_name="server.run_cmd",
            file="src/server.py",
            line=10,
            end_line=18,
            params=[ParamInfo(name="cmd", annotation="str", default=None)],
            decorators=["mcp.tool"],
            docstring="Run a shell command",
            enclosing_class=None,
            extractor="python_ast",
        )
        assert fact.type == "function"
        assert fact.id == "python:src/server.py:run_cmd"
        assert fact.language == "python"
        assert fact.name == "run_cmd"
        assert fact.qualified_name == "server.run_cmd"
        assert fact.file == "src/server.py"
        assert fact.line == 10
        assert fact.end_line == 18
        assert len(fact.params) == 1
        assert fact.params[0].name == "cmd"
        assert fact.decorators == ["mcp.tool"]
        assert fact.docstring == "Run a shell command"
        assert fact.enclosing_class is None
        assert fact.extractor == "python_ast"

    def test_import_fact_with_all_kinds(self) -> None:
        """ImportFact can be instantiated with all ImportKind variants."""
        for kind in ImportKind:
            fact = ImportFact(
                type="import",
                id=f"import:src/server.py:1:{kind.value}",
                language="python",
                file="src/server.py",
                line=1,
                module="subprocess",
                imported_name=None,
                alias=None,
                kind=kind,
                extractor="python_ast",
            )
            assert fact.kind == kind
            assert isinstance(fact.kind, ImportKind)

    def test_entrypoint_fact(self) -> None:
        """EntryPointFact has all required fields."""
        evidence = EntryPointEvidence(kind="decorator", text="@mcp.tool()")
        fact = EntryPointFact(
            type="entrypoint",
            id="entry:src/server.py:run_cmd",
            kind=EntryPointKind.MCP_TOOL,
            name="run_cmd",
            function_id="python:src/server.py:run_cmd",
            file="src/server.py",
            line=9,
            evidence=evidence,
            params=["cmd"],
            confidence=Confidence.HIGH,
            extractor="python_ast",
        )
        assert fact.type == "entrypoint"
        assert fact.kind == EntryPointKind.MCP_TOOL
        assert fact.name == "run_cmd"
        assert fact.function_id == "python:src/server.py:run_cmd"
        assert fact.evidence is not None
        assert fact.evidence.kind == "decorator"
        assert fact.params == ["cmd"]
        assert fact.confidence == Confidence.HIGH

    def test_call_fact_with_nested_args(self) -> None:
        """CallFact with CallArg, CallKwarg, and CallResolution nested structures."""
        call_arg = CallArg(index=0, expr="cmd", kind="name")
        call_kwarg = CallKwarg(expr="shell", value=True)
        resolution = CallResolution(import_alias="subprocess", confidence=Confidence.HIGH)

        fact = CallFact(
            type="call",
            id="call:src/server.py:15:4",
            caller="python:src/server.py:run_cmd",
            callee="subprocess.run",
            normalized_callee="python:subprocess.run",
            file="src/server.py",
            line=15,
            column=4,
            end_line=15,
            snippet="subprocess.run(cmd, shell=True)",
            args=[call_arg],
            kwargs={"shell": call_kwarg},
            resolution=resolution,
            extractor="python_ast",
        )
        assert fact.caller == "python:src/server.py:run_cmd"
        assert fact.callee == "subprocess.run"
        assert len(fact.args) == 1
        assert fact.args[0].index == 0
        assert fact.kwargs["shell"].value is True
        assert fact.resolution is not None
        assert fact.resolution.import_alias == "subprocess"

    def test_sink_fact(self) -> None:
        """SinkFact has all required fields including conditions and severity."""
        fact = SinkFact(
            type="sink",
            id="sink:rce:src/server.py:15",
            call_id="call:src/server.py:15:4",
            category="rce",
            rule_id="python.rce.subprocess_shell",
            sink_name="subprocess.run",
            severity_base=Severity.CRITICAL,
            reason="subprocess.run with shell=True may execute attacker-controlled shell commands",
            conditions={"shell": True},
            confidence=Confidence.HIGH,
            file="src/server.py",
            line=15,
            extractor="python_ast",
        )
        assert fact.category == "rce"
        assert fact.rule_id == "python.rce.subprocess_shell"
        assert fact.severity_base == Severity.CRITICAL
        assert fact.conditions["shell"] is True
        assert fact.confidence == Confidence.HIGH

    def test_source_fact(self) -> None:
        """SourceFact represents an untrusted input source."""
        fact = SourceFact(
            type="source",
            id="source:src/server.py:run_cmd:cmd",
            kind="mcp_tool_parameter",
            function_id="python:src/server.py:run_cmd",
            name="cmd",
            file="src/server.py",
            line=10,
            confidence=Confidence.HIGH,
            extractor="python_ast",
        )
        assert fact.kind == "mcp_tool_parameter"
        assert fact.function_id == "python:src/server.py:run_cmd"
        assert fact.name == "cmd"
        assert fact.confidence == Confidence.HIGH

    def test_dataflow_fact_with_path_steps(self) -> None:
        """DataFlowFact with multiple PathStep entries showing data propagation."""
        path = [
            PathStep(
                kind=PathStepKind.PARAM,
                line=10,
                name="cmd",
                function="run_cmd",
            ),
            PathStep(
                kind=PathStepKind.ASSIGN,
                line=12,
                from_="cmd",
                to="command",
                snippet="command = cmd.strip()",
            ),
            PathStep(
                kind=PathStepKind.CALL_ARG,
                line=15,
                call_id="call:src/server.py:15:4",
                arg_index=0,
            ),
        ]
        fact = DataFlowFact(
            type="dataflow",
            id="flow:cmd-to-subprocess",
            source_id="source:src/server.py:run_cmd:cmd",
            sink_id="sink:rce:src/server.py:15",
            path=path,
            confidence=Confidence.HIGH,
            file="src/server.py",
            line=10,
            extractor="python_ast",
        )
        assert fact.source_id == "source:src/server.py:run_cmd:cmd"
        assert fact.sink_id == "sink:rce:src/server.py:15"
        assert len(fact.path) == 3
        assert fact.path[0].kind == PathStepKind.PARAM
        assert fact.path[1].kind == PathStepKind.ASSIGN
        assert fact.path[1].from_ == "cmd"
        assert fact.path[2].kind == PathStepKind.CALL_ARG

    def test_runtime_event_fact(self) -> None:
        """RuntimeEventFact captures dynamic testing evidence."""
        fact = RuntimeEventFact(
            type="runtime_event",
            id="runtime:execve:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="execve",
            command="/bin/sh -c whoami",
            pid=12345,
            container_id="abc",
            timestamp="2026-04-29T10:00:00Z",
            correlated_entrypoint="entry:src/server.py:run_cmd",
            correlated_sink="sink:rce:src/server.py:15",
            confidence=Confidence.MEDIUM,
            file="src/server.py",
            line=0,
            extractor="dynamic_trace",
        )
        assert fact.kind == RuntimeEventKind.PROCESS_EXEC
        assert fact.syscall == "execve"
        assert fact.command == "/bin/sh -c whoami"
        assert fact.pid == 12345
        assert fact.container_id == "abc"
        assert fact.correlated_entrypoint == "entry:src/server.py:run_cmd"
        assert fact.correlated_sink == "sink:rce:src/server.py:15"
        assert fact.confidence == Confidence.MEDIUM

    def test_finding_fact(self) -> None:
        """FindingFact is the final risk conclusion with correlated evidence."""
        fact = FindingFact(
            type="finding",
            id="finding:rce:run_cmd",
            title="MCP tool run_cmd can execute shell commands",
            category="rce",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            entrypoint_id="entry:src/server.py:run_cmd",
            sink_id="sink:rce:src/server.py:15",
            call_chain=[
                {
                    "function": "run_cmd",
                    "file": "src/server.py",
                    "line": 10,
                },
                {
                    "callee": "subprocess.run",
                    "file": "src/server.py",
                    "line": 15,
                    "snippet": "subprocess.run(cmd, shell=True)",
                },
            ],
            dataflows=["flow:cmd-to-subprocess"],
            dynamic_evidence=["runtime:execve:12345"],
            evidence=[
                "entry:src/server.py:run_cmd",
                "call:src/server.py:15:4",
                "sink:rce:src/server.py:15",
            ],
            recommendation="Avoid shell=True and pass a fixed argument list to subprocess.run.",
            file="src/server.py",
            line=15,
            extractor="analysis_pass",
        )
        assert fact.title == "MCP tool run_cmd can execute shell commands"
        assert fact.category == "rce"
        assert fact.severity == Severity.CRITICAL
        assert fact.confidence == Confidence.HIGH
        assert fact.status == FindingStatus.CONFIRMED
        assert fact.entrypoint_id == "entry:src/server.py:run_cmd"
        assert len(fact.call_chain) == 2
        assert "flow:cmd-to-subprocess" in fact.dataflows

    def test_all_enums_have_expected_values(self) -> None:
        """All 7 enums have the correct predefined values."""
        assert list(ImportKind) == [
            ImportKind.IMPORT,
            ImportKind.IMPORT_AS,
            ImportKind.FROM_IMPORT,
            ImportKind.FROM_IMPORT_AS,
            ImportKind.REQUIRE,
            ImportKind.REQUIRE_DESTRUCTURE,
            ImportKind.ESM_IMPORT,
            ImportKind.ESM_IMPORT_AS,
            ImportKind.ESM_NAMED_IMPORT,
        ]
        assert list(Confidence) == [
            Confidence.HIGH,
            Confidence.MEDIUM,
            Confidence.LOW,
        ]
        assert list(Severity) == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]
        assert list(FindingStatus) == [
            FindingStatus.POTENTIAL,
            FindingStatus.CONFIRMED,
            FindingStatus.RUNTIME_ONLY,
        ]
        assert list(EntryPointKind) == [
            EntryPointKind.MCP_TOOL,
            EntryPointKind.MCP_RESOURCE,
            EntryPointKind.MCP_PROMPT,
        ]
        assert list(PathStepKind) == [
            PathStepKind.PARAM,
            PathStepKind.ASSIGN,
            PathStepKind.RETURN,
            PathStepKind.CALL_ARG,
            PathStepKind.FIELD_ACCESS,
        ]
        assert list(RuntimeEventKind) == [
            RuntimeEventKind.PROCESS_EXEC,
            RuntimeEventKind.FILE_ACCESS,
            RuntimeEventKind.NETWORK_CONNECT,
        ]


# ---------------------------------------------------------------------------
# Test class: TestIds
# ---------------------------------------------------------------------------


class TestIds:
    """Test deterministic ID generation functions."""

    _root = Path("/project")
    _server_py = Path("/project/src/server.py")
    _index_js = Path("/project/src/index.js")

    def test_make_function_id(self) -> None:
        """make_function_id generates format: <language>:<relative_path>:<name>."""
        result = ids.make_function_id("python", self._root, self._server_py, "run_cmd")
        assert result == "python:src/server.py:run_cmd"

    def test_make_import_id(self) -> None:
        """make_import_id generates format: import:<relative_path>:<line>:<imported_name>."""
        result = ids.make_import_id(self._root, self._server_py, 1, "subprocess")
        assert result == "import:src/server.py:1:subprocess"

    def test_make_entrypoint_id(self) -> None:
        """make_entrypoint_id generates format: entry:<relative_path>:<name>."""
        result = ids.make_entrypoint_id(self._root, self._server_py, "run_cmd")
        assert result == "entry:src/server.py:run_cmd"

    def test_make_call_id(self) -> None:
        """make_call_id generates format: call:<relative_path>:<line>:<column>."""
        result = ids.make_call_id(self._root, self._server_py, 15, 4)
        assert result == "call:src/server.py:15:4"

    def test_make_sink_id(self) -> None:
        """make_sink_id generates format: sink:<category>:<relative_path>:<line>."""
        result = ids.make_sink_id("rce", self._root, self._server_py, 15)
        assert result == "sink:rce:src/server.py:15"

    def test_make_source_id(self) -> None:
        """make_source_id generates format: source:<relative_path>:<function_name>:<param_name>."""
        result = ids.make_source_id(self._root, self._server_py, "run_cmd", "cmd")
        assert result == "source:src/server.py:run_cmd:cmd"

    def test_make_dataflow_id(self) -> None:
        """make_dataflow_id generates format: flow:<source_name>-to-<sink_name>."""
        result = ids.make_dataflow_id("cmd", "subprocess")
        assert result == "flow:cmd-to-subprocess"

    def test_make_runtime_event_id(self) -> None:
        """make_runtime_event_id generates format: runtime:<syscall>:<pid>."""
        result = ids.make_runtime_event_id("execve", 12345)
        assert result == "runtime:execve:12345"

    def test_make_finding_id(self) -> None:
        """make_finding_id generates format: finding:<category>:<name>."""
        result = ids.make_finding_id("rce", "run_cmd")
        assert result == "finding:rce:run_cmd"

    def test_same_filename_different_dirs_no_conflict(self) -> None:
        """Same filename in different directories produces different IDs."""
        root = Path("/project")
        file_a = Path("/project/src/utils/helper.py")
        file_b = Path("/project/lib/utils/helper.py")

        id_a = ids.make_function_id("python", root, file_a, "process")
        id_b = ids.make_function_id("python", root, file_b, "process")

        assert id_a == "python:src/utils/helper.py:process"
        assert id_b == "python:lib/utils/helper.py:process"
        assert id_a != id_b

    def test_posix_paths(self) -> None:
        """Windows-style backslash paths are converted to forward slashes."""
        root = Path("C:/project")
        file = Path("C:/project/src/server.py")

        result = ids.make_function_id("python", root, file, "run_cmd")
        # The backslash in 'src\server.py' (Windows) should become 'src/server.py'
        assert "\\" not in result
        assert result == "python:src/server.py:run_cmd"

    def test_dataflow_id_with_hyphen_in_name(self) -> None:
        """Dataflow IDs handle source/sink names containing hyphens."""
        result = ids.make_dataflow_id("my-source", "my-sink")
        assert result == "flow:my-source-to-my-sink"


# ---------------------------------------------------------------------------
# Test class: TestFactStore
# ---------------------------------------------------------------------------


class TestFactStore:
    """Test FactStore CRUD operations, querying, and error handling."""

    def _make_function_fact(self, fact_id: str) -> FunctionFact:
        return FunctionFact(
            type="function",
            id=fact_id,
            language="python",
            name="test_func",
            qualified_name="test_func",
            file="src/test.py",
            line=1,
            extractor="test",
        )

    def test_add_and_get(self) -> None:
        """add() stores a fact and get() retrieves it by ID."""
        store = FactStore()
        fact = self._make_function_fact("python:src/test.py:test_func")
        store.add(fact)

        result = store.get("python:src/test.py:test_func")
        assert result is not None
        assert result.id == "python:src/test.py:test_func"
        assert result.type == "function"

    def test_add_all(self) -> None:
        """add_all() stores multiple facts at once."""
        store = FactStore()
        facts = [
            self._make_function_fact("python:src/test.py:func_a"),
            self._make_function_fact("python:src/test.py:func_b"),
        ]
        store.add_all(facts)

        assert store.count() == 2
        assert store.get("python:src/test.py:func_a") is not None
        assert store.get("python:src/test.py:func_b") is not None

    def test_duplicate_raises_error(self) -> None:
        """Adding a fact with an existing ID raises DuplicateFactError."""
        store = FactStore()
        fact = self._make_function_fact("python:src/test.py:test_func")
        store.add(fact)

        with pytest.raises(DuplicateFactError) as exc_info:
            store.add(fact)
        assert exc_info.value.fact_id == "python:src/test.py:test_func"
        assert exc_info.value.existing_type == "function"
        assert exc_info.value.new_type == "function"

    def test_add_or_update_replaces(self) -> None:
        """add_or_update() replaces an existing fact with the same ID."""
        store = FactStore()
        fact1 = self._make_function_fact("python:src/test.py:test_func")
        fact1.docstring = "Original docstring"
        store.add(fact1)

        fact2 = self._make_function_fact("python:src/test.py:test_func")
        fact2.docstring = "Updated docstring"
        store.add_or_update(fact2)

        result = store.get("python:src/test.py:test_func")
        assert result is not None
        assert result.docstring == "Updated docstring"

    def test_has_id(self) -> None:
        """has_id() returns True for existing IDs, False otherwise."""
        store = FactStore()
        fact = self._make_function_fact("python:src/test.py:test_func")
        store.add(fact)

        assert store.has_id("python:src/test.py:test_func") is True
        assert store.has_id("python:src/test.py:nonexistent") is False

    def test_get_nonexistent_returns_none(self) -> None:
        """get() returns None for IDs that do not exist."""
        store = FactStore()
        result = store.get("python:src/test.py:nonexistent")
        assert result is None

    def test_remove(self) -> None:
        """remove() deletes a fact by ID and returns True."""
        store = FactStore()
        fact = self._make_function_fact("python:src/test.py:test_func")
        store.add(fact)

        result = store.remove("python:src/test.py:test_func")
        assert result is True
        assert store.has_id("python:src/test.py:test_func") is False
        assert store.count() == 0

    def test_remove_nonexistent(self) -> None:
        """remove() returns False when ID does not exist."""
        store = FactStore()
        result = store.remove("python:src/test.py:nonexistent")
        assert result is False

    def test_query_by_type(self) -> None:
        """query(type=...) filters facts by type."""
        store = FactStore()
        store.add(self._make_function_fact("python:src/test.py:func_a"))
        entry = EntryPointFact(
            type="entrypoint",
            id="entry:src/test.py:func_b",
            name="func_b",
            function_id="python:src/test.py:func_b",
            file="src/test.py",
            line=10,
            extractor="test",
        )
        store.add(entry)

        results = store.query(type="function")
        assert len(results) == 1
        assert results[0].type == "function"

    def test_query_by_file(self) -> None:
        """query(file=...) filters facts by exact file path."""
        store = FactStore()
        fact_a = self._make_function_fact("python:src/a.py:func")
        fact_a.file = "src/a.py"
        fact_b = self._make_function_fact("python:src/b.py:func")
        fact_b.file = "src/b.py"
        store.add(fact_a)
        store.add(fact_b)

        results = store.query(file="src/a.py")
        assert len(results) == 1
        assert results[0].file == "src/a.py"

    def test_query_by_language(self) -> None:
        """query(language=...) filters facts by language attribute."""
        store = FactStore()
        py_fact = self._make_function_fact("python:src/test.py:func")
        py_fact.language = "python"
        store.add(py_fact)

        js_fact = FunctionFact(
            type="function",
            id="js:src/test.js:func",
            language="javascript",
            name="func",
            qualified_name="func",
            file="src/test.js",
            line=1,
            extractor="test",
        )
        store.add(js_fact)

        results = store.query(language="python")
        assert len(results) == 1
        assert results[0].language == "python"

    def test_all_facts(self) -> None:
        """all_facts() returns a list of all stored facts."""
        store = FactStore()
        facts = [
            self._make_function_fact("python:src/test.py:func_a"),
            self._make_function_fact("python:src/test.py:func_b"),
        ]
        store.add_all(facts)

        all_facts = store.all_facts()
        assert len(all_facts) == 2

    def test_count_and_len(self) -> None:
        """count() and len() both return the number of stored facts."""
        store = FactStore()
        assert store.count() == 0
        assert len(store) == 0

        store.add(self._make_function_fact("python:src/test.py:func_a"))
        store.add(self._make_function_fact("python:src/test.py:func_b"))
        assert store.count() == 2
        assert len(store) == 2

    def test_clear(self) -> None:
        """clear() removes all facts from the store."""
        store = FactStore()
        store.add(self._make_function_fact("python:src/test.py:func_a"))
        store.add(self._make_function_fact("python:src/test.py:func_b"))
        assert store.count() == 2

        store.clear()
        assert store.count() == 0
        assert len(store) == 0

    def test_contains(self) -> None:
        """__contains__ allows 'in' operator to check fact existence."""
        store = FactStore()
        fact = self._make_function_fact("python:src/test.py:test_func")
        store.add(fact)

        assert "python:src/test.py:test_func" in store
        assert "python:src/test.py:nonexistent" not in store

    def test_iter(self) -> None:
        """__iter__ allows iterating over all facts."""
        store = FactStore()
        fact_a = self._make_function_fact("python:src/test.py:func_a")
        fact_b = self._make_function_fact("python:src/test.py:func_b")
        store.add(fact_a)
        store.add(fact_b)

        iterated = list(store)
        assert len(iterated) == 2
        assert fact_a in iterated
        assert fact_b in iterated


# ---------------------------------------------------------------------------
# Test class: TestSerialization
# ---------------------------------------------------------------------------


class TestSerialization:
    """Test JSON/JSONL serialization and deserialization with roundtrip verification."""

    def _roundtrip(self, fact: Fact, format: str = "json") -> Fact:
        """Serialize a fact to string then deserialize it back."""
        serialized = serialize_facts([fact], format)
        restored = deserialize_facts(serialized, format)
        assert len(restored) == 1
        return restored[0]

    def test_fact_to_dict_has_schema_version(self) -> None:
        """fact_to_dict includes schema_version in the output dict."""
        fact = FunctionFact(
            type="function",
            id="python:src/test.py:test",
            language="python",
            name="test",
            qualified_name="test",
            file="src/test.py",
            line=1,
            extractor="test",
        )
        d = fact_to_dict(fact)
        assert "schema_version" in d
        assert d["schema_version"] == SCHEMA_VERSION

    def test_enums_serialize_to_strings(self) -> None:
        """Enum values are serialized as their .value string."""
        fact = SinkFact(
            type="sink",
            id="sink:rce:src/test.py:1",
            call_id="call:src/test.py:1:1",
            category="rce",
            rule_id="test",
            sink_name="test",
            severity_base=Severity.CRITICAL,
            reason="test",
            conditions={},
            confidence=Confidence.HIGH,
            file="src/test.py",
            line=1,
            extractor="test",
        )
        d = fact_to_dict(fact)
        assert d["severity_base"] == "critical"
        assert d["confidence"] == "high"
        assert isinstance(d["severity_base"], str)
        assert isinstance(d["confidence"], str)

    def test_pathstep_from_serializes_to_from(self) -> None:
        """PathStep.from_ field serializes as 'from' in JSON (not 'from_')."""
        fact = DataFlowFact(
            type="dataflow",
            id="df:test:1",
            file="test.py",
            line=1,
            source_id="src:1",
            sink_id="sink:1",
            path=[
                PathStep(
                    kind=PathStepKind.ASSIGN,
                    line=12,
                    from_="cmd",
                    to="command",
                    snippet="command = cmd.strip()",
                ),
            ],
        )
        d = fact_to_dict(fact)
        assert "from" in d["path"][0]
        assert d["path"][0]["from"] == "cmd"
        assert "from_" not in d["path"][0]

    def test_nested_dataclass_serialization(self) -> None:
        """Nested dataclasses (ParamInfo, CallArg, CallKwarg, etc.) serialize correctly."""
        fact = FunctionFact(
            type="function",
            id="python:src/server.py:run_cmd",
            language="python",
            name="run_cmd",
            qualified_name="server.run_cmd",
            file="src/server.py",
            line=10,
            end_line=18,
            params=[ParamInfo(name="cmd", annotation="str", default=None)],
            decorators=["mcp.tool"],
            docstring="Run a shell command",
            extractor="python_ast",
        )
        d = fact_to_dict(fact)

        assert d["params"][0]["name"] == "cmd"
        assert d["params"][0]["annotation"] == "str"

    def test_json_roundtrip_function_fact(self) -> None:
        """FunctionFact survives JSON roundtrip with all fields preserved."""
        original = FunctionFact(
            type="function",
            id="python:src/server.py:run_cmd",
            language="python",
            name="run_cmd",
            qualified_name="server.run_cmd",
            file="src/server.py",
            line=10,
            end_line=18,
            params=[
                ParamInfo(name="cmd", annotation="str", default=None),
                ParamInfo(name="timeout", annotation="int | None", default="None"),
            ],
            decorators=["mcp.tool"],
            docstring="Run a shell command",
            enclosing_class="Server",
            extractor="python_ast",
        )
        restored = self._roundtrip(original)

        assert restored.type == original.type
        assert restored.id == original.id
        assert restored.language == original.language
        assert restored.name == original.name
        assert restored.qualified_name == original.qualified_name
        assert restored.file == original.file
        assert restored.line == original.line
        assert restored.end_line == original.end_line
        assert restored.enclosing_class == original.enclosing_class
        assert restored.extractor == original.extractor
        assert len(restored.params) == 2
        assert restored.params[0].name == "cmd"
        assert restored.decorators == ["mcp.tool"]

    def test_json_roundtrip_import_fact(self) -> None:
        """ImportFact with ImportKind survives JSON roundtrip."""
        original = ImportFact(
            type="import",
            id="import:src/server.py:1:subprocess",
            language="python",
            file="src/server.py",
            line=1,
            module="subprocess",
            imported_name=None,
            alias="sp",
            kind=ImportKind.IMPORT_AS,
            extractor="python_ast",
        )
        restored = self._roundtrip(original)

        assert restored.type == "import"
        assert restored.module == "subprocess"
        assert restored.alias == "sp"
        assert restored.kind == ImportKind.IMPORT_AS
        assert isinstance(restored.kind, ImportKind)

    def test_json_roundtrip_entrypoint_fact(self) -> None:
        """EntryPointFact with EntryPointKind and evidence survives roundtrip."""
        original = EntryPointFact(
            type="entrypoint",
            id="entry:src/server.py:run_cmd",
            kind=EntryPointKind.MCP_TOOL,
            name="run_cmd",
            function_id="python:src/server.py:run_cmd",
            file="src/server.py",
            line=9,
            evidence=EntryPointEvidence(kind="decorator", text="@mcp.tool()"),
            params=["cmd"],
            confidence=Confidence.HIGH,
            extractor="python_ast",
        )
        restored = self._roundtrip(original)

        assert restored.type == "entrypoint"
        assert restored.kind == EntryPointKind.MCP_TOOL
        assert restored.name == "run_cmd"
        assert restored.evidence is not None
        assert restored.evidence.kind == "decorator"
        assert restored.params == ["cmd"]

    def test_json_roundtrip_call_fact(self) -> None:
        """CallFact with CallArg, CallKwarg, and CallResolution survives roundtrip."""
        original = CallFact(
            type="call",
            id="call:src/server.py:15:4",
            caller="python:src/server.py:run_cmd",
            callee="subprocess.run",
            normalized_callee="python:subprocess.run",
            file="src/server.py",
            line=15,
            column=4,
            end_line=15,
            snippet="subprocess.run(cmd, shell=True)",
            args=[CallArg(index=0, expr="cmd", kind="name")],
            kwargs={"shell": CallKwarg(expr="shell", value=True)},
            resolution=CallResolution(import_alias="subprocess", confidence=Confidence.HIGH),
            extractor="python_ast",
        )
        restored = self._roundtrip(original)

        assert restored.caller == original.caller
        assert restored.callee == original.callee
        assert restored.normalized_callee == original.normalized_callee
        assert restored.snippet == original.snippet
        assert len(restored.args) == 1
        assert restored.args[0].index == 0
        assert restored.args[0].expr == "cmd"
        assert "shell" in restored.kwargs
        assert restored.kwargs["shell"].value is True
        assert restored.resolution is not None
        assert restored.resolution.import_alias == "subprocess"

    def test_json_roundtrip_sink_fact(self) -> None:
        """SinkFact with Severity and Confidence survives roundtrip."""
        original = SinkFact(
            type="sink",
            id="sink:rce:src/server.py:15",
            call_id="call:src/server.py:15:4",
            category="rce",
            rule_id="python.rce.subprocess_shell",
            sink_name="subprocess.run",
            severity_base=Severity.CRITICAL,
            reason="shell=True is dangerous",
            conditions={"shell": True},
            confidence=Confidence.HIGH,
            file="src/server.py",
            line=15,
            extractor="python_ast",
        )
        restored = self._roundtrip(original)

        assert restored.category == "rce"
        assert restored.severity_base == Severity.CRITICAL
        assert restored.confidence == Confidence.HIGH
        assert restored.conditions["shell"] is True

    def test_json_roundtrip_source_fact(self) -> None:
        """SourceFact survives roundtrip."""
        original = SourceFact(
            type="source",
            id="source:src/server.py:run_cmd:cmd",
            kind="mcp_tool_parameter",
            function_id="python:src/server.py:run_cmd",
            name="cmd",
            file="src/server.py",
            line=10,
            confidence=Confidence.HIGH,
            extractor="python_ast",
        )
        restored = self._roundtrip(original)

        assert restored.type == "source"
        assert restored.kind == "mcp_tool_parameter"
        assert restored.name == "cmd"
        assert restored.function_id == original.function_id

    def test_json_roundtrip_dataflow_fact(self) -> None:
        """DataFlowFact with PathStep list survives roundtrip."""
        original = DataFlowFact(
            type="dataflow",
            id="flow:cmd-to-subprocess",
            source_id="source:src/server.py:run_cmd:cmd",
            sink_id="sink:rce:src/server.py:15",
            path=[
                PathStep(
                    kind=PathStepKind.PARAM,
                    line=10,
                    name="cmd",
                    function="run_cmd",
                ),
                PathStep(
                    kind=PathStepKind.ASSIGN,
                    line=12,
                    from_="cmd",
                    to="command",
                    snippet="command = cmd.strip()",
                ),
                PathStep(
                    kind=PathStepKind.CALL_ARG,
                    line=15,
                    call_id="call:src/server.py:15:4",
                    arg_index=0,
                ),
            ],
            confidence=Confidence.HIGH,
            file="src/server.py",
            line=10,
            extractor="python_ast",
        )
        restored = self._roundtrip(original)

        assert restored.source_id == original.source_id
        assert restored.sink_id == original.sink_id
        assert len(restored.path) == 3
        assert restored.path[0].kind == PathStepKind.PARAM
        assert restored.path[1].kind == PathStepKind.ASSIGN
        assert restored.path[1].from_ == "cmd"
        assert restored.path[2].kind == PathStepKind.CALL_ARG

    def test_json_roundtrip_runtime_event_fact(self) -> None:
        """RuntimeEventFact with RuntimeEventKind survives roundtrip."""
        original = RuntimeEventFact(
            type="runtime_event",
            id="runtime:execve:12345",
            kind=RuntimeEventKind.PROCESS_EXEC,
            syscall="execve",
            command="/bin/sh -c whoami",
            pid=12345,
            container_id="abc",
            timestamp="2026-04-29T10:00:00Z",
            correlated_entrypoint="entry:src/server.py:run_cmd",
            correlated_sink="sink:rce:src/server.py:15",
            confidence=Confidence.MEDIUM,
            file="src/server.py",
            line=0,
            extractor="dynamic_trace",
        )
        restored = self._roundtrip(original)

        assert restored.kind == RuntimeEventKind.PROCESS_EXEC
        assert restored.syscall == "execve"
        assert restored.command == "/bin/sh -c whoami"
        assert restored.pid == 12345
        assert restored.correlated_entrypoint == original.correlated_entrypoint

    def test_json_roundtrip_finding_fact(self) -> None:
        """FindingFact with nested lists and maps survives roundtrip."""
        original = FindingFact(
            type="finding",
            id="finding:rce:run_cmd",
            title="MCP tool run_cmd can execute shell commands",
            category="rce",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            entrypoint_id="entry:src/server.py:run_cmd",
            sink_id="sink:rce:src/server.py:15",
            call_chain=[
                {"function": "run_cmd", "file": "src/server.py", "line": 10},
                {"callee": "subprocess.run", "file": "src/server.py", "line": 15},
            ],
            dataflows=["flow:cmd-to-subprocess"],
            dynamic_evidence=["runtime:execve:12345"],
            evidence=["entry:src/server.py:run_cmd", "call:src/server.py:15:4"],
            recommendation="Avoid shell=True",
            file="src/server.py",
            line=15,
            extractor="analysis_pass",
        )
        restored = self._roundtrip(original)

        assert restored.title == original.title
        assert restored.category == "rce"
        assert restored.severity == Severity.CRITICAL
        assert restored.status == FindingStatus.CONFIRMED
        assert len(restored.call_chain) == 2
        assert restored.call_chain[0]["function"] == "run_cmd"
        assert "flow:cmd-to-subprocess" in restored.dataflows

    def test_jsonl_roundtrip(self) -> None:
        """Multiple facts serialize and deserialize correctly via JSONL format."""
        facts = [
            FunctionFact(
                type="function",
                id="python:src/server.py:run_cmd",
                language="python",
                name="run_cmd",
                qualified_name="server.run_cmd",
                file="src/server.py",
                line=10,
                extractor="python_ast",
            ),
            ImportFact(
                type="import",
                id="import:src/server.py:1:subprocess",
                language="python",
                file="src/server.py",
                line=1,
                module="subprocess",
                imported_name=None,
                alias=None,
                kind=ImportKind.IMPORT,
                extractor="python_ast",
            ),
            SinkFact(
                type="sink",
                id="sink:rce:src/server.py:15",
                call_id="call:src/server.py:15:4",
                category="rce",
                rule_id="test",
                sink_name="subprocess.run",
                severity_base=Severity.CRITICAL,
                reason="test",
                conditions={},
                confidence=Confidence.HIGH,
                file="src/server.py",
                line=15,
                extractor="python_ast",
            ),
        ]

        serialized = serialize_facts(facts, "jsonl")
        restored = deserialize_facts(serialized, "jsonl")

        assert len(restored) == 3
        assert restored[0].id == "python:src/server.py:run_cmd"
        assert restored[1].id == "import:src/server.py:1:subprocess"
        assert restored[2].id == "sink:rce:src/server.py:15"

    def test_serialize_invalid_format_raises(self) -> None:
        """serialize_facts raises ValueError for unknown format."""
        fact = FunctionFact(
            type="function",
            id="python:src/test.py:test",
            language="python",
            name="test",
            qualified_name="test",
            file="src/test.py",
            line=1,
            extractor="test",
        )
        with pytest.raises(ValueError) as exc_info:
            serialize_facts([fact], "xml")
        assert "Unknown format" in str(exc_info.value)

    def test_deserialize_invalid_format_raises(self) -> None:
        """deserialize_facts raises ValueError for unknown format."""
        with pytest.raises(ValueError) as exc_info:
            deserialize_facts("{}", "xml")
        assert "Unknown format" in str(exc_info.value)

    def test_deserialize_missing_type_raises(self) -> None:
        """dict_to_fact raises KeyError when 'type' field is missing."""
        from analysis.facts.serialization import dict_to_fact

        with pytest.raises(KeyError) as exc_info:
            dict_to_fact({"id": "test", "file": "test.py", "line": 1})
        assert "type" in str(exc_info.value)

    def test_deserialize_unknown_type_raises(self) -> None:
        """dict_to_fact raises ValueError for unrecognized type."""
        from analysis.facts.serialization import dict_to_fact

        with pytest.raises(ValueError) as exc_info:
            dict_to_fact(
                {"type": "unknown_type", "id": "test", "file": "test.py", "line": 1}
            )
        assert "Unknown fact type" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Helpers (not tests)
# ---------------------------------------------------------------------------


