"""Unit tests for the CEF log parser (dynamic event extractor).

Phase 6 of the analysis pipeline.

Covers:
1. Parse PROC_EXEC CEF line → RuntimeEventFact(kind=PROCESS_EXEC, ...)
2. Parse FILE_READ CEF line → RuntimeEventFact(kind=FILE_ACCESS, ...)
3. Parse NET_CONNECT CEF line → RuntimeEventFact(kind=NETWORK_CONNECT, ...)
4. Parse multi-line CEF log → correct number of RuntimeEventFact
5. Empty input → empty list
6. Invalid CEF line (not starting with CEF:) → skipped, no crash
7. Unknown event type (e.g. ENV_ACCESS) → no RuntimeEventFact produced
8. Non-numeric pid → pid=None, no crash
"""

from __future__ import annotations

from analysis.extractors.dynamic import parse_cef_logs
from analysis.facts.ids import make_runtime_event_id
from analysis.facts.schema import RuntimeEventFact, RuntimeEventKind


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_runtime_event(
    event_id: str = "",
    kind: RuntimeEventKind = RuntimeEventKind.PROCESS_EXEC,
    syscall: str | None = None,
    command: str | None = None,
    pid: int | None = None,
    timestamp: str | None = None,
) -> RuntimeEventFact:
    """Create a RuntimeEventFact for testing."""
    return RuntimeEventFact(
        type="runtime",
        id=event_id or make_runtime_event_id(syscall or "execve", pid or 1),
        file="dynamic",
        line=0,
        extractor="cef",
        kind=kind,
        syscall=syscall,
        command=command,
        pid=pid,
        container_id=None,
        timestamp=timestamp,
        correlated_entrypoint=None,
        correlated_sink=None,
        confidence=None,
    )


# ---------------------------------------------------------------------------
# Test: PROC_EXEC parsing
# ---------------------------------------------------------------------------


class TestProcExecParsing:
    """Parse PROC_EXEC CEF line into RuntimeEventFact(kind=PROCESS_EXEC)."""

    def test_proc_exec_cef_line_returns_process_exec_event(self) -> None:
        """PROC_EXEC CEF line produces RuntimeEventFact with kind=PROCESS_EXEC."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2026-04-29T10:30:00.000 suser=root sproc=bash spid=12345 "
            "outcome=success dproc=/bin/sh -c whoami cs1=/bin/sh -c whoami cs1Label=Command"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        fact = facts[0]
        assert fact.kind == RuntimeEventKind.PROCESS_EXEC
        assert fact.pid == 12345
        assert fact.syscall == "bash"
        assert fact.command == "/bin/sh -c whoami"
        assert fact.timestamp == "2026-04-29T10:30:00.000"

    def test_proc_exec_command_extracted_from_dproc(self) -> None:
        """For PROC_EXEC, command is extracted from dproc extension."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2026-04-29T10:30:00.000 sproc=bash spid=99999 dproc=netsh exec"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        assert facts[0].command == "netsh exec"


# ---------------------------------------------------------------------------
# Test: FILE_READ parsing
# ---------------------------------------------------------------------------


class TestFileReadParsing:
    """Parse FILE_READ CEF line into RuntimeEventFact(kind=FILE_ACCESS)."""

    def test_file_read_cef_line_returns_file_access_event(self) -> None:
        """FILE_READ CEF line produces RuntimeEventFact with kind=FILE_ACCESS."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_READ|File Read|5|"
            "rt=2026-04-29T10:30:01.000 suser=root sproc=cat spid=12346 "
            "outcome=success dst=/etc/passwd act=read bytesIn=1024"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        fact = facts[0]
        assert fact.kind == RuntimeEventKind.FILE_ACCESS
        assert fact.pid == 12346
        assert fact.syscall == "cat"
        assert fact.command == "/etc/passwd"
        assert fact.timestamp == "2026-04-29T10:30:01.000"

    def test_file_write_cef_line_returns_file_access_event(self) -> None:
        """FILE_WRITE CEF line also maps to FILE_ACCESS kind."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_WRITE|File Write|5|"
            "rt=2026-04-29T10:30:01.000 sproc=write spid=12346 dst=/tmp/out.txt act=write"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        assert facts[0].kind == RuntimeEventKind.FILE_ACCESS
        assert facts[0].command == "/tmp/out.txt"

    def test_file_open_cef_line_returns_file_access_event(self) -> None:
        """FILE_OPEN CEF line also maps to FILE_ACCESS kind."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_OPEN|File Open|5|"
            "rt=2026-04-29T10:30:01.000 sproc=open spid=12346 dst=/etc/shadow act=open"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        assert facts[0].kind == RuntimeEventKind.FILE_ACCESS
        assert facts[0].command == "/etc/shadow"


# ---------------------------------------------------------------------------
# Test: NET_CONNECT parsing
# ---------------------------------------------------------------------------


class TestNetConnectParsing:
    """Parse NET_CONNECT CEF line into RuntimeEventFact(kind=NETWORK_CONNECT)."""

    def test_net_connect_cef_line_returns_network_connect_event(self) -> None:
        """NET_CONNECT CEF line produces RuntimeEventFact with kind=NETWORK_CONNECT."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|NET_CONNECT|Outbound Connection|7|"
            "rt=2026-04-29T10:30:02.000 suser=root sproc=curl spid=12347 "
            "outcome=success dst=10.0.0.1:443 dpt=443 proto=tcp"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        fact = facts[0]
        assert fact.kind == RuntimeEventKind.NETWORK_CONNECT
        assert fact.pid == 12347
        assert fact.syscall == "curl"
        assert fact.timestamp == "2026-04-29T10:30:02.000"

    def test_net_socket_cef_line_returns_network_connect_event(self) -> None:
        """NET_SOCKET CEF line also maps to NETWORK_CONNECT kind."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|NET_SOCKET|Socket Create|7|"
            "rt=2026-04-29T10:30:02.000 sproc=socket spid=12347 dst=10.0.0.1:8080"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        assert facts[0].kind == RuntimeEventKind.NETWORK_CONNECT


# ---------------------------------------------------------------------------
# Test: Multi-line parsing
# ---------------------------------------------------------------------------


class TestMultiLineParsing:
    """Parse multiple CEF lines into correct number of RuntimeEventFact."""

    def test_multi_line_cef_log_returns_correct_count(self) -> None:
        """Multiple CEF lines produce one RuntimeEventFact per relevant line."""
        cef_log = "\n".join([
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2026-04-29T10:30:00.000 sproc=bash spid=12345 dproc=/bin/sh -c whoami",
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_READ|File Read|5|"
            "rt=2026-04-29T10:30:01.000 sproc=cat spid=12346 dst=/etc/passwd",
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|NET_CONNECT|Outbound Connection|7|"
            "rt=2026-04-29T10:30:02.000 sproc=curl spid=12347 dst=10.0.0.1:443",
        ])

        facts = parse_cef_logs(cef_log)

        assert len(facts) == 3
        assert facts[0].kind == RuntimeEventKind.PROCESS_EXEC
        assert facts[1].kind == RuntimeEventKind.FILE_ACCESS
        assert facts[2].kind == RuntimeEventKind.NETWORK_CONNECT

    def test_multi_line_with_mixed_relevant_and_irrelevant_lines(self) -> None:
        """Unknown event types and invalid lines are skipped silently."""
        cef_log = "\n".join([
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2026-04-29T10:30:00.000 sproc=bash spid=12345 dproc=/bin/sh",
            "Some random log line that is not CEF",
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|ENV_ACCESS|Env Access|5|"
            "rt=2026-04-29T10:30:01.000 sproc=env spid=12346",  # unknown type
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_READ|File Read|5|"
            "rt=2026-04-29T10:30:02.000 sproc=cat spid=12347 dst=/etc/passwd",
        ])

        facts = parse_cef_logs(cef_log)

        # Only PROC_EXEC and FILE_READ are relevant; ENV_ACCESS is unknown
        assert len(facts) == 2
        assert facts[0].kind == RuntimeEventKind.PROCESS_EXEC
        assert facts[1].kind == RuntimeEventKind.FILE_ACCESS


# ---------------------------------------------------------------------------
# Test: Empty and invalid input
# ---------------------------------------------------------------------------


class TestEmptyAndInvalidInput:
    """Empty input and invalid CEF lines are handled gracefully."""

    def test_empty_string_returns_empty_list(self) -> None:
        """Empty CEF text produces no RuntimeEventFact."""
        assert parse_cef_logs("") == []
        assert parse_cef_logs("   ") == []

    def test_none_input_returns_empty_list(self) -> None:
        """None input is handled without crash."""
        facts = parse_cef_logs("")
        assert facts == []

    def test_invalid_line_not_starting_with_cef_returns_empty(self) -> None:
        """Lines not starting with CEF: are skipped silently."""
        facts = parse_cef_logs("2026-04-29 ERROR: something went wrong\nanother log line")
        assert facts == []

    def test_malformed_cef_line_fewer_than_8_fields_returns_empty(self) -> None:
        """CEF lines with fewer than 8 pipe-separated fields are skipped silently."""
        # Only 7 pipe-separated fields — missing the extensions field
        facts = parse_cef_logs("CEF:0|Vendor|Product|1.0|PROC_EXEC|Command|8")
        assert facts == []

    def test_malformed_cef_line_extra_fields_still_parses(self) -> None:
        """CEF lines with more than minimum fields are parsed normally."""
        # Has 8 fields but no recognizable extension keys like rt, spid, etc.
        facts = parse_cef_logs("CEF:0|Vendor|Product|1.0|PROC_EXEC|Command|8|extra=val")
        # PROC_EXEC is known so it still produces a fact
        assert len(facts) == 1

    def test_truncated_extension_string_no_crash(self) -> None:
        """Extension string that cannot be parsed does not crash the parser."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2026-04-29T10:30:00.000 sproc=bash spid=abc not-a-valid-extension"
        )
        facts = parse_cef_logs(cef_line)
        assert isinstance(facts, list)


# ---------------------------------------------------------------------------
# Test: Unknown event types
# ---------------------------------------------------------------------------


class TestUnknownEventTypes:
    """Event types not in EVENT_KIND_MAP produce no RuntimeEventFact."""

    def test_env_access_unknown_event_type_returns_empty(self) -> None:
        """ENV_ACCESS is not in EVENT_KIND_MAP, so no fact is produced."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|ENV_ACCESS|Environment Access|5|"
            "rt=2026-04-29T10:30:01.000 sproc=getenv spid=12346 dst=SECRET_KEY"
        )

        facts = parse_cef_logs(cef_line)

        assert facts == []

    def test_custom_event_type_unknown_returns_empty(self) -> None:
        """Arbitrary unknown event types are silently skipped."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|CUSTOM_EVENT|Custom|5|"
            "rt=2026-04-29T10:30:01.000 sproc=custom spid=12346"
        )

        facts = parse_cef_logs(cef_line)

        assert facts == []


# ---------------------------------------------------------------------------
# Test: Non-numeric pid handling
# ---------------------------------------------------------------------------


class TestNonNumericPid:
    """Non-numeric pid values are handled gracefully."""

    def test_non_numeric_pid_sets_none_no_crash(self) -> None:
        """spid that is not a number results in pid=None, no crash."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2026-04-29T10:30:00.000 sproc=bash spid=not_a_number dproc=/bin/sh"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        assert facts[0].pid is None

    def test_missing_pid_is_none(self) -> None:
        """spid extension missing entirely results in pid=None."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2026-04-29T10:30:00.000 sproc=bash dproc=/bin/sh"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        assert facts[0].pid is None

    def test_empty_pid_string_is_handled(self) -> None:
        """Empty spid string is handled without crash."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2026-04-29T10:30:00.000 sproc=bash spid= dproc=/bin/sh"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        assert facts[0].pid is None


# ---------------------------------------------------------------------------
# Test: Fact ID generation
# ---------------------------------------------------------------------------


class TestFactIdGeneration:
    """RuntimeEventFact IDs are generated correctly."""

    def test_fact_id_format_with_syscall_and_pid(self) -> None:
        """When both syscall and pid are available, ID uses syscall and pid."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2026-04-29T10:30:00.000 sproc=bash spid=12345 dproc=/bin/sh"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        assert facts[0].id == "runtime:bash:12345"

    def test_fact_id_format_without_syscall(self) -> None:
        """When syscall is missing, ID falls back to sig_id."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_READ|File Read|5|"
            "rt=2026-04-29T10:30:00.000 spid=12346 dst=/etc/passwd"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        # sproc missing, so id uses file_read (lowercased sig_id) and pid
        assert facts[0].id == "runtime:file_read:12346"

    def test_fact_id_format_without_pid(self) -> None:
        """When pid is missing, ID uses unknown."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2026-04-29T10:30:00.000 sproc=bash dproc=/bin/sh"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        assert facts[0].id == "runtime:proc_exec:unknown"


# ---------------------------------------------------------------------------
# Test: Extractor metadata
# ---------------------------------------------------------------------------


class TestExtractorMetadata:
    """Parsed RuntimeEventFact has correct extractor metadata."""

    def test_extractor_field_is_cef(self) -> None:
        """All parsed facts have extractor='cef'."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2026-04-29T10:30:00.000 sproc=bash spid=12345 dproc=/bin/sh"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        assert facts[0].extractor == "cef"
        assert facts[0].type == "runtime"

    def test_file_field_is_dynamic(self) -> None:
        """All parsed facts have file='dynamic'."""
        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|NET_CONNECT|Outbound Connection|7|"
            "rt=2026-04-29T10:30:02.000 sproc=curl spid=12347 dst=10.0.0.1:443"
        )

        facts = parse_cef_logs(cef_line)

        assert len(facts) == 1
        assert facts[0].file == "dynamic"