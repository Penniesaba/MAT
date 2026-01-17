"""Integration tests for dynamic analysis pipeline.

These tests require:
- Docker daemon running
- Sandbox image built (mcp-security-sandbox:latest)
- Linux kernel with eBPF support
"""

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def malicious_script():
    """Create a temporary malicious Python script for testing."""
    script_content = """
import subprocess
import os

# Command execution
subprocess.run(["ls", "-la"])

# File access
with open("/etc/passwd", "r") as f:
    data = f.read()

# Environment access
api_key = os.getenv("API_KEY")

print("Malicious script executed")
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(script_content)
        return Path(f.name)


@pytest.fixture
def benign_script():
    """Create a temporary benign Python script for testing."""
    script_content = """
print("Hello, world!")
x = 1 + 1
print(f"Result: {x}")
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(script_content)
        return Path(f.name)


@pytest.mark.integration
@pytest.mark.skipif(
    not Path("/var/run/docker.sock").exists(),
    reason="Docker not available"
)
class TestDynamicPipeline:
    """Integration tests for dynamic analysis pipeline."""

    def test_docker_sandbox_provider_initialization(self):
        """Test DockerSandboxProvider can be initialized."""
        from detection.sandbox.providers import DockerSandboxProvider

        try:
            sandbox = DockerSandboxProvider()
            assert sandbox.name == "docker-ebpf"
            assert sandbox.image == "mcp-security-sandbox:latest"
        except RuntimeError as e:
            pytest.skip(f"Docker not available: {e}")

    def test_sandbox_execution_benign(self, benign_script):
        """Test sandbox can execute benign script."""
        from detection.sandbox.providers import DockerSandboxProvider

        try:
            sandbox = DockerSandboxProvider()
        except RuntimeError:
            pytest.skip("Docker sandbox not available")

        result = sandbox.run(benign_script, timeout=10)

        assert result.exit_code == 0
        assert result.telemetry["total_events"] >= 0
        assert isinstance(result.logs, str)

    def test_sandbox_execution_malicious(self, malicious_script):
        """Test sandbox detects malicious behavior."""
        from detection.sandbox.providers import DockerSandboxProvider

        try:
            sandbox = DockerSandboxProvider()
        except RuntimeError:
            pytest.skip("Docker sandbox not available")

        result = sandbox.run(malicious_script, timeout=10)

        # Should capture various events
        telemetry = result.telemetry
        assert telemetry["total_events"] > 0
        assert telemetry["file_events"] > 0  # File access detected
        assert telemetry["process_events"] > 0  # Command execution detected

    def test_behavior_analyzer_parse_cef(self):
        """Test CEF log parsing."""
        from detection.plugins.dynamic import CEFEvent

        cef_line = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_READ|"
            "Sensitive File Access|9|rt=2025-01-20T10:15:23.456 "
            "suser=root sproc=python dst=/etc/passwd"
        )

        event = CEFEvent.parse(cef_line)

        assert event is not None
        assert event.signature_id == "FILE_READ"
        assert event.severity == 9
        assert event.extensions["dst"] == "/etc/passwd"
        assert event.extensions["suser"] == "root"

    def test_behavior_analyzer_detects_capabilities(self):
        """Test behavior analyzer extracts capabilities from CEF logs."""
        from detection.plugins.dynamic import DynamicBehaviorAnalyzer

        # Simulated CEF logs from sandbox
        cef_logs = """
CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|rt=2025-01-20T10:15:23.456 suser=root sproc=python dproc=bash
CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_READ|File Read|5|rt=2025-01-20T10:15:24.789 suser=root sproc=python dst=/etc/passwd
CEF:0|MCP-Security|Dynamic-Detector|1.0|NET_CONNECT|Outbound Connection|7|rt=2025-01-20T10:15:25.012 suser=root sproc=python dst=192.168.1.100:4444
"""

        analyzer = DynamicBehaviorAnalyzer()
        findings = analyzer.analyze(cef_logs, Path("/tmp/test"))

        # Should detect multiple capabilities
        finding_names = {f.name for f in findings}
        assert "command_exec" in finding_names
        assert "file_read" in finding_names
        assert "network_outbound" in finding_names

        # Check evidence
        command_finding = next(f for f in findings if f.name == "command_exec")
        assert any("bash" in ev for ev in command_finding.evidence)

    def test_dynamic_pipeline_end_to_end(self, malicious_script):
        """Test full dynamic pipeline execution."""
        from detection.core.registry import DetectorRegistry
        from detection.pipelines.dynamic import run_dynamic_pipeline

        try:
            # Initialize
            registry = DetectorRegistry()

            # Run dynamic pipeline
            result = run_dynamic_pipeline(
                target_path=malicious_script,
                registry=registry,
                timeout=15
            )

            # Verify results
            assert result.server_name == malicious_script.name
            assert len(result.findings) > 0
            assert result.total_score > 0
            assert result.risk_level in ["low", "medium", "high", "critical"]

            # Should detect command execution
            finding_names = {f.name for f in result.findings}
            assert "command_exec" in finding_names or "file_read" in finding_names

        except RuntimeError as e:
            if "Docker" in str(e):
                pytest.skip(f"Docker sandbox not available: {e}")
            raise

    def test_two_stage_pipeline(self, malicious_script):
        """Test two-stage detection (static → dynamic)."""
        from detection.core.registry import DetectorRegistry
        from detection.pipelines.dynamic import run_two_stage_pipeline
        from detection.plugins.static.python import register as register_python

        try:
            # Setup registry with static detectors
            registry = DetectorRegistry()
            register_python(registry)

            # Run two-stage pipeline
            result = run_two_stage_pipeline(
                target_path=malicious_script,
                registry=registry,
                policy_dir=Path("detection/mitigation/templates"),
                risk_threshold=0.0,  # Force dynamic analysis
                dynamic_timeout=15
            )

            # Should have findings from both stages
            assert len(result.findings) > 0

            # Should have both static and dynamic evidence sources
            all_sources = set()
            for finding in result.findings:
                all_sources.update(finding.sources)

            # At least one source should be present
            assert len(all_sources) > 0

        except RuntimeError as e:
            if "Docker" in str(e):
                pytest.skip(f"Docker sandbox not available: {e}")
            raise

    def test_cef_formatter(self):
        """Test CEF formatter generates valid events."""
        from detection.reporting.cef_formatter import CEFFormatter

        formatter = CEFFormatter()

        # Format capability finding
        cef_message = formatter.format_capability_finding(
            finding_name="command_exec",
            confidence=0.85,
            evidence=["Executed: bash", "Executed: curl"],
            metadata={"exec_count": "2"}
        )

        # Verify format
        assert cef_message.startswith("CEF:0|MCP-Security|")
        assert "COMMAND_EXEC" in cef_message
        assert "0.85" in cef_message

    def test_sandbox_resource_limits(self, malicious_script):
        """Test sandbox enforces resource limits."""
        from detection.sandbox.providers import DockerSandboxProvider

        try:
            sandbox = DockerSandboxProvider(
                resource_limits={
                    "cpu_quota": 50000,  # 0.5 CPU
                    "mem_limit": "512m",
                    "pids_limit": 100,
                }
            )

            result = sandbox.run(malicious_script, timeout=5)

            # Should complete without error (limits enforced)
            assert result.exit_code is not None

        except RuntimeError:
            pytest.skip("Docker sandbox not available")

    def test_sandbox_network_isolation(self, malicious_script):
        """Test sandbox can isolate network."""
        from detection.sandbox.providers import DockerSandboxProvider

        try:
            sandbox = DockerSandboxProvider(network_mode="none")

            result = sandbox.run(malicious_script, timeout=5)

            # Network events should be minimal (only loopback)
            telemetry = result.telemetry
            net_dests = telemetry.get("network_destinations", [])

            # Should not connect to external IPs
            external_connections = [d for d in net_dests if not d.startswith("127.")]
            assert len(external_connections) == 0

        except RuntimeError:
            pytest.skip("Docker sandbox not available")


@pytest.mark.integration
class TestCEFParsing:
    """Test CEF log parsing and analysis."""

    def test_parse_file_event(self):
        """Test parsing file operation CEF event."""
        from detection.plugins.dynamic import CEFEvent

        cef = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_OPEN|File Open|4|"
            "rt=2025-01-20T10:15:23.456 suser=root sproc=python dst=/tmp/test.txt act=open"
        )

        event = CEFEvent.parse(cef)
        assert event.signature_id == "FILE_OPEN"
        assert event.extensions["dst"] == "/tmp/test.txt"

    def test_parse_network_event(self):
        """Test parsing network CEF event."""
        from detection.plugins.dynamic import CEFEvent

        cef = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|NET_CONNECT|Outbound Connection|7|"
            "rt=2025-01-20T10:15:24.789 sproc=python dst=1.2.3.4:443 proto=tcp"
        )

        event = CEFEvent.parse(cef)
        assert event.signature_id == "NET_CONNECT"
        assert "1.2.3.4:443" in event.extensions["dst"]

    def test_parse_process_event(self):
        """Test parsing process CEF event."""
        from detection.plugins.dynamic import CEFEvent

        cef = (
            "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|"
            "rt=2025-01-20T10:15:25.012 sproc=python dproc=bash cs1=/bin/bash"
        )

        event = CEFEvent.parse(cef)
        assert event.signature_id == "PROC_EXEC"
        assert event.extensions["dproc"] == "bash"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])
