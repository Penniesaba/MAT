"""Docker-based sandbox provider for MCP security analysis.

This provider uses Docker containers with eBPF monitoring to execute
MCP tools in an isolated environment and capture runtime behavior.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    import docker
    from docker.errors import DockerException, ImageNotFound
    from docker.types import Mount

    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

from detection.sandbox.runner import SandboxProvider, SandboxResult


class DockerSandboxProvider:
    """Sandbox provider using Docker containers with eBPF monitoring.

    This provider:
    1. Copies target code to a temporary directory
    2. Launches a privileged Docker container with eBPF support
    3. Monitors system calls (file, network, process, env)
    4. Collects CEF-formatted logs
    5. Returns structured telemetry data

    Requirements:
    - Docker daemon running
    - docker Python package installed
    - Linux host with kernel >= 4.4 (for eBPF)
    - Privileged container support (--privileged or equivalent)
    """

    name: str = "docker-ebpf"

    def __init__(
        self,
        image: str = "mcp-security-sandbox:latest",
        network_mode: str = "bridge",
        resource_limits: dict[str, Any] | None = None,
    ):
        """Initialize Docker sandbox provider.

        Args:
            image: Docker image name (must have eBPF/BCC installed)
            network_mode: Docker network mode ('none', 'bridge', 'host')
            resource_limits: Container resource limits
                Example: {'cpu_period': 100000, 'cpu_quota': 50000,
                         'mem_limit': '2g', 'pids_limit': 512}
        """
        if not DOCKER_AVAILABLE:
            raise RuntimeError(
                "Docker Python SDK not available. Install with: pip install docker"
            )

        self.image = image
        self.network_mode = network_mode
        self.resource_limits = resource_limits or {
            "cpu_period": 100000,
            "cpu_quota": 200000,  # 2 CPUs
            "mem_limit": "2g",
            "pids_limit": 512,  # Prevent fork bombs
        }

        # Initialize Docker client
        try:
            self.client = docker.from_env()
            self.client.ping()
        except DockerException as e:
            raise RuntimeError(f"Failed to connect to Docker daemon: {e}") from e

        # Verify image exists
        self._verify_image()

    def _verify_image(self) -> None:
        """Verify sandbox image exists, provide build instructions if not."""
        try:
            self.client.images.get(self.image)
        except ImageNotFound:
            sandbox_dir = Path(__file__).parent.parent
            dockerfile_path = sandbox_dir / "Dockerfile"

            raise RuntimeError(
                f"Sandbox image '{self.image}' not found.\n\n"
                f"Build it with:\n"
                f"  cd {sandbox_dir}\n"
                f"  docker build -t {self.image} .\n\n"
                f"Or use docker-compose:\n"
                f"  cd {sandbox_dir}\n"
                f"  docker-compose build"
            )

    def run(self, target_path: Path, *, timeout: int = 60) -> SandboxResult:
        """Execute target in Docker sandbox with eBPF monitoring.

        Args:
            target_path: Path to MCP tool directory or Python file
            timeout: Maximum execution time in seconds

        Returns:
            SandboxResult with logs, telemetry, and exit code

        Raises:
            RuntimeError: If sandbox execution fails
            TimeoutError: If execution exceeds timeout
        """
        # Validate target
        target_path = Path(target_path).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        # Create temporary directories for container mounts
        with tempfile.TemporaryDirectory(prefix="mcp-sandbox-") as temp_dir:
            temp_path = Path(temp_dir)
            target_mount = temp_path / "target"
            logs_mount = temp_path / "logs"
            target_mount.mkdir()
            logs_mount.mkdir()

            # Copy target to mount point
            if target_path.is_dir():
                shutil.copytree(target_path, target_mount, dirs_exist_ok=True)
            else:
                shutil.copy2(target_path, target_mount / target_path.name)

            # Prepare mounts
            mounts = [
                Mount(
                    target="/target",
                    source=str(target_mount.absolute()),
                    type="bind",
                    read_only=True,
                ),
                Mount(
                    target="/logs",
                    source=str(logs_mount.absolute()),
                    type="bind",
                    read_only=False,
                ),
                # eBPF requires access to kernel debug/tracing filesystems
                Mount(
                    target="/sys/kernel/debug",
                    source="/sys/kernel/debug",
                    type="bind",
                    read_only=True,
                ),
                Mount(
                    target="/sys/kernel/tracing",
                    source="/sys/kernel/tracing",
                    type="bind",
                    read_only=True,
                ),
                Mount(
                    target="/sys/fs/bpf",
                    source="/sys/fs/bpf",
                    type="bind",
                    read_only=False,
                ),
            ]

            # Container configuration
            container_config = {
                "image": self.image,
                "mounts": mounts,
                "environment": {
                    "MONITOR_TIMEOUT": str(timeout),
                    "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
                },
                "network_mode": self.network_mode,
                "detach": True,
                "remove": True,  # Auto-remove after exit
                "privileged": True,  # Required for eBPF
                "cap_add": ["SYS_ADMIN", "SYS_RESOURCE", "SYS_PTRACE", "NET_ADMIN"],
                "security_opt": ["apparmor:unconfined"],
                **self.resource_limits,
            }

            # Run container
            start_time = time.time()
            try:
                container = self.client.containers.run(**container_config)

                # Wait for container to finish (with timeout + buffer)
                result = container.wait(timeout=timeout + 10)
                exit_code = result.get("StatusCode", -1)

            except docker.errors.ContainerError as e:
                return SandboxResult(
                    logs=f"Container error: {e.stderr.decode('utf-8', errors='ignore')}",
                    telemetry={"error": str(e), "exit_code": e.exit_status},
                    exit_code=e.exit_status,
                )

            except docker.errors.APIError as e:
                raise RuntimeError(f"Docker API error: {e}") from e

            finally:
                elapsed = time.time() - start_time

            # Read CEF logs
            cef_log_path = logs_mount / "events.cef"
            if cef_log_path.exists():
                logs_content = cef_log_path.read_text()
            else:
                logs_content = "(No CEF logs generated)"

            # Parse telemetry from CEF logs
            telemetry = self._parse_cef_logs(logs_content)
            telemetry["execution_time"] = elapsed
            telemetry["exit_code"] = exit_code
            telemetry["target_path"] = str(target_path)

            return SandboxResult(
                logs=logs_content,
                telemetry=telemetry,
                exit_code=exit_code,
            )

    def _parse_cef_logs(self, cef_logs: str) -> dict[str, Any]:
        """Parse CEF logs to extract telemetry statistics.

        Args:
            cef_logs: Raw CEF log content

        Returns:
            Dictionary with event counts and statistics
        """
        if not cef_logs or cef_logs.startswith("(No CEF logs"):
            return {
                "total_events": 0,
                "file_events": 0,
                "network_events": 0,
                "process_events": 0,
                "sensitive_paths": [],
                "network_destinations": [],
                "executed_commands": [],
            }

        lines = [line for line in cef_logs.split("\n") if line.startswith("CEF:")]

        # Count events by category
        file_events = 0
        network_events = 0
        process_events = 0
        sensitive_paths = set()
        network_destinations = set()
        executed_commands = set()

        for line in lines:
            parts = line.split("|")
            if len(parts) < 8:
                continue

            signature_id = parts[4]  # Event type
            extensions = parts[7]  # Extension fields

            # Categorize events
            if "FILE_" in signature_id:
                file_events += 1
                # Extract destination path
                if "dst=" in extensions:
                    dst = extensions.split("dst=")[1].split()[0]
                    if any(
                        sensitive in dst
                        for sensitive in [
                            "/etc/passwd",
                            "/etc/shadow",
                            "/.ssh",
                            "/.aws",
                            "/.env",
                        ]
                    ):
                        sensitive_paths.add(dst)

            elif "NET_" in signature_id:
                network_events += 1
                # Extract network destination
                if "dst=" in extensions:
                    dst = extensions.split("dst=")[1].split()[0]
                    network_destinations.add(dst)

            elif "PROC_" in signature_id:
                process_events += 1
                # Extract executed commands
                if "dproc=" in extensions or "cs1=" in extensions:
                    if "dproc=" in extensions:
                        cmd = extensions.split("dproc=")[1].split()[0]
                    else:
                        cmd = extensions.split("cs1=")[1].split()[0]
                    executed_commands.add(cmd)

        return {
            "total_events": len(lines),
            "file_events": file_events,
            "network_events": network_events,
            "process_events": process_events,
            "sensitive_paths": sorted(sensitive_paths),
            "network_destinations": sorted(network_destinations),
            "executed_commands": sorted(executed_commands),
        }

    def build_image(self) -> None:
        """Build the sandbox Docker image.

        This is a convenience method to build the image programmatically.
        Alternatively, users can run `docker build` or `docker-compose build`.
        """
        sandbox_dir = Path(__file__).parent.parent
        dockerfile_path = sandbox_dir / "Dockerfile"

        if not dockerfile_path.exists():
            raise FileNotFoundError(f"Dockerfile not found at {dockerfile_path}")

        print(f"Building sandbox image '{self.image}'...")
        print(f"Context: {sandbox_dir}")

        try:
            image, build_logs = self.client.images.build(
                path=str(sandbox_dir),
                tag=self.image,
                rm=True,  # Remove intermediate containers
                forcerm=True,  # Always remove intermediate containers
            )

            # Stream build logs
            for log in build_logs:
                if "stream" in log:
                    print(log["stream"].strip())

            print(f"✓ Image '{self.image}' built successfully")

        except docker.errors.BuildError as e:
            print(f"✗ Build failed: {e}")
            for log in e.build_log:
                if "stream" in log:
                    print(log["stream"].strip())
            raise


# Convenience function for importing
def get_docker_sandbox(
    image: str = "mcp-security-sandbox:latest", **kwargs: Any
) -> DockerSandboxProvider:
    """Get a configured Docker sandbox provider.

    Args:
        image: Docker image name
        **kwargs: Additional arguments for DockerSandboxProvider

    Returns:
        Configured DockerSandboxProvider instance
    """
    return DockerSandboxProvider(image=image, **kwargs)
