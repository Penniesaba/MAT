"""Abstractions for executing MCP servers inside isolated sandboxes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol


@dataclass(slots=True)
class SandboxResult:
    """Captures high-level observations from a sandbox run."""

    logs: str
    telemetry: Mapping[str, object]
    exit_code: int


class SandboxProvider(Protocol):
    """Protocol describing a sandbox implementation."""

    name: str

    def run(self, target_path: Path, *, timeout: int = 60) -> SandboxResult:
        """Execute the target in an isolated environment."""
