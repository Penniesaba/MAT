"""Map capability findings to mitigation recommendations."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Mapping

from detection.core.models import CapabilityFinding


class MitigationEngine:
    """Determines mitigation steps based on detected capabilities."""

    def __init__(self, policy_dir: Path) -> None:
        self.policy_dir = policy_dir
        self._capability_policies: Dict[str, List[str]] = defaultdict(list)
        self._load_builtin_policies()

    def _load_builtin_policies(self) -> None:
        """Load placeholder policies; future work will parse YAML files."""

        # TODO: Replace with actual policy parsing logic.
        self._capability_policies.update(
            {
                "command_exec": [
                    "Run the server inside a Docker container with no-new-privileges.",
                    "Disable outbound networking or restrict to vetted destinations.",
                ],
                "file_write": [
                    "Mount only the required directories, preferably read-only.",
                    "Rotate and inspect written files for unexpected data exfiltration.",
                ],
                "file_read": [
                    "Mount sensitive directories as read-only overlays or exclude them entirely.",
                    "Audit access patterns using filesystem monitoring before production rollout.",
                ],
                "network_outbound": [
                    "Run with egress restrictions or network namespaces to limit external calls.",
                    "Maintain an allowlist of destinations and enforce via firewall or proxy.",
                ],
                "network_inbound": [
                    "Terminate traffic with a reverse proxy that enforces auth and rate limits.",
                    "Disable unnecessary listeners when deploying the MCP server.",
                ],
                "env_access": [
                    "Inject secrets at runtime via a secrets manager rather than environment files.",
                    "Scope environment variables to the minimal set required for the tool.",
                ],
            }
        )

    def recommendations(self, findings: Iterable[CapabilityFinding]) -> List[str]:
        """Generate a deduplicated list of mitigation actions."""

        suggestions: List[str] = []
        seen: set[str] = set()
        for finding in findings:
            for suggestion in self._capability_policies.get(finding.name, ()):
                if suggestion not in seen:
                    seen.add(suggestion)
                    suggestions.append(suggestion)
        return suggestions
