"""CEF (Common Event Format) formatter for security events.

CEF is a standardized logging format used by ArcSight and many SIEM systems.
Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

This module provides utilities to format detection findings and telemetry
into CEF format for integration with security infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class CEFHeader:
    """CEF message header fields."""

    version: str = "0"
    device_vendor: str = "MCP-Security"
    device_product: str = "Detection-Framework"
    device_version: str = "1.0"


class CEFFormatter:
    """Formats security events and findings in CEF format."""

    def __init__(self, header: CEFHeader | None = None):
        """Initialize CEF formatter.

        Args:
            header: Custom CEF header (uses defaults if not provided)
        """
        self.header = header or CEFHeader()

    def format_event(
        self,
        signature_id: str,
        name: str,
        severity: int,
        extensions: dict[str, Any],
    ) -> str:
        """Format a single CEF event.

        Args:
            signature_id: Event type identifier (e.g., "FILE_READ", "NET_CONNECT")
            name: Human-readable event name
            severity: Severity level (0-10 scale)
            extensions: Key-value pairs for additional fields

        Returns:
            Formatted CEF string
        """
        # Validate severity
        severity = max(0, min(10, severity))

        # Build header
        header = (
            f"CEF:{self.header.version}|"
            f"{self.header.device_vendor}|"
            f"{self.header.device_product}|"
            f"{self.header.device_version}|"
            f"{signature_id}|"
            f"{name}|"
            f"{severity}"
        )

        # Build extension string
        extension_str = self._format_extensions(extensions)

        return f"{header}|{extension_str}"

    def format_capability_finding(
        self,
        finding_name: str,
        confidence: float,
        evidence: list[str],
        metadata: dict[str, str],
    ) -> str:
        """Format a capability finding as CEF event.

        Args:
            finding_name: Capability name (e.g., "command_exec")
            confidence: Confidence score (0.0-1.0)
            evidence: List of evidence strings
            metadata: Additional metadata

        Returns:
            CEF-formatted event
        """
        # Map finding name to signature ID
        signature_id = finding_name.upper()

        # Determine severity based on confidence
        severity = int(confidence * 10)

        # Build extensions
        extensions = {
            "cs1": finding_name,
            "cs1Label": "Capability",
            "cfp1": str(confidence),
            "cfp1Label": "Confidence",
            "rt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
            **metadata,
        }

        # Add evidence (up to 3 items in CEF extensions)
        for i, ev in enumerate(evidence[:3], 1):
            extensions[f"cs{i+1}"] = ev
            extensions[f"cs{i+1}Label"] = f"Evidence{i}"

        return self.format_event(
            signature_id=signature_id,
            name=f"Capability: {finding_name}",
            severity=severity,
            extensions=extensions,
        )

    def format_detection_result(
        self,
        server_name: str,
        risk_level: str,
        total_score: float,
        findings_count: int,
    ) -> str:
        """Format overall detection result as CEF event.

        Args:
            server_name: Name of analyzed MCP server
            risk_level: Risk level (low/medium/high/critical)
            total_score: Total risk score
            findings_count: Number of findings

        Returns:
            CEF-formatted summary event
        """
        # Map risk level to severity
        severity_map = {"low": 3, "medium": 5, "high": 8, "critical": 10}
        severity = severity_map.get(risk_level.lower(), 5)

        extensions = {
            "shost": server_name,
            "cs1": risk_level,
            "cs1Label": "RiskLevel",
            "cn1": str(findings_count),
            "cn1Label": "FindingsCount",
            "cfp1": str(total_score),
            "cfp1Label": "TotalScore",
            "rt": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
        }

        return self.format_event(
            signature_id="DETECTION_SUMMARY",
            name=f"MCP Security Analysis Complete: {server_name}",
            severity=severity,
            extensions=extensions,
        )

    def _format_extensions(self, extensions: dict[str, Any]) -> str:
        """Format extension fields as space-separated key=value pairs.

        CEF extension field naming conventions:
        - cn1, cn2, cn3: Custom numbers
        - cs1, cs2, cs3-cs6: Custom strings
        - cfp1, cfp2, cfp3: Custom floating point
        - rt: Receipt time
        - src, dst: Source/destination
        - suser, duser: Source/destination user
        - act: Action
        - outcome: Outcome (success/failure)

        Args:
            extensions: Dictionary of extension fields

        Returns:
            Formatted extension string
        """
        parts = []
        for key, value in extensions.items():
            # Escape special characters in values
            value_str = str(value).replace("\\", "\\\\").replace("=", "\\=")
            parts.append(f"{key}={value_str}")

        return " ".join(parts)

    def to_syslog(self, cef_message: str, facility: int = 16, priority: int = 5) -> str:
        """Wrap CEF message in syslog format.

        Args:
            cef_message: CEF-formatted message
            facility: Syslog facility (default: 16 = local use 0)
            priority: Syslog priority (default: 5 = notice)

        Returns:
            Syslog-formatted message with CEF payload
        """
        # Calculate syslog PRI value
        pri = facility * 8 + priority

        # Build syslog message
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        hostname = "mcp-security"

        return f"<{pri}>{timestamp} {hostname} {cef_message}"


# Convenience functions
def format_capability_cef(finding_name: str, confidence: float, **kwargs: Any) -> str:
    """Quick format a capability finding to CEF.

    Args:
        finding_name: Capability name
        confidence: Confidence score
        **kwargs: Additional metadata

    Returns:
        CEF-formatted string
    """
    formatter = CEFFormatter()
    return formatter.format_capability_finding(
        finding_name=finding_name,
        confidence=confidence,
        evidence=kwargs.get("evidence", []),
        metadata=kwargs.get("metadata", {}),
    )


def format_detection_summary_cef(server_name: str, risk_level: str, total_score: float) -> str:
    """Quick format a detection summary to CEF.

    Args:
        server_name: Server name
        risk_level: Risk level
        total_score: Total score

    Returns:
        CEF-formatted summary
    """
    formatter = CEFFormatter()
    return formatter.format_detection_result(
        server_name=server_name,
        risk_level=risk_level,
        total_score=total_score,
        findings_count=0,  # Caller can override if needed
    )
