"""Dynamic analysis plugin for runtime behavior analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from detection.core.models import CapabilityFinding, EvidenceSource
from detection.core.registry import DetectorRegistry


def register(registry: DetectorRegistry) -> None:
    """Register dynamic detectors once sandbox support is available."""
    # Dynamic analysis runs separately via sandbox, not through registry
    pass


@dataclass
class CEFEvent:
    """Parsed CEF (Common Event Format) log entry."""
    
    signature_id: str
    severity: int
    extensions: dict[str, str]
    
    @classmethod
    def parse(cls, cef_line: str) -> Optional["CEFEvent"]:
        """Parse a CEF-formatted log line.
        
        Format: CEF:Version|Device Vendor|Device Product|Device Version|
                Signature ID|Name|Severity|Extension
        """
        if not cef_line.startswith("CEF:"):
            return None
        
        try:
            # Split CEF header and extensions
            parts = cef_line.split("|")
            if len(parts) < 8:
                return None
            
            signature_id = parts[4]
            severity = int(parts[6])
            
            # Parse extensions (key=value pairs)
            extensions_str = "|".join(parts[7:])
            extensions = {}
            for match in re.finditer(r"(\w+)=([^\s]+(?:\s+[^\w=]+)?)", extensions_str):
                key, value = match.groups()
                extensions[key] = value.strip()
            
            return cls(
                signature_id=signature_id,
                severity=severity,
                extensions=extensions,
            )
        except (ValueError, IndexError):
            return None


class DynamicBehaviorAnalyzer:
    """Analyze runtime behavior from CEF logs and extract capabilities."""
    
    def analyze(self, cef_logs: str, target_path: Path) -> List[CapabilityFinding]:
        """Analyze CEF logs and extract capability findings.
        
        Args:
            cef_logs: Raw CEF-formatted logs from sandbox
            target_path: Path to analyzed tool (for context)
            
        Returns:
            List of capability findings detected from runtime behavior
        """
        # Parse CEF events
        events = []
        for line in cef_logs.splitlines():
            event = CEFEvent.parse(line.strip())
            if event:
                events.append(event)
        
        if not events:
            return []
        
        # Extract capabilities from events
        findings = []
        
        # Command execution
        exec_events = [e for e in events if e.signature_id in ("PROC_EXEC", "COMMAND_EXEC")]
        if exec_events:
            evidence = []
            commands = set()
            for event in exec_events:
                cmd = event.extensions.get("dproc") or event.extensions.get("cs1")
                if cmd:
                    commands.add(cmd)
                    evidence.append(f"Executed: {cmd}")
            
            confidence = min(0.95, 0.60 + len(commands) * 0.1)
            findings.append(
                CapabilityFinding(
                    name="command_exec",
                    description="Command execution detected at runtime",
                    confidence=confidence,
                    evidence=evidence[:10],
                    score_weight=25.0,
                    sources=[EvidenceSource.DYNAMIC],
                )
            )
        
        # File operations
        file_events = [e for e in events if e.signature_id in ("FILE_READ", "FILE_OPEN", "FILE_WRITE")]
        if file_events:
            read_files = set()
            write_files = set()
            sensitive_files = []
            
            for event in file_events:
                filepath = event.extensions.get("dst", "")
                if event.signature_id in ("FILE_READ", "FILE_OPEN"):
                    read_files.add(filepath)
                    if _is_sensitive_path(filepath):
                        sensitive_files.append(filepath)
                elif event.signature_id == "FILE_WRITE":
                    write_files.add(filepath)
            
            # File read capability
            if read_files:
                evidence = [f"Read: {f}" for f in list(read_files)[:5]]
                if sensitive_files:
                    evidence = [f"⚠️  Sensitive file read: {f}" for f in sensitive_files] + evidence
                    confidence = 0.90
                else:
                    confidence = 0.70
                
                findings.append(
                    CapabilityFinding(
                        name="file_read",
                        description="File read operations detected at runtime",
                        confidence=confidence,
                        evidence=evidence[:10],
                        score_weight=15.0,
                        sources=[EvidenceSource.DYNAMIC],
                    )
                )
            
            # File write capability
            if write_files:
                evidence = [f"Wrote: {f}" for f in list(write_files)[:5]]
                findings.append(
                    CapabilityFinding(
                        name="file_write",
                        description="File write operations detected at runtime",
                        confidence=0.75,
                        evidence=evidence[:10],
                        score_weight=15.0,
                        sources=[EvidenceSource.DYNAMIC],
                    )
                )
        
        # Network operations
        net_events = [e for e in events if e.signature_id in ("NET_CONNECT", "NET_OUTBOUND")]
        if net_events:
            destinations = set()
            for event in net_events:
                dst = event.extensions.get("dst", "")
                if dst and not dst.startswith("127."):
                    destinations.add(dst)
            
            if destinations:
                evidence = [f"Connected to: {d}" for d in list(destinations)[:5]]
                confidence = min(0.85, 0.60 + len(destinations) * 0.08)
                findings.append(
                    CapabilityFinding(
                        name="network_outbound",
                        description="Outbound network connections detected at runtime",
                        confidence=confidence,
                        evidence=evidence[:10],
                        score_weight=20.0,
                        sources=[EvidenceSource.DYNAMIC],
                    )
                )
        
        # Environment variable access
        env_events = [e for e in events if e.signature_id in ("ENV_READ", "ENV_ACCESS")]
        if env_events:
            env_vars = set()
            for event in env_events:
                var = event.extensions.get("cs1") or event.extensions.get("msg", "")
                if var:
                    env_vars.add(var)
            
            if env_vars:
                evidence = [f"Read env: {v}" for v in list(env_vars)[:5]]
                findings.append(
                    CapabilityFinding(
                        name="env_read",
                        description="Environment variable access detected at runtime",
                        confidence=0.75,
                        evidence=evidence[:10],
                        score_weight=10.0,
                        sources=[EvidenceSource.DYNAMIC],
                    )
                )
        
        return findings


def _is_sensitive_path(path: str) -> bool:
    """Check if a file path is considered sensitive."""
    sensitive_patterns = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/.ssh/",
        "/.aws/",
        "/proc/",
        "/sys/",
        "id_rsa",
        "credentials",
        "secret",
        ".env",
    ]
    
    path_lower = path.lower()
    return any(pattern.lower() in path_lower for pattern in sensitive_patterns)
