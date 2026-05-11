"""Dynamic pipeline for sandbox-driven analysis."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from detection.core.models import DetectionResult, EvidenceSource
from detection.core.registry import DetectorRegistry
from detection.core.session import DetectionSession
from detection.sandbox.providers.docker_provider import DockerSandboxProvider


@dataclass
class TriggerPlan:
    """Plan for guided dynamic analysis based on static findings."""
    execution_mode: str = "mcp_fuzz"  # "mcp_fuzz" or "direct_exec"
    target_tools: list[str] = field(default_factory=list)  # MCP tool names with findings
    risk_categories: list[str] = field(default_factory=list)  # ["rce", "file", "network"]
    sink_types: list[str] = field(default_factory=list)  # ["eval", "execSync", "fetch"]
    priority: str = "medium"  # "high" / "medium" / "low" — based on finding severity


def _detect_execution_mode(target_path: Path) -> str:
    """Detect whether target uses MCP or is a simple executable.

    Args:
        target_path: Path to the target to analyze

    Returns:
        "mcp_fuzz" if MCP entry detected, "direct_exec" otherwise
    """
    target_path = Path(target_path)

    # Check for package.json with MCP entry
    pkg_json_path = target_path / "package.json"
    if pkg_json_path.exists():
        try:
            pkg_data = json.loads(pkg_json_path.read_text(encoding="utf-8"))
            # Check for MCP-related fields or scripts
            if "mcp" in pkg_data or "main" in pkg_data:
                index_js = target_path / "index.js"
                if index_js.exists():
                    index_content = index_js.read_text(encoding="utf-8").lower()
                    # Check for MCP SDK patterns
                    if any(
                        pattern in index_content
                        for pattern in [
                            "@modelcontextprotocol/sdk",
                            "mcp",
                            "server",
                            "transport",
                        ]
                    ):
                        return "mcp_fuzz"
        except (json.JSONDecodeError, OSError):
            pass

    # Check for Python MCP server patterns
    py_files = list(target_path.glob("*.py"))
    for py_file in py_files:
        try:
            content = py_file.read_text(encoding="utf-8").lower()
            if any(
                pattern in content
                for pattern in [
                    "mcp",
                    "server",
                    "contextserver",
                    "fastmcp",
                ]
            ):
                return "mcp_fuzz"
        except OSError:
            pass

    # No MCP detected, use direct execution
    return "direct_exec"


def _build_trigger_plan(static_result: Optional[DetectionResult]) -> TriggerPlan:
    """Build a trigger plan from static analysis results.

    Guides the dynamic phase to focus on the most risky paths found statically.
    """
    plan = TriggerPlan()

    if static_result is None:
        return plan

    findings = static_result.findings
    if not findings:
        return plan

    # 1. Determine execution mode based on whether there are MCP entrypoints
    has_mcp = any("ep_" in f.name for f in findings)
    plan.execution_mode = "mcp_fuzz" if has_mcp else "direct_exec"

    # 2. Collect target tools (MCP tool names from findings)
    for f in findings:
        if "ep_" in f.name:
            # Extract tool name from finding name pattern: ep_<name>_sink_<sink>
            parts = f.name.split("_sink_")
            if len(parts) >= 1:
                tool_name = parts[0].replace("ep_", "", 1)
                if tool_name not in plan.target_tools:
                    plan.target_tools.append(tool_name)

    # 3. Collect risk categories
    for f in findings:
        cat = getattr(f, 'metadata', {}).get('category', '') if isinstance(getattr(f, 'metadata', None), dict) else ''
        if not cat:
            # Try from name
            for known_cat in ['rce', 'file', 'network']:
                if known_cat in f.name.lower():
                    cat = known_cat
                    break
        if cat and cat not in plan.risk_categories:
            plan.risk_categories.append(cat)

    # 4. Collect sink types from evidence
    for f in findings:
        for evidence_line in (f.evidence or []):
            if "Sink:" in evidence_line:
                # Extract sink name from "Sink: eval (category=...)"
                sink_name = evidence_line.split("Sink:")[1].split("(")[0].strip()
                if sink_name and sink_name not in plan.sink_types:
                    plan.sink_types.append(sink_name)

    # 5. Determine priority based on highest severity finding
    if any(f.score_weight >= 0.75 for f in findings):
        plan.priority = "high"
    elif any(f.score_weight >= 0.5 for f in findings):
        plan.priority = "medium"
    else:
        plan.priority = "low"

    return plan


def run_dynamic_pipeline(
    target_path: Path,
    registry: DetectorRegistry,
    sandbox_timeout: int = 30,
    static_result: Optional[DetectionResult] = None,
    execution_mode: Optional[str] = None,
) -> DetectionResult:
    """Run dynamic analysis using Docker sandbox with eBPF monitoring.

    Args:
        target_path: Path to MCP tool to analyze
        registry: Detector registry (not used but kept for compatibility)
        sandbox_timeout: Maximum sandbox execution time in seconds
        static_result: Optional static analysis result to merge with
        execution_mode: Execution mode - "mcp_fuzz", "direct_exec", or None for auto

    Returns:
        DetectionResult with runtime findings

    Raises:
        RuntimeError: If Docker or sandbox is not available
    """
    # Build trigger plan from static results (guides dynamic phase)
    plan = _build_trigger_plan(static_result)

    # Auto-detect execution mode if not specified, prefer static-guided plan
    if execution_mode is None:
        execution_mode = plan.execution_mode
        # Fallback to path-based detection only when no static result
        if static_result is None:
            execution_mode = _detect_execution_mode(target_path)

    # Import dynamic analyzer
    from detection.plugins.dynamic import DynamicBehaviorAnalyzer

    # Initialize sandbox
    try:
        sandbox = DockerSandboxProvider()
    except RuntimeError as e:
        raise RuntimeError(f"Dynamic analysis unavailable: {e}") from e

    # Execute in sandbox
    sandbox_result = sandbox.run(target_path, timeout=sandbox_timeout, execution_mode=execution_mode)

    # Save raw logs
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    log_file = logs_dir / f"{target_path.name}_events.cef"
    log_file.write_text(sandbox_result.logs, encoding="utf-8")

    # Analyze behavior
    analyzer = DynamicBehaviorAnalyzer()
    findings = analyzer.analyze(sandbox_result.logs, target_path)

    # Calculate total score
    total_score = sum(f.confidence * f.score_weight for f in findings)

    # Determine risk level
    if total_score >= 70:
        risk_level = "critical"
    elif total_score >= 50:
        risk_level = "high"
    elif total_score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    # Add telemetry notes
    telemetry = sandbox_result.telemetry
    notes = f"""
=== Dynamic Analysis Telemetry ===

Execution time: {telemetry.get("execution_time", 0):.2f}s
Exit code: {sandbox_result.exit_code}

Captured events: {telemetry.get("total_events", 0)}
  - File operations: {telemetry.get("file_events", 0)}
  - Network activity: {telemetry.get("network_events", 0)}
  - Process management: {telemetry.get("process_events", 0)}
  - Command executions: {telemetry.get("command_executions", 0)}
"""

    # Add trigger plan summary from static analysis
    if plan.target_tools or plan.sink_types:
        notes += f"\n=== Static-Guided Trigger Plan ===\n"
        notes += f"Priority: {plan.priority} | Mode: {plan.execution_mode}\n"
        if plan.target_tools:
            notes += f"Target tools: {', '.join(plan.target_tools)}\n"
        if plan.sink_types:
            notes += f"Sink types: {', '.join(plan.sink_types)}\n"
        if plan.risk_categories:
            notes += f"Risk categories: {', '.join(plan.risk_categories)}\n"

    if telemetry.get("executed_commands"):
        notes += "\n⚠️  Executed Commands:\n"
        for cmd in telemetry["executed_commands"]:
            notes += f"  - {cmd}\n"

    if telemetry.get("sensitive_files"):
        notes += "\n⚠️  Sensitive paths accessed:\n"
        for path in telemetry["sensitive_files"][:5]:
            notes += f"  - {path}\n"

    # Add log location
    notes += f"\nFull logs saved to: {log_file}\n"

    # Add log preview
    notes += "\n=== Raw Logs Preview (Last 20 lines) ===\n"
    log_lines = sandbox_result.logs.strip().split("\n")
    notes += "\n".join(log_lines[-20:])

    # Create result
    result = DetectionResult(
        server_name=target_path.name,
        findings=findings,
        total_score=total_score,
        risk_level=risk_level,
        mitigations=[],
        notes=notes.strip(),
    )

    # Merge with static result if provided
    if static_result:
        result = _merge_results(static_result, result)

    return result


def run_two_stage_pipeline(
    target_path: Path,
    registry: DetectorRegistry,
    policy_dir: Path,
    risk_threshold: float = 50.0,
    dynamic_timeout: int = 30,
) -> DetectionResult:
    """Run two-stage detection: static analysis → dynamic if high-risk.

    Args:
        target_path: Path to MCP tool to analyze
        registry: Detector registry with static analyzers
        policy_dir: Directory containing mitigation policy templates
        risk_threshold: Minimum score to trigger dynamic analysis
        dynamic_timeout: Maximum sandbox execution time in seconds

    Returns:
        DetectionResult with combined static + dynamic findings
    """
    from detection.pipelines.static import run_static_pipeline

    # Stage 1: Static analysis
    static_result = run_static_pipeline(target_path, registry, policy_dir)

    # Check if we should run dynamic analysis
    if static_result.total_score < risk_threshold:
        return static_result

    # Stage 2: Dynamic analysis
    try:
        dynamic_result = run_dynamic_pipeline(
            target_path=target_path,
            registry=registry,
            sandbox_timeout=dynamic_timeout,
            static_result=static_result,
        )
        return dynamic_result
    except RuntimeError:
        # If dynamic analysis fails, return static results
        return static_result


def _merge_results(
    static: DetectionResult, dynamic: DetectionResult
) -> DetectionResult:
    """Merge static and dynamic results, combining findings."""
    # Create a map of capabilities
    capability_map = {}

    # Add static findings
    for finding in static.findings:
        capability_map[finding.name] = finding

    # Merge or add dynamic findings
    for dyn_finding in dynamic.findings:
        if dyn_finding.name in capability_map:
            # Combine evidence and sources
            static_finding = capability_map[dyn_finding.name]
            merged_evidence = list(static_finding.evidence) + list(dyn_finding.evidence)
            merged_sources = set(static_finding.sources) | set(dyn_finding.sources)

            # Use higher confidence
            confidence = max(static_finding.confidence, dyn_finding.confidence)

            # Create merged finding
            from detection.core.models import CapabilityFinding

            capability_map[dyn_finding.name] = CapabilityFinding(
                name=dyn_finding.name,
                description=static_finding.description or dyn_finding.description,
                confidence=confidence,
                evidence=merged_evidence,
                score_weight=static_finding.score_weight,
                sources=list(merged_sources),
            )
        else:
            capability_map[dyn_finding.name] = dyn_finding

    # Create merged result
    merged_findings = list(capability_map.values())
    total_score = sum(f.confidence * f.score_weight for f in merged_findings)

    # Determine risk level
    if total_score >= 70:
        risk_level = "critical"
    elif total_score >= 50:
        risk_level = "high"
    elif total_score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    return DetectionResult(
        server_name=static.server_name,
        findings=merged_findings,
        total_score=total_score,
        risk_level=risk_level,
        mitigations=static.mitigations,
        notes=f"{static.notes}\n\n{dynamic.notes}".strip(),
    )
