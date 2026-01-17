"""Dynamic pipeline for sandbox-driven analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from detection.core.models import DetectionResult, EvidenceSource
from detection.core.registry import DetectorRegistry
from detection.core.session import DetectionSession
from detection.sandbox.providers.docker_provider import DockerSandboxProvider


def run_dynamic_pipeline(
    target_path: Path,
    registry: DetectorRegistry,
    sandbox_timeout: int = 30,
    static_result: Optional[DetectionResult] = None,
) -> DetectionResult:
    """Run dynamic analysis using Docker sandbox with eBPF monitoring.
    
    Args:
        target_path: Path to MCP tool to analyze
        registry: Detector registry (not used but kept for compatibility)
        sandbox_timeout: Maximum sandbox execution time in seconds
        static_result: Optional static analysis result to merge with
        
    Returns:
        DetectionResult with runtime findings
        
    Raises:
        RuntimeError: If Docker or sandbox is not available
    """
    # Import dynamic analyzer
    from detection.plugins.dynamic import DynamicBehaviorAnalyzer
    
    # Initialize sandbox
    try:
        sandbox = DockerSandboxProvider()
    except RuntimeError as e:
        raise RuntimeError(f"Dynamic analysis unavailable: {e}") from e
    
    # Execute in sandbox
    sandbox_result = sandbox.run(target_path, timeout=sandbox_timeout)
    
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

Execution time: {telemetry.get('execution_time', 0):.2f}s
Exit code: {sandbox_result.exit_code}

Captured events: {telemetry.get('total_events', 0)}
  - File operations: {telemetry.get('file_events', 0)}
  - Network activity: {telemetry.get('network_events', 0)}
  - Process management: {telemetry.get('process_events', 0)}
"""
    
    if telemetry.get('sensitive_files'):
        notes += "\n⚠️  Sensitive paths accessed:\n"
        for path in telemetry['sensitive_files'][:5]:
            notes += f"  - {path}\n"
    
    # Create result
    result = DetectionResult(
        server_name=target_path.name,
        findings=findings,
        total_score=total_score,
        risk_level=risk_level,
        mitigations=[],
        notes=notes.strip()
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


def _merge_results(static: DetectionResult, dynamic: DetectionResult) -> DetectionResult:
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
