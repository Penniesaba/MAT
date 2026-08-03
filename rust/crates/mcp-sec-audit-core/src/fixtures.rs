use std::collections::BTreeMap;

use crate::{
    config::RuntimeConfig,
    model::{
        AgentAnalysisResult, CapabilityFinding, Confidence, ConfigSnapshot, DetectionResult,
        EvidenceSource, FactBase, FindingFact, FindingStatus, FusedFinding, RuleAnalysisResult,
        Severity, StaticAnalysisResult, StaticAnalysisSummary, TaintAnalysisResult,
    },
    rules::{CapabilityRule, IndicatorRule, RuleBook},
};

pub fn synthetic_detection_result() -> DetectionResult {
    let mut metadata = BTreeMap::new();
    metadata.insert("finding_id".to_string(), "finding:demo:1".to_string());
    metadata.insert("category".to_string(), "command_exec".to_string());

    DetectionResult {
        server_name: "demo-mcp-server".to_string(),
        findings: vec![CapabilityFinding {
            name: "Command execution capability".to_string(),
            description: "MCP tool can reach a command execution sink".to_string(),
            score_weight: 0.75,
            confidence: 1.0,
            sources: vec![EvidenceSource::Static],
            evidence: vec!["subprocess.run(command)".to_string()],
            metadata,
        }],
        total_score: 0.75,
        risk_level: "high".to_string(),
        mitigations: vec!["Validate command arguments before execution".to_string()],
        notes: Some("synthetic Phase 2 fixture".to_string()),
    }
}

pub fn synthetic_finding_fact() -> FindingFact {
    FindingFact {
        base: FactBase {
            id: "finding:demo:1".to_string(),
            file: "server.py".to_string(),
            line: 42,
            extractor: "phase2_fixture".to_string(),
        },
        title: "Command execution reachable from MCP tool".to_string(),
        category: "command_exec".to_string(),
        severity: Severity::High,
        confidence: Confidence::High,
        status: FindingStatus::Potential,
        entrypoint_id: Some("entrypoint:demo:tool".to_string()),
        sink_id: Some("sink:demo:subprocess".to_string()),
        call_chain: Vec::new(),
        dataflows: vec!["dataflow:demo:1".to_string()],
        dynamic_evidence: Vec::new(),
        evidence: vec!["subprocess.run(command)".to_string()],
        recommendation: Some("Avoid shell execution or enforce allowlisted commands".to_string()),
    }
}

pub fn synthetic_runtime_config() -> RuntimeConfig {
    RuntimeConfig::default()
}

pub fn synthetic_rulebook() -> RuleBook {
    let indicator = IndicatorRule {
        languages: vec!["python".to_string()],
        indicator_type: "keyword".to_string(),
        patterns: vec!["subprocess.run".to_string()],
        pattern: None,
        case_sensitive: true,
        confidence_boost: 0.2,
    };

    let rule = CapabilityRule {
        name: "command_exec".to_string(),
        description: "Ability to spawn shell commands or subprocesses.".to_string(),
        weight: 25.0,
        base_confidence: 0.4,
        indicators: vec![indicator],
    };

    RuleBook {
        capabilities: BTreeMap::from([("command_exec".to_string(), rule)]),
    }
}

pub fn synthetic_rule_analysis_result() -> RuleAnalysisResult {
    RuleAnalysisResult {
        result_id: "rule-result:demo:1".to_string(),
        rule_id: "command_exec".to_string(),
        category: "command_execution".to_string(),
        owasp_mcp: Some("MCP05".to_string()),
        file: "server.py".to_string(),
        line: 42,
        matched_text: Some("subprocess.run(command)".to_string()),
        evidence: vec!["subprocess.run(command)".to_string()],
        severity: Severity::High,
        confidence: Confidence::Medium,
        recommendation: Some("Validate command arguments before execution".to_string()),
        related_facts_exist: true,
    }
}

pub fn synthetic_taint_analysis_result() -> TaintAnalysisResult {
    TaintAnalysisResult {
        result_id: "taint-result:demo:1".to_string(),
        source_id: "source:demo:tool-param".to_string(),
        source_kind: "mcp_tool_param".to_string(),
        entrypoint_id: Some("entrypoint:demo:tool".to_string()),
        sink_id: "sink:demo:subprocess".to_string(),
        sink_kind: "command_exec".to_string(),
        call_chain: vec!["tool_handler".to_string(), "run_command".to_string()],
        dataflow_path: vec!["command".to_string(), "subprocess.run".to_string()],
        evidence: vec!["command parameter reaches subprocess.run".to_string()],
        taint_confidence: Confidence::High,
        entrypoint_is_mcp: true,
        backward_trace_found_root: true,
    }
}

pub fn synthetic_agent_analysis_result() -> AgentAnalysisResult {
    AgentAnalysisResult {
        result_id: "agent-result:demo:1".to_string(),
        agent_id: "agent:static:demo".to_string(),
        prompt_profile: "mcp_security_audit".to_string(),
        model_provider: Some("claude".to_string()),
        input_scope: vec!["server.py".to_string()],
        candidate_title: "MCP tool parameter can drive command execution".to_string(),
        affected_locations: vec!["server.py:42".to_string()],
        reasoning_summary: "The tool accepts an external command parameter and passes it to a command execution sink.".to_string(),
        evidence_snippets: vec!["subprocess.run(command)".to_string()],
        related_rule_result_ids: vec!["rule-result:demo:1".to_string()],
        related_taint_result_ids: vec!["taint-result:demo:1".to_string()],
        confidence: Confidence::Medium,
        verification_status: "corroborated".to_string(),
        limitations: vec!["Synthetic fixture only".to_string()],
    }
}

pub fn synthetic_static_analysis_result() -> StaticAnalysisResult {
    StaticAnalysisResult {
        rule_results: vec![synthetic_rule_analysis_result()],
        taint_results: vec![synthetic_taint_analysis_result()],
        agent_results: vec![synthetic_agent_analysis_result()],
        fused_findings: vec![FusedFinding {
            finding_id: "finding:demo:fused:1".to_string(),
            title: "Command execution reachable from MCP tool".to_string(),
            category: "command_execution".to_string(),
            owasp_mcp: Some("MCP05".to_string()),
            severity: Severity::High,
            confidence: Confidence::High,
            status: FindingStatus::Potential,
            supported_by: vec!["rule".to_string(), "taint".to_string(), "agent".to_string()],
            related_rule_result_ids: vec!["rule-result:demo:1".to_string()],
            related_taint_result_ids: vec!["taint-result:demo:1".to_string()],
            related_agent_result_ids: vec!["agent-result:demo:1".to_string()],
            evidence: vec![
                "subprocess.run(command)".to_string(),
                "command parameter reaches subprocess.run".to_string(),
            ],
            call_chain: vec!["tool_handler".to_string(), "run_command".to_string()],
            dataflow_path: vec!["command".to_string(), "subprocess.run".to_string()],
            recommendation: Some(
                "Avoid shell execution or enforce allowlisted commands".to_string(),
            ),
            conflict_notes: Vec::new(),
        }],
        summary: StaticAnalysisSummary {
            target: "demo-mcp-server".to_string(),
            rule_result_count: 1,
            taint_result_count: 1,
            agent_result_count: 1,
            fused_finding_count: 1,
            highest_severity: Some(Severity::High),
            risk_level: "high".to_string(),
        },
        config_snapshot: ConfigSnapshot {
            runtime: synthetic_runtime_config(),
            rulebook_paths: vec!["rules/mcp".to_string()],
        },
    }
}
