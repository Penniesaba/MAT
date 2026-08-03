use serde::{Deserialize, Serialize};

use crate::config::RuntimeConfig;

use super::{Confidence, Fact, FindingStatus, Severity};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleAnalysisResult {
    pub result_id: String,
    pub rule_id: String,
    pub category: String,
    pub owasp_mcp: Option<String>,
    pub file: String,
    pub line: u32,
    pub matched_text: Option<String>,
    pub evidence: Vec<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub recommendation: Option<String>,
    pub related_facts_exist: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaintAnalysisResult {
    pub result_id: String,
    pub source_id: String,
    pub source_kind: String,
    pub entrypoint_id: Option<String>,
    pub sink_id: String,
    pub sink_kind: String,
    pub call_chain: Vec<String>,
    pub dataflow_path: Vec<String>,
    pub evidence: Vec<String>,
    pub taint_confidence: Confidence,
    pub entrypoint_is_mcp: bool,
    pub backward_trace_found_root: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentAnalysisResult {
    pub result_id: String,
    pub agent_id: String,
    pub prompt_profile: String,
    pub model_provider: Option<String>,
    pub input_scope: Vec<String>,
    pub candidate_title: String,
    pub affected_locations: Vec<String>,
    pub reasoning_summary: String,
    pub evidence_snippets: Vec<String>,
    pub related_rule_result_ids: Vec<String>,
    pub related_taint_result_ids: Vec<String>,
    pub confidence: Confidence,
    pub verification_status: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FusedFinding {
    pub finding_id: String,
    pub title: String,
    pub category: String,
    pub owasp_mcp: Option<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: FindingStatus,
    pub supported_by: Vec<String>,
    pub related_rule_result_ids: Vec<String>,
    pub related_taint_result_ids: Vec<String>,
    pub related_agent_result_ids: Vec<String>,
    pub evidence: Vec<String>,
    pub call_chain: Vec<String>,
    pub dataflow_path: Vec<String>,
    pub recommendation: Option<String>,
    pub conflict_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticAnalysisSummary {
    pub target: String,
    pub fact_count: usize,
    pub rule_result_count: usize,
    pub taint_result_count: usize,
    pub agent_result_count: usize,
    pub fused_finding_count: usize,
    pub highest_severity: Option<Severity>,
    pub risk_level: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub runtime: RuntimeConfig,
    pub rulebook_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaticAnalysisResult {
    pub facts: Vec<Fact>,
    pub rule_results: Vec<RuleAnalysisResult>,
    pub taint_results: Vec<TaintAnalysisResult>,
    pub agent_results: Vec<AgentAnalysisResult>,
    pub fused_findings: Vec<FusedFinding>,
    pub summary: StaticAnalysisSummary,
    pub config_snapshot: ConfigSnapshot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_analysis_result_roundtrips_json() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let json = serde_json::to_string(&result).expect("serialize static result");
        let decoded: StaticAnalysisResult =
            serde_json::from_str(&json).expect("deserialize static result");

        assert_eq!(decoded, result);
    }

    #[test]
    fn static_analysis_json_preserves_three_line_results() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let value = serde_json::to_value(&result).expect("serialize static result");

        assert!(value.get("facts").is_some());
        assert!(value.get("rule_results").is_some());
        assert!(value.get("taint_results").is_some());
        assert!(value.get("agent_results").is_some());
        assert!(value.get("fused_findings").is_some());
        assert!(value.get("summary").is_some());
        assert!(value["summary"].get("fact_count").is_some());
        assert!(value.get("config_snapshot").is_some());
    }
}
