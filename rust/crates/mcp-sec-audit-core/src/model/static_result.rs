use serde::{Deserialize, Serialize};

use crate::config::RuntimeConfig;

use super::{Confidence, Fact, FindingStatus, Severity};

/// Source location with file path and line number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub line: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// A single step in a CodeQL dataflow path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFlowPathStep {
    pub location: Location,
    pub snippet: Option<String>,
}

/// CodeQL codeFlows representation — a full taint path through the program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFlowPath {
    pub steps: Vec<DataFlowPathStep>,
}

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

/// A sink/source/sanitizer model proposed by the agent (three-role "model" output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCandidate {
    /// "sink" | "source" | "sanitizer".
    pub kind: String,
    /// Callee name, e.g. "openpyxl.load_workbook".
    pub name: String,
    /// Canonical category (snake_case), e.g. "file_read".
    pub category: String,
    /// "python" | "javascript" | "rust".
    pub language: String,
    /// Dangerous argument index (sink) — `None` when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argument: Option<u32>,
    pub confidence: Confidence,
    #[serde(default)]
    pub evidence_snippets: Vec<String>,
}

/// Combined output of the agent line: findings + proposed models.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentOutput {
    pub findings: Vec<AgentAnalysisResult>,
    #[serde(default)]
    pub model_candidates: Vec<ModelCandidate>,
}

/// Result from the CodeQL analysis line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeqlAnalysisResult {
    pub result_id: String,
    pub rule_id: String,
    pub rule_name: String,
    /// Category in the shared rule/taint vocabulary (e.g. "command_execution").
    #[serde(default = "default_uncategorized")]
    pub category: String,
    /// Where the query came from: "built-in" or a custom pack path.
    #[serde(default)]
    pub query_source: String,
    /// Languages the database was built for.
    #[serde(default)]
    pub languages: Vec<String>,
    pub message: String,
    pub severity: Severity,
    pub locations: Vec<Location>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataflow_path: Option<DataFlowPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sarif_snippet: Option<String>,
    #[serde(default)]
    pub related_rule_ids: Vec<String>,
    #[serde(default)]
    pub related_taint_ids: Vec<String>,
    #[serde(default)]
    pub related_agent_ids: Vec<String>,
    #[serde(default = "default_verification_status")]
    pub verification_status: String,
    #[serde(default)]
    pub limitations: Vec<String>,
}

fn default_verification_status() -> String {
    "uncorroborated".to_string()
}

fn default_uncategorized() -> String {
    "uncategorized".to_string()
}

/// Composite output from the CodeQL line — structured results + raw SARIF + diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeqlOutput {
    pub results: Vec<CodeqlAnalysisResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_sarif: Option<String>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

impl CodeqlOutput {
    pub fn empty() -> Self {
        Self {
            results: Vec::new(),
            raw_sarif: None,
            diagnostics: Vec::new(),
        }
    }
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
    #[serde(default)]
    pub related_codeql_result_ids: Vec<String>,
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
    pub codeql_result_count: usize,
    pub codeql_fused_count: usize,
    pub fused_finding_count: usize,
    pub highest_severity: Option<Severity>,
    pub risk_level: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub runtime: RuntimeConfig,
    pub rulebook_paths: Vec<String>,
}

/// Differential evolution + layered-validation report, surfaced in the scan
/// result so the a1/a2/b0/b1/b2 labels and the residual human-adjudication
/// items are visible (L1 migration + L2 agent explanation + L3 human review).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvolutionReport {
    /// b1: B-only → agreed (B true positive, A caught up).
    pub b1_confirmed: usize,
    /// a1: A-only → agreed (A true positive, B caught up).
    pub a1_confirmed: usize,
    /// a2: A-only still A-only (A false positive).
    pub a2_confirmed: usize,
    /// b2: new A'-only (B hallucination polluting the standard line).
    pub b2_confirmed: usize,
    /// b0: semantic-only candidates (semantic vulnerabilities A cannot express).
    pub b0_count: usize,
    /// b-only still b-only: residual ambiguity needing human review.
    pub b_still_ambiguous: usize,
    /// Whether the staged evolution was rolled back.
    #[serde(default)]
    pub rolled_back: bool,
    /// Whether the staged evolution was promoted to learned.
    #[serde(default)]
    pub promoted: bool,
    /// The b0 semantic-only candidates themselves (surfaced, not dropped).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub b0_candidates: Vec<ModelCandidate>,
    /// Residual ambiguous items surfaced for human adjudication (L3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ambiguous_for_review: Vec<AdjudicationItem>,
}

/// One residual ambiguous item awaiting human adjudication, with the optional
/// L2 agent explanation attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjudicationItem {
    pub file: String,
    pub line: u32,
    /// "b_still_ambiguous" (B-only both phases) or "a_unresolved".
    pub kind: String,
    /// L2 agent semantic explanation (why it may/may not be a vulnerability).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_explanation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaticAnalysisResult {
    pub facts: Vec<Fact>,
    pub rule_results: Vec<RuleAnalysisResult>,
    pub taint_results: Vec<TaintAnalysisResult>,
    pub agent_results: Vec<AgentAnalysisResult>,
    pub codeql_results: Vec<CodeqlAnalysisResult>,
    /// Diagnostics emitted by the CodeQL line (skip reasons, create/analyze
    /// failures, SARIF parse errors). Surfaced so "0 results" is never silent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codeql_diagnostics: Vec<String>,
    /// Raw concatenated SARIF produced by CodeQL, preserved for debugging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codeql_raw_sarif: Option<String>,
    /// Sink/source/sanitizer models proposed by the agent this run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_candidates: Vec<ModelCandidate>,
    pub fused_findings: Vec<FusedFinding>,
    pub summary: StaticAnalysisSummary,
    pub config_snapshot: ConfigSnapshot,
    /// Differential evolution + layered-validation report (L1/L2/L3).
    #[serde(default)]
    pub evolution: EvolutionReport,
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

    #[test]
    fn static_analysis_json_preserves_codeql_results() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let value = serde_json::to_value(&result).expect("serialize static result");
        assert!(value.get("codeql_results").is_some());
        assert!(value["summary"].get("codeql_result_count").is_some());
        assert_eq!(value["summary"]["codeql_result_count"].as_u64(), Some(1));
    }
}
