//! v4.0 set-partition: split the four analysis lines into the three feedback
//! sets c / a / b by reusing the fusion matcher's proximity grouping.

use crate::model::{
    AgentAnalysisResult, CodeqlAnalysisResult, ModelCandidate, RuleAnalysisResult,
    TaintAnalysisResult,
};

use super::codeql::models::mad_sink_kind;
use super::fusion::matcher::{MatchGroup, match_results};
use super::infer::name_category;

/// The three-way partition of a scan's findings for differential feedback.
/// - `agreed` = c: standard line(s) AND agent both found it.
/// - `a_only` = a: standard line(s) found it, agent did not.
/// - `b_only` = b: agent found it, standard line(s) did not.
#[derive(Debug, Default)]
pub(crate) struct LineDiff {
    pub(crate) agreed: Vec<MatchGroup>,
    pub(crate) a_only: Vec<MatchGroup>,
    pub(crate) b_only: Vec<MatchGroup>,
}

/// Partition the four lines into c / a / b using the fusion matcher's
/// proximity + category grouping (so "same finding" means what fusion means).
pub(crate) fn diff_lines(
    rule_results: Vec<RuleAnalysisResult>,
    taint_results: Vec<TaintAnalysisResult>,
    agent_results: Vec<AgentAnalysisResult>,
    codeql_results: Vec<CodeqlAnalysisResult>,
    line_proximity: u32,
) -> LineDiff {
    let groups = match_results(
        rule_results,
        taint_results,
        agent_results,
        codeql_results,
        line_proximity,
    );
    let mut diff = LineDiff::default();
    for group in groups {
        let has_standard = !group.rule_results.is_empty()
            || !group.taint_results.is_empty()
            || !group.codeql_results.is_empty();
        let has_agent = !group.agent_results.is_empty();
        match (has_standard, has_agent) {
            (true, true) => diff.agreed.push(group),
            (true, false) => diff.a_only.push(group),
            (false, true) => diff.b_only.push(group),
            (false, false) => {} // unreachable: matcher never emits empty groups
        }
    }
    diff
}

/// How an agent model candidate can be encoded into a standard-line component.
// Wired into the evolution loop in M2/M3.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Representability {
    /// Encodable as a CodeQL MaD sinkModel extension (module.function + sink kind).
    MadSink,
    /// Encodable as a taint source/sanitizer model (or a non-MaD sink model).
    TaintModel,
    /// Not encodable as any standard-line component — b0 (semantic-only).
    SemanticOnly,
}

/// Classify a B-only model candidate by its representability (the G2 gate).
// Wired into the evolution loop in M2/M3.
#[allow(dead_code)]
pub(crate) fn classify_candidate(c: &ModelCandidate) -> Representability {
    match c.kind.as_str() {
        "sink" => {
            let has_module = c.name.contains('.') || c.name.contains("::");
            if has_module && mad_sink_kind(&c.category).is_some() {
                Representability::MadSink
            } else if name_category(&c.name).is_some() {
                Representability::TaintModel
            } else {
                Representability::SemanticOnly
            }
        }
        "source" | "sanitizer" => Representability::TaintModel,
        _ => Representability::SemanticOnly,
    }
}

#[cfg(test)]
mod b0_tests {
    use super::*;
    use crate::model::{Confidence, ModelCandidate};

    fn cand(kind: &str, name: &str, category: &str) -> ModelCandidate {
        ModelCandidate {
            kind: kind.into(),
            name: name.into(),
            category: category.into(),
            language: "python".into(),
            argument: Some(0),
            confidence: Confidence::Medium,
            evidence_snippets: vec![],
        }
    }

    #[test]
    fn sink_with_mad_kind_and_module_is_mad_sink() {
        assert_eq!(
            classify_candidate(&cand("sink", "openpyxl.load_workbook", "file_read")),
            Representability::MadSink
        );
    }

    #[test]
    fn sink_without_mad_kind_but_named_is_taint_model() {
        // "deserialization" has no MaD sink kind, but "load_*" has a name prefix.
        assert_eq!(
            classify_candidate(&cand("sink", "pickle.loads", "deserialization")),
            Representability::TaintModel
        );
    }

    #[test]
    fn source_and_sanitizer_are_taint_models() {
        assert_eq!(
            classify_candidate(&cand("source", "request.get", "network_request")),
            Representability::TaintModel
        );
        assert_eq!(
            classify_candidate(&cand("sanitizer", "html.escape", "xss")),
            Representability::TaintModel
        );
    }

    #[test]
    fn unknown_kind_is_semantic_only() {
        assert_eq!(
            classify_candidate(&cand("mystery", "foo.bar", "x")),
            Representability::SemanticOnly
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Location, Severity};

    fn rule(id: &str, file: &str, line: u32, category: &str) -> RuleAnalysisResult {
        RuleAnalysisResult {
            result_id: id.into(),
            rule_id: "r".into(),
            category: category.into(),
            owasp_mcp: None,
            file: file.into(),
            line,
            matched_text: None,
            evidence: vec![],
            severity: Severity::Medium,
            confidence: Confidence::High,
            recommendation: None,
            related_facts_exist: false,
        }
    }
    fn taint(id: &str, sink_id: &str, sink_kind: &str) -> TaintAnalysisResult {
        TaintAnalysisResult {
            result_id: id.into(),
            source_id: "source:x.py:0".into(),
            source_kind: "mcp_tool_param".into(),
            entrypoint_id: None,
            sink_id: sink_id.into(),
            sink_kind: sink_kind.into(),
            call_chain: vec![],
            dataflow_path: vec![],
            evidence: vec![],
            taint_confidence: Confidence::Medium,
            entrypoint_is_mcp: false,
            backward_trace_found_root: false,
        }
    }
    fn agent(id: &str, file: &str, line: u32) -> AgentAnalysisResult {
        AgentAnalysisResult {
            result_id: id.into(),
            agent_id: "a".into(),
            prompt_profile: "p".into(),
            model_provider: None,
            input_scope: vec![],
            candidate_title: "t".into(),
            affected_locations: vec![format!("{file}:{line}")],
            reasoning_summary: String::new(),
            evidence_snippets: vec![],
            related_rule_result_ids: vec![],
            related_taint_result_ids: vec![],
            confidence: Confidence::Medium,
            verification_status: "uncorroborated".into(),
            limitations: vec![],
        }
    }
    fn codeql(id: &str, file: &str, line: u32) -> CodeqlAnalysisResult {
        CodeqlAnalysisResult {
            result_id: id.into(),
            rule_id: "py/cmd".into(),
            rule_name: "cmd".into(),
            category: "command_execution".into(),
            query_source: "built-in".into(),
            languages: vec!["python".into()],
            message: "m".into(),
            severity: Severity::High,
            locations: vec![Location {
                file: file.into(),
                line,
                column: None,
                message: None,
            }],
            dataflow_path: None,
            sarif_snippet: None,
            related_rule_ids: vec![],
            related_taint_ids: vec![],
            related_agent_ids: vec![],
            verification_status: "uncorroborated".into(),
            limitations: vec![],
        }
    }

    #[test]
    fn partitions_into_agreed_a_only_b_only() {
        // codeql@41 + agent@41 (agreed, same file+line); rule@10 on b.py (a-only);
        // agent@40 on c.py (b-only). Distinct files prevent the matcher's
        // stage-2 category merge from collapsing them into one group.
        let rules = vec![rule("r1", "b.py", 10, "file_read")];
        let taints = vec![];
        let agents = vec![agent("ag1", "a.py", 41), agent("ag2", "c.py", 40)];
        let codeqls = vec![codeql("c1", "a.py", 41)];
        let diff = diff_lines(rules, taints, agents, codeqls, 5);
        assert_eq!(diff.agreed.len(), 1);
        assert_eq!(diff.a_only.len(), 1);
        assert_eq!(diff.b_only.len(), 1);
    }

    #[test]
    fn empty_inputs_partition_empty() {
        let diff = diff_lines(vec![], vec![], vec![], vec![], 5);
        assert!(diff.agreed.is_empty());
        assert!(diff.a_only.is_empty());
        assert!(diff.b_only.is_empty());
    }

    #[test]
    fn taint_and_codeql_count_as_standard_line() {
        // taint sink at a.py:0, agent at a.py:3 — within proximity 5 → agreed.
        let taints = vec![taint("t1", "sink:file_read:a.py:0", "file_read")];
        let agents = vec![agent("ag1", "a.py", 3)];
        let diff = diff_lines(vec![], taints, agents, vec![], 5);
        assert_eq!(diff.agreed.len(), 1);
        assert!(diff.b_only.is_empty());
    }
}
