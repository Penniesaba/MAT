//! Pass CodeQL results straight through to fused findings.
//!
//! CodeQL results are not grouped or scored with the rule/taint/agent lines;
//! each is emitted as its own [`FusedFinding`] with `Confidence::Medium` and a
//! `"codeql"` line marker so downstream reporting can attribute it.

use uuid::Uuid;

use crate::model::{CodeqlAnalysisResult, Confidence, FindingStatus, FusedFinding};

pub(crate) fn passthrough_codeql(results: Vec<CodeqlAnalysisResult>) -> Vec<FusedFinding> {
    results.into_iter().map(|c| {
        let dataflow_path: Vec<String> = c.dataflow_path
            .as_ref()
            .map(|dfp| dfp.steps.iter()
                .map(|step| format!("{}:{}", step.location.file, step.location.line))
                .collect())
            .unwrap_or_default();

        FusedFinding {
            finding_id: Uuid::new_v4().to_string(),
            title: if c.rule_name.is_empty() { c.message.clone() } else { c.rule_name.clone() },
            category: c.rule_id.clone(),
            owasp_mcp: None,
            severity: c.severity.clone(),
            confidence: Confidence::Medium,
            status: FindingStatus::Potential,
            supported_by: vec!["codeql".to_string()],
            related_rule_result_ids: Vec::new(),
            related_taint_result_ids: Vec::new(),
            related_agent_result_ids: Vec::new(),
            related_codeql_result_ids: vec![c.result_id.clone()],
            evidence: vec![c.message.clone()],
            call_chain: Vec::new(),
            dataflow_path,
            recommendation: None,
            conflict_notes: Vec::new(),
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Location, Severity};

    #[test]
    fn converts_codeql_result_to_fused_finding() {
        let cr = CodeqlAnalysisResult {
            result_id: "ql:1".into(),
            rule_id: "py/cmd-injection".into(),
            rule_name: "Command Injection".into(),
            message: "User input reaches shell".into(),
            severity: Severity::High,
            locations: vec![Location { file: "a.py".into(), line: 42, column: None, message: None }],
            dataflow_path: None,
            sarif_snippet: None,
            related_rule_ids: vec![],
            related_taint_ids: vec![],
            related_agent_ids: vec![],
            verification_status: "uncorroborated".into(),
            limitations: vec![],
        };
        let findings = passthrough_codeql(vec![cr]);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.title, "Command Injection");
        assert_eq!(f.category, "py/cmd-injection");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Medium);
        assert_eq!(f.supported_by, vec!["codeql"]);
        assert_eq!(f.related_codeql_result_ids, vec!["ql:1"]);
    }

    #[test]
    fn empty_codeql_results() {
        let findings = passthrough_codeql(vec![]);
        assert!(findings.is_empty());
    }
}
