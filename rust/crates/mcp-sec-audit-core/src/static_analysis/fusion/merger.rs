//! Fuse scored [`MatchGroup`]s into final [`FusedFinding`]s.
//!
//! [`merge_groups`] takes the [`ScoredGroup`]s produced by the scorer and
//! converts each into a single fused finding: the title comes from the
//! highest-priority result's description, the category is a plurality vote
//! across the group, evidence is the deduplicated union of all evidence
//! fields, taint contributes its call chain and dataflow path, and any
//! cross-line conflicts are surfaced as notes.

use uuid::Uuid;

use crate::model::{FindingStatus, FusedFinding, Severity};

use super::scorer::ScoredGroup;

pub(crate) fn merge_groups(scored_groups: Vec<ScoredGroup>) -> Vec<FusedFinding> {
    scored_groups.into_iter().map(|sg| {
        let group = sg.group;

        // Title: highest-severity result's best description
        let title = build_title(&group);

        // Category: plurality vote, tie-broken by highest severity
        let category = build_category(&group);

        // Evidence: union of all evidence fields, deduplicated
        let evidence = build_evidence(&group);

        // Conflict notes
        let conflict_notes = build_conflict_notes(&group);

        // Call chain and dataflow path from taint (or codeql dataflow)
        let (call_chain, dataflow_path) = extract_paths(&group);

        // Recommendation
        let recommendation = extract_recommendation(&group);

        FusedFinding {
            finding_id: Uuid::new_v4().to_string(),
            title,
            category,
            owasp_mcp: None,
            severity: sg.severity,
            confidence: sg.confidence,
            status: FindingStatus::Potential,
            supported_by: group.supported_by().iter().map(|s| s.to_string()).collect(),
            related_rule_result_ids: group.rule_results.iter().map(|r| r.result_id.clone()).collect(),
            related_taint_result_ids: group.taint_results.iter().map(|t| t.result_id.clone()).collect(),
            related_agent_result_ids: group.agent_results.iter().map(|a| a.result_id.clone()).collect(),
            related_codeql_result_ids: group.codeql_results.iter().map(|c| c.result_id.clone()).collect(),
            evidence,
            call_chain,
            dataflow_path,
            recommendation,
            conflict_notes,
        }
    }).collect()
}

fn build_title(group: &super::matcher::MatchGroup) -> String {
    // Prefer rule's matched_text, then codeql rule_name/message, then agent's
    // candidate_title, then taint description.
    if let Some(rule) = group.rule_results.first() {
        if let Some(ref text) = rule.matched_text {
            return text.clone();
        }
    }
    if let Some(codeql) = group.codeql_results.first() {
        if !codeql.rule_name.is_empty() {
            return codeql.rule_name.clone();
        }
        return codeql.message.clone();
    }
    if let Some(agent) = group.agent_results.first() {
        return agent.candidate_title.clone();
    }
    if let Some(taint) = group.taint_results.first() {
        return format!("taint: {} → {}", taint.source_kind, taint.sink_kind);
    }
    "Unknown finding".to_string()
}

fn build_category(group: &super::matcher::MatchGroup) -> String {
    // Collect categories from rule and taint results (agent has no category).
    // Plurality vote; tie breaks by highest-severity result.
    use std::collections::HashMap;
    let mut counts: HashMap<&str, u32> = HashMap::new();
    for r in &group.rule_results {
        *counts.entry(&r.category).or_insert(0) += 1;
    }
    for t in &group.taint_results {
        *counts.entry(&t.sink_kind).or_insert(0) += 1;
    }
    for c in &group.codeql_results {
        *counts.entry(&c.rule_id).or_insert(0) += 1;
    }
    counts.into_iter()
        .max_by_key(|(cat, count)| (*count, cat.len())) // tie-break arbitrarily stable
        .map(|(cat, _)| cat.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn build_evidence(group: &super::matcher::MatchGroup) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut evidence = Vec::new();
    for r in &group.rule_results {
        for e in &r.evidence {
            if seen.insert(e.clone()) {
                evidence.push(e.clone());
            }
        }
    }
    for t in &group.taint_results {
        for e in &t.evidence {
            if seen.insert(e.clone()) {
                evidence.push(e.clone());
            }
        }
    }
    for a in &group.agent_results {
        for e in &a.evidence_snippets {
            if seen.insert(e.clone()) {
                evidence.push(e.clone());
            }
        }
    }
    for c in &group.codeql_results {
        if seen.insert(c.message.clone()) {
            evidence.push(c.message.clone());
        }
    }
    evidence
}

fn extract_paths(group: &super::matcher::MatchGroup) -> (Vec<String>, Vec<String>) {
    if let Some(taint) = group.taint_results.first() {
        return (taint.call_chain.clone(), taint.dataflow_path.clone());
    }
    if let Some(codeql) = group.codeql_results.first() {
        let dataflow_path = codeql
            .dataflow_path
            .as_ref()
            .map(|dfp| {
                dfp.steps
                    .iter()
                    .map(|step| format!("{}:{}", step.location.file, step.location.line))
                    .collect()
            })
            .unwrap_or_default();
        return (Vec::new(), dataflow_path);
    }
    (Vec::new(), Vec::new())
}

fn extract_recommendation(group: &super::matcher::MatchGroup) -> Option<String> {
    if let Some(rule) = group.rule_results.first() {
        return rule.recommendation.clone();
    }
    if let Some(agent) = group.agent_results.first() {
        if agent.reasoning_summary.len() > 200 {
            return Some(format!("{}…", &agent.reasoning_summary[..200]));
        }
        return Some(agent.reasoning_summary.clone());
    }
    None
}

fn build_conflict_notes(group: &super::matcher::MatchGroup) -> Vec<String> {
    let mut notes = Vec::new();

    // Check severity conflicts
    let mut severities: Vec<(&str, &Severity)> = Vec::new();
    for r in &group.rule_results {
        severities.push(("rule", &r.severity));
    }
    for c in &group.codeql_results {
        severities.push(("codeql", &c.severity));
    }
    // Taint has no severity field; skip for conflict detection
    // Agent has no severity field; skip

    if severities.len() > 1 {
        let first = severities[0];
        if severities.iter().any(|(_, s)| s != &first.1) {
            let parts: Vec<String> = severities.iter()
                .map(|(line, s)| format!("{line}={s:?}"))
                .collect();
            notes.push(format!("severity mismatch: {}", parts.join(", ")));
        }
    }

    // Check category conflicts
    let mut categories: Vec<&str> = Vec::new();
    for r in &group.rule_results {
        categories.push(&r.category);
    }
    for t in &group.taint_results {
        categories.push(&t.sink_kind);
    }
    if categories.len() > 1 {
        let first = categories[0];
        if categories.iter().any(|c| c != &first) {
            let parts: Vec<String> = categories.iter().map(|c| c.to_string()).collect();
            notes.push(format!("category mismatch: {}", parts.join(", ")));
        }
    }

    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::matcher::MatchGroup;
    use super::super::scorer::ScoredGroup;
    use crate::model::{
        AgentAnalysisResult, CodeqlAnalysisResult, Confidence, Location, RuleAnalysisResult,
        Severity,
    };

    #[test]
    fn merge_single_rule_produces_fused_finding() {
        let group = MatchGroup {
            rule_results: vec![RuleAnalysisResult {
                result_id: "r1".into(), rule_id: "cmd_exec".into(),
                category: "command_execution".into(), owasp_mcp: None,
                file: "a.py".into(), line: 42, matched_text: Some("subprocess.run(x)".into()),
                evidence: vec!["line 42: subprocess.run(x)".into()],
                severity: Severity::High, confidence: Confidence::High,
                recommendation: Some("Use allowlist".into()), related_facts_exist: true,
            }],
            taint_results: vec![],
            agent_results: vec![],
            codeql_results: vec![],
        };
        let scored = ScoredGroup { group, severity: Severity::High, confidence: Confidence::High, raw_score: 0.8 };
        let findings = merge_groups(vec![scored]);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.title, "subprocess.run(x)");
        assert_eq!(f.category, "command_execution");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::High);
        assert_eq!(f.supported_by, vec!["rule"]);
        assert_eq!(f.related_rule_result_ids, vec!["r1"]);
        assert!(f.related_codeql_result_ids.is_empty());
        assert_eq!(f.recommendation, Some("Use allowlist".into()));
    }

    #[test]
    fn evidence_is_deduplicated() {
        let group = MatchGroup {
            rule_results: vec![RuleAnalysisResult {
                result_id: "r1".into(), rule_id: "x".into(), category: "x".into(),
                owasp_mcp: None, file: "a.py".into(), line: 1, matched_text: None,
                evidence: vec!["dup".into(), "unique".into()],
                severity: Severity::Medium, confidence: Confidence::Medium,
                recommendation: None, related_facts_exist: false,
            }],
            taint_results: vec![],
            agent_results: vec![AgentAnalysisResult {
                result_id: "a1".into(), agent_id: "ag".into(), prompt_profile: "t".into(),
                model_provider: None, input_scope: vec![], candidate_title: "t".into(),
                affected_locations: vec![], reasoning_summary: "".into(),
                evidence_snippets: vec!["dup".into()],
                related_rule_result_ids: vec![], related_taint_result_ids: vec![],
                confidence: Confidence::Medium, verification_status: "u".into(), limitations: vec![],
            }],
            codeql_results: vec![],
        };
        let scored = ScoredGroup { group, severity: Severity::Medium, confidence: Confidence::Medium, raw_score: 0.6 };
        let findings = merge_groups(vec![scored]);
        assert_eq!(findings[0].evidence.len(), 2); // "dup" appears once, "unique" once
    }

    #[test]
    fn empty_input() {
        let findings = merge_groups(vec![]);
        assert!(findings.is_empty());
    }

    #[test]
    fn merge_codeql_only_produces_fused_finding() {
        let group = MatchGroup {
            rule_results: vec![],
            taint_results: vec![],
            agent_results: vec![],
            codeql_results: vec![CodeqlAnalysisResult {
                result_id: "ql:1".into(),
                rule_id: "py/cmd-injection".into(),
                rule_name: "Command Injection".into(),
                message: "User input reaches shell".into(),
                severity: Severity::High,
                locations: vec![Location {
                    file: "a.py".into(),
                    line: 42,
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
            }],
        };
        let scored = ScoredGroup {
            group,
            severity: Severity::High,
            confidence: Confidence::Medium,
            raw_score: 0.6,
        };
        let findings = merge_groups(vec![scored]);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.title, "Command Injection");
        assert_eq!(f.category, "py/cmd-injection");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.supported_by, vec!["codeql".to_string()]);
        assert_eq!(f.related_codeql_result_ids, vec!["ql:1".to_string()]);
        assert_eq!(f.evidence, vec!["User input reaches shell".to_string()]);
    }
}
