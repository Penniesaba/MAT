//! Two-stage greedy matcher for fusing results across analysis lines.
//!
//! This module groups [`RuleAnalysisResult`], [`TaintAnalysisResult`], and
//! [`AgentAnalysisResult`] values into [`MatchGroup`]s. Matching runs in two
//! stages:
//!
//! 1. **Proximity**: an item joins the first group that contains a member
//!    sharing its file with a line within `line_proximity`.
//! 2. **Category**: items that were left solo in stage 1 get a second chance
//!    by sharing file *and* category with a group member.
//!
//! Agent results have no category field, so they can only ever join via
//! stage 1 proximity. Items that never match become single-item groups, so no
//! result is silently dropped.

use std::path::Path;

use crate::model::{AgentAnalysisResult, CodeqlAnalysisResult, RuleAnalysisResult, TaintAnalysisResult};

/// A group of related results from different analysis lines.
#[derive(Debug, Clone)]
pub(crate) struct MatchGroup {
    pub rule_results: Vec<RuleAnalysisResult>,
    pub taint_results: Vec<TaintAnalysisResult>,
    pub agent_results: Vec<AgentAnalysisResult>,
    pub codeql_results: Vec<CodeqlAnalysisResult>,
}

impl MatchGroup {
    /// Number of distinct lines present (0–4).
    pub fn line_count(&self) -> u32 {
        let mut count = 0u32;
        if !self.rule_results.is_empty() {
            count += 1;
        }
        if !self.taint_results.is_empty() {
            count += 1;
        }
        if !self.agent_results.is_empty() {
            count += 1;
        }
        if !self.codeql_results.is_empty() {
            count += 1;
        }
        count
    }

    /// Line names present, ordered rule/taint/agent/codeql.
    pub fn supported_by(&self) -> Vec<&'static str> {
        let mut lines = Vec::new();
        if !self.rule_results.is_empty() {
            lines.push("rule");
        }
        if !self.taint_results.is_empty() {
            lines.push("taint");
        }
        if !self.agent_results.is_empty() {
            lines.push("agent");
        }
        if !self.codeql_results.is_empty() {
            lines.push("codeql");
        }
        lines
    }
}

/// Which analysis line produced a given [`Matchable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchKind {
    Rule,
    Taint,
    Agent,
    Codeql,
}

/// A normalized view of a single result, carrying just what the matcher needs
/// plus the index it occupies in its original result vec.
#[derive(Debug, Clone)]
struct Matchable {
    file: String,
    line: u32,
    category: Option<String>,
    kind: MatchKind,
    /// Index into the original `rule_results` vec (for Rule items).
    rule_idx: Option<usize>,
    /// Index into the original `taint_results` vec (for Taint items).
    taint_idx: Option<usize>,
    /// Index into the original `agent_results` vec (for Agent items).
    agent_idx: Option<usize>,
    /// Index into the original `codeql_results` vec (for Codeql items).
    codeql_idx: Option<usize>,
}

/// Group all results into [`MatchGroup`]s using the two-stage greedy algorithm.
///
/// - Stage 1 (proximity): same file, line difference <= `line_proximity`.
/// - Stage 2 (category): same file + same category, for items left unmatched.
///
/// Greedy first-match: an item joins the first group it is compatible with,
/// which naturally prefers earlier/insertion-ordered items. Items that never
/// match become single-item groups.
pub(crate) fn match_results(
    rule_results: Vec<RuleAnalysisResult>,
    taint_results: Vec<TaintAnalysisResult>,
    agent_results: Vec<AgentAnalysisResult>,
    codeql_results: Vec<CodeqlAnalysisResult>,
    line_proximity: u32,
) -> Vec<MatchGroup> {
    let rule_orig = rule_results;
    let taint_orig = taint_results;
    let agent_orig = agent_results;
    let codeql_orig = codeql_results;

    let mut items: Vec<Matchable> = Vec::with_capacity(
        rule_orig.len() + taint_orig.len() + agent_orig.len() + codeql_orig.len(),
    );

    // Rules carry an explicit file/line/category.
    for (i, r) in rule_orig.iter().enumerate() {
        items.push(Matchable {
            file: r.file.clone(),
            line: r.line,
            category: Some(r.category.clone()),
            kind: MatchKind::Rule,
            rule_idx: Some(i),
            taint_idx: None,
            agent_idx: None,
            codeql_idx: None,
        });
    }

    // Taint results have no file/line fields; derive the file heuristically
    // from the sink_id. Lines default to 0 (see parse_line_from_id).
    for (i, t) in taint_orig.iter().enumerate() {
        items.push(Matchable {
            file: parse_file_from_id(&t.sink_id),
            line: parse_line_from_id(&t.sink_id),
            category: Some(t.sink_kind.clone()),
            kind: MatchKind::Taint,
            rule_idx: None,
            taint_idx: Some(i),
            agent_idx: None,
            codeql_idx: None,
        });
    }

    // Agent results have no category field; derive file/line from the first
    // affected location. They can therefore only match via stage 1 proximity.
    for (i, a) in agent_orig.iter().enumerate() {
        let (file, line) = parse_first_location(&a.affected_locations);
        items.push(Matchable {
            file,
            line,
            category: None,
            kind: MatchKind::Agent,
            rule_idx: None,
            taint_idx: None,
            agent_idx: Some(i),
            codeql_idx: None,
        });
    }

    // CodeQL results carry a clean first Location; use its file/line for
    // proximity matching and rule_id as the category (best-effort against the
    // rule/taint category vocabularies, which use different naming).
    for (i, c) in codeql_orig.iter().enumerate() {
        let (file, line) = c
            .locations
            .first()
            .map(|l| (l.file.clone(), l.line))
            .unwrap_or_else(|| (String::new(), 0));
        items.push(Matchable {
            file,
            line,
            category: Some(c.rule_id.clone()),
            kind: MatchKind::Codeql,
            rule_idx: None,
            taint_idx: None,
            agent_idx: None,
            codeql_idx: Some(i),
        });
    }

    let mut groups: Vec<Vec<usize>> = Vec::new();

    // Stage 1: file + line proximity (greedy first-match).
    for i in 0..items.len() {
        if items[i].file.is_empty() {
            // No location to anchor proximity or category against; keep the
            // result as its own solo group rather than dropping it.
            groups.push(vec![i]);
            continue;
        }
        let mut matched = false;
        for group in groups.iter_mut() {
            if can_join_group_proximity(i, group, &items, line_proximity) {
                group.push(i);
                matched = true;
                break;
            }
        }
        if !matched {
            groups.push(vec![i]);
        }
    }

    // Stage 2: file + category for items that ended up solo in stage 1.
    let mut stage2_groups: Vec<Vec<usize>> = Vec::new();
    let mut unmatched: Vec<usize> = Vec::new();
    for group in &groups {
        if group.len() == 1 {
            unmatched.push(group[0]);
        } else {
            stage2_groups.push(group.clone());
        }
    }

    for idx in unmatched {
        if items[idx].category.is_none() {
            // Agent results (or anything without a category) stay solo.
            stage2_groups.push(vec![idx]);
            continue;
        }
        let mut matched = false;
        for group in stage2_groups.iter_mut() {
            if can_join_group_category(idx, group, &items) {
                group.push(idx);
                matched = true;
                break;
            }
        }
        if !matched {
            stage2_groups.push(vec![idx]);
        }
    }

    // Build MatchGroup values from the grouped indices.
    stage2_groups
        .into_iter()
        .map(|indices| {
            let mut rule_results = Vec::new();
            let mut taint_results = Vec::new();
            let mut agent_results = Vec::new();
            let mut codeql_results = Vec::new();
            for idx in indices {
                match items[idx].kind {
                    MatchKind::Rule => {
                        if let Some(ri) = items[idx].rule_idx {
                            rule_results.push(rule_orig[ri].clone());
                        }
                    }
                    MatchKind::Taint => {
                        if let Some(ti) = items[idx].taint_idx {
                            taint_results.push(taint_orig[ti].clone());
                        }
                    }
                    MatchKind::Agent => {
                        if let Some(ai) = items[idx].agent_idx {
                            agent_results.push(agent_orig[ai].clone());
                        }
                    }
                    MatchKind::Codeql => {
                        if let Some(ci) = items[idx].codeql_idx {
                            codeql_results.push(codeql_orig[ci].clone());
                        }
                    }
                }
            }
            MatchGroup {
                rule_results,
                taint_results,
                agent_results,
                codeql_results,
            }
        })
        .collect()
}

/// Extract the file segment from an id like `"sink:command_exec:server.py:42"` or
/// `"source:server.py:handler:cmd"`. For the standard 4-segment sink_id format
/// (`"prefix:kind:file:name_or_line"`), the file is the 3rd segment (index 2).
fn parse_file_from_id(id: &str) -> String {
    let parts: Vec<&str> = id.splitn(4, ':').collect();
    if parts.len() >= 3 {
        parts[2].to_string()
    } else if parts.len() >= 2 {
        parts[1].to_string() // fallback for 2-segment ids
    } else {
        String::new()
    }
}

/// Parse the line number from the last segment of a 4-segment
/// sink_id (`"prefix:kind:file:line"`). Returns 0 when the line
/// segment is missing or non-numeric.
///
/// Kept as a distinct function so a future facts-aware implementation can
/// supply real line numbers without changing callers.
fn parse_line_from_id(id: &str) -> u32 {
    let parts: Vec<&str> = id.splitn(4, ':').collect();
    if parts.len() >= 4 {
        parts[3].parse::<u32>().unwrap_or(0)
    } else {
        0
    }
}

/// Parse `"file.py:line"` from the first affected location.
fn parse_first_location(locations: &[String]) -> (String, u32) {
    if let Some(first) = locations.first() {
        if let Some((file, line_str)) = first.rsplit_once(':') {
            return (file.to_string(), line_str.parse::<u32>().unwrap_or(0));
        }
        return (first.clone(), 0);
    }
    (String::new(), 0)
}

/// 取文件身份键：优先 basename（`a/b/main.rs` → `main.rs`）。
/// 消除 rule（完整路径）与 fact-derived（basename）之间的路径不一致。
fn file_key(file: &str) -> &str {
    Path::new(file)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(file)
}

/// Stage 1: can the item at `candidate_idx` join `group` by sharing a file
/// with a member whose line is within `line_proximity`?
fn can_join_group_proximity(
    candidate_idx: usize,
    group: &[usize],
    items: &[Matchable],
    line_proximity: u32,
) -> bool {
    let candidate = &items[candidate_idx];
    group.iter().any(|&member_idx| {
        let member = &items[member_idx];
        let member_key = file_key(&member.file);
        let candidate_key = file_key(&candidate.file);
        member_key == candidate_key
            && member.line.abs_diff(candidate.line) <= line_proximity
    })
}

/// Stage 2: can the item at `candidate_idx` join `group` by sharing a file and
/// category with a member?
fn can_join_group_category(candidate_idx: usize, group: &[usize], items: &[Matchable]) -> bool {
    let candidate = &items[candidate_idx];
    candidate.category.is_some()
        && group.iter().any(|&member_idx| {
            let member = &items[member_idx];
            file_key(&member.file) == file_key(&candidate.file)
                && member.category == candidate.category
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CodeqlAnalysisResult, Confidence, Location, Severity};

    fn make_rule(
        id: &str,
        file: &str,
        line: u32,
        category: &str,
        confidence: Confidence,
    ) -> RuleAnalysisResult {
        RuleAnalysisResult {
            result_id: id.to_string(),
            rule_id: "test_rule".to_string(),
            category: category.to_string(),
            owasp_mcp: None,
            file: file.to_string(),
            line,
            matched_text: None,
            evidence: vec![],
            severity: Severity::Medium,
            confidence,
            recommendation: None,
            related_facts_exist: false,
        }
    }

    fn make_taint(
        id: &str,
        sink_id: &str,
        sink_kind: &str,
        confidence: Confidence,
    ) -> TaintAnalysisResult {
        TaintAnalysisResult {
            result_id: id.to_string(),
            source_id: "source:test.py:param".to_string(),
            source_kind: "mcp_tool_param".to_string(),
            entrypoint_id: None,
            sink_id: sink_id.to_string(),
            sink_kind: sink_kind.to_string(),
            call_chain: vec![],
            dataflow_path: vec![],
            evidence: vec![],
            taint_confidence: confidence,
            entrypoint_is_mcp: false,
            backward_trace_found_root: false,
        }
    }

    fn make_agent(
        id: &str,
        file: &str,
        line: u32,
        confidence: Confidence,
    ) -> AgentAnalysisResult {
        AgentAnalysisResult {
            result_id: id.to_string(),
            agent_id: "test_agent".to_string(),
            prompt_profile: "test".to_string(),
            model_provider: None,
            input_scope: vec![],
            candidate_title: "Test finding".to_string(),
            affected_locations: vec![format!("{}:{}", file, line)],
            reasoning_summary: String::new(),
            evidence_snippets: vec![],
            related_rule_result_ids: vec![],
            related_taint_result_ids: vec![],
            confidence,
            verification_status: "uncorroborated".to_string(),
            limitations: vec![],
        }
    }

    fn make_codeql(
        id: &str,
        file: &str,
        line: u32,
        rule_id: &str,
        severity: Severity,
    ) -> CodeqlAnalysisResult {
        CodeqlAnalysisResult {
            result_id: id.to_string(),
            rule_id: rule_id.to_string(),
            rule_name: format!("{rule_id} rule"),
            category: "command_execution".to_string(),
            query_source: "built-in".to_string(),
            languages: vec!["python".to_string()],
            message: "CodeQL finding".to_string(),
            severity,
            locations: vec![Location {
                file: file.to_string(),
                line,
                column: None,
                message: None,
            }],
            dataflow_path: None,
            sarif_snippet: None,
            related_rule_ids: vec![],
            related_taint_ids: vec![],
            related_agent_ids: vec![],
            verification_status: "uncorroborated".to_string(),
            limitations: vec![],
        }
    }

    #[test]
    fn stage1_proximity_matches_same_file_nearby_lines() {
        // Taint line defaults to 0; a rule on line 3 is within proximity 5.
        let rules = vec![make_rule("r1", "a.py", 3, "cmd_inj", Confidence::High)];
        let taints = vec![make_taint("t1", "sink:command_exec:a.py:0", "command_exec", Confidence::Medium)];
        let agents = vec![];
        let groups = match_results(rules, taints, agents, vec![], 5);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].line_count(), 2);
        assert_eq!(groups[0].supported_by(), vec!["rule", "taint"]);
    }

    #[test]
    fn stage1_proximity_excludes_far_lines() {
        let rules = vec![make_rule("r1", "a.py", 10, "cmd_inj", Confidence::High)];
        let taints = vec![make_taint("t1", "sink:command_exec:a.py:0", "command_exec", Confidence::Medium)];
        let agents = vec![];
        let groups = match_results(rules, taints, agents, vec![], 5);
        // taint line is 0, proximity |10-0|=10 > 5
        assert_eq!(groups.len(), 2);
        for g in &groups {
            assert_eq!(g.line_count(), 1);
        }
    }

    #[test]
    fn stage2_category_matches_same_file_same_category() {
        let rules = vec![make_rule("r1", "a.py", 10, "cmd_inj", Confidence::High)];
        let taints = vec![make_taint("t1", "sink:cmd_inj:a.py:0", "cmd_inj", Confidence::Medium)];
        let agents = vec![];
        // line proximity fails but category should match in stage 2
        let groups = match_results(rules, taints, agents, vec![], 1);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].line_count(), 2);
    }

    #[test]
    fn unmatched_results_become_solo_groups() {
        let rules = vec![make_rule("r1", "a.py", 10, "cmd_inj", Confidence::High)];
        let taints = vec![make_taint("t1", "sink:file_read:b.py:0", "file_read", Confidence::Medium)];
        let agents = vec![];
        let groups = match_results(rules, taints, agents, vec![], 5);
        // Different files, different categories — both solo
        assert_eq!(groups.len(), 2);
        for g in &groups {
            assert_eq!(g.line_count(), 1);
        }
    }

    #[test]
    fn empty_inputs_produce_empty_groups() {
        let groups = match_results(vec![], vec![], vec![], vec![], 5);
        assert!(groups.is_empty());
    }

    #[test]
    fn same_category_results_group_even_without_line_proximity() {
        // Two rules far apart plus a taint; stage 1 proximity fails everywhere
        // but stage 2 category matching merges all three. No confidence
        // pre-sorting is used — greedy first-match on insertion order.
        let rules = vec![
            make_rule("r1", "a.py", 10, "cmd_inj", Confidence::Low),
            make_rule("r2", "a.py", 100, "cmd_inj", Confidence::High),
        ];
        let taints = vec![make_taint("t1", "sink:cmd_inj:a.py:0", "cmd_inj", Confidence::Medium)];
        let agents = vec![];
        let groups = match_results(rules, taints, agents, vec![], 5);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rule_results.len(), 2);
        assert_eq!(groups[0].taint_results.len(), 1);
    }

    #[test]
    fn greedy_first_match_joins_earliest_group() {
        // The agent (a.py:15) is within proximity of BOTH rule1 (a.py:10) and
        // rule2 (a.py:20), but those two groups are not merged with each other
        // (10 lines apart). Greedy first-match joins rule1's group, which was
        // created first.
        let rules = vec![
            make_rule("r1", "a.py", 10, "cmd_inj", Confidence::High),
            make_rule("r2", "a.py", 20, "file_read", Confidence::High),
        ];
        let agents = vec![make_agent("a1", "a.py", 15, Confidence::Medium)];
        let groups = match_results(rules, vec![], agents, vec![], 5);
        assert_eq!(groups.len(), 2);
        let joined = groups
            .iter()
            .find(|g| g.agent_results.len() == 1)
            .expect("agent should be in a group");
        assert_eq!(joined.rule_results.len(), 1);
        assert_eq!(joined.rule_results[0].result_id, "r1");
    }

    #[test]
    fn agent_matches_by_proximity_only() {
        // Agent within proximity joins the rule group in stage 1.
        let rules = vec![make_rule("r1", "a.py", 42, "cmd_inj", Confidence::High)];
        let agents = vec![make_agent("a1", "a.py", 41, Confidence::Medium)];
        let groups = match_results(rules, vec![], agents, vec![], 5);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].line_count(), 2);
        assert_eq!(groups[0].agent_results.len(), 1);

        // Agent far away in a different file cannot join via category
        // (category is None) — it stays solo.
        let rules2 = vec![make_rule("r2", "a.py", 42, "cmd_inj", Confidence::High)];
        let agents2 = vec![make_agent("a2", "b.py", 42, Confidence::Medium)];
        let groups2 = match_results(rules2, vec![], agents2, vec![], 5);
        assert_eq!(groups2.len(), 2);
        for g in &groups2 {
            assert_eq!(g.line_count(), 1);
        }
    }

    #[test]
    fn codeql_matches_rule_by_proximity() {
        let rules = vec![make_rule("r1", "a.py", 42, "cmd_inj", Confidence::High)];
        let codeql = vec![make_codeql("c1", "a.py", 41, "py/cmd-injection", Severity::High)];
        let groups = match_results(rules, vec![], vec![], codeql, 5);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].line_count(), 2);
        assert_eq!(groups[0].codeql_results.len(), 1);
        assert_eq!(groups[0].supported_by(), vec!["rule", "codeql"]);
    }

    #[test]
    fn codeql_solo_group() {
        let codeql = vec![make_codeql("c1", "a.py", 42, "py/cmd-injection", Severity::High)];
        let groups = match_results(vec![], vec![], vec![], codeql, 5);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].line_count(), 1);
        assert_eq!(groups[0].supported_by(), vec!["codeql"]);
    }

    #[test]
    fn matches_rule_full_path_with_taint_basename() {
        // rule 用完整路径，taint sink_id 只含 basename —— 应能融合
        let rules = vec![make_rule("r1", "proj/src/main.rs", 33, "cmd_inj", Confidence::High)];
        let taints = vec![make_taint("t1", "sink:command_execution:main.rs:36", "command_execution", Confidence::Medium)];
        let groups = match_results(rules, taints, vec![], vec![], 5);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].supported_by(), vec!["rule", "taint"]);
    }
}
