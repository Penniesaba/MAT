//! 跨阶段迁移校验（v4.0 M2）：比较阶段 1 与阶段 2 的差分分区，把 a、b 两个混沌态
//! 剥成确定性标签 a1/a2、b1/b2（b0 语义漏洞由 pipeline 门控回填）。
//!
//! M3 接线：两阶段编排在阶段 2 跑完后用 `migrate` 比较两个 `LineDiff`，`should_rollback`
//! 决定是否回退试探性进化。

use std::collections::BTreeSet;

use super::diff::LineDiff;
use super::fusion::matcher::MatchGroup;

/// 跨阶段比较用的稳定 finding 身份（basename + 行号）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FindingKey {
    pub(crate) file: String, // basename
    pub(crate) line: u32,
}

/// 两个阶段比较的结果：a 二分（a1/a2）、b 三分（b0/b1/b2）的确定性计数。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Migration {
    /// b-only(阶段1) → agreed(阶段2)：B 真阳性 + A 已补上（b1 确认）。
    pub(crate) b1_confirmed: usize,
    /// a-only(阶段1) → agreed(阶段2)：A 真阳性 + B 已补上（a1 确认）。
    pub(crate) a1_confirmed: usize,
    /// a-only(阶段1) 仍是 a-only(阶段2)：A 误报（B 未重复报告是对的，a2）。
    pub(crate) a2_confirmed: usize,
    /// 新增 A'-only（a-only(阶段2) \ a-only(阶段1)）：B 幻觉污染标准线（b2）。
    pub(crate) b2_confirmed: usize,
    /// b0 语义漏洞：G2 判为 SemanticOnly / 无信号的候选数（pipeline 门控后回填）。
    pub(crate) b0_count: usize,
    /// b-only(阶段1) 仍是 b-only(阶段2)：仍混沌（b0 或 b2，需人工）。
    pub(crate) b_still_ambiguous: usize,
}

impl Migration {
    /// 回退触发：新增噪声（b2）> 确认收益（b1）。
    pub(crate) fn should_rollback(&self) -> bool {
        self.b2_confirmed > self.b1_confirmed
    }
}

fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string()
}

fn group_key(group: &MatchGroup) -> Option<FindingKey> {
    if let Some(c) = group.codeql_results.first()
        && let Some(loc) = c.locations.first()
    {
        return Some(FindingKey {
            file: basename(&loc.file),
            line: loc.line,
        });
    }
    if let Some(r) = group.rule_results.first() {
        return Some(FindingKey {
            file: basename(&r.file),
            line: r.line,
        });
    }
    if let Some(t) = group.taint_results.first() {
        let parts: Vec<&str> = t.sink_id.splitn(4, ':').collect();
        let file = parts.get(2).map(|s| basename(s)).unwrap_or_default();
        let line = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
        return Some(FindingKey { file, line });
    }
    if let Some(a) = group.agent_results.first()
        && let Some(first) = a.affected_locations.first()
        && let Some((file, line)) = first.rsplit_once(':')
    {
        return Some(FindingKey {
            file: basename(file),
            line: line.parse().ok().unwrap_or(0),
        });
    }
    None
}

fn key_set(groups: &[MatchGroup]) -> BTreeSet<FindingKey> {
    groups.iter().filter_map(group_key).collect()
}

/// b-only(阶段1) 仍是 b-only(阶段2) 的条目（仍混沌，需人工裁决，L3）。
pub(crate) fn ambiguous_items(
    phase1: &LineDiff,
    phase2: &LineDiff,
) -> Vec<crate::AdjudicationItem> {
    let p2_keys = key_set(&phase2.b_only);
    phase1
        .b_only
        .iter()
        .filter_map(|g| {
            let key = group_key(g)?;
            if p2_keys.contains(&key) {
                Some(crate::AdjudicationItem {
                    file: key.file,
                    line: key.line,
                    kind: "b_still_ambiguous".to_string(),
                    agent_explanation: None,
                })
            } else {
                None
            }
        })
        .collect()
}

/// 比较阶段 1 与阶段 2 的分区，产出 a1/a2/b1/b2 确定性计数（b0 由 pipeline 回填）。
pub(crate) fn migrate(phase1: &LineDiff, phase2: &LineDiff) -> Migration {
    let p1_b = key_set(&phase1.b_only);
    let p1_a = key_set(&phase1.a_only);
    let p2_c = key_set(&phase2.agreed);
    let p2_a = key_set(&phase2.a_only);
    let p2_b = key_set(&phase2.b_only);

    Migration {
        b1_confirmed: p1_b.intersection(&p2_c).count(),
        a1_confirmed: p1_a.intersection(&p2_c).count(),
        // a2 = A 独有且 B 阶段 2 仍未报（仍是 A 独有）→ A 的误报。
        a2_confirmed: p1_a.intersection(&p2_a).count(),
        // b2 = 进化后新增的 A'-only（B 幻觉污染）。
        b2_confirmed: p2_a.difference(&p1_a).count(),
        b0_count: 0,
        b_still_ambiguous: p1_b.intersection(&p2_b).count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AgentAnalysisResult, CodeqlAnalysisResult, Confidence, Location, RuleAnalysisResult,
        Severity,
    };

    fn rule(file: &str, line: u32, category: &str) -> RuleAnalysisResult {
        RuleAnalysisResult {
            result_id: "r".into(),
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
    fn codeql(file: &str, line: u32) -> CodeqlAnalysisResult {
        CodeqlAnalysisResult {
            result_id: "c".into(),
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
    fn agent(file: &str, line: u32) -> AgentAnalysisResult {
        AgentAnalysisResult {
            result_id: "a".into(),
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
    fn group_rule(r: RuleAnalysisResult) -> MatchGroup {
        MatchGroup {
            rule_results: vec![r],
            taint_results: vec![],
            agent_results: vec![],
            codeql_results: vec![],
        }
    }
    fn group_agent(a: AgentAnalysisResult) -> MatchGroup {
        MatchGroup {
            rule_results: vec![],
            taint_results: vec![],
            agent_results: vec![a],
            codeql_results: vec![],
        }
    }

    #[test]
    fn b_only_confirmed_when_agent_and_standard_agree_in_phase2() {
        // 阶段1：仅 agent 报 b.py:5。阶段2：codeql + agent 都报 b.py:5（agreed）。
        let p1 = LineDiff {
            agreed: vec![],
            a_only: vec![],
            b_only: vec![group_agent(agent("b.py", 5))],
        };
        let p2 = LineDiff {
            agreed: vec![MatchGroup {
                rule_results: vec![],
                taint_results: vec![],
                agent_results: vec![agent("b.py", 5)],
                codeql_results: vec![codeql("b.py", 5)],
            }],
            a_only: vec![],
            b_only: vec![],
        };
        let m = migrate(&p1, &p2);
        assert_eq!(m.b1_confirmed, 1);
        assert!(!m.should_rollback());
    }

    #[test]
    fn a_only_confirmed_when_agent_catches_it_in_phase2() {
        // 阶段1：仅 rule 报 a.py:10。阶段2：rule + agent 都报 a.py:10。
        let p1 = LineDiff {
            agreed: vec![],
            a_only: vec![group_rule(rule("a.py", 10, "file_read"))],
            b_only: vec![],
        };
        let p2 = LineDiff {
            agreed: vec![MatchGroup {
                rule_results: vec![rule("a.py", 10, "file_read")],
                taint_results: vec![],
                agent_results: vec![agent("a.py", 10)],
                codeql_results: vec![],
            }],
            a_only: vec![],
            b_only: vec![],
        };
        assert_eq!(migrate(&p1, &p2).a1_confirmed, 1);
    }

    #[test]
    fn new_a_only_findings_trigger_rollback() {
        // 阶段1：一个 a-only。阶段2：两个 a-only（一个新增）且无 b1 收益 → 回退。
        let p1 = LineDiff {
            agreed: vec![],
            a_only: vec![group_rule(rule("a.py", 10, "file_read"))],
            b_only: vec![],
        };
        let p2 = LineDiff {
            agreed: vec![],
            a_only: vec![
                group_rule(rule("a.py", 10, "file_read")),
                group_rule(rule("c.py", 99, "file_read")),
            ],
            b_only: vec![],
        };
        let m = migrate(&p1, &p2);
        assert_eq!(m.b2_confirmed, 1);
        assert!(m.should_rollback());
    }

    #[test]
    fn a_only_still_a_only_is_a2_false_positive() {
        // 阶段1：rule 报 a.py:10（a-only）。阶段2：仍是 a-only（B 仍未报）→ a2。
        let p1 = LineDiff {
            agreed: vec![],
            a_only: vec![group_rule(rule("a.py", 10, "file_read"))],
            b_only: vec![],
        };
        let p2 = LineDiff {
            agreed: vec![],
            a_only: vec![group_rule(rule("a.py", 10, "file_read"))],
            b_only: vec![],
        };
        let m = migrate(&p1, &p2);
        assert_eq!(m.a2_confirmed, 1);
        assert_eq!(m.a1_confirmed, 0);
    }

    #[test]
    fn still_b_only_is_ambiguous() {
        let p1 = LineDiff {
            agreed: vec![],
            a_only: vec![],
            b_only: vec![group_agent(agent("b.py", 5))],
        };
        let p2 = LineDiff {
            agreed: vec![],
            a_only: vec![],
            b_only: vec![group_agent(agent("b.py", 5))],
        };
        assert_eq!(migrate(&p1, &p2).b_still_ambiguous, 1);
    }

    #[test]
    fn ambiguous_items_surfaces_still_b_only() {
        let p1 = LineDiff {
            agreed: vec![],
            a_only: vec![],
            b_only: vec![group_agent(agent("b.py", 5))],
        };
        let p2 = LineDiff {
            agreed: vec![],
            a_only: vec![],
            b_only: vec![group_agent(agent("b.py", 5))],
        };
        let items = ambiguous_items(&p1, &p2);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file, "b.py");
        assert_eq!(items[0].line, 5);
        assert_eq!(items[0].kind, "b_still_ambiguous");
    }
}
