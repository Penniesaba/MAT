//! Weighted confidence scoring for fused result groups.
//!
//! [`score_groups`] takes the [`MatchGroup`]s produced by the matcher, filters
//! out groups with too few corroborating lines, computes a weighted confidence
//! average across the rule/taint/agent results in each group, applies
//! corroboration boosts and advisory caps, and produces a [`ScoredGroup`] with
//! a final [`Confidence`] and maximum [`Severity`].

use crate::model::{Confidence, Severity};

use super::matcher::MatchGroup;

#[derive(Debug, Clone)]
pub(crate) struct ScoredGroup {
    pub group: MatchGroup,
    pub severity: Severity,
    pub confidence: Confidence,
    pub raw_score: f64,
}

/// Convert Confidence to numeric value for scoring.
fn confidence_value(c: &Confidence) -> f64 {
    match c {
        Confidence::High => 0.8,
        Confidence::Medium => 0.6,
        Confidence::Low => 0.4,
    }
}

/// CodeQL results carry no confidence field; treat them as a fixed `Medium`
/// (CodeQL is static analysis, not runtime).
const CODEQL_CONFIDENCE: f64 = 0.6;

/// Convert numeric raw score back to Confidence.
fn raw_to_confidence(raw: f64) -> Confidence {
    if raw >= 0.7 {
        Confidence::High
    } else if raw >= 0.5 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

/// Convert Confidence to numeric for ordering.
///
/// Available for external consumers that need to sort or compare Confidence values.
/// Currently unused within this crate (pipeline.rs uses its own `scorer_ord` for
/// Severity ordering), but kept as a public(crate) utility.
#[allow(dead_code)]
pub(crate) fn confidence_ord(c: &Confidence) -> u8 {
    match c {
        Confidence::High => 3,
        Confidence::Medium => 2,
        Confidence::Low => 1,
    }
}

/// Ordering value for severity comparison.
pub(crate) fn severity_ord(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

pub(crate) fn score_groups(
    groups: Vec<MatchGroup>,
    config: &crate::config::FusionConfig,
) -> Vec<ScoredGroup> {
    groups.into_iter().filter_map(|group| {
        if group.line_count() < config.require_confirmed_by {
            return None; // filtered out
        }

        // Collect all confidences in the group for weighted average
        let mut weighted_sum = 0.0f64;
        let mut weight_sum = 0u32;

        for r in &group.rule_results {
            weighted_sum += config.rule_weight as f64 * confidence_value(&r.confidence);
            weight_sum += config.rule_weight;
        }
        for t in &group.taint_results {
            weighted_sum += config.taint_weight as f64 * confidence_value(&t.taint_confidence);
            weight_sum += config.taint_weight;
        }
        for a in &group.agent_results {
            weighted_sum += config.agent_weight as f64 * confidence_value(&a.confidence);
            weight_sum += config.agent_weight;
        }
        for _ in &group.codeql_results {
            weighted_sum += config.codeql_weight as f64 * CODEQL_CONFIDENCE;
            weight_sum += config.codeql_weight;
        }

        let mut raw = if weight_sum > 0 {
            weighted_sum / weight_sum as f64
        } else {
            0.0
        };

        // Corroboration boost
        if config.boost_when_multiple_lines_agree && group.line_count() >= 2 {
            raw = (raw + 0.1).min(1.0);
        }

        // Agent-only downgrade
        if config.agent_only_as_advisory
            && group.line_count() == 1
            && !group.agent_results.is_empty()
        {
            raw = raw.min(0.6);
        }

        // Compute max severity
        let severity = group_max_severity(&group);

        Some(ScoredGroup {
            group,
            severity,
            confidence: raw_to_confidence(raw),
            raw_score: raw,
        })
    }).collect()
}

fn group_max_severity(group: &MatchGroup) -> Severity {
    let mut max_sev = Severity::Low;
    for r in &group.rule_results {
        if severity_ord(&r.severity) > severity_ord(&max_sev) {
            max_sev = r.severity.clone();
        }
    }
    for t in &group.taint_results {
        // TaintAnalysisResult has taint_confidence but no severity field.
        // Map taint_confidence to severity as a heuristic.
        let taint_sev = taint_confidence_to_severity(&t.taint_confidence);
        if severity_ord(&taint_sev) > severity_ord(&max_sev) {
            max_sev = taint_sev;
        }
    }
    for a in &group.agent_results {
        // Agent has confidence but no severity. Map similarly.
        let agent_sev = confidence_to_severity(&a.confidence);
        if severity_ord(&agent_sev) > severity_ord(&max_sev) {
            max_sev = agent_sev;
        }
    }
    for c in &group.codeql_results {
        // CodeQL has a real severity field; use it directly.
        if severity_ord(&c.severity) > severity_ord(&max_sev) {
            max_sev = c.severity.clone();
        }
    }
    max_sev
}

fn taint_confidence_to_severity(c: &Confidence) -> Severity {
    match c {
        Confidence::High => Severity::High,
        Confidence::Medium => Severity::Medium,
        Confidence::Low => Severity::Low,
    }
}

fn confidence_to_severity(c: &Confidence) -> Severity {
    match c {
        Confidence::High => Severity::High,
        Confidence::Medium => Severity::Medium,
        Confidence::Low => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::super::matcher::MatchGroup;
    use super::*;
    use crate::config::FusionConfig;
    use crate::model::{
        AgentAnalysisResult, CodeqlAnalysisResult, Confidence, Location, RuleAnalysisResult,
        Severity, TaintAnalysisResult,
    };

    fn make_rule(confidence: Confidence) -> RuleAnalysisResult {
        RuleAnalysisResult {
            result_id: "r1".into(), rule_id: "test".into(), category: "cmd".into(),
            owasp_mcp: None, file: "a.py".into(), line: 1, matched_text: None,
            evidence: vec![], severity: Severity::High, confidence,
            recommendation: None, related_facts_exist: false,
        }
    }

    fn make_taint(confidence: Confidence) -> TaintAnalysisResult {
        TaintAnalysisResult {
            result_id: "t1".into(), source_id: "s:x".into(), source_kind: "p".into(),
            entrypoint_id: None, sink_id: "sink:x".into(), sink_kind: "cmd".into(),
            call_chain: vec![], dataflow_path: vec![], evidence: vec![],
            taint_confidence: confidence, entrypoint_is_mcp: false, backward_trace_found_root: false,
        }
    }

    fn make_agent(confidence: Confidence) -> AgentAnalysisResult {
        AgentAnalysisResult {
            result_id: "a1".into(), agent_id: "ag".into(), prompt_profile: "t".into(),
            model_provider: None, input_scope: vec![], candidate_title: "t".into(),
            affected_locations: vec!["a.py:1".into()], reasoning_summary: "".into(),
            evidence_snippets: vec![], related_rule_result_ids: vec![],
            related_taint_result_ids: vec![], confidence,
            verification_status: "u".into(), limitations: vec![],
        }
    }

    fn make_codeql(rule_id: &str, severity: Severity) -> CodeqlAnalysisResult {
        CodeqlAnalysisResult {
            result_id: format!("c:{rule_id}"),
            rule_id: rule_id.to_string(),
            rule_name: format!("{rule_id} rule"),
            message: "CodeQL finding".to_string(),
            severity,
            locations: vec![Location {
                file: "a.py".into(),
                line: 1,
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
    fn weighted_average_rule_plus_taint() {
        let group = MatchGroup {
            rule_results: vec![make_rule(Confidence::High)],
            taint_results: vec![make_taint(Confidence::Medium)],
            agent_results: vec![],
            codeql_results: vec![],
        };
        let config = FusionConfig::default();
        let scored = score_groups(vec![group], &config);
        assert_eq!(scored.len(), 1);
        // (3*0.8 + 2*0.6) / (3+2) = (2.4 + 1.2) / 5 = 0.72
        // boost +0.1 → 0.82 → High (≥0.7)
        assert_eq!(scored[0].confidence, Confidence::High);
        assert!(scored[0].raw_score > 0.8);
    }

    #[test]
    fn agent_only_capped_to_medium() {
        let group = MatchGroup {
            rule_results: vec![],
            taint_results: vec![],
            agent_results: vec![make_agent(Confidence::High)],
            codeql_results: vec![],
        };
        let config = FusionConfig::default();
        let scored = score_groups(vec![group], &config);
        assert_eq!(scored.len(), 1);
        // 1*0.8/1 = 0.8, cap at 0.6 → Medium (≥0.5)
        assert_eq!(scored[0].confidence, Confidence::Medium);
    }

    #[test]
    fn require_confirmed_by_filters_solo() {
        let group = MatchGroup {
            rule_results: vec![make_rule(Confidence::High)],
            taint_results: vec![],
            agent_results: vec![],
            codeql_results: vec![],
        };
        let mut config = FusionConfig::default();
        config.require_confirmed_by = 2;
        let scored = score_groups(vec![group], &config);
        assert!(scored.is_empty());
    }

    #[test]
    fn empty_input() {
        let scored = score_groups(vec![], &FusionConfig::default());
        assert!(scored.is_empty());
    }

    #[test]
    fn severity_is_max_of_group() {
        let group = MatchGroup {
            rule_results: vec![{
                let mut r = make_rule(Confidence::High);
                r.severity = Severity::Critical;
                r
            }],
            taint_results: vec![make_taint(Confidence::Low)],
            agent_results: vec![],
            codeql_results: vec![],
        };
        let scored = score_groups(vec![group], &FusionConfig::default());
        assert_eq!(scored[0].severity, Severity::Critical);
    }

    #[test]
    fn codeql_weight_contributes_to_confidence() {
        // Solo codeql: raw = (codeql_weight * 0.6) / codeql_weight = 0.6 → Medium
        let group = MatchGroup {
            rule_results: vec![],
            taint_results: vec![],
            agent_results: vec![],
            codeql_results: vec![make_codeql("py/cmd-injection", Severity::High)],
        };
        let scored = score_groups(vec![group], &FusionConfig::default());
        assert_eq!(scored.len(), 1);
        assert_eq!(scored[0].confidence, Confidence::Medium);
        assert_eq!(scored[0].severity, Severity::High);
    }

    #[test]
    fn codeql_severity_is_max_of_group() {
        let group = MatchGroup {
            rule_results: vec![{
                let mut r = make_rule(Confidence::High);
                r.severity = Severity::High;
                r
            }],
            taint_results: vec![],
            agent_results: vec![],
            codeql_results: vec![make_codeql("py/cmd-injection", Severity::Critical)],
        };
        let scored = score_groups(vec![group], &FusionConfig::default());
        assert_eq!(scored[0].severity, Severity::Critical);
    }
}
