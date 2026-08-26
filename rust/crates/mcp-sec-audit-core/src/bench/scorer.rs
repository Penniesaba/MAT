//! Scoring: map report findings to ground-truth sink lines and classify.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::ground_truth::{GroundTruth, VulnEntry};
use crate::model::{FusedFinding, StaticAnalysisResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Classification {
    Tp,
    Fp,
    Unconfirmed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoMetrics {
    pub slug: String,
    pub language: String,
    pub evidence_tier: String,
    pub status: String,
    pub ground_truth: usize,
    pub tp: usize,
    pub fp: usize,
    pub unconfirmed: usize,
    pub hits: Vec<String>,
    pub misses: Vec<String>,
    pub recall: f64,
    pub precision_optimistic: f64,
    pub precision_pessimistic: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AggregateMetrics {
    pub ground_truth: usize,
    pub tp: usize,
    pub fp: usize,
    pub unconfirmed: usize,
    pub recall: f64,
    pub precision_optimistic: f64,
    pub precision_pessimistic: f64,
}

impl Default for AggregateMetrics {
    fn default() -> Self {
        Self { ground_truth: 0, tp: 0, fp: 0, unconfirmed: 0, recall: 0.0, precision_optimistic: 0.0, precision_pessimistic: 0.0 }
    }
}

/// Parses an evidence string `path:line:snippet` (the path may itself contain
/// colons, e.g. a Windows drive, so the snippet and line are split from the
/// right). Returns a normalized repo-relative path and the line number.
pub fn parse_line(evidence: &str) -> Option<(String, u32)> {
    let (path_and_line, _snippet) = evidence.rsplit_once(':')?;
    let (path, line_str) = path_and_line.rsplit_once(':')?;
    let line: u32 = line_str.parse().ok()?;
    Some((normalize_path(path), line))
}

/// Normalize a file path for matching: backslashes to forward slashes, and
/// strip leading `../<dir>/` checkout prefixes so an analyzer path like
/// `../x/src/lib.py` collapses to the repo-relative `src/lib.py`.
fn normalize_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').collect();
    let mut start = 0;
    while start < parts.len() && parts[start] == ".." {
        start += 1; // drop the `..`
        if start < parts.len() && parts[start] != ".." {
            start += 1; // drop the directory that follows a leading `..`
        }
    }
    parts[start..].join("/")
}

/// Collects candidate `(file, line)` pairs for a fused finding: resolve its
/// `related_*` ids against the raw per-line results first, then fall back to
/// parsing the finding's own `evidence` strings.
pub fn finding_lines(fused: &FusedFinding, result: &StaticAnalysisResult) -> Vec<(String, u32)> {
    let mut out: Vec<(String, u32)> = Vec::new();

    for id in &fused.related_rule_result_ids {
        if let Some(r) = result.rule_results.iter().find(|r| &r.result_id == id) {
            out.push((normalize_path(&r.file), r.line));
        }
    }
    for id in &fused.related_taint_result_ids {
        if let Some(t) = result.taint_results.iter().find(|t| &t.result_id == id) {
            for e in &t.evidence {
                if let Some(p) = parse_line(e) {
                    out.push(p);
                }
            }
        }
    }
    for id in &fused.related_codeql_result_ids {
        if let Some(c) = result.codeql_results.iter().find(|c| &c.result_id == id) {
            for loc in &c.locations {
                out.push((normalize_path(&loc.file), loc.line));
            }
        }
    }
    if out.is_empty() {
        for e in &fused.evidence {
            if let Some(p) = parse_line(e) {
                out.push(p);
            }
        }
    }
    out
}

/// `known_clean` entries use the same normalized-relative-path + line format.
fn clean_line_is_hit(entry: &VulnEntry, file: &str, line: u32) -> bool {
    entry.known_clean.iter().any(|c| {
        parse_line(c).is_some_and(|(f, l)| f == file && l == line)
    })
}

pub fn score_repo(
    slug: &str,
    status: &str,
    gt: &GroundTruth,
    result: &StaticAnalysisResult,
    tolerance: u32,
) -> RepoMetrics {
    let gt_entries = gt.for_repo(slug);
    let language = gt_entries.first().map(|(_, e)| e.language.clone()).unwrap_or_default();
    let tier = gt_entries.first().map(|(_, e)| e.evidence_tier.clone()).unwrap_or_default();

    // A vuln is "hit" when at least one finding line matches its sink line.
    let mut hits: BTreeSet<String> = BTreeSet::new();
    let mut fp = 0usize;
    let mut unconfirmed = 0usize;

    for fused in &result.fused_findings {
        let lines = finding_lines(fused, result);
        let mut matched = false;
        for (key, entry) in &gt_entries {
            let sink_ok = lines.iter().any(|(f, l)| {
                file_suffix_matches(f, &entry.sink_file)
                    && (l.abs_diff(entry.sink_line) <= tolerance)
            });
            if sink_ok {
                hits.insert((*key).clone());
                matched = true;
            }
        }
        if !matched {
            // FP only when it lands in a `known_clean` region of some entry.
            let in_clean = gt_entries.iter().any(|(_, e)| {
                lines.iter().any(|(f, l)| clean_line_is_hit(e, f, *l))
            });
            if in_clean {
                fp += 1;
            } else {
                unconfirmed += 1;
            }
        }
    }

    let ground_truth = gt_entries.len();
    let tp = hits.len();
    let misses: Vec<String> = gt_entries
        .iter()
        .map(|(k, _)| (*k).clone())
        .filter(|k| !hits.contains(k))
        .collect();
    let hits_vec: Vec<String> = hits.into_iter().collect();

    let (recall, p_opt, p_pes) = compute_scores(tp, fp, unconfirmed, ground_truth);
    RepoMetrics {
        slug: slug.to_string(),
        language,
        evidence_tier: tier,
        status: status.to_string(),
        ground_truth,
        tp,
        fp,
        unconfirmed,
        hits: hits_vec,
        misses,
        recall,
        precision_optimistic: p_opt,
        precision_pessimistic: p_pes,
    }
}

pub fn aggregate(repos: &[RepoMetrics]) -> AggregateMetrics {
    let (tp, fp, unconf, gt): (usize, usize, usize, usize) = repos
        .iter()
        .map(|r| (r.tp, r.fp, r.unconfirmed, r.ground_truth))
        .fold((0, 0, 0, 0), |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2, a.3 + b.3));
    let (recall, p_opt, p_pes) = compute_scores(tp, fp, unconf, gt);
    AggregateMetrics { ground_truth: gt, tp, fp, unconfirmed: unconf, recall, precision_optimistic: p_opt, precision_pessimistic: p_pes }
}

fn file_suffix_matches(finding_file: &str, sink_file: &str) -> bool {
    let f = normalize_path(finding_file);
    let s = normalize_path(sink_file);
    f == s || f.ends_with(&format!("/{s}"))
}

/// `pub(crate)` so a later task can reuse the shared metric formulas across
/// sibling `bench` modules.
pub(crate) fn compute_scores(tp: usize, fp: usize, unconfirmed: usize, gt: usize) -> (f64, f64, f64) {
    let recall = if gt == 0 { 0.0 } else { tp as f64 / gt as f64 };
    let p_opt = if tp + fp == 0 { 0.0 } else { tp as f64 / (tp + fp) as f64 };
    let p_pes = if tp + fp + unconfirmed == 0 {
        0.0
    } else {
        tp as f64 / (tp + fp + unconfirmed) as f64
    };
    (recall, p_opt, p_pes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::ground_truth::{GroundTruth, VulnEntry};
    use crate::model::{
        Confidence, ConfigSnapshot, FindingStatus, FusedFinding, Severity,
        StaticAnalysisResult, StaticAnalysisSummary,
    };

    fn gt_one() -> GroundTruth {
        GroundTruth {
            vulns: [(
                "CVE-1".to_string(),
                VulnEntry {
                    repo_slug: "r".into(),
                    language: "python".into(),
                    cwe: "CWE-78".into(),
                    category: "command_execution".into(),
                    severity: "high".into(),
                    evidence_tier: "cve".into(),
                    sink_line: 12,
                    sink_file: "src/lib.py".into(),
                    source_urls: vec![],
                    known_clean: vec!["src/clean.py".into()],
                },
            )]
            .into_iter()
            .collect(),
        }
    }

    fn fused(evidence: &[&str]) -> FusedFinding {
        FusedFinding {
            finding_id: "f1".into(),
            title: "t".into(),
            category: "command_execution".into(),
            owasp_mcp: None,
            severity: Severity::High,
            confidence: Confidence::High,
            status: FindingStatus::Potential,
            supported_by: vec![],
            related_rule_result_ids: vec![],
            related_taint_result_ids: vec![],
            related_agent_result_ids: vec![],
            related_codeql_result_ids: vec![],
            evidence: evidence.iter().map(|s| s.to_string()).collect(),
            call_chain: vec![],
            dataflow_path: vec![],
            recommendation: None,
            conflict_notes: vec![],
        }
    }

    /// A `StaticAnalysisResult` with no raw per-line results, so fused
    /// evidence strings drive line extraction. `StaticAnalysisResult` has no
    /// `Default` impl (its summary/config types do not), so build one by hand.
    fn empty_result() -> StaticAnalysisResult {
        StaticAnalysisResult {
            facts: vec![],
            rule_results: vec![],
            taint_results: vec![],
            agent_results: vec![],
            codeql_results: vec![],
            codeql_diagnostics: vec![],
            codeql_raw_sarif: None,
            model_candidates: vec![],
            fused_findings: vec![],
            summary: StaticAnalysisSummary {
                target: "r".to_string(),
                fact_count: 0,
                rule_result_count: 0,
                taint_result_count: 0,
                agent_result_count: 0,
                codeql_result_count: 0,
                codeql_fused_count: 0,
                fused_finding_count: 0,
                highest_severity: None,
                risk_level: "low".to_string(),
            },
            config_snapshot: ConfigSnapshot {
                runtime: crate::fixtures::synthetic_runtime_config(),
                rulebook_paths: vec![],
            },
            evolution: Default::default(),
        }
    }

    #[test]
    fn parses_path_line_snippet() {
        assert_eq!(
            parse_line("../x/src/lib.py:12:subprocess.run"),
            Some(("src/lib.py".to_string(), 12))
        );
        assert_eq!(parse_line("no colon here"), None);
    }

    #[test]
    fn sink_line_within_tolerance_is_tp() {
        let gt = gt_one();
        let mut result = empty_result(); // empty raw results; fused evidence drives it
        result.fused_findings.push(fused(&["../x/src/lib.py:14:subprocess.run"]));
        let metrics = score_repo("r", "ok", &gt, &result, 5);
        assert_eq!(metrics.tp, 1);
        assert_eq!(metrics.hits, vec!["CVE-1".to_string()]);
        assert!(metrics.misses.is_empty());
    }
}
