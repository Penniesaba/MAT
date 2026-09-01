//! Benchmark scoring for known-vulnerable MCP repositories (v5).

pub mod ground_truth;
pub mod manifest;
pub mod report;
pub mod scorer;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

pub use manifest::{BenchManifest, RepoEntry, load_manifest, to_batch_config};
pub use report::BenchMetrics;
pub use scorer::{AggregateMetrics, RepoMetrics};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchOptions {
    pub tolerance: u32,
    pub max_parallel: usize,
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self { tolerance: 5, max_parallel: 4 }
    }
}

/// A `StaticAnalysisResult` with no findings. `StaticAnalysisResult` has no
/// `Default` impl (its summary/config types do not), so build one by hand for
/// repos that produced no report (failed/cancelled).
fn empty_static_result() -> crate::model::StaticAnalysisResult {
    crate::model::StaticAnalysisResult {
        facts: vec![],
        rule_results: vec![],
        taint_results: vec![],
        agent_results: vec![],
        codeql_results: vec![],
        codeql_diagnostics: vec![],
        codeql_raw_sarif: None,
        model_candidates: vec![],
        fused_findings: vec![],
        summary: crate::model::StaticAnalysisSummary {
            target: String::new(),
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
        config_snapshot: crate::model::ConfigSnapshot {
            runtime: crate::fixtures::synthetic_runtime_config(),
            rulebook_paths: vec![],
        },
        evolution: Default::default(),
    }
}

/// Runs the benchmark: loads manifest + ground truth, drives the batch
/// orchestrator over the corpus, scores each repo, and writes `metrics.json`
/// + `metrics.md` under `<manifest_dir>/bench_results/<timestamp>/`.
pub async fn run_bench(
    manifest_path: &Path,
    opts: &BenchOptions,
    cancel: CancellationToken,
) -> Result<BenchMetrics> {
    let manifest = load_manifest(manifest_path)?;
    let gt_path = manifest_path.with_file_name("ground-truth.toml");
    let gt = ground_truth::load_ground_truth(&gt_path)?;

    // Fail loudly on unpinned data: a `<PENDING>` marker means the verify pass
    // has not pinned commit SHAs / sink lines yet, and benching would silently
    // score recall≈0.
    if manifest.repos.iter().any(|r| r.commit == "<PENDING>")
        || gt.vulns.values().any(|e| e.sink_file == "<PENDING>")
    {
        anyhow::bail!(
            "benchmark data is not pinned yet: run the verify pass (pin commit SHAs and sink lines) before benching"
        );
    }

    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let timestamp = crate::reporting::current_local_timestamp();
    let out_dir = manifest_dir.join("bench_results").join(&timestamp);
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("create bench output dir {}", out_dir.display()))?;

    let corpus_root = manifest_dir.join("corpus");
    let batch_cfg = to_batch_config(
        &manifest,
        &corpus_root,
        &out_dir.to_string_lossy(),
        opts.max_parallel,
    );
    let summary = crate::batch::run_batch(batch_cfg, cancel, crate::events::EventSink::noop()).await?;

    let mut repo_metrics = Vec::new();
    for repo in &summary.repos {
        let report_path = repo
            .report_paths
            .iter()
            .find(|p| p.ends_with(".json") && !p.ends_with("batch-summary.json"));
        let Some(report_path) = report_path else {
            repo_metrics.push(scorer::score_repo(
                &repo.name,
                repo.status.as_str(),
                &gt,
                &empty_static_result(),
                opts.tolerance,
            ));
            continue;
        };
        let text = std::fs::read_to_string(report_path)
            .with_context(|| format!("read report {}", report_path))?;
        let result: crate::model::StaticAnalysisResult =
            serde_json::from_str(&text).with_context(|| format!("parse report {}", report_path))?;
        repo_metrics.push(scorer::score_repo(&repo.name, repo.status.as_str(), &gt, &result, opts.tolerance));
    }

    let metrics = build_metrics(
        repo_metrics,
        &gt,
        &manifest_path.to_string_lossy(),
        opts.tolerance,
        &timestamp,
    );

    let json = report::render_metrics_json(&metrics)?;
    std::fs::write(out_dir.join("metrics.json"), json).context("write metrics.json")?;
    let md = report::render_metrics_markdown(&metrics);
    std::fs::write(out_dir.join("metrics.md"), md).context("write metrics.md")?;

    Ok(metrics)
}

fn build_metrics(
    repos: Vec<RepoMetrics>,
    gt: &ground_truth::GroundTruth,
    manifest_path: &str,
    tolerance: u32,
    generated_at: &str,
) -> BenchMetrics {
    let overall = scorer::aggregate(&repos);
    let mut by_language: BTreeMap<String, AggregateMetrics> = BTreeMap::new();
    let mut by_tier: BTreeMap<String, AggregateMetrics> = BTreeMap::new();

    for r in &repos {
        by_language
            .entry(r.language.clone())
            .and_modify(|a| merge_into(a, r))
            .or_insert_with(|| single(r));
        by_tier
            .entry(r.evidence_tier.clone())
            .and_modify(|a| merge_into(a, r))
            .or_insert_with(|| single(r));
    }

    let by_category = category_breakdown(gt, &repos);

    BenchMetrics {
        generated_at: generated_at.to_string(),
        manifest_path: manifest_path.to_string(),
        tolerance,
        overall,
        by_language,
        by_tier,
        by_category,
        repos,
    }
}

/// Per-category recall: `GT` = vulns in the category, `TP` = those found in a
/// repo's `hits`. FP/unconfirmed are finding-level and stay on the overall
/// metrics, so category entries carry `fp = 0` / `unconfirmed = 0`.
fn category_breakdown(gt: &ground_truth::GroundTruth, repos: &[RepoMetrics]) -> BTreeMap<String, AggregateMetrics> {
    let mut acc: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for r in repos {
        let hits: BTreeSet<&str> = r.hits.iter().map(String::as_str).collect();
        for (key, entry) in gt.for_repo(&r.slug) {
            let e = acc.entry(entry.category.clone()).or_insert((0, 0));
            e.0 += 1;
            if hits.contains(key.as_str()) {
                e.1 += 1;
            }
        }
    }
    acc.into_iter()
        .map(|(cat, (gt, tp))| {
            let (recall, p_opt, p_pes) = scorer::compute_scores(tp, 0, 0, gt);
            (
                cat,
                AggregateMetrics {
                    ground_truth: gt,
                    tp,
                    fp: 0,
                    unconfirmed: 0,
                    recall,
                    precision_optimistic: p_opt,
                    precision_pessimistic: p_pes,
                },
            )
        })
        .collect()
}

fn single(r: &RepoMetrics) -> AggregateMetrics {
    AggregateMetrics {
        ground_truth: r.ground_truth,
        tp: r.tp,
        fp: r.fp,
        unconfirmed: r.unconfirmed,
        recall: r.recall,
        precision_optimistic: r.precision_optimistic,
        precision_pessimistic: r.precision_pessimistic,
    }
}

fn merge_into(acc: &mut AggregateMetrics, r: &RepoMetrics) {
    acc.ground_truth += r.ground_truth;
    acc.tp += r.tp;
    acc.fp += r.fp;
    acc.unconfirmed += r.unconfirmed;
    let (recall, p_opt, p_pes) = scorer::compute_scores(
        acc.tp, acc.fp, acc.unconfirmed, acc.ground_truth,
    );
    acc.recall = recall;
    acc.precision_optimistic = p_opt;
    acc.precision_pessimistic = p_pes;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::ground_truth::{GroundTruth, VulnEntry};
    use crate::bench::scorer::RepoMetrics;

    fn gt() -> GroundTruth {
        GroundTruth {
            vulns: [
                ("CVE-1".into(), VulnEntry {
                    repo_slug: "a".into(), language: "python".into(), cwe: "CWE-78".into(),
                    category: "command_execution".into(), severity: "high".into(),
                    evidence_tier: "cve".into(), sink_line: 1, sink_file: "app.py".into(),
                    source_urls: vec![], known_clean: vec![],
                }),
                ("X".into(), VulnEntry {
                    repo_slug: "b".into(), language: "python".into(), cwe: "CWE-22".into(),
                    category: "path_traversal".into(), severity: "high".into(),
                    evidence_tier: "issue".into(), sink_line: 1, sink_file: "app.py".into(),
                    source_urls: vec![], known_clean: vec![],
                }),
            ].into_iter().collect(),
        }
    }

    #[test]
    fn builds_layered_metrics_from_repo_metrics() {
        let repos = vec![
            RepoMetrics { slug: "a".into(), language: "python".into(), evidence_tier: "cve".into(), status: "ok".into(), ground_truth: 1, tp: 1, fp: 0, unconfirmed: 1, hits: vec!["CVE-1".into()], misses: vec![], recall: 1.0, precision_optimistic: 1.0, precision_pessimistic: 0.5 },
            RepoMetrics { slug: "b".into(), language: "python".into(), evidence_tier: "issue".into(), status: "ok".into(), ground_truth: 1, tp: 0, fp: 0, unconfirmed: 0, hits: vec![], misses: vec!["X".into()], recall: 0.0, precision_optimistic: 0.0, precision_pessimistic: 0.0 },
        ];
        let m = build_metrics(repos, &gt(), "benchmark/manifest.toml", 5, "20260826-120000");
        assert_eq!(m.overall.ground_truth, 2);
        assert_eq!(m.overall.tp, 1);
        assert_eq!(m.by_language["python"].ground_truth, 2);
        assert_eq!(m.by_tier["cve"].tp, 1);
        assert_eq!(m.by_tier["issue"].tp, 0);
        assert_eq!(m.by_category["command_execution"].ground_truth, 1);
        assert_eq!(m.by_category["command_execution"].tp, 1);
        assert_eq!(m.by_category["path_traversal"].ground_truth, 1);
        assert_eq!(m.by_category["path_traversal"].tp, 0);
    }
}
