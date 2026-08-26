//! Benchmark metrics rendering (JSON + Markdown).

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::scorer::{AggregateMetrics, RepoMetrics};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchMetrics {
    pub generated_at: String,
    pub manifest_path: String,
    pub tolerance: u32,
    pub overall: AggregateMetrics,
    pub by_language: BTreeMap<String, AggregateMetrics>,
    pub by_tier: BTreeMap<String, AggregateMetrics>,
    pub by_category: BTreeMap<String, AggregateMetrics>,
    pub repos: Vec<RepoMetrics>,
}

pub fn render_metrics_json(m: &BenchMetrics) -> Result<String> {
    serde_json::to_string_pretty(m).map_err(Into::into)
}

pub fn render_metrics_markdown(m: &BenchMetrics) -> String {
    let mut lines = vec![
        "# MCP Vulnerability Benchmark".to_string(),
        String::new(),
        format!("- Generated: {}", m.generated_at),
        format!("- Manifest: {}", m.manifest_path),
        format!("- Tolerance: ±{} lines", m.tolerance),
        String::new(),
        "## overall".to_string(),
        format!("- ground_truth: {}", m.overall.ground_truth),
        format!("- tp: {}", m.overall.tp),
        format!("- fp: {}", m.overall.fp),
        format!("- unconfirmed: {}", m.overall.unconfirmed),
        format!("- recall: {:.3}", m.overall.recall),
        format!("- precision_optimistic: {:.3}", m.overall.precision_optimistic),
        format!("- precision_pessimistic: {:.3}", m.overall.precision_pessimistic),
        String::new(),
        "## repos".to_string(),
        String::new(),
        "| slug | language | tier | status | GT | TP | FP | unconf | recall | P_opt | P_pes |".to_string(),
        "|---|---|---|---|---|---|---|---|---|---|---|".to_string(),
    ];
    for r in &m.repos {
        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.3} | {:.3} | {:.3} |",
            r.slug,
            r.language,
            r.evidence_tier,
            r.status,
            r.ground_truth,
            r.tp,
            r.fp,
            r.unconfirmed,
            r.recall,
            r.precision_optimistic,
            r.precision_pessimistic,
        ));
        if !r.misses.is_empty() {
            lines.push(format!("  - misses: {}", r.misses.join(", ")));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BenchMetrics {
        BenchMetrics {
            generated_at: "20260826-120000".into(),
            manifest_path: "benchmark/manifest.toml".into(),
            tolerance: 5,
            overall: AggregateMetrics { ground_truth: 1, tp: 1, fp: 0, unconfirmed: 1, recall: 1.0, precision_optimistic: 1.0, precision_pessimistic: 0.5 },
            by_language: BTreeMap::new(),
            by_tier: BTreeMap::new(),
            by_category: BTreeMap::new(),
            repos: vec![RepoMetrics {
                slug: "r".into(),
                language: "python".into(),
                evidence_tier: "cve".into(),
                status: "ok".into(),
                ground_truth: 1,
                tp: 1,
                fp: 0,
                unconfirmed: 1,
                hits: vec!["CVE-1".into()],
                misses: vec![],
                recall: 1.0,
                precision_optimistic: 1.0,
                precision_pessimistic: 0.5,
            }],
        }
    }

    #[test]
    fn json_roundtrips() {
        let m = sample();
        let json = render_metrics_json(&m).expect("render");
        let back: BenchMetrics = serde_json::from_str(&json).expect("parse");
        assert_eq!(back.overall.tp, 1);
        assert_eq!(back.repos[0].slug, "r");
    }

    #[test]
    fn markdown_has_optimistic_and_pessimistic_precision() {
        let md = render_metrics_markdown(&sample());
        assert!(md.contains("precision_optimistic"));
        assert!(md.contains("precision_pessimistic"));
        assert!(md.contains("## repos"));
    }
}
