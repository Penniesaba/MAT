//! Batch summary report (v5 parallel multi-repository analysis).
//!
//! [`BatchSummary`] aggregates the per-repository outcomes of a single batch
//! run into one document, rendered as `batch-summary.md` + `batch-summary.json`.
//! This module is pure data + pure rendering: the orchestrator builds the
//! summary, and CI compares the rendered files across runs.
//!
//! The `learning_bus_enabled` field is carried explicitly so a CI diff can
//! tell ordering-induced differences (the learning bus is on and cross-repo
//! promotion reordered the results) apart from genuine regressions.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Outcome of one repository within a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoStatus {
    Ok,
    Failed,
    Cancelled,
}

impl RepoStatus {
    /// Snake-case label matching the JSON serialization (for markdown tables).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Aggregate result of a whole batch run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSummary {
    pub batch_id: String,
    pub started_at: String,
    pub repos: Vec<BatchRepoSummary>,
    pub total_fused_findings: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub cancelled: usize,
    /// Whether the shared learning bus was enabled for this batch. When `true`
    /// the per-repo results are ordering-dependent, so a CI diff must not treat
    /// ordering-induced changes as regressions.
    pub learning_bus_enabled: bool,
    /// Names of models learned from another repository in this batch.
    pub cross_repo_learned: Vec<String>,
}

/// Outcome of a single repository within a batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRepoSummary {
    pub name: String,
    pub path: String,
    pub status: RepoStatus,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub risk_level: Option<String>,
    pub fused_finding_count: Option<usize>,
    pub report_paths: Vec<String>,
}

/// Serialize a [`BatchSummary`] to pretty-printed JSON (the `batch-summary.json`
/// form). Matches the single-report JSON style (`serde_json::to_string_pretty`).
pub fn render_batch_summary_json(summary: &BatchSummary) -> Result<String> {
    serde_json::to_string_pretty(summary).map_err(Into::into)
}

/// Render a [`BatchSummary`] as a compact, human-readable markdown document (the
/// `batch-summary.md` form), consistent with the single-report markdown style.
pub fn render_batch_summary_markdown(summary: &BatchSummary) -> String {
    let mut lines = vec![
        format!("# Batch Summary — {}", summary.batch_id),
        String::new(),
        format!("- Started: {}", summary.started_at),
        format!(
            "- Repositories: {} ({} succeeded, {} failed, {} cancelled)",
            summary.repos.len(),
            summary.succeeded,
            summary.failed,
            summary.cancelled
        ),
        format!("- Total Fused Findings: {}", summary.total_fused_findings),
        format!(
            "- Learning Bus Enabled: {}",
            summary.learning_bus_enabled
        ),
    ];

    if !summary.cross_repo_learned.is_empty() {
        lines.push(format!(
            "- Cross-Repo Learned: {}",
            summary.cross_repo_learned.join(", ")
        ));
    }

    for repo in &summary.repos {
        lines.push(String::new());
        lines.push(format!("## {} — {}", repo.name, repo.status.as_str()));
        lines.push(format!("- Path: {}", repo.path));
        lines.push(format!("- Duration: {} ms", repo.duration_ms));
        if let Some(risk_level) = &repo.risk_level {
            lines.push(format!("- Risk Level: {risk_level}"));
        }
        if let Some(count) = repo.fused_finding_count {
            lines.push(format!("- Fused Findings: {count}"));
        }
        if let Some(error) = &repo.error {
            lines.push(format!("- Error: {error}"));
        }
        if !repo.report_paths.is_empty() {
            lines.push(format!("- Reports: {}", repo.report_paths.join(", ")));
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_summary() -> BatchSummary {
        BatchSummary {
            batch_id: "batch-1".to_string(),
            started_at: "20260826-090000".to_string(),
            repos: vec![
                BatchRepoSummary {
                    name: "excel".to_string(),
                    path: "test-targets/MCTS/examples".to_string(),
                    status: RepoStatus::Ok,
                    error: None,
                    duration_ms: 42,
                    risk_level: Some("High".to_string()),
                    fused_finding_count: Some(3),
                    report_paths: vec!["docs/result/excel.md".to_string()],
                },
                BatchRepoSummary {
                    name: "broken".to_string(),
                    path: "test-targets/broken".to_string(),
                    status: RepoStatus::Failed,
                    error: Some("missing CodeQL CLI".to_string()),
                    duration_ms: 7,
                    risk_level: None,
                    fused_finding_count: None,
                    report_paths: Vec::new(),
                },
            ],
            total_fused_findings: 3,
            succeeded: 1,
            failed: 1,
            cancelled: 0,
            learning_bus_enabled: true,
            cross_repo_learned: vec!["sink:command".to_string()],
        }
    }

    #[test]
    fn json_render_serializes_snake_case_status_and_learning_bus_flag() {
        let summary = sample_summary();
        let json = render_batch_summary_json(&summary).expect("render json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse json");

        assert_eq!(value["batch_id"], "batch-1");
        assert_eq!(value["repos"][0]["status"], "ok");
        assert_eq!(value["repos"][1]["status"], "failed");
        assert_eq!(value["learning_bus_enabled"], true);
        assert_eq!(value["cross_repo_learned"][0], "sink:command");
        assert_eq!(value["total_fused_findings"], 3);
    }

    #[test]
    fn markdown_render_lists_batch_and_per_repo_sections() {
        let markdown = render_batch_summary_markdown(&sample_summary());

        assert!(markdown.contains("# Batch Summary — batch-1"));
        assert!(markdown.contains("- Learning Bus Enabled: true"));
        assert!(markdown.contains("- Cross-Repo Learned: sink:command"));
        assert!(markdown.contains("## excel — ok"));
        assert!(markdown.contains("- Fused Findings: 3"));
        assert!(markdown.contains("## broken — failed"));
        assert!(markdown.contains("- Error: missing CodeQL CLI"));
    }

    #[test]
    fn markdown_render_omits_empty_optional_fields() {
        let summary = BatchSummary {
            batch_id: "batch-2".to_string(),
            started_at: "20260826-090000".to_string(),
            repos: vec![BatchRepoSummary {
                name: "cancelled".to_string(),
                path: "x".to_string(),
                status: RepoStatus::Cancelled,
                error: None,
                duration_ms: 0,
                risk_level: None,
                fused_finding_count: None,
                report_paths: Vec::new(),
            }],
            total_fused_findings: 0,
            succeeded: 0,
            failed: 0,
            cancelled: 1,
            learning_bus_enabled: false,
            cross_repo_learned: Vec::new(),
        };

        let markdown = render_batch_summary_markdown(&summary);
        assert!(markdown.contains("## cancelled — cancelled"));
        assert!(!markdown.contains("- Error:"));
        assert!(!markdown.contains("- Risk Level:"));
        assert!(!markdown.contains("- Fused Findings:"));
        assert!(!markdown.contains("- Cross-Repo Learned:"));
        assert!(!markdown.contains("- Reports:"));
    }
}
