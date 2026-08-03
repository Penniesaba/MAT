use anyhow::Result;
use serde::Serialize;

use crate::{ReportConfig, StaticAnalysisResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Jsonl,
    Markdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkdownRenderOptions {
    pub include_fused_results: bool,
    pub include_raw_rule_results: bool,
    pub include_raw_taint_results: bool,
    pub include_raw_agent_results: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonlRenderOptions {
    pub include_fused_results: bool,
    pub include_raw_rule_results: bool,
    pub include_raw_taint_results: bool,
    pub include_raw_agent_results: bool,
}

#[derive(Debug, Serialize)]
struct JsonlRecord<'a, T> {
    event: &'a str,
    data: T,
}

impl From<&ReportConfig> for MarkdownRenderOptions {
    fn from(config: &ReportConfig) -> Self {
        Self {
            include_fused_results: config.include_fused_results,
            include_raw_rule_results: config.include_raw_rule_results,
            include_raw_taint_results: config.include_raw_taint_results,
            include_raw_agent_results: config.include_raw_agent_results,
        }
    }
}

impl From<&ReportConfig> for JsonlRenderOptions {
    fn from(config: &ReportConfig) -> Self {
        Self {
            include_fused_results: config.include_fused_results,
            include_raw_rule_results: config.include_raw_rule_results,
            include_raw_taint_results: config.include_raw_taint_results,
            include_raw_agent_results: config.include_raw_agent_results,
        }
    }
}

impl Default for MarkdownRenderOptions {
    fn default() -> Self {
        Self {
            include_fused_results: true,
            include_raw_rule_results: false,
            include_raw_taint_results: false,
            include_raw_agent_results: false,
        }
    }
}

impl Default for JsonlRenderOptions {
    fn default() -> Self {
        Self {
            include_fused_results: true,
            include_raw_rule_results: true,
            include_raw_taint_results: true,
            include_raw_agent_results: true,
        }
    }
}

pub fn render_json(result: &StaticAnalysisResult) -> Result<String> {
    serde_json::to_string_pretty(result).map_err(Into::into)
}

pub fn render_jsonl(result: &StaticAnalysisResult, options: &JsonlRenderOptions) -> Result<String> {
    let mut lines = Vec::new();
    lines.push(serde_json::to_string(&JsonlRecord {
        event: "summary",
        data: &result.summary,
    })?);

    if options.include_fused_results {
        for finding in &result.fused_findings {
            lines.push(serde_json::to_string(&JsonlRecord {
                event: "fused_finding",
                data: finding,
            })?);
        }
    }

    if options.include_raw_rule_results {
        for rule_result in &result.rule_results {
            lines.push(serde_json::to_string(&JsonlRecord {
                event: "rule_result",
                data: rule_result,
            })?);
        }
    }

    if options.include_raw_taint_results {
        for taint_result in &result.taint_results {
            lines.push(serde_json::to_string(&JsonlRecord {
                event: "taint_result",
                data: taint_result,
            })?);
        }
    }

    if options.include_raw_agent_results {
        for agent_result in &result.agent_results {
            lines.push(serde_json::to_string(&JsonlRecord {
                event: "agent_result",
                data: agent_result,
            })?);
        }
    }

    Ok(lines.join("\n"))
}

pub fn render_markdown(result: &StaticAnalysisResult, options: &MarkdownRenderOptions) -> String {
    let mut lines = vec![
        format!("# Static Analysis Summary — {}", result.summary.target),
        String::new(),
        format!("- Risk Level: {}", result.summary.risk_level),
        format!("- Fused Findings: {}", result.summary.fused_finding_count),
        format!("- Rule Results: {}", result.summary.rule_result_count),
        format!("- Taint Results: {}", result.summary.taint_result_count),
        format!("- Agent Results: {}", result.summary.agent_result_count),
    ];

    if let Some(severity) = &result.summary.highest_severity {
        lines.push(format!("- Highest Severity: {:?}", severity));
    }

    if options.include_fused_results {
        lines.push(String::new());
        lines.push("## Fused Findings".to_string());
        if result.fused_findings.is_empty() {
            lines.push("- None".to_string());
        }
        for finding in &result.fused_findings {
            lines.push(format!(
                "- **{}** [{:?}/{:?}] — {}",
                finding.title, finding.severity, finding.confidence, finding.category
            ));
            if !finding.supported_by.is_empty() {
                lines.push(format!(
                    "  - Supported by: {}",
                    finding.supported_by.join(", ")
                ));
            }
            if let Some(recommendation) = &finding.recommendation {
                lines.push(format!("  - Recommendation: {recommendation}"));
            }
        }
    }

    if options.include_raw_rule_results {
        lines.push(String::new());
        lines.push("## Raw Rule Results".to_string());
        for item in &result.rule_results {
            lines.push(format!(
                "- `{}` at {}:{} — {}",
                item.rule_id, item.file, item.line, item.category
            ));
        }
    }

    if options.include_raw_taint_results {
        lines.push(String::new());
        lines.push("## Raw Taint Results".to_string());
        for item in &result.taint_results {
            lines.push(format!(
                "- `{}`: {} -> {}",
                item.result_id, item.source_kind, item.sink_kind
            ));
        }
    }

    if options.include_raw_agent_results {
        lines.push(String::new());
        lines.push("## Raw Agent Results".to_string());
        for item in &result.agent_results {
            lines.push(format!(
                "- `{}`: {} ({:?})",
                item.agent_id, item.candidate_title, item.confidence
            ));
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_renderer_preserves_full_static_result() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let json = render_json(&result).expect("render json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse json");

        assert!(value.get("rule_results").is_some());
        assert!(value.get("taint_results").is_some());
        assert!(value.get("agent_results").is_some());
        assert!(value.get("fused_findings").is_some());
        assert!(value.get("config_snapshot").is_some());
    }

    #[test]
    fn jsonl_renderer_emits_expected_events() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let jsonl = render_jsonl(&result, &JsonlRenderOptions::default()).expect("render jsonl");
        let lines = jsonl.lines().collect::<Vec<_>>();

        assert_eq!(lines.len(), 5);
        assert!(lines[0].contains(r#""event":"summary""#));
        assert!(lines[1].contains(r#""event":"fused_finding""#));
        assert!(lines[2].contains(r#""event":"rule_result""#));
        assert!(lines[3].contains(r#""event":"taint_result""#));
        assert!(lines[4].contains(r#""event":"agent_result""#));
    }

    #[test]
    fn markdown_default_includes_summary_and_fused_findings() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let markdown = render_markdown(&result, &MarkdownRenderOptions::default());

        assert!(markdown.contains("# Static Analysis Summary"));
        assert!(markdown.contains("## Fused Findings"));
        assert!(markdown.contains("Command execution reachable from MCP tool"));
        assert!(!markdown.contains("## Raw Rule Results"));
    }

    #[test]
    fn markdown_can_include_raw_sections() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let markdown = render_markdown(
            &result,
            &MarkdownRenderOptions {
                include_fused_results: true,
                include_raw_rule_results: true,
                include_raw_taint_results: true,
                include_raw_agent_results: true,
            },
        );

        assert!(markdown.contains("## Raw Rule Results"));
        assert!(markdown.contains("## Raw Taint Results"));
        assert!(markdown.contains("## Raw Agent Results"));
    }
}
