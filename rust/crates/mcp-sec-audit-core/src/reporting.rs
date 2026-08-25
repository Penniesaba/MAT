use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;

use crate::{ReportConfig, StaticAnalysisResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Jsonl,
    Markdown,
}

impl ReportFormat {
    /// Parse a report format name as used in `[report].formats`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "json" => Some(Self::Json),
            "jsonl" => Some(Self::Jsonl),
            "markdown" => Some(Self::Markdown),
            _ => None,
        }
    }

    /// File extension (without leading dot) for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Markdown => "md",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkdownRenderOptions {
    pub include_fused_results: bool,
    pub include_raw_rule_results: bool,
    pub include_raw_taint_results: bool,
    pub include_raw_agent_results: bool,
    pub include_raw_codeql_results: bool,
    pub include_facts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonlRenderOptions {
    pub include_fused_results: bool,
    pub include_raw_rule_results: bool,
    pub include_raw_taint_results: bool,
    pub include_raw_agent_results: bool,
    pub include_raw_codeql_results: bool,
    pub include_facts: bool,
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
            include_raw_codeql_results: config.include_raw_codeql_results,
            include_facts: config.include_facts,
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
            include_raw_codeql_results: config.include_raw_codeql_results,
            include_facts: config.include_facts,
        }
    }
}

impl Default for MarkdownRenderOptions {
    fn default() -> Self {
        Self {
            include_fused_results: true,
            include_raw_rule_results: true,
            include_raw_taint_results: true,
            include_raw_agent_results: true,
            include_raw_codeql_results: true,
            include_facts: false,
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
            include_raw_codeql_results: true,
            include_facts: true,
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

    if options.include_facts {
        for fact in &result.facts {
            lines.push(serde_json::to_string(&JsonlRecord {
                event: "fact",
                data: fact,
            })?);
        }
    }

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

    if options.include_raw_codeql_results {
        for codeql_result in &result.codeql_results {
            lines.push(serde_json::to_string(&JsonlRecord {
                event: "codeql_result",
                data: codeql_result,
            })?);
        }
    }

    for diag in &result.codeql_diagnostics {
        lines.push(serde_json::to_string(&JsonlRecord {
            event: "codeql_diagnostic",
            data: diag,
        })?);
    }

    Ok(lines.join("\n"))
}

pub fn render_markdown(result: &StaticAnalysisResult, options: &MarkdownRenderOptions) -> String {
    let mut lines = vec![
        format!("# Static Analysis Summary — {}", result.summary.target),
        String::new(),
        format!("- Risk Level: {}", result.summary.risk_level),
        format!("- Facts: {}", result.summary.fact_count),
        format!("- Fused Findings: {}", result.summary.fused_finding_count),
        format!("- Rule Results: {}", result.summary.rule_result_count),
        format!("- Taint Results: {}", result.summary.taint_result_count),
        format!("- Agent Results: {}", result.summary.agent_result_count),
        format!("- CodeQL Results: {}", result.summary.codeql_result_count),
    ];

    if !result.codeql_diagnostics.is_empty() {
        lines.push(String::new());
        lines.push("## CodeQL Diagnostics".to_string());
        for diag in &result.codeql_diagnostics {
            lines.push(format!("- {diag}"));
        }
    }

    if options.include_facts {
        lines.push(String::new());
        lines.push("## Facts".to_string());
        if result.facts.is_empty() {
            lines.push("- None".to_string());
        } else {
            for (kind, count) in fact_type_counts(result) {
                lines.push(format!("- {kind}: {count}"));
            }
        }
    }

    if options.include_fused_results {
        lines.push(String::new());
        lines.push("## Fused Findings".to_string());
        if result.fused_findings.is_empty() {
            lines.push("- None".to_string());
        }
        for finding in &result.fused_findings {
            lines.push(format!(
                "- **{}** [sev: {:?}, conf: {:?}] — {}",
                finding.title, finding.severity, finding.confidence, finding.category
            ));
            if !finding.supported_by.is_empty() {
                lines.push(format!(
                    "  - Supported by: {}",
                    finding.supported_by.join(", ")
                ));
            }
            if !finding.dataflow_path.is_empty() {
                lines.push(format!(
                    "  - Dataflow path: {}",
                    finding.dataflow_path.join(" → ")
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
                "- `{}` at {}:{}",
                item.rule_id, item.file, item.line
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

    if options.include_raw_codeql_results {
        lines.push(String::new());
        lines.push("## Raw CodeQL Results".to_string());
        for item in &result.codeql_results {
            lines.push(format!(
                "- `{}` at {}:{} — {}",
                item.rule_id,
                item.locations
                    .first()
                    .map(|l| l.file.as_str())
                    .unwrap_or("?"),
                item.locations.first().map(|l| l.line).unwrap_or(0),
                item.message
            ));
            if let Some(path) = &item.dataflow_path {
                let rendered = path
                    .steps
                    .iter()
                    .map(|s| format!("{}:{}", s.location.file, s.location.line))
                    .collect::<Vec<_>>()
                    .join(" → ");
                if !rendered.is_empty() {
                    lines.push(format!("  - Dataflow path: {rendered}"));
                }
            }
        }
    }

    // Differential evolution + layered validation report (L1/L2/L3).
    let ev = &result.evolution;
    if ev.promoted
        || ev.rolled_back
        || !ev.b0_candidates.is_empty()
        || !ev.ambiguous_for_review.is_empty()
    {
        lines.push(String::new());
        lines.push("## Evolution & Verification".to_string());
        lines.push(format!(
            "- Migration: b1={} a1={} a2={} b2={} b0={} still_ambiguous={}",
            ev.b1_confirmed,
            ev.a1_confirmed,
            ev.a2_confirmed,
            ev.b2_confirmed,
            ev.b0_count,
            ev.b_still_ambiguous
        ));
        if ev.promoted {
            lines.push("- Decision: promoted staged models to learned".to_string());
        }
        if ev.rolled_back {
            lines.push("- Decision: rolled back staged models".to_string());
        }
        if !ev.b0_candidates.is_empty() {
            lines.push("- b0 (semantic-only, surfaced for human review):".to_string());
            for c in &ev.b0_candidates {
                lines.push(format!("  - {} ({})", c.name, c.category));
            }
        }
        if !ev.ambiguous_for_review.is_empty() {
            lines.push("- L3 residual items awaiting human adjudication:".to_string());
            for a in &ev.ambiguous_for_review {
                let explanation = a.agent_explanation.as_deref().unwrap_or("-");
                lines.push(format!(
                    "  - {}:{} [{}] — {explanation}",
                    a.file, a.line, a.kind
                ));
            }
        }
    }

    lines.join("\n")
}

/// Resolve a `[report].output` path template by replacing the `<timestamp>`
/// placeholder with the current local timestamp (`%Y%m%d-%H%M%S`, e.g.
/// `20260819-131244`) and, when `repo` is `Some`, the `<repo>` placeholder with
/// a filename-sanitized repository name. Paths without a placeholder are
/// returned unchanged.
///
/// The timestamp is generated once per call, so a single resolved value shared
/// across all report formats keeps `.md`/`.json`/`.jsonl` on the same second.
/// The `<repo>` placeholder is left verbatim when `repo` is `None` (a single
/// repo path that never mentions it), matching the per-repo vs. batch split.
pub fn resolve_output_path(output: &str, repo: Option<&str>) -> String {
    let mut resolved = output.to_string();
    if resolved.contains("<timestamp>") {
        resolved = resolved.replace("<timestamp>", &current_local_timestamp());
    }
    if let Some(repo) = repo {
        resolved = resolved.replace("<repo>", &crate::runctx::sanitize(repo));
    }
    resolved
}

/// Current local time formatted as `YYYYMMDD-HHMMSS`.
fn current_local_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as libc::time_t;

    // `localtime_r` is reentrant: it writes the local-time breakdown into `tm`
    // directly rather than sharing a static buffer across threads.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `tm` outlives the call and is a valid writable buffer; `secs` is
    // a valid `time_t`. `localtime_r` never reads from uninitialized `tm`.
    let result = unsafe { libc::localtime_r(&secs, &mut tm) };
    if result.is_null() {
        // No local timezone data available on this platform — fall back to UTC.
        return current_utc_timestamp();
    }

    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
    )
}

/// Current UTC time formatted as `YYYYMMDD-HHMMSS`.
fn current_utc_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}")
}

/// Convert days since the Unix epoch to a `(year, month, day)` tuple in the
/// proleptic Gregorian calendar (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

fn fact_type_name(fact: &crate::Fact) -> &'static str {
    match fact {
        crate::Fact::Function(_) => "function",
        crate::Fact::Import(_) => "import",
        crate::Fact::Entrypoint(_) => "entrypoint",
        crate::Fact::Call(_) => "call",
        crate::Fact::Sink(_) => "sink",
        crate::Fact::Sanitizer(_) => "sanitizer",
        crate::Fact::Source(_) => "source",
        crate::Fact::Assign(_) => "assign",
        crate::Fact::Dataflow(_) => "dataflow",
        crate::Fact::RuntimeEvent(_) => "runtime_event",
        crate::Fact::Finding(_) => "finding",
    }
}

fn fact_type_counts(result: &StaticAnalysisResult) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for fact in &result.facts {
        *counts.entry(fact_type_name(fact)).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_renderer_preserves_full_static_result() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let json = render_json(&result).expect("render json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse json");

        assert!(value.get("facts").is_some());
        assert_eq!(value["facts"].as_array().expect("facts array").len(), 1);
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

        assert_eq!(lines.len(), 8);
        assert!(lines[0].contains(r#""event":"summary""#));
        assert!(lines[1].contains(r#""event":"fact""#));
        assert!(lines[2].contains(r#""event":"fused_finding""#));
        assert!(lines[3].contains(r#""event":"rule_result""#));
        assert!(lines[4].contains(r#""event":"taint_result""#));
        assert!(lines[5].contains(r#""event":"agent_result""#));
        assert!(lines[6].contains(r#""event":"codeql_result""#));
        assert!(lines[7].contains(r#""event":"codeql_diagnostic""#));
    }

    #[test]
    fn markdown_default_includes_summary_and_fused_findings() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let markdown = render_markdown(&result, &MarkdownRenderOptions::default());

        assert!(markdown.contains("# Static Analysis Summary"));
        assert!(markdown.contains("## Fused Findings"));
        assert!(markdown.contains("Command execution reachable from MCP tool"));
        // Fused findings label both severity and confidence so the per-finding
        // line agrees with the summary's `Risk Level` (derived from severity).
        assert!(markdown.contains("[sev: High, conf: High]"));
        // Raw per-line sections now render by default.
        assert!(markdown.contains("## Raw Rule Results"));
        assert!(markdown.contains("## Raw Taint Results"));
        assert!(markdown.contains("## Raw Agent Results"));
        assert!(markdown.contains("## Raw CodeQL Results"));
    }

    #[test]
    fn markdown_can_include_fact_summary() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let markdown = render_markdown(
            &result,
            &MarkdownRenderOptions {
                include_fused_results: true,
                include_raw_rule_results: false,
                include_raw_taint_results: false,
                include_raw_agent_results: false,
                include_raw_codeql_results: false,
                include_facts: true,
            },
        );

        assert!(markdown.contains("- Facts: 1"));
        assert!(markdown.contains("## Facts"));
        assert!(markdown.contains("- source: 1"));
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
                include_raw_codeql_results: true,
                include_facts: false,
            },
        );

        assert!(markdown.contains("## Raw Rule Results"));
        assert!(markdown.contains("## Raw Taint Results"));
        assert!(markdown.contains("## Raw Agent Results"));
        assert!(markdown.contains("## Raw CodeQL Results"));
    }

    #[test]
    fn report_format_maps_name_and_extension() {
        use super::ReportFormat;

        assert_eq!(ReportFormat::parse("json"), Some(ReportFormat::Json));
        assert_eq!(ReportFormat::parse("jsonl"), Some(ReportFormat::Jsonl));
        assert_eq!(
            ReportFormat::parse("markdown"),
            Some(ReportFormat::Markdown)
        );
        assert_eq!(ReportFormat::parse("yaml"), None);

        assert_eq!(ReportFormat::Json.extension(), "json");
        assert_eq!(ReportFormat::Jsonl.extension(), "jsonl");
        assert_eq!(ReportFormat::Markdown.extension(), "md");
    }

    #[test]
    fn resolve_output_path_replaces_timestamp_placeholder() {
        let resolved = resolve_output_path("/tmp/report-<timestamp>", None);
        assert!(!resolved.contains("<timestamp>"));
        assert!(resolved.starts_with("/tmp/report-"));
        // Local format is `YYYYMMDD-HHMMSS`.
        let stamp = resolved.trim_start_matches("/tmp/report-");
        assert_eq!(stamp.len(), 15);
        assert_eq!(stamp.as_bytes()[8], b'-');
    }

    #[test]
    fn local_timestamp_is_well_formed_and_whole_minute_offset() {
        let local = current_local_timestamp();
        let utc = current_utc_timestamp();
        assert_eq!(local.len(), 15);
        assert_eq!(utc.len(), 15);
        // Timezone offsets are always a whole number of minutes, so the seconds
        // field must agree between the local and UTC breakdowns even though the
        // hours/minutes (and possibly the date) may shift.
        assert_eq!(&local[13..15], &utc[13..15]);
    }

    #[test]
    fn resolve_output_path_ignores_missing_placeholder() {
        assert_eq!(resolve_output_path("/tmp/report", None), "/tmp/report");
        assert_eq!(resolve_output_path("report", None), "report");
    }

    #[test]
    fn resolve_output_path_substitutes_repo() {
        let out = resolve_output_path("docs/result/batch-<timestamp>/<repo>", Some("excel"));
        assert!(out.ends_with("/excel"));
        assert!(!out.contains("<timestamp>"));
    }

    #[test]
    fn resolve_output_path_leaves_repo_placeholder_when_absent() {
        let out = resolve_output_path("docs/result/<repo>/report", None);
        assert_eq!(out, "docs/result/<repo>/report");
    }

    #[test]
    fn repo_name_is_sanitized_for_filenames() {
        let out = resolve_output_path("r/<repo>", Some("MCTS/examples"));
        assert!(
            !out.trim_start_matches("r/").contains('/'),
            "must not create nested dirs"
        );
    }

    #[test]
    fn civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        // 2000-01-01 is 10957 days after the Unix epoch.
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
    }

    #[test]
    fn markdown_renders_codeql_diagnostics_when_present() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let markdown = render_markdown(&result, &MarkdownRenderOptions::default());
        assert!(markdown.contains("## CodeQL Diagnostics"));
        assert!(markdown.contains("- Synthetic CodeQL diagnostic"));
    }

    #[test]
    fn markdown_renders_dataflow_path() {
        let result = crate::fixtures::synthetic_static_analysis_result();
        let markdown = render_markdown(&result, &MarkdownRenderOptions::default());

        // Fused finding renders its (taint-style) dataflow path.
        assert!(markdown.contains("  - Dataflow path: command → subprocess.run"));

        // Raw CodeQL result renders its structured `file:line` path steps.
        assert!(markdown.contains("  - Dataflow path: server.py:40 → server.py:42"));
    }
}
