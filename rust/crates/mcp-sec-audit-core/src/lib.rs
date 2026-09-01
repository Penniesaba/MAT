//! Shared core types and utilities for the Rust MCP Security Auditor rewrite.

pub mod batch;
pub mod bench;
pub mod config;
pub mod events;
pub mod fixtures;
pub mod model;
pub mod models;
pub mod reporting;
pub mod rules;
pub mod runctx;
pub mod static_analysis;

pub use batch::{
    BatchConfig, BatchRepoSummary, BatchSettings, BatchSummary, BusMsg, LearningBusHandle,
    LimitsConfig, PromoteRequest, RepoConfig, RepoStatus, ResourceClass, ResourceGovernor,
    load_batch_config, merge_repo_config, parse_batch_config_toml, render_batch_summary_json,
    render_batch_summary_markdown, run_batch,
};
pub use bench::{AggregateMetrics, BenchMetrics, BenchOptions, RepoMetrics, run_bench};
pub use events::{AnalysisEvent, EventSink, Stage};
pub use config::{
    DynamicConfig, FusionConfig, LogFormat, LogLevel, LoggingConfig, ReportConfig, RuntimeConfig,
    ScanConfig, StaticAgentConfig, StaticConfig, StaticRuleConfig, StaticTaintConfig,
    load_runtime_config, parse_runtime_config_toml,
};
pub use model::{
    AdjudicationItem, AgentAnalysisResult, AgentOutput, CapabilityFinding, Confidence,
    ConfigSnapshot, DetectionResult, EvidenceSource, EvolutionReport, Fact, FindingFact,
    FindingStatus, FusedFinding, ModelCandidate, RuleAnalysisResult, SCHEMA_VERSION, Severity,
    StaticAnalysisResult, StaticAnalysisSummary, TaintAnalysisResult,
};
pub use models::{
    ModelCatalog, SanitizerModel, SinkModel, SourceModel, default_catalog, load_models_dir,
    parse_sinks,
};
pub use reporting::{
    JsonlRenderOptions, MarkdownRenderOptions, ReportFormat, render_json, render_jsonl,
    render_markdown, resolve_output_path,
};
pub use rules::{CapabilityRule, IndicatorRule, RuleBook, load_rulebook, parse_rulebook_toml};
pub use runctx::{Progress, RunContext, RunId};
pub use static_analysis::{
    DiscoveredFile, DiscoverySummary, ExtractionDiagnostic, JsTsDiagnostic, JsTsExtractionResult,
    PythonExtractionResult, RustExtractionResult, ScanLanguage, StaticScanContext, detect_language,
    discover_files, extract_js_ts_facts, extract_python_facts, extract_rust_facts,
    extract_static_facts, run_static_scan, run_static_scan_async, run_static_scan_inner,
    run_static_scan_with_progress,
};

/// Current Rust rewrite phase implemented by this crate.
pub const CURRENT_PHASE: &str = "phase13-static-result-fusion";

/// Returns a short human-readable product name used by the CLI.
pub fn product_name() -> &'static str {
    "MCP Security Auditor"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_product_name() {
        assert_eq!(product_name(), "MCP Security Auditor");
    }

    #[test]
    fn exposes_current_phase() {
        assert_eq!(CURRENT_PHASE, "phase13-static-result-fusion");
    }

    #[test]
    fn exposes_schema_version() {
        assert_eq!(SCHEMA_VERSION, "1.0.0");
    }
}
