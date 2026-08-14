//! Shared core types and utilities for the Rust MCP Security Auditor rewrite.

pub mod config;
pub mod fixtures;
pub mod model;
pub mod reporting;
pub mod rules;
pub mod static_analysis;

pub use config::{
    DynamicConfig, FusionConfig, ReportConfig, RuntimeConfig, ScanConfig, StaticAgentConfig,
    StaticConfig, StaticRuleConfig, StaticTaintConfig, load_runtime_config,
    parse_runtime_config_toml,
};
pub use model::{
    AgentAnalysisResult, CapabilityFinding, Confidence, ConfigSnapshot, DetectionResult,
    EvidenceSource, Fact, FindingFact, FindingStatus, FusedFinding, RuleAnalysisResult,
    SCHEMA_VERSION, Severity, StaticAnalysisResult, StaticAnalysisSummary, TaintAnalysisResult,
};
pub use reporting::{
    JsonlRenderOptions, MarkdownRenderOptions, ReportFormat, render_json, render_jsonl,
    render_markdown,
};
pub use rules::{CapabilityRule, IndicatorRule, RuleBook, load_rulebook, parse_rulebook_toml};
pub use static_analysis::{
    DiscoveredFile, DiscoverySummary, ExtractionDiagnostic, JsTsDiagnostic, JsTsExtractionResult,
    PythonExtractionResult, RustExtractionResult, ScanLanguage, StaticScanContext,
    detect_language, discover_files, extract_js_ts_facts, extract_python_facts,
    extract_rust_facts, extract_static_facts, run_static_scan,
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
