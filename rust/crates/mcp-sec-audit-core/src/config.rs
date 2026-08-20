use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default, rename = "static")]
    pub static_: StaticConfig,
    #[serde(default)]
    pub dynamic: DynamicConfig,
    #[serde(default)]
    pub fusion: FusionConfig,
    #[serde(default)]
    pub report: ReportConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_targets")]
    pub targets: Vec<String>,
    #[serde(default = "default_exclude")]
    pub exclude: Vec<String>,
    #[serde(default = "default_languages")]
    pub languages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub save_facts: bool,
    #[serde(default)]
    pub rule: StaticRuleConfig,
    #[serde(default)]
    pub taint: StaticTaintConfig,
    #[serde(default)]
    pub agent: StaticAgentConfig,
    #[serde(default)]
    pub codeql: StaticCodeqlConfig,
    /// Optional directory of extra sink-model TOML files, merged onto the
    /// built-in catalog at runtime (the seam R5's `learned/` dir reuses).
    #[serde(default)]
    pub models_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticRuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rule_paths")]
    pub rule_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticTaintConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub forward: bool,
    #[serde(default = "default_true")]
    pub backward: bool,
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
    #[serde(default = "default_true")]
    pub entrypoint_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticAgentConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_agent_provider")]
    pub provider: String,
    #[serde(default)]
    pub prompt_template_path: Option<String>,
    #[serde(default = "default_agent_max_turns")]
    pub max_turns: u32,
    #[serde(default = "default_agent_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub extra_args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCodeqlConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub query_pack_path: Option<String>,
    #[serde(default = "default_codeql_binary")]
    pub binary: String,
    #[serde(default = "default_codeql_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub extra_args: Vec<String>,
}

fn default_codeql_binary() -> String {
    "codeql".to_string()
}

fn default_codeql_timeout() -> u64 {
    1200
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_dynamic_sandbox")]
    pub sandbox: String,
    #[serde(default = "default_dynamic_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_require_confirmed_by")]
    pub require_confirmed_by: u32,
    #[serde(default = "default_true")]
    pub boost_when_multiple_lines_agree: bool,
    #[serde(default = "default_true")]
    pub agent_only_as_advisory: bool,
    #[serde(default = "default_line_proximity")]
    pub line_proximity: u32,
    #[serde(default = "default_rule_weight")]
    pub rule_weight: u32,
    #[serde(default = "default_taint_weight")]
    pub taint_weight: u32,
    #[serde(default = "default_agent_weight")]
    pub agent_weight: u32,
    #[serde(default = "default_codeql_weight")]
    pub codeql_weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportConfig {
    #[serde(default = "default_report_formats")]
    pub formats: Vec<String>,
    #[serde(default = "default_report_output")]
    pub output: String,
    #[serde(default = "default_true")]
    pub include_fused_results: bool,
    #[serde(default)]
    pub include_raw_rule_results: bool,
    #[serde(default)]
    pub include_raw_taint_results: bool,
    #[serde(default)]
    pub include_raw_agent_results: bool,
    #[serde(default)]
    pub include_raw_codeql_results: bool,
    #[serde(default)]
    pub include_facts: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Full,
    Compact,
    Pretty,
    Json,
}

impl Default for LogFormat {
    fn default() -> Self {
        LogFormat::Compact
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default)]
    pub level: LogLevel,
    #[serde(default)]
    pub format: LogFormat,
    #[serde(default = "default_true")]
    pub ansi: bool,
    #[serde(default = "default_true")]
    pub show_timestamps: bool,
    #[serde(default = "default_true")]
    pub show_progress: bool,
    #[serde(default)]
    pub log_file: Option<String>,
    #[serde(default)]
    pub scopes: BTreeMap<String, LogLevel>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Compact,
            ansi: true,
            show_timestamps: true,
            show_progress: true,
            log_file: None,
            scopes: BTreeMap::new(),
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            static_: StaticConfig::default(),
            dynamic: DynamicConfig::default(),
            fusion: FusionConfig::default(),
            report: ReportConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: default_targets(),
            exclude: default_exclude(),
            languages: default_languages(),
        }
    }
}

impl Default for StaticConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            save_facts: true,
            rule: StaticRuleConfig::default(),
            taint: StaticTaintConfig::default(),
            agent: StaticAgentConfig::default(),
            codeql: StaticCodeqlConfig::default(),
            models_dir: None,
        }
    }
}

impl Default for StaticRuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rule_paths: default_rule_paths(),
        }
    }
}

impl Default for StaticTaintConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            forward: true,
            backward: true,
            max_depth: default_max_depth(),
            entrypoint_required: true,
        }
    }
}

impl Default for StaticAgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_agent_provider(),
            prompt_template_path: None,
            max_turns: default_agent_max_turns(),
            timeout_seconds: default_agent_timeout(),
            extra_args: Vec::new(),
        }
    }
}

impl Default for StaticCodeqlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            query_pack_path: None,
            binary: default_codeql_binary(),
            timeout_seconds: default_codeql_timeout(),
            extra_args: Vec::new(),
        }
    }
}

impl Default for DynamicConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sandbox: default_dynamic_sandbox(),
            timeout_seconds: default_dynamic_timeout(),
        }
    }
}

impl Default for FusionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_confirmed_by: 1,
            boost_when_multiple_lines_agree: true,
            agent_only_as_advisory: true,
            line_proximity: 5,
            rule_weight: 3,
            taint_weight: 2,
            agent_weight: 1,
            codeql_weight: 4,
        }
    }
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            formats: default_report_formats(),
            output: default_report_output(),
            include_fused_results: true,
            include_raw_rule_results: true,
            include_raw_taint_results: true,
            include_raw_agent_results: true,
            include_raw_codeql_results: true,
            include_facts: false,
        }
    }
}

pub fn parse_runtime_config_toml(input: &str) -> Result<RuntimeConfig> {
    toml::from_str(input).context("parse runtime config TOML")
}

pub fn load_runtime_config(path: &Path) -> Result<RuntimeConfig> {
    let input = fs::read_to_string(path)
        .with_context(|| format!("read runtime config from {}", path.display()))?;
    parse_runtime_config_toml(&input)
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_targets() -> Vec<String> {
    vec![".".to_string()]
}

fn default_exclude() -> Vec<String> {
    ["node_modules", "target", ".venv", "dist"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_languages() -> Vec<String> {
    ["python", "javascript", "typescript", "rust"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_rule_paths() -> Vec<String> {
    ["rules/mcp", "rules/languages"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_max_depth() -> u32 {
    8
}

fn default_agent_provider() -> String {
    "claude".to_string()
}

fn default_agent_max_turns() -> u32 {
    30
}

fn default_agent_timeout() -> u64 {
    600
}

fn default_dynamic_sandbox() -> String {
    "existing_python_runtime".to_string()
}

fn default_dynamic_timeout() -> u64 {
    120
}

fn default_require_confirmed_by() -> u32 {
    1
}

fn default_line_proximity() -> u32 {
    5
}

fn default_rule_weight() -> u32 {
    3
}

fn default_taint_weight() -> u32 {
    2
}

fn default_agent_weight() -> u32 {
    1
}

fn default_codeql_weight() -> u32 {
    4
}

fn default_report_formats() -> Vec<String> {
    vec!["json".to_string(), "markdown".to_string()]
}

fn default_report_output() -> String {
    "report".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_config_parses_three_line_switches() {
        let config = parse_runtime_config_toml(
            r#"
            [static.rule]
            enabled = false
            rule_paths = ["rules/mcp"]

            [static.taint]
            enabled = true
            max_depth = 4

            [static.agent]
            enabled = true

            [dynamic]
            enabled = true
            timeout_seconds = 30
            "#,
        )
        .expect("parse config");

        assert!(!config.static_.rule.enabled);
        assert!(config.static_.taint.enabled);
        assert_eq!(config.static_.taint.max_depth, 4);
        assert!(config.static_.agent.enabled);
        assert_eq!(config.static_.agent.provider, "claude");
        assert_eq!(config.static_.agent.max_turns, default_agent_max_turns());
        assert_eq!(
            config.static_.agent.timeout_seconds,
            default_agent_timeout()
        );
        assert_eq!(config.static_.agent.prompt_template_path, None);
        assert!(config.static_.agent.extra_args.is_empty());
        // CodeQL config defaults
        assert!(!config.static_.codeql.enabled);
        assert_eq!(
            config.static_.codeql.timeout_seconds,
            default_codeql_timeout()
        );
        assert_eq!(config.static_.codeql.query_pack_path, None);
        assert!(config.static_.codeql.extra_args.is_empty());
        assert!(config.dynamic.enabled);
        assert_eq!(config.dynamic.timeout_seconds, 30);
    }

    #[test]
    fn runtime_config_defaults_are_stable() {
        let config = parse_runtime_config_toml("").expect("parse empty config");

        assert_eq!(config.scan.targets, vec!["."]);
        assert!(config.static_.enabled);
        assert!(config.static_.rule.enabled);
        assert!(!config.static_.taint.enabled);
        assert!(config.static_.taint.forward);
        assert!(!config.static_.agent.enabled);
        assert!(!config.dynamic.enabled);
        assert_eq!(config.fusion.line_proximity, 5);
        assert_eq!(config.fusion.rule_weight, 3);
        assert_eq!(config.fusion.taint_weight, 2);
        assert_eq!(config.fusion.agent_weight, 1);
        assert_eq!(config.fusion.codeql_weight, 4);
        assert_eq!(config.report.formats, vec!["json", "markdown"]);
        assert_eq!(config.report.output, "report");
    }

    #[test]
    fn default_taint_is_disabled() {
        assert!(!RuntimeConfig::default().static_.taint.enabled);
        assert!(!StaticTaintConfig::default().enabled);
    }

    #[test]
    fn missing_taint_enabled_defaults_to_disabled() {
        let config = parse_runtime_config_toml(
            r#"
            [static.taint]
            max_depth = 4
            "#,
        )
        .expect("parse config");

        assert!(!config.static_.taint.enabled);
        assert_eq!(config.static_.taint.max_depth, 4);
    }

    #[test]
    fn fusion_config_defaults_are_correct() {
        let config = FusionConfig::default();
        assert!(config.enabled);
        assert_eq!(config.require_confirmed_by, 1);
        assert!(config.boost_when_multiple_lines_agree);
        assert!(config.agent_only_as_advisory);
        assert_eq!(config.line_proximity, 5);
        assert_eq!(config.rule_weight, 3);
        assert_eq!(config.taint_weight, 2);
        assert_eq!(config.agent_weight, 1);
        assert_eq!(config.codeql_weight, 4);
    }

    #[test]
    fn fusion_config_parses_new_fields_from_toml() {
        let config: RuntimeConfig = toml::from_str(
            r#"
        [fusion]
        line_proximity = 10
        rule_weight = 5
        "#,
        )
        .expect("parse");
        assert_eq!(config.fusion.line_proximity, 10);
        assert_eq!(config.fusion.rule_weight, 5);
        // defaults preserved
        assert_eq!(config.fusion.taint_weight, 2);
        assert!(config.fusion.enabled);
    }

    #[test]
    fn logging_config_parses_from_toml() {
        let config: RuntimeConfig = toml::from_str(
            r#"
            [logging]
            level = "debug"
            format = "json"
            ansi = false
            show_timestamps = false
            show_progress = false
            log_file = "logs/audit.log"

            [logging.scopes]
            codeql = "trace"
            rule = "debug"
            "#,
        )
        .expect("parse config");

        assert_eq!(config.logging.level, LogLevel::Debug);
        assert_eq!(config.logging.format, LogFormat::Json);
        assert!(!config.logging.ansi);
        assert!(!config.logging.show_timestamps);
        assert!(!config.logging.show_progress);
        assert_eq!(config.logging.log_file.as_deref(), Some("logs/audit.log"));
        assert_eq!(config.logging.scopes.get("codeql"), Some(&LogLevel::Trace));
        assert_eq!(config.logging.scopes.get("rule"), Some(&LogLevel::Debug));
    }

    #[test]
    fn logging_config_defaults_are_stable() {
        let logging = LoggingConfig::default();
        assert_eq!(logging.level, LogLevel::Info);
        assert_eq!(logging.format, LogFormat::Compact);
        assert!(logging.ansi);
        assert!(logging.show_timestamps);
        assert!(logging.show_progress);
        assert!(logging.log_file.is_none());
        assert!(logging.scopes.is_empty());
    }

    #[test]
    fn models_dir_parses_from_toml() {
        let config: RuntimeConfig = toml::from_str(
            r#"
            [scan]
            targets = ["src"]

            [static]
            models_dir = "models/custom"
            "#,
        )
        .expect("parse config");
        assert_eq!(config.static_.models_dir.as_deref(), Some("models/custom"));
    }

    #[test]
    fn models_dir_defaults_to_none() {
        assert_eq!(StaticConfig::default().models_dir, None);
    }
}
