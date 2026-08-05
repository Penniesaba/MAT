use std::{fs, path::Path};

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticRuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rule_paths")]
    pub rule_paths: Vec<String>,
    #[serde(default = "default_rule_mode")]
    pub mode: String,
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
    #[serde(default = "default_codeql_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub extra_args: Vec<String>,
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
    #[serde(default = "default_fusion_strategy")]
    pub strategy: String,
    #[serde(default = "default_require_confirmed_by")]
    pub require_confirmed_by: u32,
    #[serde(default = "default_true")]
    pub boost_when_multiple_lines_agree: bool,
    #[serde(default = "default_true")]
    pub agent_only_as_advisory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportConfig {
    #[serde(default = "default_report_formats")]
    pub formats: Vec<String>,
    #[serde(default = "default_true")]
    pub include_fused_results: bool,
    #[serde(default)]
    pub include_raw_rule_results: bool,
    #[serde(default)]
    pub include_raw_taint_results: bool,
    #[serde(default)]
    pub include_raw_agent_results: bool,
    #[serde(default)]
    pub include_facts: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            static_: StaticConfig::default(),
            dynamic: DynamicConfig::default(),
            fusion: FusionConfig::default(),
            report: ReportConfig::default(),
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
        }
    }
}

impl Default for StaticRuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rule_paths: default_rule_paths(),
            mode: default_rule_mode(),
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
            strategy: default_fusion_strategy(),
            require_confirmed_by: default_require_confirmed_by(),
            boost_when_multiple_lines_agree: true,
            agent_only_as_advisory: true,
        }
    }
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            formats: default_report_formats(),
            include_fused_results: true,
            include_raw_rule_results: false,
            include_raw_taint_results: false,
            include_raw_agent_results: false,
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

fn default_rule_mode() -> String {
    "strict".to_string()
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

fn default_fusion_strategy() -> String {
    "weighted_evidence".to_string()
}

fn default_require_confirmed_by() -> u32 {
    1
}

fn default_report_formats() -> Vec<String> {
    vec!["json".to_string(), "markdown".to_string()]
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
        assert_eq!(config.fusion.strategy, "weighted_evidence");
        assert_eq!(config.report.formats, vec!["json", "markdown"]);
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
}
