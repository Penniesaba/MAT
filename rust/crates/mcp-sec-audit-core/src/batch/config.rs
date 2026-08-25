//! Batch configuration schema and the per-repository override merge.
//!
//! A batch file is a superset of the single-repository runtime config: the
//! top-level `[batch]` table controls the parallel run, every other key is a
//! shared [`RuntimeConfig`] base, and each `[[batch.repo]]` entry pairs a
//! `name`/`path` with arbitrary nested overrides that are deep-merged onto the
//! base for that repository alone.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::RuntimeConfig;

/// Top-level format for a parallel multi-repository batch run.
///
/// `runtime` is the shared base config (same syntax as a single-repo config
/// file); `batch.repos` list the repositories to analyse, each with optional
/// overrides applied on top of `runtime`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BatchConfig {
    #[serde(default)]
    pub batch: BatchSettings,
    #[serde(flatten)]
    pub runtime: RuntimeConfig,
}

/// The `[batch]` table: how the parallel run is governed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchSettings {
    /// Upper bound on concurrently-running repositories.
    #[serde(default = "default_max_parallel")]
    pub max_parallel: usize,
    /// Whether repositories share a learning bus within the batch.
    #[serde(default = "default_true")]
    pub learning_bus: bool,
    /// Whether the first repository failure aborts the whole batch.
    #[serde(default)]
    pub fail_fast: bool,
    /// Per-resource-class concurrency limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// The repository list; each entry may override any base field.
    #[serde(default, rename = "repo")]
    pub repos: Vec<RepoConfig>,
}

/// Per-resource-class concurrency limits (see `ResourceGovernor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Concurrent CodeQL CLI processes (memory-heavy; keep conservative).
    #[serde(default = "default_one")]
    pub codeql: usize,
    /// Concurrent agent (LLM CLI) processes (latency-bound, rate-limited).
    #[serde(default = "default_one")]
    pub agent: usize,
    /// Concurrent CPU-bound phases (rule/taint/fusion/fact extraction).
    #[serde(default = "default_cpu")]
    pub cpu: usize,
}

/// One repository in a batch, plus its overrides.
///
/// `overrides` is `#[serde(flatten)]`ed so an entry may carry any nested
/// `[batch.repo.static...]` / `[batch.repo.report...]` / `[batch.repo.fusion...]`
/// table without a hand-written Option-mirror struct. Keys are the top-level
/// `RuntimeConfig` field names (`scan`, `static`, `report`, ...); values are
/// the override subtree deep-merged onto the base.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoConfig {
    pub name: String,
    pub path: String,
    #[serde(flatten)]
    pub overrides: BTreeMap<String, toml::Value>,
}

impl Default for BatchSettings {
    fn default() -> Self {
        Self {
            max_parallel: default_max_parallel(),
            learning_bus: true,
            fail_fast: false,
            limits: LimitsConfig::default(),
            repos: Vec::new(),
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            codeql: 1,
            agent: 1,
            cpu: default_cpu(),
        }
    }
}

/// Parses batch-config TOML into a [`BatchConfig`].
pub fn parse_batch_config_toml(input: &str) -> Result<BatchConfig> {
    toml::from_str(input).context("parse batch config TOML")
}

/// Reads and parses a batch config file.
pub fn load_batch_config(path: &Path) -> Result<BatchConfig> {
    let input = fs::read_to_string(path)
        .with_context(|| format!("read batch config from {}", path.display()))?;
    parse_batch_config_toml(&input)
}

/// Resolves one repository's effective [`RuntimeConfig`].
///
/// The merge is a pure function over TOML values: the base is serialized to a
/// [`toml::Value`], each top-level key of `repo.overrides` is deep-merged in
/// (tables merge recursively; scalars and arrays replace the base value
/// wholesale), then `scan.targets` is set to the override value if one was
/// supplied, or to `[repo.path]` otherwise. The result is deserialized back
/// into a [`RuntimeConfig`].
///
/// The round-trip through `toml::Value` is field-preserving: `Option::None`
/// fields are simply absent from the serialized value and re-default to `None`
/// on the way back, and unit enum variants serialize as their lowercase string.
pub fn merge_repo_config(base: &RuntimeConfig, repo: &RepoConfig) -> Result<RuntimeConfig> {
    let mut value = toml::Value::try_from(base).context("serialize base runtime config")?;

    {
        let table = value
            .as_table_mut()
            .context("serialized runtime config is not a table")?;

        // Deep-merge each top-level override key into the base table.
        for (key, override_value) in &repo.overrides {
            match table.get_mut(key) {
                Some(existing) => deep_merge(existing, override_value.clone()),
                None => {
                    table.insert(key.clone(), override_value.clone());
                }
            }
        }

        // `scan.targets` defaults to the repo path unless the repo explicitly
        // overrode it. Detect that by looking at the *override* source (the
        // base always has a `scan.targets`, so the merged value alone can't
        // tell us whether it came from an override).
        let has_targets_override = repo
            .overrides
            .get("scan")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("targets"))
            .is_some();

        if !has_targets_override {
            let targets = toml::Value::Array(vec![toml::Value::String(repo.path.clone())]);
            match table.get_mut("scan") {
                Some(toml::Value::Table(scan_table)) => {
                    scan_table.insert("targets".to_string(), targets);
                }
                // The base always serializes a `scan` table, so this arm only
                // fires if an override replaced `scan` with a non-table value;
                // replace it with a fresh table so the config stays valid.
                _ => {
                    let mut scan_table = toml::Table::new();
                    scan_table.insert("targets".to_string(), targets);
                    table.insert("scan".to_string(), toml::Value::Table(scan_table));
                }
            }
        }
    }

    value
        .try_into::<RuntimeConfig>()
        .context("deserialize merged runtime config")
}

/// Deep-merges `override_value` into `base` in place.
///
/// Tables merge recursively (missing keys are inserted, present keys recurse);
/// every other kind of value — scalars, arrays, datetimes — replaces `base`
/// wholesale.
fn deep_merge(base: &mut toml::Value, override_value: toml::Value) {
    match (&mut *base, override_value) {
        (toml::Value::Table(base_table), toml::Value::Table(override_table)) => {
            for (key, value) in override_table {
                match base_table.get_mut(&key) {
                    Some(existing) => deep_merge(existing, value),
                    None => {
                        base_table.insert(key, value);
                    }
                }
            }
        }
        (base_slot, override_value) => *base_slot = override_value,
    }
}

fn default_max_parallel() -> usize {
    4
}

fn default_true() -> bool {
    true
}

fn default_one() -> usize {
    1
}

fn default_cpu() -> usize {
    4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogLevel;

    #[test]
    fn repo_path_becomes_scan_target() {
        let base = RuntimeConfig::default();
        let repo = RepoConfig {
            name: "excel".into(),
            path: "../t/excel".into(),
            overrides: Default::default(),
        };
        let merged = merge_repo_config(&base, &repo).expect("merge");
        assert_eq!(merged.scan.targets, vec!["../t/excel".to_string()]);
    }

    #[test]
    fn nested_override_replaces_only_that_key() {
        let toml = r#"
[static.codeql]
enabled = true
timeout_seconds = 1200
[[batch.repo]]
name = "a"
path = "/a"
[batch.repo.static.codeql]
enabled = false
"#;
        let cfg: BatchConfig = toml::from_str(toml).expect("parse");
        let merged = merge_repo_config(&cfg.runtime, &cfg.batch.repos[0]).expect("merge");
        assert!(!merged.static_.codeql.enabled, "override applied");
        assert_eq!(merged.static_.codeql.timeout_seconds, 1200, "sibling key preserved");
    }

    #[test]
    fn limits_have_conservative_defaults() {
        let cfg: BatchConfig = toml::from_str("[batch]\n").expect("parse");
        assert_eq!(cfg.batch.limits.codeql, 1);
        assert_eq!(cfg.batch.limits.agent, 1);
        assert!(cfg.batch.learning_bus, "learning bus on by default");
    }

    #[test]
    fn merge_preserves_unoverridden_base_fields() {
        let mut base = RuntimeConfig::default();
        base.report.output = "docs/result/custom".to_string();
        base.report.formats = vec!["json".to_string()];
        base.fusion.line_proximity = 11;
        base.logging.level = LogLevel::Debug;

        let repo = RepoConfig {
            name: "r".into(),
            path: "/r".into(),
            overrides: Default::default(),
        };

        let merged = merge_repo_config(&base, &repo).expect("merge");

        // Non-default base settings survive a merge with no override for them.
        assert_eq!(merged.report.output, "docs/result/custom");
        assert_eq!(merged.report.formats, vec!["json".to_string()]);
        assert_eq!(merged.fusion.line_proximity, 11);
        assert_eq!(merged.logging.level, LogLevel::Debug);
        // The `toml::Value` round-trip re-defaults absent `Option` fields to
        // `None` rather than erroring or inventing values.
        assert_eq!(merged.static_.models_dir, None);
        assert_eq!(merged.static_.learned_dir, None);
        assert_eq!(merged.logging.log_file, None);
    }

    #[test]
    fn scalar_override_replaces_base_value() {
        let toml = r#"
[fusion]
line_proximity = 5
[[batch.repo]]
name = "a"
path = "/a"
[batch.repo.fusion]
line_proximity = 20
"#;
        let cfg: BatchConfig = toml::from_str(toml).expect("parse");
        let merged = merge_repo_config(&cfg.runtime, &cfg.batch.repos[0]).expect("merge");
        assert_eq!(merged.fusion.line_proximity, 20);
        assert_eq!(merged.fusion.rule_weight, 3, "sibling fusion key preserved");
    }

    #[test]
    fn array_override_replaces_whole_array() {
        let toml = r#"
[scan]
exclude = ["node_modules", "target"]
[[batch.repo]]
name = "a"
path = "/a"
[batch.repo.scan]
exclude = ["only-this"]
"#;
        let cfg: BatchConfig = toml::from_str(toml).expect("parse");
        let merged = merge_repo_config(&cfg.runtime, &cfg.batch.repos[0]).expect("merge");
        assert_eq!(merged.scan.exclude, vec!["only-this".to_string()]);
        // No scan.targets override => defaults to the repo path.
        assert_eq!(merged.scan.targets, vec!["/a".to_string()]);
    }

    #[test]
    fn explicit_scan_targets_override_wins_over_repo_path() {
        let toml = r#"
[[batch.repo]]
name = "a"
path = "/a"
[batch.repo.scan]
targets = ["/custom", "/other"]
"#;
        let cfg: BatchConfig = toml::from_str(toml).expect("parse");
        let merged = merge_repo_config(&cfg.runtime, &cfg.batch.repos[0]).expect("merge");
        assert_eq!(merged.scan.targets, vec!["/custom".to_string(), "/other".to_string()]);
    }

    #[test]
    fn batch_config_defaults_match_batch_settings_defaults() {
        let cfg = BatchConfig::default();
        assert_eq!(cfg.batch.max_parallel, 4);
        assert!(cfg.batch.learning_bus);
        assert!(!cfg.batch.fail_fast);
        assert_eq!(cfg.batch.limits.codeql, 1);
        assert_eq!(cfg.batch.limits.agent, 1);
        assert_eq!(cfg.batch.limits.cpu, 4);
        assert!(cfg.batch.repos.is_empty());
    }
}
