//! Benchmark manifest: the list of pinned repositories to fetch and scan.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::batch::{BatchConfig, BatchSettings, LimitsConfig, RepoConfig};
use crate::config::RuntimeConfig;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchManifest {
    /// Shared base runtime config (same syntax as a single-repo config file).
    #[serde(flatten)]
    pub base: RuntimeConfig,
    #[serde(default, rename = "repo")]
    pub repos: Vec<RepoEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoEntry {
    pub slug: String,
    pub url: String,
    pub commit: String,
    pub language: String,
    #[serde(default)]
    pub scan_targets: Vec<String>,
    #[serde(default = "default_tier")]
    pub evidence_tier: String,
    pub vulns: Vec<String>,
}

fn default_tier() -> String {
    "cve".to_string()
}

pub fn load_manifest(path: &Path) -> Result<BenchManifest> {
    let input = std::fs::read_to_string(path)
        .with_context(|| format!("read benchmark manifest from {}", path.display()))?;
    toml::from_str(&input).context("parse benchmark manifest TOML")
}

pub fn to_batch_config(
    manifest: &BenchManifest,
    corpus_root: &Path,
    out_dir: &str,
    max_parallel: usize,
) -> BatchConfig {
    let mut base = manifest.base.clone();
    // Reproducible eval: force JSON-only reports landing under the bench output
    // directory, keyed by repo slug via the `<repo>` placeholder.
    base.report.formats = vec!["json".to_string()];
    base.report.output = format!("{out_dir}/<repo>");

    let repos = manifest
        .repos
        .iter()
        .map(|entry| {
            let repo_dir = corpus_root.join(&entry.slug);
            let repo_dir_str = repo_dir.to_string_lossy().to_string();
            let mut overrides = std::collections::BTreeMap::new();
            let targets = if entry.scan_targets.is_empty() {
                vec![repo_dir_str.clone()]
            } else {
                entry
                    .scan_targets
                    .iter()
                    .map(|t| repo_dir.join(t).to_string_lossy().to_string())
                    .collect()
            };
            overrides.insert(
                "scan".to_string(),
                toml::Value::Table({
                    let mut t = toml::Table::new();
                    t.insert(
                        "targets".to_string(),
                        toml::Value::Array(targets.into_iter().map(toml::Value::String).collect()),
                    );
                    t.insert(
                        "languages".to_string(),
                        toml::Value::Array(vec![toml::Value::String(entry.language.clone())]),
                    );
                    t
                }),
            );
            RepoConfig {
                name: entry.slug.clone(),
                path: repo_dir_str,
                overrides,
            }
        })
        .collect();

    BatchConfig {
        batch: BatchSettings {
            max_parallel,
            learning_bus: false,
            fail_fast: false,
            limits: LimitsConfig::default(),
            repos,
        },
        runtime: base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> BenchManifest {
        let base: RuntimeConfig =
            toml::from_str("[scan]\nlanguages = [\"python\"]\n").expect("base");
        BenchManifest {
            base,
            repos: vec![
                RepoEntry {
                    slug: "servers-git-py".into(),
                    url: "git@github.com:modelcontextprotocol/servers.git".into(),
                    commit: "abc123".into(),
                    language: "python".into(),
                    scan_targets: vec!["src/git".into()],
                    evidence_tier: "cve".into(),
                    vulns: vec!["CVE-2025-68144".into()],
                },
                RepoEntry {
                    slug: "servers-filesystem-ts".into(),
                    url: "git@github.com:modelcontextprotocol/servers.git".into(),
                    commit: "abc123".into(),
                    language: "typescript".into(),
                    scan_targets: vec!["src/filesystem".into()],
                    evidence_tier: "cve".into(),
                    vulns: vec!["CVE-2025-53110".into()],
                },
            ],
        }
    }

    #[test]
    fn translates_to_batch_config_with_scan_scope() {
        let m = sample_manifest();
        let cfg = to_batch_config(
            &m,
            std::path::Path::new("/tmp/bench-corpus"),
            "benchmark/bench_results/run1",
            2,
        );
        assert_eq!(cfg.batch.max_parallel, 2);
        assert!(!cfg.batch.learning_bus);
        assert_eq!(cfg.batch.repos.len(), 2);
        assert_eq!(cfg.batch.repos[0].name, "servers-git-py");
        assert_eq!(cfg.batch.repos[0].path, "/tmp/bench-corpus/servers-git-py");
        assert_eq!(cfg.runtime.report.formats, vec!["json".to_string()]);
    }

    #[test]
    fn repo_key_maps_to_repos_field() {
        let toml = r#"
[scan]
languages = ["python"]

[[repo]]
slug = "r"
url = "git@github.com:o/r.git"
commit = "abc"
language = "python"
vulns = ["CVE-1"]
"#;
        let m: BenchManifest = toml::from_str(toml).expect("parse");
        assert_eq!(m.repos.len(), 1);
        assert_eq!(m.repos[0].slug, "r");
    }
}
