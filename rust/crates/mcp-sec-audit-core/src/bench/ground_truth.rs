//! Ground-truth schema: one known vulnerability per `vulns` key in TOML.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroundTruth {
    #[serde(default)]
    pub vulns: BTreeMap<String, VulnEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnEntry {
    pub repo_slug: String,
    pub language: String,
    pub cwe: String,
    pub category: String,
    pub severity: String,
    pub evidence_tier: String,
    pub sink_line: u32,
    pub sink_file: String,
    #[serde(default)]
    pub source_urls: Vec<String>,
    #[serde(default)]
    pub known_clean: Vec<String>,
}

pub fn load_ground_truth(path: &Path) -> Result<GroundTruth> {
    let input = std::fs::read_to_string(path)
        .with_context(|| format!("read ground truth from {}", path.display()))?;
    toml::from_str(&input).context("parse ground truth TOML")
}

impl GroundTruth {
    pub fn for_repo(&self, slug: &str) -> Vec<(&String, &VulnEntry)> {
        self.vulns
            .iter()
            .filter(|(_, e)| e.repo_slug == slug)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_keyed_toml_and_filters_by_repo() {
        let toml = r#"
[vulns."CVE-2025-68144"]
repo_slug = "servers-git-py"
language = "python"
cwe = "CWE-88"
category = "command_execution"
severity = "high"
evidence_tier = "cve"
sink_line = 123
sink_file = "src/git/server.py"
source_urls = ["https://github.com/advisories/GHSA-9xwc-hfwc-8w59"]

[vulns."CVE-2025-53110"]
repo_slug = "servers-filesystem-ts"
language = "typescript"
cwe = "CWE-22"
category = "path_traversal"
severity = "high"
evidence_tier = "cve"
sink_line = 45
sink_file = "src/filesystem/index.ts"
"#;
        let gt: GroundTruth = toml::from_str(toml).expect("parse");
        assert_eq!(gt.vulns.len(), 2);
        assert_eq!(gt.for_repo("servers-git-py").len(), 1);
        let (key, entry) = gt.for_repo("servers-git-py")[0];
        assert_eq!(*key, "CVE-2025-68144");
        assert_eq!(entry.sink_line, 123);
    }
}
