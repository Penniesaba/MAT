# MCP Vulnerability Benchmark (v5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `bench` subcommand that runs 20 pinned, known-vulnerable MCP repositories through the v5 batch orchestrator and scores P/R/F1 against a ground-truth file.

**Architecture:** A new `bench` module in `mcp-sec-audit-core` (manifest + ground-truth + scorer + metrics rendering) plus a thin CLI `bench` subcommand that reuses the existing `batch::run_batch` orchestrator. The scorer reads each repo's report JSON, extracts finding sink lines, and classifies each finding TP/FP/unconfirmed against ground truth.

**Tech Stack:** Rust 2024 (workspace at `rust/`), clap, serde/serde_json, toml, tokio, anyhow. All new code is in the existing `mcp-sec-audit-core` and `mcp-sec-audit-cli` crates.

**Spec:** `docs/superpowers/specs/2026-08-26-mcp-vuln-benchmark-design.md`

## Global Constraints

- Rust edition 2024, rust-version 1.88 (workspace).
- `serde` is pinned to `=1.0.224` in the workspace — do not bump it.
- All commands in this plan run from the `rust/` directory (`cargo` workspace root).
- No new third-party dependencies. `toml`, `serde`, `serde_json`, `tokio`, `anyhow`, `clap` are already workspace deps.
- The benchmark corpus (cloned repos) and results must be git-ignored; only `manifest.toml`, `ground-truth.toml`, `fetch.sh`, and the Rust code are committed.
- Match semantics are locked: **only sink-line hits count**, tolerance `±N` (default 5), three-way TP/FP/unconfirmed classification, optimistic + pessimistic precision.
- Never commit the spec/pinned commit SHAs as "verified" until Task 7 runs `git ls-remote`/tag checks.

---

## File Structure

**Create (core):**
- `rust/crates/mcp-sec-audit-core/src/bench/mod.rs` — module root: `BenchOptions`, `run_bench`, re-exports.
- `rust/crates/mcp-sec-audit-core/src/bench/manifest.rs` — manifest schema + `to_batch_config`.
- `rust/crates/mcp-sec-audit-core/src/bench/ground_truth.rs` — ground-truth schema + loader.
- `rust/crates/mcp-sec-audit-core/src/bench/scorer.rs` — finding sink-line extraction + matching + classification + aggregates.
- `rust/crates/mcp-sec-audit-core/src/bench/report.rs` — metrics JSON/Markdown renderers.

**Modify (core):**
- `rust/crates/mcp-sec-audit-core/src/lib.rs` — `pub mod bench;` + re-export `BenchMetrics`, `run_bench`.

**Create (cli):**
- `rust/crates/mcp-sec-audit-cli/src/bench.rs` — `bench` subcommand entry.

**Modify (cli):**
- `rust/crates/mcp-sec-audit-cli/src/main.rs` — `mod bench;`, `Command::Bench`, dispatch arm.

**Create (benchmark data):**
- `benchmark/manifest.toml`
- `benchmark/ground-truth.toml`
- `benchmark/fetch.sh`

**Modify (gitignore):**
- `.gitignore` — ignore `benchmark/corpus/` and `benchmark/bench_results/`.

---

## Task 1: Manifest schema + batch-config translation

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/bench/mod.rs`
- Create: `rust/crates/mcp-sec-audit-core/src/bench/manifest.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/lib.rs`

**Interfaces:**
- Consumes: `crate::batch::{BatchConfig, BatchSettings, LimitsConfig, RepoConfig}`, `crate::config::RuntimeConfig`.
- Produces:
  - `pub struct BenchManifest { pub base: RuntimeConfig, pub repos: Vec<RepoEntry> }`
  - `pub struct RepoEntry { pub slug: String, pub url: String, pub commit: String, pub language: String, #[serde(default)] pub scan_targets: Vec<String>, #[serde(default = "default_tier")] pub evidence_tier: String, pub vulns: Vec<String> }`
  - `pub fn load_manifest(path: &Path) -> Result<BenchManifest>`
  - `pub fn to_batch_config(manifest: &BenchManifest, out_dir: &str, max_parallel: usize) -> BatchConfig`
  - `pub fn dedupe_commits(repos: &[RepoEntry]) -> Vec<&RepoEntry>` (one entry per `(url, commit)` pair; used by `fetch.sh`).

- [ ] **Step 1: Write the failing test**

Create `rust/crates/mcp-sec-audit-core/src/bench/manifest.rs` with only the schema + a `#[cfg(test)] mod tests` that fails to compile (functions not yet present):

```rust
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
    #[serde(default)]
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

pub fn load_manifest(_path: &Path) -> Result<BenchManifest> {
    unreachable!("not implemented")
}

pub fn dedupe_commits(_repos: &[RepoEntry]) -> Vec<&RepoEntry> {
    unreachable!("not implemented")
}

pub fn to_batch_config(
    _manifest: &BenchManifest,
    _out_dir: &str,
    _max_parallel: usize,
) -> BatchConfig {
    unreachable!("not implemented")
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
    fn dedupes_repos_sharing_url_and_commit() {
        let m = sample_manifest();
        let deduped = dedupe_commits(&m.repos);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].slug, "servers-git-py");
    }

    #[test]
    fn translates_to_batch_config_with_scan_scope() {
        let m = sample_manifest();
        let cfg = to_batch_config(&m, "benchmark/bench_results/run1", 2);
        assert_eq!(cfg.batch.max_parallel, 2);
        assert!(!cfg.batch.learning_bus);
        assert_eq!(cfg.repos.len(), 2);
        assert_eq!(cfg.repos[0].name, "servers-git-py");
        assert_eq!(cfg.repos[0].path, "../benchmark/corpus/servers-git-py");
        assert_eq!(cfg.runtime.report.formats, vec!["json".to_string()]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rust && cargo test -p mcp-sec-audit-core bench::manifest::tests`
Expected: FAIL — compile error "cannot find function `dedupe_commits`" / "cannot find function `to_batch_config`".

- [ ] **Step 3: Register the module**

Modify `rust/crates/mcp-sec-audit-core/src/lib.rs`: add `pub mod bench;` after `pub mod batch;`. Create `rust/crates/mcp-sec-audit-core/src/bench/mod.rs`:

```rust
//! Benchmark scoring for known-vulnerable MCP repositories (v5).

pub mod ground_truth;
pub mod manifest;
pub mod report;
pub mod scorer;

pub use manifest::{BenchManifest, RepoEntry, dedupe_commits, load_manifest, to_batch_config};
```

- [ ] **Step 4: Implement the three functions**

Replace the stub bodies in `manifest.rs`:

```rust
pub fn load_manifest(path: &Path) -> Result<BenchManifest> {
    let input = std::fs::read_to_string(path)
        .with_context(|| format!("read benchmark manifest from {}", path.display()))?;
    toml::from_str(&input).context("parse benchmark manifest TOML")
}

pub fn dedupe_commits(repos: &[RepoEntry]) -> Vec<&RepoEntry> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for repo in repos {
        let key = (repo.url.as_str(), repo.commit.as_str());
        if seen.insert(key) {
            out.push(repo);
        }
    }
    out
}

pub fn to_batch_config(
    manifest: &BenchManifest,
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
            let mut overrides = std::collections::BTreeMap::new();
            let targets = if entry.scan_targets.is_empty() {
                vec![format!("../benchmark/corpus/{}", entry.slug)]
            } else {
                entry
                    .scan_targets
                    .iter()
                    .map(|t| format!("../benchmark/corpus/{}/{}", entry.slug, t))
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
                path: format!("../benchmark/corpus/{}", entry.slug),
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd rust && cargo test -p mcp-sec-audit-core bench::manifest::tests`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
cd rust
git add crates/mcp-sec-audit-core/src/bench crates/mcp-sec-audit-core/src/lib.rs
git commit -m "feat(bench): manifest schema and batch-config translation"
```

---

## Task 2: Ground-truth schema + loader

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/bench/ground_truth.rs`

**Interfaces:**
- Consumes: nothing new (uses `serde`, `toml`, `anyhow`).
- Produces:
  - `pub struct GroundTruth { pub vulns: std::collections::BTreeMap<String, VulnEntry> }`
  - `pub struct VulnEntry { pub repo_slug: String, pub language: String, pub cwe: String, pub category: String, pub severity: String, pub evidence_tier: String, pub sink_line: u32, pub sink_file: String, #[serde(default)] pub source_urls: Vec<String>, #[serde(default)] pub known_clean: Vec<String> }`
  - `pub fn load_ground_truth(path: &Path) -> Result<GroundTruth>`
  - `impl GroundTruth { pub fn for_repo(&self, slug: &str) -> Vec<(&String, &VulnEntry)> }`

- [ ] **Step 1: Write the failing test + schema**

Create `ground_truth.rs`:

```rust
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
["CVE-2025-68144"]
repo_slug = "servers-git-py"
language = "python"
cwe = "CWE-88"
category = "command_execution"
severity = "high"
evidence_tier = "cve"
sink_line = 123
sink_file = "src/git/server.py"
source_urls = ["https://github.com/advisories/GHSA-9xwc-hfwc-8w59"]

["CVE-2025-53110"]
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
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cd rust && cargo test -p mcp-sec-audit-core bench::ground_truth::tests`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
cd rust
git add crates/mcp-sec-audit-core/src/bench/ground_truth.rs
git commit -m "feat(bench): ground-truth schema and loader"
```

---

## Task 3: Scorer — sink-line extraction, matching, classification, aggregates

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/bench/scorer.rs`

**Interfaces:**
- Consumes: `crate::model::{FusedFinding, StaticAnalysisResult, TaintAnalysisResult, RuleAnalysisResult, CodeqlAnalysisResult}`, `crate::bench::ground_truth::{GroundTruth, VulnEntry}`.
- Produces:
  - `pub enum Classification { Tp, Fp, Unconfirmed }`
  - `pub struct RepoMetrics { pub slug: String, pub language: String, pub evidence_tier: String, pub status: String, pub ground_truth: usize, pub tp: usize, pub fp: usize, pub unconfirmed: usize, pub hits: Vec<String>, pub misses: Vec<String>, pub recall: f64, pub precision_optimistic: f64, pub precision_pessimistic: f64 }`
  - `pub struct AggregateMetrics { pub ground_truth: usize, pub tp: usize, pub fp: usize, pub unconfirmed: usize, pub recall: f64, pub precision_optimistic: f64, pub precision_pessimistic: f64 }`
  - `pub fn parse_line(evidence: &str) -> Option<(String, u32)>`
  - `pub fn finding_lines(fused: &FusedFinding, result: &StaticAnalysisResult) -> Vec<(String, u32)>`
  - `pub fn score_repo(slug: &str, status: &str, gt: &GroundTruth, result: &StaticAnalysisResult, tolerance: u32) -> RepoMetrics`
  - `pub fn aggregate(repos: &[RepoMetrics]) -> AggregateMetrics`

- [ ] **Step 1: Write the failing test** (functions referenced, not yet implemented)

Add to `scorer.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::ground_truth::{GroundTruth, VulnEntry};
    use crate::model::{Confidence, FusedFinding, FindingStatus, Severity, StaticAnalysisResult};

    fn gt_one() -> GroundTruth {
        GroundTruth {
            vulns: [(
                "CVE-1".to_string(),
                VulnEntry {
                    repo_slug: "r".into(),
                    language: "python".into(),
                    cwe: "CWE-78".into(),
                    category: "command_execution".into(),
                    severity: "high".into(),
                    evidence_tier: "cve".into(),
                    sink_line: 12,
                    sink_file: "src/lib.py".into(),
                    source_urls: vec![],
                    known_clean: vec!["src/clean.py".into()],
                },
            )]
            .into_iter()
            .collect(),
        }
    }

    fn fused(evidence: &[&str]) -> FusedFinding {
        FusedFinding {
            finding_id: "f1".into(),
            title: "t".into(),
            category: "command_execution".into(),
            owasp_mcp: None,
            severity: Severity::High,
            confidence: Confidence::High,
            status: FindingStatus::Potential,
            supported_by: vec![],
            related_rule_result_ids: vec![],
            related_taint_result_ids: vec![],
            related_agent_result_ids: vec![],
            related_codeql_result_ids: vec![],
            evidence: evidence.iter().map(|s| s.to_string()).collect(),
            call_chain: vec![],
            dataflow_path: vec![],
            recommendation: None,
            conflict_notes: vec![],
        }
    }

    #[test]
    fn parses_path_line_snippet() {
        assert_eq!(
            parse_line("../x/src/lib.py:12:subprocess.run"),
            Some(("src/lib.py".to_string(), 12))
        );
        assert_eq!(parse_line("no colon here"), None);
    }

    #[test]
    fn sink_line_within_tolerance_is_tp() {
        let gt = gt_one();
        let result = StaticAnalysisResult::default(); // empty raw results; fused evidence drives it
        let mut f = fused(&["../x/src/lib.py:14:subprocess.run"]);
        f.related_taint_result_ids = vec![]; // force evidence-string fallback
        let metrics = score_repo("r", "ok", &gt, &result, 5);
        assert_eq!(metrics.tp, 1);
        assert_eq!(metrics.hits, vec!["CVE-1".to_string()]);
        assert!(metrics.misses.is_empty());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rust && cargo test -p mcp-sec-audit-core bench::scorer::tests`
Expected: FAIL — `parse_line`/`score_repo`/`StaticAnalysisResult::default` not present.

- [ ] **Step 3: Implement**

Write `scorer.rs` body:

```rust
//! Scoring: map report findings to ground-truth sink lines and classify.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::ground_truth::{GroundTruth, VulnEntry};
use crate::model::{CodeqlAnalysisResult, FusedFinding, RuleAnalysisResult, StaticAnalysisResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Classification {
    Tp,
    Fp,
    Unconfirmed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoMetrics {
    pub slug: String,
    pub language: String,
    pub evidence_tier: String,
    pub status: String,
    pub ground_truth: usize,
    pub tp: usize,
    pub fp: usize,
    pub unconfirmed: usize,
    pub hits: Vec<String>,
    pub misses: Vec<String>,
    pub recall: f64,
    pub precision_optimistic: f64,
    pub precision_pessimistic: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AggregateMetrics {
    pub ground_truth: usize,
    pub tp: usize,
    pub fp: usize,
    pub unconfirmed: usize,
    pub recall: f64,
    pub precision_optimistic: f64,
    pub precision_pessimistic: f64,
}

impl Default for AggregateMetrics {
    fn default() -> Self {
        Self { ground_truth: 0, tp: 0, fp: 0, unconfirmed: 0, recall: 0.0, precision_optimistic: 0.0, precision_pessimistic: 0.0 }
    }
}

/// Parses an evidence string `path:line:snippet` (path may itself contain
/// colons, so the line is split from the last colon). Returns a normalized
/// relative path (leading `../` prefixes stripped) and the line number.
pub fn parse_line(evidence: &str) -> Option<(String, u32)> {
    let (path, line_colon_rest) = evidence.rsplit_once(':')?;
    let line_str = line_colon_rest.split(':').next()?;
    let line: u32 = line_str.parse().ok()?;
    let norm = path.replace('\\', "/");
    let rel = norm.split('/').filter(|s| *s != "..").collect::<Vec<_>>().join("/");
    Some((rel, line))
}

/// Collects candidate `(file, line)` pairs for a fused finding: resolve its
/// `related_*` ids against the raw per-line results first, then fall back to
/// parsing the finding's own `evidence` strings.
pub fn finding_lines(fused: &FusedFinding, result: &StaticAnalysisResult) -> Vec<(String, u32)> {
    let mut out: Vec<(String, u32)> = Vec::new();

    for id in &fused.related_rule_result_ids {
        if let Some(r) = result.rule_results.iter().find(|r| &r.result_id == id) {
            out.push((normalize_path(&r.file), r.line));
        }
    }
    for id in &fused.related_taint_result_ids {
        if let Some(t) = result.taint_results.iter().find(|t| &t.result_id == id) {
            for e in &t.evidence {
                if let Some(p) = parse_line(e) {
                    out.push(p);
                }
            }
        }
    }
    for id in &fused.related_codeql_result_ids {
        if let Some(c) = result.codeql_results.iter().find(|c| &c.result_id == id) {
            for loc in &c.locations {
                out.push((normalize_path(&loc.file), loc.line));
            }
        }
    }
    if out.is_empty() {
        for e in &fused.evidence {
            if let Some(p) = parse_line(e) {
                out.push(p);
            }
        }
    }
    out
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .split('/')
        .filter(|s| *s != "..")
        .collect::<Vec<_>>()
        .join("/")
}

/// `known_clean` entries use the same normalized-relative-path + line format.
fn clean_line_is_hit(entry: &VulnEntry, file: &str, line: u32) -> bool {
    entry.known_clean.iter().any(|c| {
        parse_line(c).is_some_and(|(f, l)| f == file && l == line)
    })
}

pub fn score_repo(
    slug: &str,
    status: &str,
    gt: &GroundTruth,
    result: &StaticAnalysisResult,
    tolerance: u32,
) -> RepoMetrics {
    let gt_entries = gt.for_repo(slug);
    let language = gt_entries.first().map(|(_, e)| e.language.clone()).unwrap_or_default();
    let tier = gt_entries.first().map(|(_, e)| e.evidence_tier.clone()).unwrap_or_default();

    // A vuln is "hit" when at least one finding line matches its sink line.
    let mut hits: BTreeSet<String> = BTreeSet::new();
    let mut fp = 0usize;
    let mut unconfirmed = 0usize;

    for fused in &result.fused_findings {
        let lines = finding_lines(fused, result);
        let mut matched = false;
        for (key, entry) in &gt_entries {
            let sink_ok = lines.iter().any(|(f, l)| {
                file_suffix_matches(f, &entry.sink_file)
                    && (l.abs_diff(entry.sink_line) <= tolerance)
            });
            if sink_ok {
                hits.insert((*key).clone());
                matched = true;
            }
        }
        if !matched {
            // FP only when it lands in a `known_clean` region of some entry.
            let in_clean = gt_entries.iter().any(|(_, e)| {
                lines.iter().any(|(f, l)| clean_line_is_hit(e, f, *l))
            });
            if in_clean {
                fp += 1;
            } else {
                unconfirmed += 1;
            }
        }
    }

    let ground_truth = gt_entries.len();
    let tp = hits.len();
    let misses: Vec<String> = gt_entries
        .iter()
        .map(|(k, _)| (*k).clone())
        .filter(|k| !hits.contains(k))
        .collect();
    let hits_vec: Vec<String> = hits.into_iter().collect();

    let (recall, p_opt, p_pes) = compute_scores(tp, fp, unconfirmed, ground_truth);
    RepoMetrics {
        slug: slug.to_string(),
        language,
        evidence_tier: tier,
        status: status.to_string(),
        ground_truth,
        tp,
        fp,
        unconfirmed,
        hits: hits_vec,
        misses,
        recall,
        precision_optimistic: p_opt,
        precision_pessimistic: p_pes,
    }
}

pub fn aggregate(repos: &[RepoMetrics]) -> AggregateMetrics {
    let (tp, fp, unconf, gt): (usize, usize, usize, usize) = repos
        .iter()
        .map(|r| (r.tp, r.fp, r.unconfirmed, r.ground_truth))
        .fold((0, 0, 0, 0), |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2, a.3 + b.3));
    let (recall, p_opt, p_pes) = compute_scores(tp, fp, unconf, gt);
    AggregateMetrics { ground_truth: gt, tp, fp, unconfirmed: unconf, recall, precision_optimistic: p_opt, precision_pessimistic: p_pes }
}

fn file_suffix_matches(finding_file: &str, sink_file: &str) -> bool {
    let f = normalize_path(finding_file);
    let s = normalize_path(sink_file);
    f == s || f.ends_with(&format!("/{s}"))
}

fn compute_scores(tp: usize, fp: usize, unconfirmed: usize, gt: usize) -> (f64, f64, f64) {
    let recall = if gt == 0 { 0.0 } else { tp as f64 / gt as f64 };
    let p_opt = if tp + fp == 0 { 0.0 } else { tp as f64 / (tp + fp) as f64 };
    let p_pes = if tp + fp + unconfirmed == 0 {
        0.0
    } else {
        tp as f64 / (tp + fp + unconfirmed) as f64
    };
    (recall, p_opt, p_pes)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rust && cargo test -p mcp-sec-audit-core bench::scorer::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd rust
git add crates/mcp-sec-audit-core/src/bench/scorer.rs
git commit -m "feat(bench): sink-line scorer with TP/FP/unconfirmed classification"
```

---

## Task 4: Metrics rendering (JSON + Markdown)

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/bench/report.rs`

**Interfaces:**
- Consumes: `scorer::{AggregateMetrics, RepoMetrics}`.
- Produces:
  - `pub struct BenchMetrics { pub generated_at: String, pub manifest_path: String, pub tolerance: u32, pub overall: AggregateMetrics, pub by_language: std::collections::BTreeMap<String, AggregateMetrics>, pub by_tier: std::collections::BTreeMap<String, AggregateMetrics>, pub by_category: std::collections::BTreeMap<String, AggregateMetrics>, pub repos: Vec<RepoMetrics> }`
  - `pub fn render_metrics_json(m: &BenchMetrics) -> Result<String>`
  - `pub fn render_metrics_markdown(m: &BenchMetrics) -> String`

- [ ] **Step 1: Write the failing test + structs**

Create `report.rs`:

```rust
//! Benchmark metrics rendering (JSON + Markdown).

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::scorer::{AggregateMetrics, RepoMetrics};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchMetrics {
    pub generated_at: String,
    pub manifest_path: String,
    pub tolerance: u32,
    pub overall: AggregateMetrics,
    pub by_language: BTreeMap<String, AggregateMetrics>,
    pub by_tier: BTreeMap<String, AggregateMetrics>,
    pub by_category: BTreeMap<String, AggregateMetrics>,
    pub repos: Vec<RepoMetrics>,
}

pub fn render_metrics_json(_m: &BenchMetrics) -> Result<String> {
    unreachable!("not implemented")
}

pub fn render_metrics_markdown(_m: &BenchMetrics) -> String {
    unreachable!("not implemented")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BenchMetrics {
        BenchMetrics {
            generated_at: "20260826-120000".into(),
            manifest_path: "benchmark/manifest.toml".into(),
            tolerance: 5,
            overall: AggregateMetrics { ground_truth: 1, tp: 1, fp: 0, unconfirmed: 1, recall: 1.0, precision_optimistic: 1.0, precision_pessimistic: 0.5 },
            by_language: BTreeMap::new(),
            by_tier: BTreeMap::new(),
            by_category: BTreeMap::new(),
            repos: vec![RepoMetrics {
                slug: "r".into(),
                language: "python".into(),
                evidence_tier: "cve".into(),
                status: "ok".into(),
                ground_truth: 1,
                tp: 1,
                fp: 0,
                unconfirmed: 1,
                hits: vec!["CVE-1".into()],
                misses: vec![],
                recall: 1.0,
                precision_optimistic: 1.0,
                precision_pessimistic: 0.5,
            }],
        }
    }

    #[test]
    fn json_roundtrips() {
        let m = sample();
        let json = render_metrics_json(&m).expect("render");
        let back: BenchMetrics = serde_json::from_str(&json).expect("parse");
        assert_eq!(back.overall.tp, 1);
        assert_eq!(back.repos[0].slug, "r");
    }

    #[test]
    fn markdown_has_optimistic_and_pessimistic_precision() {
        let md = render_metrics_markdown(&sample());
        assert!(md.contains("precision_optimistic"));
        assert!(md.contains("precision_pessimistic"));
        assert!(md.contains("## repos"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rust && cargo test -p mcp-sec-audit-core bench::report::tests`
Expected: FAIL — functions not implemented.

- [ ] **Step 3: Implement renderers**

```rust
pub fn render_metrics_json(m: &BenchMetrics) -> Result<String> {
    serde_json::to_string_pretty(m).map_err(Into::into)
}

pub fn render_metrics_markdown(m: &BenchMetrics) -> String {
    let mut lines = vec![
        "# MCP Vulnerability Benchmark".to_string(),
        String::new(),
        format!("- Generated: {}", m.generated_at),
        format!("- Manifest: {}", m.manifest_path),
        format!("- Tolerance: ±{} lines", m.tolerance),
        String::new(),
        "## overall".to_string(),
        format!("- ground_truth: {}", m.overall.ground_truth),
        format!("- tp: {}", m.overall.tp),
        format!("- fp: {}", m.overall.fp),
        format!("- unconfirmed: {}", m.overall.unconfirmed),
        format!("- recall: {:.3}", m.overall.recall),
        format!("- precision_optimistic: {:.3}", m.overall.precision_optimistic),
        format!("- precision_pessimistic: {:.3}", m.overall.precision_pessimistic),
        String::new(),
        "## repos".to_string(),
        String::new(),
        "| slug | language | tier | status | GT | TP | FP | unconf | recall | P_opt | P_pes |".to_string(),
        "|---|---|---|---|---|---|---|---|---|---|---|".to_string(),
    ];
    for r in &m.repos {
        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.3} | {:.3} | {:.3} |",
            r.slug,
            r.language,
            r.evidence_tier,
            r.status,
            r.ground_truth,
            r.tp,
            r.fp,
            r.unconfirmed,
            r.recall,
            r.precision_optimistic,
            r.precision_pessimistic,
        ));
        if !r.misses.is_empty() {
            lines.push(format!("  - misses: {}", r.misses.join(", ")));
        }
    }
    lines.join("\n")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rust && cargo test -p mcp-sec-audit-core bench::report::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd rust
git add crates/mcp-sec-audit-core/src/bench/report.rs
git commit -m "feat(bench): metrics JSON and markdown rendering"
```

---

## Task 5: `run_bench` orchestration

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/bench/mod.rs`

**Interfaces:**
- Consumes: `crate::batch::run_batch`, `crate::model::StaticAnalysisResult`, `crate::reporting::current_local_timestamp`, `scorer`, `report`, `manifest`, `ground_truth`.
- Produces:
  - `pub struct BenchOptions { pub tolerance: u32, pub max_parallel: usize }`
  - `pub async fn run_bench(manifest_path: &Path, opts: &BenchOptions, cancel: CancellationToken) -> Result<BenchMetrics>`

- [ ] **Step 1: Write the failing test** (a unit test that `run_bench` needs; assert the helper that builds `BenchMetrics` from per-repo results)

Add to `bench/mod.rs` a test module exercising a pure helper `build_metrics` (defined in this task) so the aggregation path is tested without a full pipeline:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::ground_truth::{GroundTruth, VulnEntry};
    use crate::bench::scorer::{AggregateMetrics, RepoMetrics};

    fn gt() -> GroundTruth {
        GroundTruth {
            vulns: [
                ("CVE-1".into(), VulnEntry {
                    repo_slug: "a".into(), language: "python".into(), cwe: "CWE-78".into(),
                    category: "command_execution".into(), severity: "high".into(),
                    evidence_tier: "cve".into(), sink_line: 1, sink_file: "app.py".into(),
                    source_urls: vec![], known_clean: vec![],
                }),
                ("X".into(), VulnEntry {
                    repo_slug: "b".into(), language: "python".into(), cwe: "CWE-22".into(),
                    category: "path_traversal".into(), severity: "high".into(),
                    evidence_tier: "issue".into(), sink_line: 1, sink_file: "app.py".into(),
                    source_urls: vec![], known_clean: vec![],
                }),
            ].into_iter().collect(),
        }
    }

    #[test]
    fn builds_layered_metrics_from_repo_metrics() {
        let repos = vec![
            RepoMetrics { slug: "a".into(), language: "python".into(), evidence_tier: "cve".into(), status: "ok".into(), ground_truth: 1, tp: 1, fp: 0, unconfirmed: 1, hits: vec!["CVE-1".into()], misses: vec![], recall: 1.0, precision_optimistic: 1.0, precision_pessimistic: 0.5 },
            RepoMetrics { slug: "b".into(), language: "python".into(), evidence_tier: "issue".into(), status: "ok".into(), ground_truth: 1, tp: 0, fp: 0, unconfirmed: 0, hits: vec![], misses: vec!["X".into()], recall: 0.0, precision_optimistic: 0.0, precision_pessimistic: 0.0 },
        ];
        let m = build_metrics(repos, &gt(), "benchmark/manifest.toml", 5, "20260826-120000");
        assert_eq!(m.overall.ground_truth, 2);
        assert_eq!(m.overall.tp, 1);
        assert_eq!(m.by_language["python"].ground_truth, 2);
        assert_eq!(m.by_tier["cve"].tp, 1);
        assert_eq!(m.by_tier["issue"].tp, 0);
        assert_eq!(m.by_category["command_execution"].ground_truth, 1);
        assert_eq!(m.by_category["command_execution"].tp, 1);
        assert_eq!(m.by_category["path_traversal"].ground_truth, 1);
        assert_eq!(m.by_category["path_traversal"].tp, 0);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rust && cargo test -p mcp-sec-audit-core bench::tests`
Expected: FAIL — `build_metrics` not defined.

- [ ] **Step 3: Implement**

Replace `bench/mod.rs` with:

```rust
//! Benchmark scoring for known-vulnerable MCP repositories (v5).

pub mod ground_truth;
pub mod manifest;
pub mod report;
pub mod scorer;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

pub use manifest::{BenchManifest, RepoEntry, dedupe_commits, load_manifest, to_batch_config};
pub use report::BenchMetrics;
pub use scorer::{AggregateMetrics, RepoMetrics};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchOptions {
    pub tolerance: u32,
    pub max_parallel: usize,
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self { tolerance: 5, max_parallel: 4 }
    }
}

/// Runs the benchmark: loads manifest + ground truth, drives the batch
/// orchestrator over the corpus, scores each repo, and writes `metrics.json`
/// + `metrics.md` under `<manifest_dir>/bench_results/<timestamp>/`.
pub async fn run_bench(
    manifest_path: &Path,
    opts: &BenchOptions,
    cancel: CancellationToken,
) -> Result<BenchMetrics> {
    let manifest = load_manifest(manifest_path)?;
    let gt_path = manifest_path.with_file_name("ground-truth.toml");
    let gt = ground_truth::load_ground_truth(&gt_path)?;

    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let timestamp = crate::reporting::current_local_timestamp();
    let out_dir = manifest_dir.join("bench_results").join(&timestamp);
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("create bench output dir {}", out_dir.display()))?;

    let batch_cfg = to_batch_config(&manifest, &out_dir.to_string_lossy(), opts.max_parallel);
    let summary = crate::batch::run_batch(batch_cfg, cancel).await?;

    let mut repo_metrics = Vec::new();
    for repo in &summary.repos {
        let report_path = repo
            .report_paths
            .iter()
            .find(|p| p.ends_with(".json") && !p.ends_with("batch-summary.json"));
        let Some(report_path) = report_path else {
            repo_metrics.push(scorer::score_repo(
                &repo.name,
                repo.status.as_str(),
                &gt,
                &crate::model::StaticAnalysisResult::default(),
                opts.tolerance,
            ));
            continue;
        };
        let text = std::fs::read_to_string(report_path)
            .with_context(|| format!("read report {}", report_path))?;
        let result: crate::model::StaticAnalysisResult =
            serde_json::from_str(&text).with_context(|| format!("parse report {}", report_path))?;
        repo_metrics.push(scorer::score_repo(&repo.name, repo.status.as_str(), &gt, &result, opts.tolerance));
    }

    let metrics = build_metrics(
        repo_metrics,
        &gt,
        &manifest_path.to_string_lossy(),
        opts.tolerance,
        &timestamp,
    );

    let json = report::render_metrics_json(&metrics)?;
    std::fs::write(out_dir.join("metrics.json"), json).context("write metrics.json")?;
    let md = report::render_metrics_markdown(&metrics);
    std::fs::write(out_dir.join("metrics.md"), md).context("write metrics.md")?;

    Ok(metrics)
}

fn build_metrics(
    repos: Vec<RepoMetrics>,
    gt: &ground_truth::GroundTruth,
    manifest_path: &str,
    tolerance: u32,
    generated_at: &str,
) -> BenchMetrics {
    let overall = scorer::aggregate(&repos);
    let mut by_language: BTreeMap<String, AggregateMetrics> = BTreeMap::new();
    let mut by_tier: BTreeMap<String, AggregateMetrics> = BTreeMap::new();

    for r in &repos {
        by_language
            .entry(r.language.clone())
            .and_modify(|a| merge_into(a, r))
            .or_insert_with(|| single(r));
        by_tier
            .entry(r.evidence_tier.clone())
            .and_modify(|a| merge_into(a, r))
            .or_insert_with(|| single(r));
    }

    let by_category = category_breakdown(gt, &repos);

    BenchMetrics {
        generated_at: generated_at.to_string(),
        manifest_path: manifest_path.to_string(),
        tolerance,
        overall,
        by_language,
        by_tier,
        by_category,
        repos,
    }
}

/// Per-category recall: `GT` = vulns in the category, `TP` = those found in a
/// repo's `hits`. FP/unconfirmed are finding-level and stay on the overall
/// metrics, so category entries carry `fp = 0` / `unconfirmed = 0`.
fn category_breakdown(gt: &ground_truth::GroundTruth, repos: &[RepoMetrics]) -> BTreeMap<String, AggregateMetrics> {
    let mut acc: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for r in repos {
        let hits: BTreeSet<&str> = r.hits.iter().map(String::as_str).collect();
        for (key, entry) in gt.for_repo(&r.slug) {
            let e = acc.entry(entry.category.clone()).or_insert((0, 0));
            e.0 += 1;
            if hits.contains(key.as_str()) {
                e.1 += 1;
            }
        }
    }
    acc.into_iter()
        .map(|(cat, (gt, tp))| {
            let (recall, p_opt, p_pes) = scorer::compute_scores(tp, 0, 0, gt);
            (
                cat,
                AggregateMetrics {
                    ground_truth: gt,
                    tp,
                    fp: 0,
                    unconfirmed: 0,
                    recall,
                    precision_optimistic: p_opt,
                    precision_pessimistic: p_pes,
                },
            )
        })
        .collect()
}

fn single(r: &RepoMetrics) -> AggregateMetrics {
    AggregateMetrics {
        ground_truth: r.ground_truth,
        tp: r.tp,
        fp: r.fp,
        unconfirmed: r.unconfirmed,
        recall: r.recall,
        precision_optimistic: r.precision_optimistic,
        precision_pessimistic: r.precision_pessimistic,
    }
}

fn merge_into(acc: &mut AggregateMetrics, r: &RepoMetrics) {
    acc.ground_truth += r.ground_truth;
    acc.tp += r.tp;
    acc.fp += r.fp;
    acc.unconfirmed += r.unconfirmed;
    let (recall, p_opt, p_pes) = scorer::compute_scores(
        acc.tp, acc.fp, acc.unconfirmed, acc.ground_truth,
    );
    acc.recall = recall;
    acc.precision_optimistic = p_opt;
    acc.precision_pessimistic = p_pes;
}
```

- [ ] **Step 4: Expose `compute_scores` in `scorer.rs` as `pub(crate)`**

In `scorer.rs`, change `fn compute_scores(...)` to `pub(crate) fn compute_scores(...)` (no other changes).

- [ ] **Step 5: Re-export in `lib.rs`**

In `rust/crates/mcp-sec-audit-core/src/lib.rs`, add to the batch re-export block (or a new line):

```rust
pub use bench::{AggregateMetrics, BenchMetrics, BenchOptions, RepoMetrics, run_bench};
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd rust && cargo test -p mcp-sec-audit-core bench::`
Expected: PASS (all bench tests).

- [ ] **Step 7: Commit**

```bash
cd rust
git add crates/mcp-sec-audit-core/src/bench/mod.rs crates/mcp-sec-audit-core/src/bench/scorer.rs crates/mcp-sec-audit-core/src/lib.rs
git commit -m "feat(bench): run_bench orchestration over the batch pipeline"
```

---

## Task 6: CLI `bench` subcommand

**Files:**
- Create: `rust/crates/mcp-sec-audit-cli/src/bench.rs`
- Modify: `rust/crates/mcp-sec-audit-cli/src/main.rs`

**Interfaces:**
- Consumes: `mcp_sec_audit_core::{run_bench, BenchOptions}`, `tokio_util::sync::CancellationToken`.
- Produces: `pub async fn run(manifest: &Path, tolerance: u32, max_parallel: usize, cancel: CancellationToken) -> anyhow::Result<BenchMetrics>`.

- [ ] **Step 1: Write the CLI module**

Create `rust/crates/mcp-sec-audit-cli/src/bench.rs`:

```rust
//! CLI entry point for the `bench` subcommand.

use std::path::Path;

use anyhow::Result;
use mcp_sec_audit_core::{BenchMetrics, BenchOptions, run_bench};
use tokio_util::sync::CancellationToken;

pub async fn run(
    manifest: &Path,
    tolerance: u32,
    max_parallel: usize,
    cancel: CancellationToken,
) -> Result<BenchMetrics> {
    let opts = BenchOptions { tolerance, max_parallel };
    let metrics = run_bench(manifest, &opts, cancel).await?;
    Ok(metrics)
}
```

- [ ] **Step 2: Wire the subcommand into `main.rs`**

Edit `rust/crates/mcp-sec-audit-cli/src/main.rs`:

1. Add `mod bench;` next to `mod batch;`.
2. Add `Bench(BenchArgs)` to `enum Command` (after `Batch`).
3. Add the args struct:

```rust
#[derive(Debug, Args)]
struct BenchArgs {
    /// Path to the benchmark manifest TOML file.
    manifest: PathBuf,
    /// Sink-line match tolerance (±N lines).
    #[arg(long, default_value_t = 5)]
    tolerance: u32,
    /// Repositories to scan concurrently.
    #[arg(long, default_value_t = 4)]
    max_parallel: usize,
}
```

4. Add a dispatch arm mirroring the `Batch` arm. Insert after the `Batch` arm's closing brace (`std::process::exit(...)` block) and before `None =>`:

```rust
Some(Command::Bench(args)) => {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    let cancel = CancellationToken::new();
    let ctrl_c = CancellationToken::new();
    {
        let cancel = cancel.clone();
        let ctrl_c = ctrl_c.clone();
        rt.spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                ctrl_c.cancel();
                cancel.cancel();
            }
        });
    }
    let result = rt.block_on(bench::run(
        &args.manifest,
        args.tolerance,
        args.max_parallel,
        cancel.clone(),
    ));
    std::process::exit(match result {
        Ok(_) if ctrl_c.is_cancelled() => 130,
        Ok(_) => 0,
        Err(_) => 2,
    });
}
```

- [ ] **Step 3: Build**

Run: `cd rust && cargo build -p mcp-sec-audit-cli`
Expected: compiles cleanly.

- [ ] **Step 4: Smoke-test `--help`**

Run: `cd rust && cargo run -p mcp-sec-audit-cli -- bench --help`
Expected: prints `--manifest`, `--tolerance`, `--max-parallel`.

- [ ] **Step 5: Commit**

```bash
cd rust
git add crates/mcp-sec-audit-cli/src/bench.rs crates/mcp-sec-audit-cli/src/main.rs
git commit -m "feat(bench): add bench CLI subcommand"
```

---

## Task 7: Benchmark data — manifest, ground truth, fetch script

**Files:**
- Create: `benchmark/manifest.toml`
- Create: `benchmark/ground-truth.toml`
- Create: `benchmark/fetch.sh`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: the `BenchManifest`/`GroundTruth` schemas from Tasks 1–2, the SSH-clone convention.
- Produces: a fetchable corpus + 20 ground-truth entries + an SSH clone script.

- [ ] **Step 1: Add gitignore entries**

Append to `.gitignore`:

```
# Benchmark corpus (SSH-cloned) and results (generated)
benchmark/corpus/
benchmark/bench_results/
```

- [ ] **Step 2: Write the manifest skeleton**

Create `benchmark/manifest.toml`. Fill `commit` with `"<PENDING>"` for all 20 entries (resolved in Step 4). The `[base]` section mirrors `test-targets/configs/all-languages-config.toml` but keeps agent/codeql off by default for a deterministic CPU-only baseline:

```toml
# MCP Vulnerability Benchmark manifest (20 items: 10 py / 4 ts / 2 js / 4 rust).
# `commit` must be pinned to the VULNERABLE commit (not HEAD). Run fetch.sh to clone.

[base.scan]
exclude = ["__pycache__", ".venv", "node_modules", "target", ".git"]

[base.static]
enabled = true
save_facts = true

[base.static.rule]
enabled = true
rule_paths = ["rules/mcp", "rules/languages"]

[base.static.taint]
enabled = true
forward = true
backward = true
max_depth = 8
entrypoint_required = false

[base.static.agent]
enabled = false

[base.static.codeql]
enabled = false

[base.fusion]
enabled = true
require_confirmed_by = 1
boost_when_multiple_lines_agree = true
agent_only_as_advisory = true
line_proximity = 5
rule_weight = 3
taint_weight = 2
agent_weight = 1
codeql_weight = 4

# --- Python (10) ---
[[repo]]
slug = "servers-git-py"
url = "git@github.com:modelcontextprotocol/servers.git"
commit = "<PENDING>"
language = "python"
scan_targets = ["src/git"]
evidence_tier = "cve"
vulns = ["CVE-2025-68144", "CVE-2025-68143"]

[[repo]]
slug = "sqlite-mcp"
url = "git@github.com:dubydu/sqlite-mcp.git"
commit = "<PENDING>"
language = "python"
evidence_tier = "cve"
vulns = ["CVE-2026-7206"]

[[repo]]
slug = "kubectl-mcp-server"
url = "git@github.com:rohitg00/kubectl-mcp-server.git"
commit = "<PENDING>"
language = "python"
evidence_tier = "cve"
vulns = ["CVE-2025-65719"]

[[repo]]
slug = "fastmcp"
url = "git@github.com:jlowin/fastmcp.git"
commit = "<PENDING>"
language = "python"
evidence_tier = "cve"
vulns = ["CVE-2025-64340", "CVE-2026-32871"]

[[repo]]
slug = "litellm"
url = "git@github.com:BerriAI/litellm.git"
commit = "<PENDING>"
language = "python"
scan_targets = ["litellm/proxy"]
evidence_tier = "cve"
vulns = ["CVE-2026-42271"]

[[repo]]
slug = "aws-api-mcp-server"
url = "git@github.com:awslabs/aws-api-mcp-server.git"
commit = "<PENDING>"
language = "python"
evidence_tier = "cve"
vulns = ["CVE-2026-4270"]

[[repo]]
slug = "python-sdk"
url = "git@github.com:modelcontextprotocol/python-sdk.git"
commit = "<PENDING>"
language = "python"
evidence_tier = "cve"
vulns = ["CVE-2025-66416"]

# --- TypeScript (4) ---
[[repo]]
slug = "servers-filesystem-ts"
url = "git@github.com:modelcontextprotocol/servers.git"
commit = "<PENDING>"
language = "typescript"
scan_targets = ["src/filesystem"]
evidence_tier = "cve"
vulns = ["CVE-2025-53109", "CVE-2025-53110"]

[[repo]]
slug = "inspector"
url = "git@github.com:modelcontextprotocol/inspector.git"
commit = "<PENDING>"
language = "typescript"
evidence_tier = "cve"
vulns = ["CVE-2025-49596"]

[[repo]]
slug = "mcp-remote"
url = "git@github.com:punkpeye/mcp-remote.git"
commit = "<PENDING>"
language = "typescript"
evidence_tier = "cve"
vulns = ["CVE-2025-6514"]

[[repo]]
slug = "figma-context-mcp"
url = "git@github.com:GLips/Figma-Context-MCP.git"
commit = "<PENDING>"
language = "typescript"
evidence_tier = "cve"
vulns = ["CVE-2025-53967"]

# --- JavaScript (2) ---
[[repo]]
slug = "serverless-mcp"
url = "git@github.com:serverless/serverless.git"
commit = "<PENDING>"
language = "javascript"
scan_targets = ["packages/mcp"]
evidence_tier = "cve"
vulns = ["CVE-2025-69256"]

[[repo]]
slug = "vulnerable-mcp-servers-lab"
url = "git@github.com:appsecco/vulnerable-mcp-servers-lab.git"
commit = "<PENDING>"
language = "javascript"
scan_targets = ["vulnerable-mcp-servers-lab/filesystem-server"]
evidence_tier = "synthetic"
vulns = ["LAB-filesystem-path-traversal"]

# --- Rust (4) ---
[[repo]]
slug = "rust-sdk"
url = "git@github.com:modelcontextprotocol/rust-sdk.git"
commit = "<PENDING>"
language = "rust"
evidence_tier = "cve"
vulns = ["RUSTSEC-2026-0189"]

[[repo]]
slug = "ruvector"
url = "git@github.com:ruvnet/RuVector.git"
commit = "<PENDING>"
language = "rust"
evidence_tier = "issue"
vulns = ["RUVECTOR-207"]

[[repo]]
slug = "nucleus"
url = "git@github.com:coproduct-opensource/nucleus.git"
commit = "<PENDING>"
language = "rust"
evidence_tier = "issue"
vulns = ["NUCLEUS-102"]

[[repo]]
slug = "frigg"
url = "git@github.com:bnomei/frigg.git"
commit = "<PENDING>"
language = "rust"
evidence_tier = "issue"
vulns = ["FRIGG-symlink-traversal"]
```

- [ ] **Step 3: Write the ground-truth skeleton**

Create `benchmark/ground-truth.toml`. Fill `sink_file`/`sink_line` with `<PENDING>` values resolved in Step 5. Include all 20 keys referenced by `manifest.toml`:

```toml
# Ground truth — one vulnerability per key. sink_line is the sink expression's
# line number in the VULNERABLE commit (verify against the pinned commit).

["CVE-2025-68144"]
repo_slug = "servers-git-py"
language = "python"
cwe = "CWE-88"
category = "command_execution"
severity = "high"
evidence_tier = "cve"
sink_line = 0          # <PENDING>
sink_file = "<PENDING>" # src/git/... handler

["CVE-2025-68143"]
repo_slug = "servers-git-py"
language = "python"
cwe = "CWE-22"
category = "path_traversal"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2026-7206"]
repo_slug = "sqlite-mcp"
language = "python"
cwe = "CWE-89"
category = "sql_injection"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2025-65719"]
repo_slug = "kubectl-mcp-server"
language = "python"
cwe = "CWE-94"
category = "command_execution"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2025-64340"]
repo_slug = "fastmcp"
language = "python"
cwe = "CWE-78"
category = "command_execution"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2026-32871"]
repo_slug = "fastmcp"
language = "python"
cwe = "CWE-918"
category = "ssrf"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2026-42271"]
repo_slug = "litellm"
language = "python"
cwe = "CWE-78"
category = "command_execution"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2026-4270"]
repo_slug = "aws-api-mcp-server"
language = "python"
cwe = "CWE-284"
category = "access_control"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2025-66416"]
repo_slug = "python-sdk"
language = "python"
cwe = "CWE-346"
category = "origin_validation"
severity = "medium"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2025-53109"]
repo_slug = "servers-filesystem-ts"
language = "typescript"
cwe = "CWE-59"
category = "path_traversal"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2025-53110"]
repo_slug = "servers-filesystem-ts"
language = "typescript"
cwe = "CWE-22"
category = "path_traversal"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2025-49596"]
repo_slug = "inspector"
language = "typescript"
cwe = "CWE-306"
category = "auth_bypass"
severity = "critical"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2025-6514"]
repo_slug = "mcp-remote"
language = "typescript"
cwe = "CWE-78"
category = "command_execution"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2025-53967"]
repo_slug = "figma-context-mcp"
language = "typescript"
cwe = "CWE-77"
category = "command_execution"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["CVE-2025-69256"]
repo_slug = "serverless-mcp"
language = "javascript"
cwe = "CWE-78"
category = "command_execution"
severity = "high"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["LAB-filesystem-path-traversal"]
repo_slug = "vulnerable-mcp-servers-lab"
language = "javascript"
cwe = "CWE-22"
category = "path_traversal"
severity = "high"
evidence_tier = "synthetic"
sink_line = 0
sink_file = "<PENDING>"

["RUSTSEC-2026-0189"]
repo_slug = "rust-sdk"
language = "rust"
cwe = "CWE-346"
category = "origin_validation"
severity = "medium"
evidence_tier = "cve"
sink_line = 0
sink_file = "<PENDING>"

["RUVECTOR-207"]
repo_slug = "ruvector"
language = "rust"
cwe = "CWE-22"
category = "path_traversal"
severity = "high"
evidence_tier = "issue"
sink_line = 0
sink_file = "<PENDING>"

["NUCLEUS-102"]
repo_slug = "nucleus"
language = "rust"
cwe = "CWE-59"
category = "path_traversal"
severity = "high"
evidence_tier = "issue"
sink_line = 0
sink_file = "<PENDING>"

["FRIGG-symlink-traversal"]
repo_slug = "frigg"
language = "rust"
cwe = "CWE-59"
category = "path_traversal"
severity = "high"
evidence_tier = "issue"
sink_line = 0
sink_file = "<PENDING>"
```

- [ ] **Step 4: Write the SSH fetch script**

Create `benchmark/fetch.sh` (executable). It parses `manifest.toml` with a small embedded Python helper (Python 3.11+ has `tomllib`), clones via SSH, and checks out the pinned commit:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Fetch the benchmark corpus via SSH (avoids GitHub HTTPS network issues).
# Usage: bash benchmark/fetch.sh
cd "$(dirname "$0")"

python3 - <<'PY' > /tmp/mcp-bench-repos.tsv
import tomllib
with open("manifest.toml", "rb") as f:
    m = tomllib.load(f)
for r in m.get("repo", []):
    print(r["slug"], r["url"], r["commit"], sep="\t")
PY

mkdir -p corpus
while IFS=$'\t' read -r slug url commit; do
  dest="corpus/$slug"
  if [ -d "$dest/.git" ]; then
    echo "exists: $slug"
    git -C "$dest" fetch --depth 1 origin "$commit" || true
  else
    echo "cloning: $slug"
    git clone "$url" "$dest"
  fi
  git -C "$dest" checkout "$commit"
done < /tmp/mcp-bench-repos.tsv
rm -f /tmp/mcp-bench-repos.tsv
echo "done. corpus under benchmark/corpus/"
```

- [ ] **Step 5: Verify the manifest parses**

Run: `cd rust && cargo test -p mcp-sec-audit-core bench::manifest::tests` (existing tests still pass) and a schema check:
Run: `python3 -c "import tomllib; tomllib.load(open('../benchmark/manifest.toml','rb')); print('manifest OK')"`
Expected: `manifest OK`.

- [ ] **Step 6: Commit the skeleton**

```bash
git add benchmark/manifest.toml benchmark/ground-truth.toml benchmark/fetch.sh .gitignore
git commit -m "feat(bench): benchmark manifest, ground-truth skeleton, SSH fetch script"
```

- [ ] **Step 7 (verify task, run once): resolve the 20 pinned commits and sink lines**

This is the spec's §11 "落地前校验". For each of the 20 repos, run `git ls-remote <url> HEAD` and locate the vulnerable tag/commit from the advisory (tag ≤ fix version), then update `commit` in `manifest.toml` and the `sink_file`/`sink_line` in `ground-truth.toml` after cloning that commit and reading the source. Do NOT mark the benchmark "done" until every `"<PENDING>"` is replaced. Re-run the schema check and `bash benchmark/fetch.sh` to confirm all 20 checkouts succeed.

---

## Task 8: End-to-end smoke test + docs

**Files:**
- Modify: `README.md` (add a "Benchmark" section).

- [ ] **Step 1: Write an e2e smoke test in the CLI crate**

Create `rust/crates/mcp-sec-audit-cli/tests/bench_smoke.rs`. It runs a tiny Python repo through `run_bench` (CPU-only path, taint on, rule/agent/codeql off) and asserts `metrics.json` parses with 20-consistent fields:

```rust
//! End-to-end smoke: a tiny vulnerable Python repo through `run_bench`.

use std::path::PathBuf;

use mcp_sec_audit_core::{run_bench, BenchOptions};
use tokio_util::sync::CancellationToken;

fn tiny_repo(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("app.py"), "import subprocess\nsubprocess.run(['ls'])\n").unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bench_runs_over_a_tiny_repo_and_writes_metrics() {
    let root = std::env::temp_dir().join(format!("mcp-bench-smoke-{}", std::process::id()));
    let corpus = root.join("corpus").join("tiny");
    tiny_repo(&corpus);
    let manifest_path = root.join("manifest.toml");
    let gt_path = root.join("ground-truth.toml");
    std::fs::write(
        &manifest_path,
        r#"
[scan]
exclude = ["__pycache__", ".venv", "node_modules", "target", ".git"]
[static]
enabled = true
[static.rule]
enabled = false
[static.taint]
enabled = true
forward = true
backward = true
max_depth = 8
entrypoint_required = false
[static.agent]
enabled = false
[static.codeql]
enabled = false
[fusion]
enabled = false
[[repo]]
slug = "tiny"
url = "git@github.com:example/tiny.git"
commit = "deadbeef"
language = "python"
evidence_tier = "cve"
vulns = ["CVE-tiny"]
"#,
    )
    .unwrap();
    std::fs::write(
        &gt_path,
        r#"
["CVE-tiny"]
repo_slug = "tiny"
language = "python"
cwe = "CWE-78"
category = "command_execution"
severity = "high"
evidence_tier = "cve"
sink_line = 2
sink_file = "app.py"
"#,
    )
    .unwrap();

    let metrics = run_bench(&manifest_path, &BenchOptions { tolerance: 5, max_parallel: 1 }, CancellationToken::new())
        .await
        .expect("bench");

    // This is a *plumbing* smoke test, not a detection test: it asserts the
    // bench path runs end-to-end and writes metrics; the scorer's hit/FP logic
    // is covered by the bench::scorer unit tests. `tp` is not asserted here
    // because whether the taint line flags the bare `subprocess.run` depends
    // on the built-in catalog, which this test does not assume.
    assert_eq!(metrics.repos.len(), 1);
    assert_eq!(metrics.overall.ground_truth, 1);

    let out_dir = manifest_path
        .parent()
        .unwrap()
        .join("bench_results");
    let metrics_files: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .unwrap()
        .flat_map(|e| e)
        .flat_map(|e| std::fs::read_dir(e.path()).ok())
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()) == Some("metrics.json"))
        .collect();
    assert_eq!(metrics_files.len(), 1);
}
```

- [ ] **Step 2: Run the smoke test**

Run: `cd rust && cargo test -p mcp-sec-audit-cli --test bench_smoke`
Expected: PASS.

- [ ] **Step 3: Document the command in `README.md`**

Add a `## Benchmark` section to `README.md` (place it after the batch section):

```markdown
## Benchmark

Run the known-vulnerable MCP benchmark (20 repos, see `benchmark/`):

```bash
bash benchmark/fetch.sh                         # SSH-clone the corpus (once)
cd rust && cargo run -- bench ../benchmark/manifest.toml
```

Results land in `benchmark/bench_results/<timestamp>/metrics.json` (+ `.md`).
Scoring: sink-line match ±N (default 5), TP/FP/unconfirmed classification,
optimistic + pessimistic precision, grouped by language/tier.
```

- [ ] **Step 4: Commit**

```bash
git add rust/crates/mcp-sec-audit-cli/tests/bench_smoke.rs README.md
git commit -m "test(bench): end-to-end smoke test and README docs"
```

---

## Final verification

- [ ] Run the full core test suite: `cd rust && cargo test -p mcp-sec-audit-core`
- [ ] Run the full CLI test suite: `cd rust && cargo test -p mcp-sec-audit-cli`
- [ ] Confirm `git status` is clean except the git-ignored `benchmark/corpus/` and `benchmark/bench_results/`.
