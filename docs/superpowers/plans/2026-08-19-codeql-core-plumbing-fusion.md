# CodeQL Line v2 — Core Plumbing, Category Fusion & Rust Enablement (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the CodeQL line run on Rust, organize queries per language, and
align CodeQL results onto the shared category vocabulary so they fuse with the
rule/taint lines by category.

**Architecture:** Split the single Python-only query pack into per-language packs
(`mcp-python` / `mcp-js` / `mcp-rust`), resolve the pack per database language,
add `category`/`query_source`/`languages` to `CodeqlAnalysisResult`, and extract
the category in the SARIF parser from `@tags` plus a curated `rule_id → category`
map. Fusion then consumes `category` instead of `rule_id`.

**Tech Stack:** Rust (cargo), CodeQL CLI 2.26.2, CodeQL standard query packs,
SARIF v2.1.0.

**Spec:** `docs/superpowers/specs/2026-08-19-codeql-industrial-mcp-design.md`
(the plan argues from the spec — executors read both).

**Scope note:** This plan delivers the cross-cutting core (plumbing + fusion +
category vocabulary + Rust enablement + Rust QL API spike). The full per-language
query matrix (spec §6: Python M2 / JS M3 / Rust M4) is a **follow-up plan** that
depends on the Rust QL API reference produced by Task 9 here.

## Global Constraints

- CodeQL CLI binary default is `"codeql"` (on PATH); config override is `[static.codeql].binary`.
- Standard packs are NOT bundled — `codeql/{python,javascript,rust}-queries` must be downloaded (Task 1).
- **Pack refs are version-pinned** (CLI 2.26.2 cannot resolve unversioned/latest — see M0 findings): `codeql/python-queries@1.8.7`, `codeql/javascript-queries@2.4.2`, `codeql/rust-queries@0.1.39`. Revert to unversioned only after CLI upgrade to 2.26.3+.
- Category vocabulary is snake_case: `command_execution`, `dynamic_execution`, `database_injection`, `file_read`, `file_write`, `network_request`, `deserialization`, `template_injection`, `path_traversal`, `prompt_injection`, `data_exfiltration`, `tool_poisoning`, `unsafe_block`, `env_access`.
- Unknown/uncategorized CodeQL results use `category = "uncategorized"` (still fuse by line proximity).
- `cargo test` must stay green at the end of every task.
- Query pack directories are resolved relative to `CARGO_MANIFEST_DIR` at build time.

---

### Task 1: M0 — Install standard query packs + smoke test

**Files:**
- No source changes. Environment setup only.

**Interfaces:**
- Produces: `codeql/python-queries`, `codeql/javascript-queries`, `codeql/rust-queries` (and transitively `-all` library packs) visible to `codeql resolve packs`.

- [ ] **Step 1: Download the standard packs**

```bash
codeql pack download codeql/python-queries codeql/javascript-queries codeql/rust-queries
```

- [ ] **Step 2: Verify packs resolve**

```bash
codeql resolve packs | grep -E 'python-queries|javascript-queries|rust-queries|python-all|javascript-all|rust-all'
```

Expected: lines for `codeql/python-queries`, `codeql/javascript-queries`,
`codeql/rust-queries` and the `-all` library packs.

- [ ] **Step 3: Smoke test — build a Rust DB and run the official pack**

```bash
cd /home/xiao/Project/mcp-sec-audit
codeql database create /tmp/db-rust-smoke \
  --language=rust \
  --source-root=test-targets/rust-mcp-server \
  --overwrite
codeql database analyze /tmp/db-rust-smoke \
  codeql/rust-queries \
  --format=sarif-latest \
  --output=/tmp/rust-smoke.sarif
```

Expected: exit 0, and `/tmp/rust-smoke.sarif` is a valid SARIF JSON with a
`runs[].tool.driver.rules` array (even if `results` is empty — the goal is that
the Rust extractor + official pack run end-to-end).

- [ ] **Step 4: Smoke test — Python and JS, same shape**

```bash
codeql database create /tmp/db-py-smoke --language=python --source-root=test-targets/python-mcp-server --overwrite
codeql database analyze /tmp/db-py-smoke codeql/python-queries --format=sarif-latest --output=/tmp/py-smoke.sarif
codeql database create /tmp/db-js-smoke --language=javascript --source-root=test-targets/js-mcp-server --overwrite
codeql database analyze /tmp/db-js-smoke codeql/javascript-queries --format=sarif-latest --output=/tmp/js-smoke.sarif
```

Expected: all exit 0. Record the result counts for the M5 baseline.

- [ ] **Step 5: Commit nothing**

Environment-only task. No git commit (packs live under `~/.codeql/packages`,
outside the repo).

---

### Task 2: Add `category`/`query_source`/`languages` to `CodeqlAnalysisResult` + extract category in parser

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/model/static_result.rs:83-104`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/parser.rs` (struct + `parse_sarif` + add `resolve_category`)
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/fusion/matcher.rs:439-458` (test helper `make_codeql`)
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/fusion/merger.rs:288-307` (test constructor)

**Interfaces:**
- Produces: `CodeqlAnalysisResult.category: String`, `.query_source: String`, `.languages: Vec<String>`.
- Produces: `parser::resolve_category(rule_id: &str, rule: Option<&serde_json::Value>) -> String`.

- [ ] **Step 1: Add fields to the model**

In `model/static_result.rs`, insert after `rule_name`:

```rust
    pub rule_name: String,
    /// Category in the shared rule/taint vocabulary (e.g. "command_execution").
    #[serde(default = "default_uncategorized")]
    pub category: String,
    /// Where the query came from: "built-in" or a custom pack path.
    #[serde(default)]
    pub query_source: String,
    /// Languages the database was built for.
    #[serde(default)]
    pub languages: Vec<String>,
    pub message: String,
```

Add the default helper near `default_verification_status`:

```rust
fn default_uncategorized() -> String {
    "uncategorized".to_string()
}
```

- [ ] **Step 2: Add `resolve_category` + tag parsing to parser.rs**

At the top of `parser.rs`, after the `CodeqlMetadata` struct, add:

```rust
/// Categories in the shared vocabulary (snake_case).
const KNOWN_CATEGORIES: &[&str] = &[
    "command_execution",
    "dynamic_execution",
    "database_injection",
    "file_read",
    "file_write",
    "network_request",
    "deserialization",
    "template_injection",
    "path_traversal",
    "prompt_injection",
    "data_exfiltration",
    "tool_poisoning",
    "unsafe_block",
    "env_access",
];

fn normalize_tag(tag: &str) -> String {
    tag.trim().replace('-', "_").replace(' ', "_").to_lowercase()
}

/// Extract a shared-vocabulary category from a SARIF rule's `properties.tags`.
fn category_from_tags(rule: &serde_json::Value) -> Option<String> {
    let tags = rule.get("properties")?.get("tags")?;
    let list: Vec<String> = if let Some(arr) = tags.as_array() {
        arr.iter().filter_map(|t| t.as_str().map(str::to_string)).collect()
    } else if let Some(s) = tags.as_str() {
        s.split(',').map(|t| t.trim().to_string()).collect()
    } else {
        return None;
    };
    list.iter().find_map(|t| {
        let n = normalize_tag(t);
        KNOWN_CATEGORIES.contains(&n.as_str()).then(|| n)
    })
}

/// Curated map from official CodeQL rule ids to shared categories.
fn category_from_rule_id(rule_id: &str) -> Option<String> {
    let cat = match rule_id {
        "rust/sql-injection" => "database_injection",
        "rust/ssrf" => "network_request",
        "rust/path-injection" => "path_traversal",
        "rust/invalid-pointer-access" | "rust/access-invalid-pointer" => "unsafe_block",
        "py/cmd-injection" | "py/command-injection" => "command_execution",
        "py/sql-injection" => "database_injection",
        "py/ssrf" => "network_request",
        "py/path-injection" => "path_traversal",
        "py/deserialization" => "deserialization",
        "py/code-injection" => "dynamic_execution",
        "js/command-line-injection" => "command_execution",
        "js/sql-injection" => "database_injection",
        "js/ssrf" => "network_request",
        "js/path-injection" => "path_traversal",
        "js/code-injection" => "dynamic_execution",
        _ => return None,
    };
    Some(cat.to_string())
}

/// Resolve a result's category: our query's `@tags` first, then the curated
/// official rule_id map, then "uncategorized".
pub fn resolve_category(rule_id: &str, rule: Option<&serde_json::Value>) -> String {
    if let Some(rule) = rule {
        if let Some(cat) = category_from_tags(rule) {
            return cat;
        }
    }
    category_from_rule_id(rule_id).unwrap_or_else(|| "uncategorized".to_string())
}
```

- [ ] **Step 3: Populate the new fields in `parse_sarif`**

Change the signature and body: rename `_metadata` to `metadata`, look up the rule
before constructing each result, and set the new fields.

```rust
pub fn parse_sarif(sarif_json: &str, metadata: &CodeqlMetadata) -> Result<Vec<CodeqlAnalysisResult>> {
```

Inside the per-result loop, after `let rule_name = ...;`, add:

```rust
            let rule = rule_index.get(rule_id.as_str()).copied();
            let category = resolve_category(&rule_id, rule);
```

And in the `CodeqlAnalysisResult { ... }` literal, after `rule_name,`:

```rust
                rule_name,
                category,
                query_source: metadata.query_source.clone(),
                languages: metadata.languages.clone(),
                message,
```

- [ ] **Step 4: Remove `#[allow(dead_code)]` from `CodeqlMetadata`**

In `parser.rs`, delete the `#[allow(dead_code)]` line above `pub struct CodeqlMetadata`.

- [ ] **Step 5: Fix the two test constructors (compilation)**

In `matcher.rs` test helper `make_codeql` (around line 439), after `rule_name:`, add:

```rust
            rule_name: format!("{rule_id} rule"),
            category: "command_execution".to_string(),
            query_source: "built-in".to_string(),
            languages: vec!["python".to_string()],
            message: "CodeQL finding".to_string(),
```

In `merger.rs` test `merge_codeql_only_produces_fused_finding` (around line 288),
after `rule_name: "Command Injection".into(),`, add:

```rust
                category: "command_execution".into(),
                query_source: "built-in".into(),
                languages: vec!["python".into()],
```

- [ ] **Step 6: Run tests**

```bash
cd /home/xiao/Project/mcp-sec-audit/rust && cargo test -p mcp-sec-audit-core codeql
```

Expected: PASS (existing parser tests still pass; category defaults to
"uncategorized" for the minimal SARIF fixtures).

- [ ] **Step 7: Add a parser test for category extraction**

Append to the `parser.rs` `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn extracts_category_from_tags_and_rule_id_map() {
        // Our query: @tags carry the category directly (kebab → snake).
        assert_eq!(
            resolve_category("mcp/python/command-execution", Some(&serde_json::json!({
                "properties": { "tags": ["security", "mcp", "command-execution"] }
            }))),
            "command_execution"
        );
        // Official query: curated rule_id → category map.
        assert_eq!(resolve_category("rust/sql-injection", None), "database_injection");
        // Unknown: uncategorized fallback.
        assert_eq!(resolve_category("rust/unknown-thing", None), "uncategorized");
    }
```

Run: `cargo test -p mcp-sec-audit-core codeql::parser` — expected PASS.

- [ ] **Step 8: Commit**

```bash
cd /home/xiao/Project/mcp-sec-audit && git add rust/crates/mcp-sec-audit-core/src/model/static_result.rs rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/parser.rs rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/matcher.rs rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/merger.rs
git commit -m "feat(codeql): add category/query_source/languages to results and extract category from SARIF"
```

---

### Task 3: Fusion consumes `category` (matcher + merger)

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/fusion/matcher.rs:175`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/fusion/merger.rs:94-96` and test `:319`

**Interfaces:**
- Consumes: `CodeqlAnalysisResult.category` (from Task 2).
- Produces: CodeQL results join stage-2 fusion by shared-vocabulary category.

- [ ] **Step 1: matcher — use category, not rule_id**

In `matcher.rs`, in the codeql `Matchable` construction, change:

```rust
            category: Some(c.rule_id.clone()),
```
to:
```rust
            category: Some(c.category.clone()),
```

- [ ] **Step 2: merger — count category, not rule_id**

In `merger.rs` `build_category`, change:

```rust
    for c in &group.codeql_results {
        *counts.entry(&c.rule_id).or_insert(0) += 1;
    }
```
to:
```rust
    for c in &group.codeql_results {
        *counts.entry(&c.category).or_insert(0) += 1;
    }
```

- [ ] **Step 3: Update the merger test assertion**

In `merger.rs` `merge_codeql_only_produces_fused_finding`, change:

```rust
        assert_eq!(f.category, "py/cmd-injection");
```
to:
```rust
        assert_eq!(f.category, "command_execution");
```

- [ ] **Step 4: Run tests**

```bash
cd /home/xiao/Project/mcp-sec-audit/rust && cargo test -p mcp-sec-audit-core fusion
```

Expected: PASS — `codeql_matches_rule_by_proximity` and
`merge_codeql_only_produces_fused_finding` now exercise category.

- [ ] **Step 5: Commit**

```bash
cd /home/xiao/Project/mcp-sec-audit && git add rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/matcher.rs rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/merger.rs
git commit -m "fix(fusion): match and vote CodeQL results by category, not rule_id"
```

---

### Task 4: Add 5 new categories to `keywords.toml`

**Files:**
- Modify: `rust/rules/languages/keywords.toml`

**Interfaces:**
- Produces: the rule/taint lines can also emit `path_traversal`, `template_injection`, `prompt_injection`, `data_exfiltration`, `tool_poisoning`, so CodeQL hits on these categories cross-verify.

- [ ] **Step 1: Append the five capability blocks**

Append to `keywords.toml` (following the existing `[[capabilities]]` shape):

```toml
[[capabilities]]
name = "path_traversal"
weight = 20.0
base_confidence = 0.35

  [[capabilities.indicators]]
  languages = ["python"]
  type = "keyword"
  patterns = [
    "..",
    "os.path.join",
    "Path(",
  ]

  [[capabilities.indicators]]
  languages = ["javascript", "typescript"]
  type = "keyword"
  patterns = [
    "path.join",
    "..",
    "resolve(",
  ]

  [[capabilities.indicators]]
  languages = ["rust"]
  type = "keyword"
  patterns = [
    "Path::new",
    "..",
    "canonicalize",
  ]

[[capabilities]]
name = "template_injection"
weight = 20.0
base_confidence = 0.35

  [[capabilities.indicators]]
  languages = ["python"]
  type = "keyword"
  patterns = [
    "render_template_string",
    "jinja2",
    "Template(",
  ]

[[capabilities]]
name = "prompt_injection"
weight = 25.0
base_confidence = 0.4

  [[capabilities.indicators]]
  languages = ["python"]
  type = "keyword"
  patterns = [
    "openai",
    "anthropic",
    "ChatCompletion",
    "messages.create",
  ]

  [[capabilities.indicators]]
  languages = ["javascript", "typescript"]
  type = "keyword"
  patterns = [
    "openai",
    "anthropic",
    "chat.completions",
  ]

[[capabilities]]
name = "data_exfiltration"
weight = 20.0
base_confidence = 0.35

  [[capabilities.indicators]]
  languages = ["python"]
  type = "keyword"
  patterns = [
    "os.environ",
    "requests.post",
    "urllib",
  ]

  [[capabilities.indicators]]
  languages = ["javascript", "typescript"]
  type = "keyword"
  patterns = [
    "process.env",
    "fetch(",
    "axios.",
  ]

[[capabilities]]
name = "tool_poisoning"
weight = 20.0
base_confidence = 0.3

  [[capabilities.indicators]]
  languages = ["python"]
  type = "keyword"
  patterns = [
    "description",
    "<IMPORTANT>",
    "ignore previous instructions",
  ]

  [[capabilities.indicators]]
  languages = ["javascript", "typescript"]
  type = "keyword"
  patterns = [
    "description:",
    "<IMPORTANT>",
    "ignore previous instructions",
  ]

  [[capabilities.indicators]]
  languages = ["rust"]
  type = "keyword"
  patterns = [
    "description =",
    "<IMPORTANT>",
    "ignore previous instructions",
  ]
```

- [ ] **Step 2: Verify TOML parses**

```bash
cd /home/xiao/Project/mcp-sec-audit/rust && cargo test -p mcp-sec-audit-core config
```

Expected: PASS (any config-loading test that parses `keywords.toml` still works).

- [ ] **Step 3: Commit**

```bash
cd /home/xiao/Project/mcp-sec-audit && git add rust/rules/languages/keywords.toml
git commit -m "feat(rules): add path_traversal/template_injection/prompt_injection/data_exfiltration/tool_poisoning categories"
```

---

### Task 5: Per-language query pack registry (`queries.rs`) + restructure query dirs

**Files:**
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/qlpack.yml`
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-js/qlpack.yml`
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-rust/qlpack.yml`
- Move (git): `queries/mcp/*.ql` + `queries/mcp/qlpack.yml` → `queries/mcp-python/`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries.rs`

**Interfaces:**
- Consumes: `ScanLanguage` config keys (`"python"`, `"javascript"`, `"typescript"`, `"rust"`).
- Produces: `QueryPack::for_language(language: &str) -> Result<QueryPack>` and `resolve_query_pack(custom_path: Option<&str>, language: &str) -> Result<QueryPack>`.

- [ ] **Step 1: Move the existing Python queries**

```bash
cd /home/xiao/Project/mcp-sec-audit
git mv rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python
```

- [ ] **Step 2: Write the three qlpack.yml files**

`mcp-python/qlpack.yml` (already exists from the move — keep, but confirm name):

```yaml
name: mcp-sec-audit/mcp-python-queries
version: 0.0.0
dependencies:
  codeql/python-all: "*"
```

`mcp-js/qlpack.yml`:

```yaml
name: mcp-sec-audit/mcp-js-queries
version: 0.0.0
dependencies:
  codeql/javascript-all: "*"
```

`mcp-rust/qlpack.yml`:

```yaml
name: mcp-sec-audit/mcp-rust-queries
version: 0.0.0
dependencies:
  codeql/rust-all: "*"
```

- [ ] **Step 3: Rewrite `queries.rs` for per-language packs**

Replace `QueryPack::default`, `suite_refs_for`, `suite_matches_language`,
`resolve_query_pack`, and `builtin_mcp_query_dir` with:

```rust
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// Represents a resolved query pack ready for CodeQL analysis.
#[derive(Debug, Clone)]
pub struct QueryPack {
    /// Paths to .ql files or .qlref references (language-native for this DB).
    pub query_files: Vec<PathBuf>,
    /// Standard query pack references for this language (e.g. "codeql/rust-queries").
    pub suite_refs: Vec<String>,
    /// Whether this is a built-in pack (whose queries are language-native).
    pub is_builtin: bool,
}

impl QueryPack {
    /// Build the built-in query pack for one database language.
    pub fn for_language(language: &str) -> Result<Self> {
        let dir = builtin_mcp_query_dir_for(language)?;
        let mut query_files = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("ql") {
                query_files.push(path);
            }
        }
        Ok(Self {
            query_files,
            suite_refs: standard_suite_refs_for(language),
            is_builtin: true,
        })
    }

    /// Load a user-specified query pack directory (applies to every language).
    pub fn from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!("CodeQL query pack path does not exist: {}", path.display());
        }
        let mut query_files = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("ql") {
                query_files.push(p);
            }
        }
        Ok(Self {
            query_files,
            suite_refs: Vec::new(),
            is_builtin: false,
        })
    }
}

/// Standard security suite reference for a database language.
///
/// Version-pinned: CLI 2.26.2 cannot resolve unversioned pack refs from the
/// local cache, and the latest packs (built by CLI 2.26.3) fail to download.
/// See Global Constraints. Revert to unversioned refs after a CLI upgrade.
fn standard_suite_refs_for(language: &str) -> Vec<String> {
    match language {
        "python" => vec!["codeql/python-queries@1.8.7".to_string()],
        "javascript" | "typescript" => vec!["codeql/javascript-queries@2.4.2".to_string()],
        "rust" => vec!["codeql/rust-queries@0.1.39".to_string()],
        _ => Vec::new(),
    }
}

/// Resolve the active query pack: user override or built-in per-language default.
pub fn resolve_query_pack(custom_path: Option<&str>, language: &str) -> Result<QueryPack> {
    match custom_path {
        Some(p) => QueryPack::from_path(Path::new(p)),
        None => QueryPack::for_language(language),
    }
}

/// Directory containing built-in MCP CodeQL queries for one language.
fn builtin_mcp_query_dir_for(language: &str) -> Result<PathBuf> {
    let lang_dir = match language {
        "python" => "mcp-python",
        "javascript" | "typescript" => "mcp-js",
        "rust" => "mcp-rust",
        _ => bail!("no built-in MCP query pack for language '{}'", language),
    };
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("static_analysis")
        .join("codeql")
        .join("queries")
        .join(lang_dir);
    if !dir.exists() {
        bail!(
            "Built-in CodeQL query directory not found: {}. \
             Ensure the crate is built from the correct directory.",
            dir.display()
        );
    }
    Ok(dir)
}
```

- [ ] **Step 4: Update `queries.rs` tests**

Replace the test module body with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_pack_has_mcp_queries_and_python_suite() {
        let pack = QueryPack::for_language("python").expect("python pack");
        assert!(pack.query_files.iter().any(|p| {
            p.file_name().and_then(|n| n.to_str()).map_or(false, |n| n.contains("ToolParameterToSink"))
        }));
        assert_eq!(pack.suite_refs, vec!["codeql/python-queries@1.8.7"]);
    }

    #[test]
    fn rust_pack_has_rust_suite() {
        let pack = QueryPack::for_language("rust").expect("rust pack");
        assert_eq!(pack.suite_refs, vec!["codeql/rust-queries@0.1.39"]);
    }

    #[test]
    fn unknown_language_errors() {
        let err = QueryPack::for_language("cobol").expect_err("unknown language should fail");
        assert!(err.to_string().contains("no built-in MCP query pack"));
    }

    #[test]
    fn resolve_custom_path_overrides_default() {
        let tmp = std::env::temp_dir().join("codeql-test-queries");
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        std::fs::write(tmp.join("test.ql"), "// test query").expect("write test file");
        let pack = resolve_query_pack(Some(tmp.to_str().unwrap()), "python").expect("resolve custom pack");
        assert!(!pack.query_files.is_empty());
        assert!(pack.suite_refs.is_empty());
        std::fs::remove_dir_all(&tmp).expect("cleanup");
    }

    #[test]
    fn missing_custom_path_returns_error() {
        let err = resolve_query_pack(Some("/nonexistent/path/xyz"), "python")
            .expect_err("nonexistent path should fail");
        assert!(err.to_string().contains("does not exist"));
    }
}
```

Run: `cargo test -p mcp-sec-audit-core codeql::queries` — expected PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/xiao/Project/mcp-sec-audit && git add rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/queries.rs rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/
git commit -m "feat(codeql): per-language query packs (mcp-python/mcp-js/mcp-rust)"
```

---

### Task 6: `provider.rs` — drop the Python-only skip

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/provider.rs:132-143`

**Interfaces:**
- Consumes: `QueryPack.query_files` and `QueryPack.suite_refs` (already language-native).
- Produces: every DB runs its language's `.ql` files + standard suite, no skip hack.

- [ ] **Step 1: Replace the query-selection block**

In `run_analysis`, replace:

```rust
        // Add query files. Built-in MCP queries are Python-only, so skip them
        // for non-Python databases to avoid `import python` failures.
        if !queries.is_builtin || db.language == "python" {
            for qf in &queries.query_files {
                cmd.arg(qf);
            }
        }

        // Add suite references filtered to this database's language.
        for suite in queries.suite_refs_for(&db.language) {
            cmd.arg(suite);
        }
```

with:

```rust
        // Query files are already language-native (per-language pack).
        for qf in &queries.query_files {
            cmd.arg(qf);
        }

        // Standard suite refs are already scoped to this database's language.
        for suite in &queries.suite_refs {
            cmd.arg(suite);
        }
```

- [ ] **Step 2: Run tests**

```bash
cd /home/xiao/Project/mcp-sec-audit/rust && cargo test -p mcp-sec-audit-core codeql
```

Expected: PASS (the provider unit test uses a missing-CLI binary and is
unaffected).

- [ ] **Step 3: Commit**

```bash
cd /home/xiao/Project/mcp-sec-audit && git add rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/provider.rs
git commit -m "feat(codeql): run language-native queries for every DB, drop python-only skip"
```

---

### Task 7: `mod.rs` — add Rust, fix `target_root`, resolve pack per language

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs`

**Interfaces:**
- Consumes: `resolve_query_pack(custom, language)` (Task 5).
- Produces: Rust targets run CodeQL; per-language pack resolution; robust source root.

- [ ] **Step 1: Add Rust to the supported set and fix the comment**

```rust
/// Languages CodeQL supports — Rust is supported as of CodeQL 2.26.x.
const SUPPORTED_LANGUAGES: &[&str] = &["python", "javascript", "typescript", "rust"];
```

- [ ] **Step 2: Update the "no supported language" diagnostic text**

Change the two occurrences of "No Python/JS/TS files" to "No CodeQL-supported
language files" (the progress string and the diagnostic push).

- [ ] **Step 3: Derive `target_root` from scan targets**

Replace the current `target_root` block (from `// Determine source root from the
first file.` through the `.unwrap_or_else(|| ".".to_string());`) with:

```rust
    // Determine source root from the configured scan targets (a directory target
    // is used as-is; a file target contributes its parent directory).
    let target_root = ctx
        .config
        .scan
        .targets
        .first()
        .map(|t| {
            let p = std::path::Path::new(t);
            if p.is_dir() {
                p.display().to_string()
            } else {
                p.parent()
                    .map(|d| d.display().to_string())
                    .unwrap_or_else(|| ".".to_string())
            }
        })
        .unwrap_or_else(|| ".".to_string());
```

- [ ] **Step 4: Resolve the query pack inside the language loop**

Delete the standalone `let query_pack = resolve_query_pack(...)?;` line before
the loop, and add at the top of the loop body (after `for language in &languages {`):

```rust
        let query_pack = resolve_query_pack(codeql_config.query_pack_path.as_deref(), language)?;
```

- [ ] **Step 5: Update the two affected tests**

`enabled_with_no_files_returns_empty_with_diagnostic` — change the assertion:

```rust
        assert!(output.diagnostics[0].contains("No CodeQL-supported language"));
```

`unsupported_language_emits_skip_progress` — Rust is now supported, so switch the
fixture to `ScanLanguage::Json`:

```rust
            discovered_files: vec![DiscoveredFile {
                path: "data.json".into(),
                language: ScanLanguage::Json,
            }],
```

- [ ] **Step 6: Run tests**

```bash
cd /home/xiao/Project/mcp-sec-audit/rust && cargo test -p mcp-sec-audit-core codeql
```

Expected: PASS (all three `mod.rs` tests updated).

- [ ] **Step 7: Commit**

```bash
cd /home/xiao/Project/mcp-sec-audit && git add rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs
git commit -m "feat(codeql): enable Rust, derive target_root from scan targets, per-language pack resolution"
```

---

### Task 8: Rust QL API spike — produce the reference doc

**Files:**
- Create: `rust/docs/rust-ql-api-notes.md`

**Interfaces:**
- Produces: `rust/docs/rust-ql-api-notes.md` — the exact Rust CodeQL predicates
  (function attribute name, parameter node, call callee, TaintTracking config)
  that the follow-up Rust-query plan consumes.

- [ ] **Step 1: Locate the Rust standard library + example queries**

```bash
find ~/.codeql/packages -type d -name 'rust-all' -o -type d -name 'rust-queries'
find ~/.codeql/packages -name '*.qll' -path '*rust*' | head -50
```

- [ ] **Step 2: Read the example SQL-injection query**

```bash
find ~/.codeql/packages -path '*rust*' -name '*.ql' | xargs grep -l 'sql-injection\|SqlInjection' 2>/dev/null | head
```

Open the example (`rust/examples/simple-sql-injection.ql`) and record its exact
`import` lines and source/sink predicates.

- [ ] **Step 3: Inspect the function/attribute and dataflow library**

```bash
grep -rn 'class Function\|getAnAttribute\|class Attribute\|class CallExpr\|getFunctionName\|parameterNode' ~/.codeql/packages/*/rust-all*/ 2>/dev/null | head -40
```

- [ ] **Step 4: Write `rust/docs/rust-ql-api-notes.md`**

Record, with exact predicate signatures and a minimal working example:

1. The `import` line(s) for the Rust dataflow/taint library.
2. How to identify a function's attribute name (`#[tool]`, `#[tool_router]`).
3. How to get a function's parameter nodes.
4. How to identify a call expression and its callee/path name
   (`std::process::Command::new`, `std::fs::write`, `serde_json::from_str`).
5. The `DataFlow`/`TaintTracking` config shape (whether `semmle.rust.dataflow`
   uses `ConfigSig`/`Global` like Python, or a different API).

Use the table format from the spec §5.1 as the "target predicates to find". If a
predicate is missing (library is too young), record the closest alternative and
flag it.

- [ ] **Step 5: Commit**

```bash
cd /home/xiao/Project/mcp-sec-audit && git add rust/docs/rust-ql-api-notes.md
git commit -m "docs(codeql): Rust QL API reference from spike"
```

---

### Task 9: Regression — full `cargo test` green

**Files:**
- No new files; verify only.

- [ ] **Step 1: Run the full suite**

```bash
cd /home/xiao/Project/mcp-sec-audit/rust && cargo test
```

Expected: PASS (all crates). If any test outside `codeql`/`fusion` broke (e.g. a
report or pipeline test that constructs `CodeqlAnalysisResult`), fix the
constructor to include the new fields.

- [ ] **Step 2: Run a real end-to-end Rust scan if CodeQL is on PATH**

```bash
cd /home/xiao/Project/mcp-sec-audit/rust && cargo run -p mcp-sec-audit-core --bin mcp-sec-audit 2>/dev/null || echo "see README for the CLI entrypoint"
```

If a CLI entrypoint exists, scan `test-targets/rust-mcp-server` and confirm the
CodeQL line no longer emits "skipped: no supported language" and instead runs
(the official `rust-queries` pack produces SARIF).

- [ ] **Step 3: Commit any fixes**

Only if Step 1 surfaced constructor fixes; otherwise no commit.

---

## Self-Review Notes

- **Spec coverage:** §4 (per-language packs) → Task 5/6/7; §5.1 Rust source
  model + spike → Task 8; §7 (category alignment + fusion + target_root) → Task
  2/3/4/7; §6 vocabulary → Task 4; §9 M0 → Task 1. The query matrix (spec §6
  table) and Python strengthen (M1) are **not** in this plan — they are the
  follow-up plan (see Scope note).
- **Placeholders:** none — every code step carries exact code.
- **Type consistency:** `resolve_query_pack(custom, language)`,
  `QueryPack::for_language`, `resolve_category(rule_id, rule)` are the single
  canonical names used across tasks.
