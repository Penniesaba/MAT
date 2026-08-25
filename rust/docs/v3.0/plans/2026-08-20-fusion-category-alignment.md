# Fusion Category Alignment + CodeQL Diagnostics Surfacing (R1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the rule/taint/codeql lines corroborate across their differing category vocabularies, and stop silently dropping CodeQL `diagnostics` / `raw_sarif`.

**Architecture:** A single shared category vocabulary module normalizes every line's raw category string to one canonical form before the fusion matcher compares and the merger votes. The pipeline surfaces CodeQL `diagnostics` and `raw_sarif` into `StaticAnalysisResult`, logs each diagnostic, and renders them in the markdown/JSONL reports.

**Tech Stack:** Rust, `serde`, `tracing` (already wired in R0).

**Spec:** `docs/ARCHITECTURE_REDESIGN.md` §5.6 融合与置信度分级 + §8 里程碑 **R1**:
> 融合前置修复:basename 归一化 + 类别对齐 + CodeQL diagnostics 透明;交付判据:`rule+taint+codeql` 能交叉印证;`0` 结果不再静默.

## Global Constraints

- Rust edition 2024, `rust-version = 1.88`.
- `cargo test` must stay green (currently 189 core + 4 CLI tests) after every task.
- Category vocabulary is a single source of truth (`static_analysis/category.rs`); no line may keep a private duplicate list.
- Serde additions use `#[serde(default)]` / `skip_serializing_if` so old JSON stays deserializable.
- basename 归一化 is **already done** (commit `2de34d9`, `file_key()` in `matcher.rs`); this plan only adds the missing codeql-path test coverage and does not re-implement it.

---

### Task 1: Shared category vocabulary module

**Files:**
- Create: `crates/mcp-sec-audit-core/src/static_analysis/category.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/mod.rs`

**Interfaces:**
- Produces (used by Task 2 and Task 3):
  - `pub(crate) fn normalize_category(raw: &str) -> String`
  - `pub(crate) fn is_known_category(raw: &str) -> bool`
  - `pub(crate) const CANONICAL_CATEGORIES: &[&str]`

- [ ] **Step 1: Write the failing test** — append to the new `category.rs`:

```rust
//! Canonical vulnerability-category vocabulary shared across the rule, taint,
//! and CodeQL analysis lines.
//!
//! Each line reports categories in its own vocabulary (rulebook names, sink
//! `category` fields, CodeQL `rule_id` maps). Fusion compares categories by
//! exact string, so a `command_exec` rule finding and a `command_execution`
//! taint finding would never corroborate. [`normalize_category`] collapses
//! that drift to one shared vocabulary before any comparison or vote.

/// The canonical category set (snake_case), the union of all line vocabularies.
pub(crate) const CANONICAL_CATEGORIES: &[&str] = &[
    "command_execution",
    "dynamic_execution",
    "database_injection",
    "file_read",
    "file_write",
    "file_delete",
    "network_request",
    "deserialization",
    "template_injection",
    "path_traversal",
    "prompt_injection",
    "data_exfiltration",
    "tool_poisoning",
    "unsafe_block",
    "env_access",
    "xml_parsing",
    "xpath_injection",
];

/// Resolve a normalized category to its canonical form if it is a known
/// synonym of one. Returns `None` for already-canonical or unknown categories
/// so free-form names are preserved rather than collapsed.
fn alias_map(normalized: &str) -> Option<&'static str> {
    Some(match normalized {
        "command_exec" | "cmd_inj" | "cmd_injection" | "command_injection" | "shell_exec"
        | "shell_injection" => "command_execution",
        "code_injection" | "dynamic_import" | "dynamic_loading" | "eval" => "dynamic_execution",
        "sql_injection" | "sqli" => "database_injection",
        "ssrf" => "network_request",
        "path_injection" => "path_traversal",
        "deserialization_rce" => "deserialization",
        _ => return None,
    })
}

/// Normalize a raw category to the shared vocabulary: trim, lowercase, fold
/// `-`/spaces to `_`, then resolve known synonyms. Unknown categories are
/// returned as-is (normalized) so identical free-form names still match.
pub(crate) fn normalize_category(raw: &str) -> String {
    let normalized: String = raw.trim().to_lowercase().replace(['-', ' '], "_");
    alias_map(&normalized)
        .map(str::to_string)
        .unwrap_or(normalized)
}

/// Whether `raw` normalizes to a member of [`CANONICAL_CATEGORIES`].
pub(crate) fn is_known_category(raw: &str) -> bool {
    let normalized = normalize_category(raw);
    CANONICAL_CATEGORIES.contains(&normalized.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_maps_aliases_to_canonical() {
        assert_eq!(normalize_category("command_exec"), "command_execution");
        assert_eq!(normalize_category("cmd_inj"), "command_execution");
        assert_eq!(normalize_category("command-injection"), "command_execution");
        assert_eq!(normalize_category("sql_injection"), "database_injection");
        assert_eq!(normalize_category("ssrf"), "network_request");
        assert_eq!(normalize_category("path_injection"), "path_traversal");
        assert_eq!(normalize_category("deserialization_rce"), "deserialization");
        assert_eq!(normalize_category("code_injection"), "dynamic_execution");
        assert_eq!(normalize_category("dynamic_import"), "dynamic_execution");
    }

    #[test]
    fn normalize_preserves_unknown_and_canonical() {
        assert_eq!(normalize_category("command_execution"), "command_execution");
        assert_eq!(normalize_category("file_read"), "file_read");
        // Unknown free-form names survive (not collapsed to "uncategorized").
        assert_eq!(normalize_category("MyCustom Rule"), "mycustom_rule");
    }

    #[test]
    fn known_category_detection() {
        assert!(is_known_category("command_exec")); // alias of canonical
        assert!(is_known_category("file_write"));
        assert!(!is_known_category("bogus_category"));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails to compile**

Run: `cargo test -p mcp-sec-audit-core category`
Expected: FAIL — `category` module does not exist / `mod` missing.

- [ ] **Step 3: Declare the module** — in `static_analysis/mod.rs`, add `pub(crate) mod category;` among the existing `mod` declarations (after `mod agent;`).

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p mcp-sec-audit-core category::tests`
Expected: PASS — 3 tests green.

- [ ] **Step 5: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/category.rs crates/mcp-sec-audit-core/src/static_analysis/mod.rs
git commit -m "feat(fusion): add shared canonical category vocabulary"
```

---

### Task 2: Use normalization in matcher + merger

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/fusion/matcher.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/fusion/merger.rs`

**Interfaces:**
- Consumes: `crate::static_analysis::category::normalize_category` (Task 1).
- Produces: unchanged public signatures (`match_results`, `merge_groups`); only comparison/vote semantics change.

- [ ] **Step 1: Write the failing tests**

In `matcher.rs` tests, add:

```rust
#[test]
fn stage2_category_matches_across_vocabularies() {
    // rule uses "command_exec", taint uses "command_execution" — must fuse.
    let rules = vec![make_rule("r1", "a.py", 10, "command_exec", Confidence::High)];
    let taints = vec![make_taint("t1", "sink:command_execution:a.py:0", "command_execution", Confidence::Medium)];
    let groups = match_results(rules, taints, vec![], vec![], 1);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].line_count(), 2);
}

#[test]
fn codeql_relative_path_matches_rule_full_path_via_basename() {
    let rules = vec![make_rule("r1", "/proj/src/main.py", 42, "command_execution", Confidence::High)];
    let codeql = vec![make_codeql("c1", "src/main.py", 41, "py/cmd-injection", Severity::High)];
    let groups = match_results(rules, vec![], vec![], codeql, 5);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].supported_by(), vec!["rule", "codeql"]);
}
```

In `merger.rs` tests, add (uses the `MatchGroup` import already present in that test module):

```rust
#[test]
fn build_category_votes_canonical_across_vocabularies() {
    use crate::model::{Confidence, TaintAnalysisResult};
    let group = MatchGroup {
        rule_results: vec![RuleAnalysisResult {
            result_id: "r1".into(), rule_id: "command_exec".into(),
            category: "command_exec".into(), owasp_mcp: None, file: "a.py".into(),
            line: 1, matched_text: None, evidence: vec![],
            severity: Severity::High, confidence: Confidence::High,
            recommendation: None, related_facts_exist: false,
        }],
        taint_results: vec![TaintAnalysisResult {
            result_id: "t1".into(), source_id: "s:x".into(), source_kind: "p".into(),
            entrypoint_id: None, sink_id: "sink:command_execution:a.py:0".into(),
            sink_kind: "command_execution".into(), call_chain: vec![],
            dataflow_path: vec![], evidence: vec![], taint_confidence: Confidence::Medium,
            entrypoint_is_mcp: false, backward_trace_found_root: false,
        }],
        agent_results: vec![],
        codeql_results: vec![],
    };
    assert_eq!(build_category(&group), "command_execution");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p mcp-sec-audit-core fusion`
Expected: FAIL — `stage2_category_matches_across_vocabularies` (2 solo groups), `build_category_votes_canonical_across_vocabularies` (votes two distinct strings → "command_exec").

- [ ] **Step 3: Normalize in `matcher.rs`**

Add `use crate::static_analysis::category::normalize_category;` to the top `use` block. Replace `can_join_group_category`:

```rust
fn can_join_group_category(candidate_idx: usize, group: &[usize], items: &[Matchable]) -> bool {
    let candidate = &items[candidate_idx];
    candidate.category.is_some()
        && group.iter().any(|&member_idx| {
            let member = &items[member_idx];
            file_key(&member.file) == file_key(&candidate.file)
                && member.category.as_deref().map(normalize_category)
                    == candidate.category.as_deref().map(normalize_category)
        })
}
```

- [ ] **Step 4: Normalize in `merger.rs`**

Add `use crate::static_analysis::category::normalize_category;` and replace `build_category`:

```rust
fn build_category(group: &super::matcher::MatchGroup) -> String {
    use std::collections::HashMap;
    let mut counts: HashMap<String, u32> = HashMap::new();
    for r in &group.rule_results {
        *counts.entry(normalize_category(&r.category)).or_insert(0) += 1;
    }
    for t in &group.taint_results {
        *counts.entry(normalize_category(&t.sink_kind)).or_insert(0) += 1;
    }
    for c in &group.codeql_results {
        *counts.entry(normalize_category(&c.category)).or_insert(0) += 1;
    }
    counts.into_iter()
        .max_by_key(|(cat, count)| (*count, cat.len()))
        .map(|(cat, _)| cat)
        .unwrap_or_else(|| "unknown".to_string())
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core fusion`
Expected: PASS — all matcher + merger + scorer tests green, including the 3 new ones.

- [ ] **Step 6: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/fusion/matcher.rs crates/mcp-sec-audit-core/src/static_analysis/fusion/merger.rs
git commit -m "fix(fusion): align categories across rule/taint/codeql vocabularies"
```

---

### Task 3: Refactor CodeQL parser onto the shared vocabulary

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/parser.rs`

**Interfaces:**
- Consumes: `crate::static_analysis::category::{is_known_category, normalize_category}` (Task 1).
- Produces: `resolve_category(rule_id, rule)` unchanged signature.

- [ ] **Step 1: Swap the tag-scanning to the shared vocabulary**

Delete the local `const KNOWN_CATEGORIES: &[&str] = &[...]` block (currently lines 12–28). Add after the existing `use` line:

```rust
use crate::static_analysis::category::{is_known_category, normalize_category};
```

Replace the `category_from_tags` return expression `KNOWN_CATEGORIES.contains(&n.as_str()).then(|| n)` with:

```rust
is_known_category(&n).then(|| normalize_category(&n))
```

Keep `category_from_rule_id` and `resolve_category` unchanged (their literal outputs are already canonical).

- [ ] **Step 2: Run parser tests**

Run: `cargo test -p mcp-sec-audit-core codeql::parser`
Expected: PASS — `extracts_category_from_tags_and_rule_id_map` and all other parser tests stay green (tags like `"command-execution"` still normalize to `"command_execution"`; `rust/sql-injection` etc. still map via `category_from_rule_id`).

- [ ] **Step 3: Add an alias-tag test**

Append to the existing `extracts_category_from_tags_and_rule_id_map` test (or add a new one):

```rust
#[test]
fn tags_use_shared_alias_normalization() {
    // A tag using a rule-style alias must normalize to the canonical category.
    assert_eq!(
        resolve_category("mcp/python/command-exec", Some(&serde_json::json!({
            "properties": { "tags": ["mcp", "command_exec"] }
        }))),
        "command_execution"
    );
}
```

- [ ] **Step 4: Run the full core suite**

Run: `cargo test -p mcp-sec-audit-core`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/codeql/parser.rs
git commit -m "refactor(codeql): reuse shared category vocabulary in SARIF parser"
```

---

### Task 4: Surface CodeQL diagnostics + raw_sarif in the result

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/model/static_result.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`
- Modify: `crates/mcp-sec-audit-core/src/fixtures.rs`

**Interfaces:**
- Produces (new fields on `StaticAnalysisResult`):
  - `pub codeql_diagnostics: Vec<String>` (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`)
  - `pub codeql_raw_sarif: Option<String>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`)

- [ ] **Step 1: Write the failing test**

In `pipeline.rs` tests, add:

```rust
#[test]
fn codeql_skip_diagnostic_is_surfaced_in_result() {
    let root = temp_dir("codeql-skip-diag");
    let rules = write_rulebook(&root, "rules.toml", "command_exec");
    fs::write(root.join("data.json"), "{}").expect("write json");
    let mut config = RuntimeConfig::default();
    config.static_.codeql.enabled = true;
    let result = run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");
    assert!(result
        .codeql_diagnostics
        .iter()
        .any(|d| d.contains("No CodeQL-supported language")));
    fs::remove_dir_all(root).expect("cleanup");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mcp-sec-audit-core codeql_skip_diagnostic_is_surfaced_in_result`
Expected: FAIL — `StaticAnalysisResult` has no `codeql_diagnostics` field.

- [ ] **Step 3: Add the fields to `StaticAnalysisResult`**

In `static_result.rs`, after the `pub codeql_results: Vec<CodeqlAnalysisResult>,` field, add:

```rust
    /// Diagnostics emitted by the CodeQL line (skip reasons, create/analyze
    /// failures, SARIF parse errors). Surfaced so "0 results" is never silent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codeql_diagnostics: Vec<String>,
    /// Raw concatenated SARIF produced by CodeQL, preserved for debugging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codeql_raw_sarif: Option<String>,
```

- [ ] **Step 4: Populate in `pipeline.rs`**

Inside the `codeql_output` block, after the existing `tracing::info!(...)` and `progress(...)` lines but before `output` is returned, add a per-diagnostic warn loop:

```rust
        for diag in &output.diagnostics {
            tracing::warn!(target: "mcp_sec_audit::codeql", "{diag}");
        }
```

In the final `Ok(StaticAnalysisResult { ... })` literal, change `codeql_results: codeql_output.results,` to move the remaining fields too:

```rust
        codeql_results: codeql_output.results,
        codeql_diagnostics: codeql_output.diagnostics,
        codeql_raw_sarif: codeql_output.raw_sarif,
```

In `empty_result`, add the two fields after `codeql_results: Vec::new(),`:

```rust
        codeql_diagnostics: Vec::new(),
        codeql_raw_sarif: None,
```

- [ ] **Step 5: Update `fixtures.rs`**

In `synthetic_static_analysis_result`, after `codeql_results: vec![synthetic_codeql_analysis_result()],` add:

```rust
        codeql_diagnostics: vec!["Synthetic CodeQL diagnostic".to_string()],
        codeql_raw_sarif: None,
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p mcp-sec-audit-core`
Expected: PASS — including the new surfacing test and the existing roundtrip test `static_analysis_result_roundtrips_json`.

- [ ] **Step 7: Commit**

```bash
git add crates/mcp-sec-audit-core/src/model/static_result.rs crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs crates/mcp-sec-audit-core/src/fixtures.rs
git commit -m "feat(codeql): surface diagnostics and raw SARIF in scan result"
```

---

### Task 5: Render CodeQL diagnostics in reports

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/reporting.rs`

**Interfaces:**
- Consumes: `StaticAnalysisResult.codeql_diagnostics` (Task 4).
- Produces: markdown `## CodeQL Diagnostics` section + JSONL `codeql_diagnostic` events.

- [ ] **Step 1: Write the failing tests**

Add to `reporting.rs` tests:

```rust
#[test]
fn markdown_renders_codeql_diagnostics_when_present() {
    let result = crate::fixtures::synthetic_static_analysis_result();
    let markdown = render_markdown(&result, &MarkdownRenderOptions::default());
    assert!(markdown.contains("## CodeQL Diagnostics"));
    assert!(markdown.contains("- Synthetic CodeQL diagnostic"));
}
```

Update `jsonl_renderer_emits_expected_events` to expect the new trailing event:

```rust
assert_eq!(lines.len(), 8);
// ... existing lines[0..=6] assertions unchanged ...
assert!(lines[7].contains(r#""event":"codeql_diagnostic""#));
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p mcp-sec-audit-core reporting`
Expected: FAIL — markdown lacks the section; JSONL has 7 lines not 8.

- [ ] **Step 3: Render markdown diagnostics**

In `render_markdown`, immediately after the summary header lines block (after the `format!("- CodeQL Results: {}", ...)` line) and before `if options.include_facts`, add:

```rust
    if !result.codeql_diagnostics.is_empty() {
        lines.push(String::new());
        lines.push("## CodeQL Diagnostics".to_string());
        for diag in &result.codeql_diagnostics {
            lines.push(format!("- {diag}"));
        }
    }
```

- [ ] **Step 4: Emit JSONL diagnostic events**

In `render_jsonl`, after the `include_raw_codeql_results` loop (the last event-emitting block), add:

```rust
    for diag in &result.codeql_diagnostics {
        lines.push(serde_json::to_string(&JsonlRecord {
            event: "codeql_diagnostic",
            data: diag,
        })?);
    }
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p mcp-sec-audit-core reporting`
Expected: PASS — the two new/changed tests and all existing reporting tests green.

- [ ] **Step 6: Commit**

```bash
git add crates/mcp-sec-audit-core/src/reporting.rs
git commit -m "feat(report): render CodeQL diagnostics in markdown and JSONL"
```

---

## Final Verification

- [ ] Run the full workspace suite:

```bash
cargo test
```

Expected: all green (core + CLI).

- [ ] Run the CLI smoke test to confirm diagnostics reach the terminal (warn-level logs) and the report file:

```bash
cargo run -p mcp-sec-audit-cli -- <a config whose target is a JSON-only dir with codeql enabled>
```

Expected: terminal shows a `WARN mcp_sec_audit::codeql` line with the skip reason; the markdown report contains a `## CodeQL Diagnostics` section.
