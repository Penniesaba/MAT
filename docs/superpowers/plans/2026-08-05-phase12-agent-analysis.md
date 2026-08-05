# Phase 12: Agent Analysis Line + Three-Line Decoupling — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the Agent analysis line (CLI-based) and restructure the static analysis module into three independent, equal peer directories.

**Architecture:** Three lines (rule, taint, agent) become independent peer directories under `static_analysis/`, each with a single `pub fn run()` entry point. Fact extraction moves inside the taint line. Agent line uses CLI subprocess to invoke external agent tools with a security audit prompt template.

**Tech Stack:** Rust, `std::process::Command`, serde/serde_json, anyhow, no new external dependencies.

## Global Constraints

- Three lines are fully independent — no cross-line imports allowed
- Each line directory has exactly one `pub fn run()` entry point
- Fact extraction (`extract_static_facts`) is called ONLY from `taint::run()`, never from pipeline
- All 97 existing tests must keep passing after each task
- `lines.rs` is deleted — dispatcher logic moves into each line's `mod.rs`
- `rule.rs` → `rule/mod.rs` — content preserved, adds `pub fn run()` wrapper
- `StaticAgentConfig` removes: `mode`, `prompt_profile`, `max_files`, `include_low_confidence` (become hardcoded constants in agent module)
- `StaticAgentConfig` adds: `prompt_template_path: Option<String>`, `max_turns: u32` (default 30), `timeout_seconds: u64` (default 600), `extra_args: Vec<String>`
- `AgentAnalysisResult.related_rule_result_ids` and `related_taint_result_ids` are always empty vec (Phase 13 fills them)
- `AgentAnalysisResult.verification_status` is always `"uncorroborated"` from agent line (Phase 13 updates it)
- Built-in prompt template is embedded as a Rust constant string in `agent/prompt.rs`
- No new external crate dependencies — all agent CLI interaction uses `std::process::Command`
- Production-grade: no empty implementations, no silent returns, clear errors

---

### Task 1: Config cleanup — StaticAgentConfig field changes

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/config.rs`
- Modify: `rust/config/default.toml`

**Interfaces:**
- Consumes: nothing
- Produces: new `StaticAgentConfig` shape with 6 fields; updated default functions

**Purpose:** Remove config fields that should be hardcoded program constants (`mode`, `prompt_profile`, `max_files`, `include_low_confidence`). Add fields needed for CLI agent control (`prompt_template_path`, `max_turns`, `timeout_seconds`, `extra_args`).

- [ ] **Step 1: Update StaticAgentConfig struct**

Replace the struct definition at `config.rs:68-82`:

```rust
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
```

- [ ] **Step 2: Update Default impl for StaticAgentConfig**

Replace at `config.rs:180-191`:

```rust
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
```

- [ ] **Step 3: Remove old default functions, add new ones**

Remove `default_agent_mode()` (line 279-281), `default_prompt_profile()` (line 287-289), `default_max_files()` (line 291-293).

Keep `default_agent_provider()` (line 283-285, returns `"claude"`).

Add:

```rust
fn default_agent_max_turns() -> u32 {
    30
}

fn default_agent_timeout() -> u64 {
    600
}
```

- [ ] **Step 4: Update config test that references agent.mode**

At `config.rs:331-346`, update the test `runtime_config_from_toml_overrides_defaults`:

Remove line 333 `mode = "source_only"` from the test TOML string.
Remove line 346 `assert_eq!(config.static_.agent.mode, "source_only");`.

Replace with assertions for new fields if desired, or simply remove:

```rust
[static.agent]
enabled = true
```

And assertion line 346 becomes:

```rust
assert!(config.static_.agent.enabled);
assert_eq!(config.static_.agent.provider, "claude");
```

- [ ] **Step 5: Update default.toml**

Replace `rust/config/default.toml:22-28`:

Current:
```toml
[static.agent]
enabled = false
mode = "evidence_aware"
provider = "claude"
prompt_profile = "mcp_security_audit"
max_files = 80
include_low_confidence = false
```

New:
```toml
[static.agent]
enabled = false
provider = "claude"
# prompt_template_path = "/path/to/custom-prompt.md"  # optional
max_turns = 30
timeout_seconds = 600
extra_args = []
```

- [ ] **Step 6: Run tests to verify**

```bash
cargo test -p mcp-sec-audit-core
```
Expected: 97 tests pass. Config tests (`runtime_config_from_toml_overrides_defaults`, `runtime_config_defaults_are_stable`) updated.

- [ ] **Step 7: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/config.rs rust/config/default.toml
git commit -m "refactor(config): simplify StaticAgentConfig fields for agent line

Remove mode/prompt_profile/max_files/include_low_confidence (become
hardcoded constants in agent module). Add prompt_template_path,
max_turns, timeout_seconds, extra_args for CLI agent control.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 2: Move rule.rs → rule/mod.rs with run() wrapper

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/rule/mod.rs`
- Delete: `rust/crates/mcp-sec-audit-core/src/static_analysis/rule.rs`

**Interfaces:**
- Consumes: `StaticScanContext`, `RuleBook` (existing types)
- Produces: `pub fn run(ctx: &StaticScanContext, rulebook: Option<&RuleBook>) -> Result<Vec<RuleAnalysisResult>>`
- Existing `analyze_rule_line()` stays as private function

**Purpose:** Move the single-file rule module into a directory, add the `run()` entry wrapper that handles enabled check and rulebook validation. This matches the taint and agent directory structure.

- [ ] **Step 1: Create rule/ directory**

```bash
mkdir -p rust/crates/mcp-sec-audit-core/src/static_analysis/rule
```

- [ ] **Step 2: Move and rename rule.rs → rule/mod.rs**

```bash
cp rust/crates/mcp-sec-audit-core/src/static_analysis/rule.rs \
   rust/crates/mcp-sec-audit-core/src/static_analysis/rule/mod.rs
```

- [ ] **Step 3: Edit rule/mod.rs — add run() wrapper, make analyze_rule_line private**

In `rule/mod.rs`, add `use anyhow::bail;` to the imports.

Change `pub fn analyze_rule_line` to `fn analyze_rule_line` (remove `pub`).

Add the `pub fn run()` entry point before `analyze_rule_line`:

```rust
use anyhow::{Context, Result, bail};

// ... existing imports ...

/// Rule line entry point. Handles config gating and rulebook validation,
/// then delegates to the internal regex-based analyzer.
pub fn run(
    ctx: &StaticScanContext,
    rulebook: Option<&RuleBook>,
) -> Result<Vec<RuleAnalysisResult>> {
    if !ctx.config.static_.rule.enabled {
        return Ok(Vec::new());
    }

    let Some(rulebook) = rulebook else {
        bail!("rule analysis line is enabled but no rulebook was loaded");
    };

    if rulebook.is_empty() {
        bail!("rule analysis line is enabled but rulebook is empty");
    }

    analyze_rule_line(ctx, rulebook)
}

// existing analyze_rule_line (now private) ...
fn analyze_rule_line(
    ctx: &StaticScanContext,
    rulebook: &RuleBook,
) -> Result<Vec<RuleAnalysisResult>> {
    // ... existing implementation unchanged ...
```

- [ ] **Step 4: Delete old rule.rs**

```bash
rm rust/crates/mcp-sec-audit-core/src/static_analysis/rule.rs
```

- [ ] **Step 5: Run tests**

```bash
cargo test -p mcp-sec-audit-core
```
Expected: 97 tests pass. Rule line behavior unchanged.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/rule/
git rm rust/crates/mcp-sec-audit-core/src/static_analysis/rule.rs
git commit -m "refactor(rule): move rule.rs to rule/mod.rs with run() entry

Mirrors taint/ and agent/ directory structure. analyze_rule_line becomes
private; pub fn run() handles enabled check and rulebook validation.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 3: Update taint/mod.rs — add run() wrapper with fact extraction

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/mod.rs`

**Interfaces:**
- Consumes: `StaticScanContext`, `extract_static_facts` from `super::facts`
- Produces: `pub fn run(ctx: &StaticScanContext) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)>`
- Existing `run_taint_analysis()` stays public (used by tests, called internally by `run()`)

**Purpose:** `taint::run()` becomes the single entry point. It internally calls `extract_static_facts` then `run_taint_analysis`, and returns all facts (extracted + dataflow). Pipeline no longer calls fact extraction separately.

- [ ] **Step 1: Add run() function to taint/mod.rs**

Insert after the module declarations (line 4) and before `run_taint_analysis` (line 10):

```rust
use super::facts::extract_static_facts;
use super::pipeline::StaticScanContext;

/// Taint line entry point. Extracts facts from source files,
/// builds program graph, runs BFS propagation, returns results + all facts.
pub fn run(ctx: &StaticScanContext) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)> {
    if !ctx.config.static_.taint.enabled {
        return Ok((Vec::new(), Vec::new()));
    }

    let facts = extract_static_facts(ctx)?;
    let (results, dataflow_facts) =
        run_taint_analysis(&facts, &ctx.config.static_.taint)?;

    let mut all_facts = facts;
    all_facts.extend(dataflow_facts);

    Ok((results, all_facts))
}
```

- [ ] **Step 2: Add test for taint::run() with disabled config**

Add to the tests module at the bottom of the file, after existing tests:

```rust
#[test]
fn run_disabled_taint_returns_empty() {
    use crate::RuntimeConfig;
    use crate::static_analysis::DiscoveredFile;

    let ctx = StaticScanContext {
        config: RuntimeConfig::default(),  // taint disabled by default
        rulebook_paths: Vec::new(),
        discovered_files: Vec::new(),
    };

    let (results, facts) = run(&ctx).expect("run disabled taint");
    assert!(results.is_empty());
    assert!(facts.is_empty());
}
```

- [ ] **Step 3: Run all tests**

```bash
cargo test -p mcp-sec-audit-core
```
Expected: 98 tests pass (existing 97 + 1 new).

- [ ] **Step 4: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/taint/mod.rs
git commit -m "refactor(taint): add run() entry point with internal fact extraction

taint::run(ctx) now extracts facts internally, removing the need for
pipeline to call extract_static_facts as a separate step. Existing
run_taint_analysis() stays public for tests.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: Remove lines.rs, update mod.rs, update pipeline.rs

**Files:**
- Delete: `rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`

**Interfaces:**
- Consumes: `rule::run`, `taint::run`, `agent::run` (new entry points from Tasks 2, 3, 8)
- Produces: Clean pipeline.rs with direct line imports, no `extract_static_facts` call

**Purpose:** Wire the three independent lines together in pipeline. Remove the old `lines.rs` dispatcher layer. Each line is now called directly. Fact extraction is handled internally by taint line.

- [ ] **Step 1: Update mod.rs — remove lines, update imports**

Replace `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`:

```rust
pub mod facts;

mod agent;
mod discovery;
mod pipeline;
mod rule;
mod taint;

pub use discovery::{
    DiscoveredFile, DiscoverySummary, ScanLanguage, detect_language, discover_files,
};
pub use facts::{
    ExtractionDiagnostic, JsTsExtractionResult, JsTsDiagnostic, PythonExtractionResult,
    RustExtractionResult, extract_js_ts_facts, extract_python_facts, extract_rust_facts,
    extract_static_facts,
};
pub use pipeline::{StaticScanContext, run_static_scan};
```

Changes:
- Remove `mod lines;`
- Add `mod agent;`
- Add `mod rule;` (was implicit via `rule.rs`, now explicit for `rule/mod.rs`)

- [ ] **Step 2: Update pipeline.rs imports and call sites**

Current imports (lines 1-14):
```rust
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use crate::{
    ConfigSnapshot, RuleBook, RuntimeConfig, StaticAnalysisResult, StaticAnalysisSummary,
    load_rulebook,
};

use super::{DiscoveredFile, discover_files, extract_static_facts, lines};
```

Change to:
```rust
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use crate::{
    ConfigSnapshot, RuleBook, RuntimeConfig, StaticAnalysisResult, StaticAnalysisSummary,
    load_rulebook,
};

use super::{agent, discovery, rule, taint, DiscoveredFile, discover_files};
```

Current pipeline body (lines 76-82):
```rust
let facts = extract_static_facts(&ctx)?;
let rule_results = lines::run_rule_line(&ctx, loaded_rulebook.as_ref())?;
let (taint_results, dataflow_facts) = lines::run_taint_line(&ctx, &facts)?;
let agent_results = lines::run_agent_line(&ctx)?;

let mut all_facts = facts;
all_facts.extend(dataflow_facts);
```

Change to:
```rust
let rule_results = rule::run(&ctx, loaded_rulebook.as_ref())?;
let (taint_results, all_facts) = taint::run(&ctx)?;
let agent_results = agent::run(&ctx)?;
```

- [ ] **Step 3: Delete lines.rs**

```bash
rm rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs
```

- [ ] **Step 4: Update pipeline tests if needed**

The existing pipeline tests create source files on disk (e.g., `server.py` with `@mcp.tool()` decorator). Since `taint::run()` now internally calls `extract_static_facts`, those tests should still work — the taint line extracts facts from the same source files.

Because taint is DISABLED by default and facts now come from `taint::run()` internally, pipeline tests that verify fact contents must enable taint. The following tests need `config.static_.taint.enabled = true`:

- [ ] **Step 4: Update pipeline tests for new fact flow**

**Test `enabled_static_scan_runs_rule_line` (line 241):** Enable taint so facts are available:
```rust
let mut config = RuntimeConfig::default();
config.static_.taint.enabled = true;
let result = run_static_scan(&config, &[rules.clone()], Some(&[root.clone()])).expect("run scan");
```
Keep all existing assertions — they should pass now that taint is enabled.

**Test `enabled_static_scan_includes_python_facts_and_fact_count` (line 279):** Same fix:
```rust
let mut config = RuntimeConfig::default();
config.static_.taint.enabled = true;
let result = run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");
```

**Test `enabled_static_scan_includes_js_ts_facts` (line 379):** Same fix:
```rust
let mut config = RuntimeConfig::default();
config.static_.taint.enabled = true;
let result = run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");
```

**Test `enabled_static_scan_includes_typescript_facts` (line 443):** Same fix:
```rust
let mut config = RuntimeConfig::default();
config.static_.taint.enabled = true;
let result = run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");
```

**Test `disabled_static_scan_returns_empty_result` (line 226):** This test has `config.static_.enabled = false`, so taint line is never reached. No change needed — `facts` will be empty, and the test already expects `result.summary.risk_level == "none"`.

- [ ] **Step 5: Run tests**

```bash
cargo test -p mcp-sec-audit-core
```
Expected: All 97+ tests pass.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/
git rm rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs
git commit -m "refactor(pipeline): remove lines.rs, wire rule/taint/agent directly

Three lines are now independent peer directories. Pipeline imports
rule::run, taint::run, agent::run directly. extract_static_facts is
removed from pipeline — facts come from taint::run() internally.
Pipeline tests updated to enable taint when verifying fact extraction.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5: Create agent/prompt.rs — template + rendering

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/prompt.rs`

**Interfaces:**
- Consumes: `DiscoveredFile` from `super::super::discovery`
- Produces: `pub fn render_template(custom_path: Option<&str>, files: &[FileSummary], target_root: &str) -> Result<String>`
- Produces: `pub struct FileSummary { pub path: String, pub language: String, pub line_count: usize }`

**Purpose:** Built-in prompt template as a Rust constant. Template rendering with variable substitution. Optional custom template loading from file path.

- [ ] **Step 1: Write agent/prompt.rs**

```rust
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use super::super::discovery::ScanLanguage;

/// Summary of a single file for prompt rendering.
pub struct FileSummary {
    pub path: String,
    pub language: String,
    pub line_count: usize,
}

/// Built-in MCP security audit prompt template.
const BUILT_IN_TEMPLATE: &str = r#"## Role

You are an MCP security auditor. Your task is to analyze MCP (Model
Context Protocol) server source code for security vulnerabilities.

## MCP Vulnerability Taxonomy

MCP servers expose tools, resources, and prompts to AI models. The
following vulnerability categories are specific to MCP server contexts:

1. **Tool Poisoning** — A tool's description misrepresents its actual
   behavior, causing the calling AI to invoke it under false assumptions.
   Check whether tool descriptions match implementation.

2. **Prompt Injection** — User-controlled input reaches prompt
   construction or template rendering without sanitization, allowing
   injection of instructions that override system behavior.

3. **Command Injection** — MCP tool parameters flow into shell command
   execution (e.g., os.system, subprocess, exec, Command::new) without
   proper validation or sanitization.

4. **Path Traversal** — Tool parameters specifying file paths are not
   validated, allowing access to files outside intended directories
   (e.g., ../ escapes, absolute paths to sensitive files).

5. **Credential Leaks** — API keys, tokens, or secrets are hardcoded in
   source, passed through tool parameters in plaintext, or logged
   unsafely.

6. **Capability Over-Exposure** — The MCP server exposes more tools or
   capabilities than necessary for its stated purpose. Each tool should
   be evaluated: does it need to exist? Could it be abused?

7. **Context Over-Sharing** — Tools that read or return large amounts of
   data (file contents, database dumps, memory/vector-store queries) may
   leak sensitive context to the calling AI model.

## Target Overview

- Project root: {target_root}
- Primary language: {language}

### Files

{file_list}

## Instructions

1. Read each source file thoroughly using available tools (Read, Grep,
   Glob). Focus on MCP tool/resource/prompt definitions and their
   implementations.

2. For each file, identify:
   - MCP entrypoints (tools, resources, prompts) — their names,
     descriptions, parameters
   - Where user-controlled parameters flow within the code
   - Dangerous operations (command execution, file I/O, network calls,
     deserialization) that consume these parameters
   - Missing validation, sanitization, or authorization checks
   - Tool descriptions that differ from actual implementation behavior

3. Prioritize findings that:
   - Are NOT trivially catchable by simple pattern matching (e.g.,
     grep for "subprocess" alone)
   - Involve semantic risks: logic flaws, auth bypass, composite
     vulnerabilities from tool combinations
   - Represent MCP-specific attack surfaces: prompt injection,
     capability over-exposure, context over-sharing

4. For each finding, provide:
   - A clear title describing the vulnerability
   - The exact file:line locations affected
   - A reasoning summary explaining the risk
   - Code snippets as evidence
   - Your confidence level (high/medium/low)
   - Any limitations or caveats about your analysis

## Output Format

After completing your analysis, output EXACTLY ONE JSON block (wrapped
in a ```json code fence) containing all findings. Do not include any
other JSON blocks in your response.

```json
{
  "findings": [
    {
      "candidate_title": "Clear vulnerability description",
      "affected_locations": ["path/to/file.rs:42", "path/to/file.rs:58"],
      "reasoning_summary": "Explanation of why this is a vulnerability,
          how it could be exploited, and what the impact would be.",
      "evidence_snippets": [
        "let output = Command::new(\"sh\").arg(user_input).output()",
        "fn run_tool(cmd: String) {"
      ],
      "confidence": "high",
      "limitations": [
        "Did not verify if input validation happens in caller"
      ]
    }
  ]
}
```

If you find NO vulnerabilities, return:
```json
{"findings": []}
```

Begin your analysis now. Read the source files and identify
vulnerabilities.
"#;

/// Determine the primary language label from a slice of file summaries.
pub fn primary_language(files: &[FileSummary]) -> String {
    let mut counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    for f in files {
        *counts.entry(&f.language).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(lang, _)| lang.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Build the bullet list of files for template rendering.
pub fn file_list_text(files: &[FileSummary]) -> String {
    files
        .iter()
        .map(|f| format!("- {} ({}, {} lines)", f.path, f.language, f.line_count))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Load template content: custom file path if provided, otherwise built-in.
fn load_template(custom_path: Option<&str>) -> Result<String> {
    match custom_path {
        Some(path) => {
            let p = Path::new(path);
            if !p.exists() {
                bail!("prompt template not found: {}", path);
            }
            fs::read_to_string(p)
                .with_context(|| format!("read prompt template: {}", path))
        }
        None => Ok(BUILT_IN_TEMPLATE.to_string()),
    }
}

/// Render the prompt template with variable substitution.
pub fn render(
    custom_template_path: Option<&str>,
    files: &[FileSummary],
    target_root: &str,
) -> Result<String> {
    let template = load_template(custom_template_path)?;
    let language = primary_language(files);
    let file_list = file_list_text(files);

    let prompt = template
        .replace("{target_root}", target_root)
        .replace("{language}", &language)
        .replace("{file_list}", &file_list);

    Ok(prompt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_builtin_template_substitutes_variables() {
        let files = vec![
            FileSummary {
                path: "src/main.rs".into(),
                language: "rust".into(),
                line_count: 100,
            },
            FileSummary {
                path: "src/lib.rs".into(),
                language: "rust".into(),
                line_count: 50,
            },
        ];
        let prompt = render(None, &files, "/tmp/test-project")
            .expect("render template");
        assert!(prompt.contains("/tmp/test-project"));
        assert!(prompt.contains("rust"));
        assert!(prompt.contains("src/main.rs"));
        assert!(prompt.contains("100 lines"));
        assert!(prompt.contains("src/lib.rs"));
        assert!(prompt.contains("50 lines"));
        // Verify key template sections are present
        assert!(prompt.contains("Tool Poisoning"));
        assert!(prompt.contains("Command Injection"));
        assert!(prompt.contains("## Output Format"));
    }

    #[test]
    fn render_missing_custom_template_fails() {
        let err = render(
            Some("/nonexistent/path/template.md"),
            &[],
            "/tmp/test",
        )
        .expect_err("missing template should fail");
        assert!(err.to_string().contains("prompt template not found"));
    }

    #[test]
    fn primary_language_picks_most_common() {
        let files = vec![
            FileSummary { path: "a.py".into(), language: "python".into(), line_count: 10 },
            FileSummary { path: "b.py".into(), language: "python".into(), line_count: 20 },
            FileSummary { path: "c.js".into(), language: "javascript".into(), line_count: 5 },
        ];
        assert_eq!(primary_language(&files), "python");
    }

    #[test]
    fn primary_language_empty_returns_unknown() {
        assert_eq!(primary_language(&[]), "unknown");
    }

    #[test]
    fn file_list_text_formats_correctly() {
        let files = vec![FileSummary {
            path: "server.py".into(),
            language: "python".into(),
            line_count: 42,
        }];
        let text = file_list_text(&files);
        assert_eq!(text, "- server.py (python, 42 lines)");
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p mcp-sec-audit-core
```
Expected: All tests pass including the 5 new prompt tests.

- [ ] **Step 3: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/agent/
git commit -m "feat(agent): add prompt template and rendering

Built-in MCP security audit template with 7-category vulnerability
taxonomy. Supports custom template via file path. Variable substitution
for {target_root}, {language}, {file_list}.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 6: Create agent/provider.rs — AgentProvider trait + CliAgentProvider

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/provider.rs`

**Interfaces:**
- Consumes: nothing outside agent module
- Produces: `pub trait AgentProvider`, `pub struct AgentRunConfig`, `pub struct AgentRunOutput`, `pub struct CliAgentProvider`

**Purpose:** Abstraction for agent invocation. CliAgentProvider uses `std::process::Command` to spawn agent CLI, capture output with timeout.

- [ ] **Step 1: Write agent/provider.rs**

```rust
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

/// Configuration for a single agent run.
pub struct AgentRunConfig {
    /// Working directory (project root).
    pub working_dir: String,
    /// Rendered prompt to pass to the agent.
    pub prompt: String,
    /// CLI binary name (e.g., "claude").
    pub provider_binary: String,
    /// Maximum tool-use turns the agent may take.
    pub max_turns: u32,
    /// Wall-clock timeout for the agent process.
    pub timeout_seconds: u64,
    /// Extra CLI arguments (e.g., ["--model", "sonnet"]).
    pub extra_args: Vec<String>,
}

/// Output from a completed (or timed-out) agent run.
#[derive(Debug)]
pub struct AgentRunOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration: Duration,
    /// True if the process was killed due to timeout.
    pub timed_out: bool,
}

/// Pluggable agent backend.
pub trait AgentProvider {
    /// Execute an agent run with the given configuration.
    fn run(&self, config: &AgentRunConfig) -> Result<AgentRunOutput>;
}

/// Default provider: invokes an agent CLI as a subprocess.
pub struct CliAgentProvider;

impl AgentProvider for CliAgentProvider {
    fn run(&self, config: &AgentRunConfig) -> Result<AgentRunOutput> {
        let start = Instant::now();

        let mut cmd = Command::new(&config.provider_binary);
        cmd.arg("-p")
            .arg(&config.prompt)
            .arg("--max-turns")
            .arg(config.max_turns.to_string())
            .arg("--output-format")
            .arg("text")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for arg in &config.extra_args {
            cmd.arg(arg);
        }

        if !config.working_dir.is_empty() {
            cmd.current_dir(&config.working_dir);
        }

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "agent provider '{}' not found in PATH. \
                     Ensure the CLI tool is installed.",
                    config.provider_binary
                )
            } else {
                anyhow::anyhow!("failed to spawn agent process: {}", e)
            }
        })?;

        // Read stdout/stderr and wait in a separate thread so we can timeout
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut stdout = String::new();
            let mut stderr = String::new();

            // Read pipes — these are available until process exits
            if let Some(mut out) = child.stdout.take() {
                use std::io::Read;
                let _ = out.read_to_string(&mut stdout);
            }
            if let Some(mut err) = child.stderr.take() {
                use std::io::Read;
                let _ = err.read_to_string(&mut stderr);
            }

            let status = child.wait();
            let exit_code = status.ok().and_then(|s| s.code()).unwrap_or(-1);
            let _ = tx.send((stdout, stderr, exit_code));
        });

        let timeout = Duration::from_secs(config.timeout_seconds);
        match rx.recv_timeout(timeout) {
            Ok((stdout, stderr, exit_code)) => {
                let duration = start.elapsed();
                Ok(AgentRunOutput {
                    stdout,
                    stderr,
                    exit_code,
                    duration,
                    timed_out: false,
                })
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let duration = start.elapsed();
                Ok(AgentRunOutput {
                    stdout: String::new(),
                    stderr: "agent process timed out".to_string(),
                    exit_code: -1,
                    duration,
                    timed_out: true,
                })
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("agent process communication channel disconnected");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_not_found_returns_error() {
        let config = AgentRunConfig {
            working_dir: ".".to_string(),
            prompt: "test".to_string(),
            provider_binary: "nonexistent-agent-cli-xyz".to_string(),
            max_turns: 5,
            timeout_seconds: 5,
            extra_args: vec![],
        };
        let provider = CliAgentProvider;
        let err = provider.run(&config).expect_err("nonexistent binary should fail");
        assert!(err.to_string().contains("not found in PATH"));
    }

    #[test]
    fn timeout_happens_for_sleeping_process() {
        let config = AgentRunConfig {
            working_dir: ".".to_string(),
            prompt: "test".to_string(),
            provider_binary: "sleep".to_string(),
            max_turns: 5,
            timeout_seconds: 1,
            extra_args: vec!["10".to_string()], // sleep 10 — will timeout
        };
        let provider = CliAgentProvider;
        let output = provider.run(&config).expect("run with timeout");
        assert!(output.timed_out);
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p mcp-sec-audit-core
```
Expected: All tests pass. Provider tests verify binary-not-found and timeout behavior.

Note: the `timeout_happens_for_sleeping_process` test works on any Unix system with `sleep` command. On Windows, it would be skipped or adapted.

- [ ] **Step 3: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/agent/provider.rs
git commit -m "feat(agent): add AgentProvider trait and CliAgentProvider

CliAgentProvider spawns agent CLI via std::process::Command with
timeout via thread+channel. AgentProvider trait enables future
alternative backends (API-based, mock).

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 7: Create agent/parser.rs — JSON extraction + validation

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/parser.rs`

**Interfaces:**
- Consumes: `AgentAnalysisResult`, `Confidence` from crate model
- Produces: `pub fn parse_agent_output(stdout: &str) -> Result<Vec<AgentAnalysisResult>>`
- Produces: `pub struct AgentMetadata { pub agent_id, pub prompt_profile, pub input_scope }`

**Purpose:** Extract JSON block from agent stdout (fenced or bare), deserialize, validate required fields, map to AgentAnalysisResult with metadata.

- [ ] **Step 1: Write agent/parser.rs**

```rust
use anyhow::{Result, bail};
use serde::Deserialize;

use crate::model::{AgentAnalysisResult, Confidence};

/// Metadata attached to every agent-produced result.
pub struct AgentMetadata {
    pub agent_id: String,
    pub prompt_profile: String,
    pub input_scope: Vec<String>,
}

/// Raw finding from agent JSON output before enrichment.
#[derive(Debug, Deserialize)]
struct RawFinding {
    candidate_title: String,
    #[serde(default)]
    affected_locations: Vec<String>,
    #[serde(default)]
    reasoning_summary: String,
    #[serde(default)]
    evidence_snippets: Vec<String>,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawOutput {
    #[serde(default)]
    findings: Vec<RawFinding>,
}

/// Hardcoded threshold: discard findings below this confidence.
const MIN_CONFIDENCE: &str = "low";

fn parse_confidence(raw: &str) -> Confidence {
    match raw.to_lowercase().as_str() {
        "high" => Confidence::High,
        "medium" => Confidence::Medium,
        "low" => Confidence::Low,
        _ => Confidence::Low,
    }
}

fn confidence_meets_threshold(confidence: &str) -> bool {
    match confidence.to_lowercase().as_str() {
        "high" | "medium" => true,
        "low" => true, // "low" is the minimum; everything passes
        _ => false,
    }
}

/// Locate the JSON block in agent output.
/// Tries ```json ... ``` code fence first, then bare { ... }.
fn extract_json_block(stdout: &str) -> Option<&str> {
    // Try fenced JSON block
    if let Some(start) = stdout.find("```json") {
        let after_fence = &stdout[start + 7..];
        if let Some(end) = after_fence.find("```") {
            return Some(after_fence[..end].trim());
        }
    }
    // Try bare JSON object
    if let Some(start) = stdout.find("{\"findings\"") {
        return Some(&stdout[start..]);
    }
    // Also try { "findings" (with space)
    if let Some(start) = stdout.find("{ \"findings\"") {
        return Some(&stdout[start..]);
    }
    None
}

/// Parse agent stdout into structured results.
pub fn parse_agent_output(
    stdout: &str,
    metadata: &AgentMetadata,
) -> Result<Vec<AgentAnalysisResult>> {
    let json_str = extract_json_block(stdout)
        .ok_or_else(|| anyhow::anyhow!(
            "no valid JSON output from agent provider. \
             Expected a ```json code fence or a {{\"findings\": [...]}} block.\n\
             Raw output (first 500 chars): {}",
            &stdout[..stdout.len().min(500)]
        ))?;

    let raw: RawOutput = serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!(
            "failed to parse agent JSON output: {}\n\
             JSON excerpt (first 500 chars): {}",
            e,
            &json_str[..json_str.len().min(500)]
        ))?;

    let mut results = Vec::new();
    for (i, finding) in raw.findings.into_iter().enumerate() {
        // Validate required fields
        if finding.candidate_title.trim().is_empty() {
            continue; // skip empty titles, don't fail the whole batch
        }
        if finding.affected_locations.is_empty() {
            continue; // skip findings without locations
        }
        if finding.reasoning_summary.trim().is_empty() {
            continue;
        }

        if !confidence_meets_threshold(&finding.confidence) {
            continue; // confidence too low
        }

        results.push(AgentAnalysisResult {
            result_id: format!("agent:{}:{}", metadata.agent_id, i),
            agent_id: metadata.agent_id.clone(),
            prompt_profile: metadata.prompt_profile.clone(),
            model_provider: Some(metadata.agent_id.clone()),
            input_scope: metadata.input_scope.clone(),
            candidate_title: finding.candidate_title,
            affected_locations: finding.affected_locations,
            reasoning_summary: finding.reasoning_summary,
            evidence_snippets: finding.evidence_snippets,
            related_rule_result_ids: Vec::new(),    // Phase 13
            related_taint_result_ids: Vec::new(),   // Phase 13
            confidence: parse_confidence(&finding.confidence),
            verification_status: "uncorroborated".to_string(), // Phase 13
            limitations: finding.limitations,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> AgentMetadata {
        AgentMetadata {
            agent_id: "test-agent".to_string(),
            prompt_profile: "mcp_security_audit".to_string(),
            input_scope: vec!["test.py".to_string()],
        }
    }

    #[test]
    fn parse_fenced_json_block() {
        let stdout = r#"
Some preamble text...

```json
{
  "findings": [
    {
      "candidate_title": "Command injection in run_cmd",
      "affected_locations": ["server.py:42"],
      "reasoning_summary": "User input flows to os.system without validation",
      "evidence_snippets": ["os.system(cmd)"],
      "confidence": "high",
      "limitations": []
    }
  ]
}
```

Some trailing text.
"#;
        let results = parse_agent_output(stdout, &metadata()).expect("parse");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].candidate_title, "Command injection in run_cmd");
        assert_eq!(results[0].affected_locations, vec!["server.py:42"]);
        assert_eq!(results[0].confidence, Confidence::High);
        assert_eq!(results[0].verification_status, "uncorroborated");
        assert!(results[0].related_rule_result_ids.is_empty());
        assert!(results[0].related_taint_result_ids.is_empty());
        assert_eq!(results[0].agent_id, "test-agent");
    }

    #[test]
    fn parse_bare_json() {
        let stdout = r#"{"findings":[{"candidate_title":"Test","affected_locations":["a.rs:1"],"reasoning_summary":"x","confidence":"medium"}]}"#;
        let results = parse_agent_output(stdout, &metadata()).expect("parse");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].confidence, Confidence::Medium);
    }

    #[test]
    fn no_json_returns_error() {
        let stdout = "Just some random text without any JSON.";
        let err = parse_agent_output(stdout, &metadata()).expect_err("should fail");
        assert!(err.to_string().contains("no valid JSON output"));
    }

    #[test]
    fn invalid_json_returns_error() {
        let stdout = r#"```json
{"findings": [{"candidate_title": "incomplete
```"#;
        let err = parse_agent_output(stdout, &metadata()).expect_err("should fail");
        assert!(err.to_string().contains("failed to parse"));
    }

    #[test]
    fn empty_findings_returns_empty_vec() {
        let stdout = r#"```json
{"findings": []}
```"#;
        let results = parse_agent_output(stdout, &metadata()).expect("parse");
        assert!(results.is_empty());
    }

    #[test]
    fn skips_invalid_entries() {
        let stdout = r#"```json
{
  "findings": [
    {
      "candidate_title": "",
      "affected_locations": [],
      "reasoning_summary": "",
      "confidence": "high"
    },
    {
      "candidate_title": "Valid finding",
      "affected_locations": ["f.rs:10"],
      "reasoning_summary": "This one is valid",
      "confidence": "high"
    }
  ]
}
```"#;
        let results = parse_agent_output(stdout, &metadata()).expect("parse");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].candidate_title, "Valid finding");
    }

    #[test]
    fn extract_json_handles_whitespace_variations() {
        // JSON with space after {
        let stdout = r#"{ "findings": [{"candidate_title":"T","affected_locations":["x:1"],"reasoning_summary":"r","confidence":"high"}] }"#;
        let results = parse_agent_output(stdout, &metadata()).expect("parse");
        assert_eq!(results.len(), 1);
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p mcp-sec-audit-core
```
Expected: All tests pass including 7 new parser tests.

- [ ] **Step 3: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/agent/parser.rs
git commit -m "feat(agent): add output parser for JSON extraction and validation

Extracts JSON block from agent stdout (fenced or bare). Validates
required fields, maps to AgentAnalysisResult with metadata.
related_*_ids are empty (Phase 13), verification_status is
'uncorroborated'.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 8: Create agent/mod.rs — orchestration entry point

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/mod.rs`

**Interfaces:**
- Consumes: `StaticScanContext`, `StaticAgentConfig`, `FileSummary` from prompt, `AgentMetadata` from parser, `CliAgentProvider` from provider
- Produces: `pub fn run(ctx: &StaticScanContext) -> Result<Vec<AgentAnalysisResult>>`

**Purpose:** The `run()` entry point orchestrates the full agent analysis flow: check config, prepare file summaries, render prompt, invoke provider, parse output.

- [ ] **Step 1: Write agent/mod.rs**

```rust
mod parser;
mod prompt;
mod provider;

use anyhow::Result;

use crate::model::AgentAnalysisResult;

use super::pipeline::StaticScanContext;
use prompt::FileSummary;
use provider::{AgentRunConfig, CliAgentProvider};

/// Hardcoded constants (not user-configurable).
const PROMPT_PROFILE: &str = "mcp_security_audit";
const MAX_FILES: usize = 80;

/// Agent line entry point.
///
/// Prepares file context, renders the prompt template, invokes the
/// configured CLI agent provider, and parses structured results from
/// the agent's output.
pub fn run(ctx: &StaticScanContext) -> Result<Vec<AgentAnalysisResult>> {
    let agent_config = &ctx.config.static_.agent;

    if !agent_config.enabled {
        return Ok(Vec::new());
    }

    // Build file summaries (capped at MAX_FILES)
    let file_summaries: Vec<FileSummary> = ctx
        .discovered_files
        .iter()
        .take(MAX_FILES)
        .map(|df| {
            let line_count = std::fs::read_to_string(&df.path)
                .map(|s| s.lines().count())
                .unwrap_or(0);
            FileSummary {
                path: df.path.display().to_string(),
                language: df.language.to_string(),
                line_count,
            }
        })
        .collect();

    if file_summaries.is_empty() {
        return Ok(Vec::new());
    }

    // Determine target root from the first file's parent
    let target_root = ctx
        .discovered_files
        .first()
        .and_then(|df| df.path.parent())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| ".".to_string());

    // Render the prompt
    let prompt = prompt::render(
        agent_config.prompt_template_path.as_deref(),
        &file_summaries,
        &target_root,
    )?;

    // Build input scope for metadata
    let input_scope: Vec<String> = file_summaries
        .iter()
        .map(|fs| fs.path.clone())
        .collect();

    // Invoke the agent provider
    let provider = CliAgentProvider;
    let run_config = AgentRunConfig {
        working_dir: target_root,
        prompt,
        provider_binary: agent_config.provider.clone(),
        max_turns: agent_config.max_turns,
        timeout_seconds: agent_config.timeout_seconds,
        extra_args: agent_config.extra_args.clone(),
    };

    let output = provider.run(&run_config)?;

    // Parse results
    let metadata = parser::AgentMetadata {
        agent_id: agent_config.provider.clone(),
        prompt_profile: PROMPT_PROFILE.to_string(),
        input_scope,
    };

    let mut results = parser::parse_agent_output(&output.stdout, &metadata)?;

    // Annotate timeout limitation
    if output.timed_out {
        for r in &mut results {
            r.limitations.push(format!(
                "agent analysis timed out after {}s",
                agent_config.timeout_seconds
            ));
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeConfig;
    use crate::static_analysis::DiscoveredFile;

    #[test]
    fn disabled_agent_returns_empty() {
        let ctx = StaticScanContext {
            config: RuntimeConfig::default(), // agent disabled by default
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        let results = run(&ctx).expect("run disabled agent");
        assert!(results.is_empty());
    }

    #[test]
    fn enabled_with_no_files_returns_empty() {
        let mut config = RuntimeConfig::default();
        config.static_.agent.enabled = true;
        let ctx = StaticScanContext {
            config,
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        let results = run(&ctx).expect("run agent with no files");
        assert!(results.is_empty());
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p mcp-sec-audit-core
```
Expected: All tests pass including the 2 new agent mod tests.

- [ ] **Step 3: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/agent/mod.rs
git commit -m "feat(agent): add agent line orchestration entry point

agent::run(ctx) orchestrates: file summaries → prompt render →
CLI provider invocation → output parsing → AgentAnalysisResult.
Disabled by default; returns empty when disabled or no files.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 9: Integration — static_analysis/mod.rs module declaration + full test suite

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs` (if not already done in Task 4)
- Modify: `rust/docs/REFACTOR_PLAN.md`

**Interfaces:**
- Consumes: all previous tasks
- Produces: complete working agent line, clean module structure, passing test suite

**Purpose:** Ensure the `mod agent;` declaration is in place. Update Phase 12 status in REFACTOR_PLAN.md. Run full test suite as final verification.

- [ ] **Step 1: Verify mod.rs has agent module declaration**

From Task 4, `mod.rs` should already have:
```rust
mod agent;
```

If not, add it. The `agent` module does NOT need re-exports — `agent::run()` is called directly by `pipeline.rs` via `use super::agent`.

- [ ] **Step 2: Run full test suite**

```bash
cargo test -p mcp-sec-audit-core
```
Expected: All tests pass (97 original + ~20 new tests from Tasks 3-8).

- [ ] **Step 3: Run the full workspace test**

```bash
cargo test
```
Expected: All workspace tests pass.

- [ ] **Step 4: Check for compiler warnings**

```bash
cargo build -p mcp-sec-audit-core 2>&1 | grep -i "warning"
```
Expected: No warnings (or only pre-existing ones).

- [ ] **Step 5: Update REFACTOR_PLAN.md Phase 12 status**

Change Phase 12 row from:
```
| Phase 12：Agent 分析线          | 未开始 | ...
```
To:
```
| Phase 12：Agent 分析线          | 完成 | ...
```

And add completion note below:
```
Phase 12 已完成 Agent 辅助分析线实现。Agent 线通过 CLI 子进程调用外部 Agent 工具（claude），传入 MCP 安全审计 prompt 模板，Agent 自主使用工具探索源码并产出结构化 AgentAnalysisResult。同时完成了三线工程化解耦重构：规则线（rule/）、污点线（taint/）、Agent 线（agent/）各自独立目录，每条线有单一 pub fn run() 入口，pipeline.rs 纯编排。Fact 提取下沉至 taint 线内部，不再作为全局前置步骤。
```

- [ ] **Step 6: Commit**

```bash
git add rust/docs/REFACTOR_PLAN.md
git commit -m "docs: mark Phase 12 as complete

Agent analysis line implemented with CLI subprocess invocation,
built-in MCP security audit prompt template, and structured output
parsing. Three-line decoupling refactoring also completed:
rule/, taint/, agent/ are independent peer directories.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task Summary

| # | Task | Files | Test impact |
|---|------|-------|-------------|
| 1 | Config cleanup | `config.rs`, `default.toml` | Update 1 test assertion |
| 2 | Rule move | `rule.rs` → `rule/mod.rs` | None (internal refactor) |
| 3 | Taint run() wrapper | `taint/mod.rs` | +1 new test |
| 4 | Remove lines.rs, wire pipeline | `lines.rs`(-), `mod.rs`, `pipeline.rs` | Fix 4 tests (enable taint) |
| 5 | Agent prompt.rs | `agent/prompt.rs` (new) | +5 new tests |
| 6 | Agent provider.rs | `agent/provider.rs` (new) | +2 new tests |
| 7 | Agent parser.rs | `agent/parser.rs` (new) | +7 new tests |
| 8 | Agent mod.rs | `agent/mod.rs` (new) | +2 new tests |
| 9 | Integration & docs | `REFACTOR_PLAN.md` | Full suite verification |

**Total: ~9 files created/modified, ~17 new tests, 97 existing tests preserved.**
