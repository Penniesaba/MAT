# Phase 7 Python Fact Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build production-grade Rust-native Python fact extraction for Phase 7, with real facts exposed through the static scan result and no enabled empty implementations.

**Architecture:** Add a dedicated `static_analysis::facts` subsystem with deterministic fact IDs, a RustPython-based Python AST extractor, and a pipeline pass that runs after discovery. Extend `StaticAnalysisResult` and reporting so JSON preserves `facts`, Markdown can summarize facts when configured, and unimplemented taint analysis fails clearly when explicitly enabled.

**Tech Stack:** Rust 2024 workspace under `rust/`; `rustpython-parser = "0.4"`; existing `anyhow`, `serde`, `serde_json`, `regex`, and model types in `mcp-sec-audit-core`.

## Global Constraints

- Implement方案 A: production-grade complete Phase 7 Python fact extraction, not the minimal extractor.
- Documentation language remains Chinese when editing `rust/docs/*.md`.
- Do not commit unless the user explicitly asks for a commit.
- Do not implement JS/TS fact extraction, Rust fact extraction, call graph, taint propagation, Agent analysis, finding fusion, or dynamic analysis in Phase 7.
- Do not leave empty implementations. If a feature is enabled but not implemented in this phase, it must fail clearly or remain disabled.
- JSON output must preserve `facts`; Markdown fact display remains configurable through `report.include_facts`.
- Keep `REFACTOR_PLAN.md` concise; put phase-level detail in this plan and the Phase 7 spec.
- Match existing Rust code style: small modules, `anyhow::{Context, Result}`, deterministic ordering in tests, and focused unit tests with temporary fixtures.

---

## File Structure

Modify:

- `rust/Cargo.toml`
  - Add workspace dependency `rustpython-parser = "0.4"`.
- `rust/crates/mcp-sec-audit-core/Cargo.toml`
  - Add `rustpython-parser.workspace = true`.
- `rust/crates/mcp-sec-audit-core/src/model/static_result.rs`
  - Add `facts: Vec<Fact>` to `StaticAnalysisResult`.
  - Add `fact_count: usize` to `StaticAnalysisSummary`.
  - Update JSON preservation tests.
- `rust/crates/mcp-sec-audit-core/src/fixtures.rs`
  - Add at least one synthetic fact to synthetic static results.
- `rust/crates/mcp-sec-audit-core/src/reporting.rs`
  - Add `include_facts` to Markdown and JSONL render options.
  - Emit `fact` JSONL events when enabled.
  - Show fact counts and type breakdown in Markdown when enabled.
- `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`
  - Expose the new `facts` module API.
- `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`
  - Run fact extraction after discovery.
  - Store facts in `StaticAnalysisResult`.
  - Populate `summary.fact_count`.
  - Keep disabled static scan returning empty facts.
- `rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs`
  - Replace enabled taint empty result with clear error until Phase 10/11.
- `rust/crates/mcp-sec-audit-core/src/lib.rs`
  - Re-export Phase 7 fact extraction APIs.
  - Update `CURRENT_PHASE`.
- `rust/config/default.toml`
  - Temporarily set `[static.taint].enabled = false` until Phase 10/11.
- `rust/docs/REFACTOR_PLAN.md`
  - Mark Phase 7 complete after verification.
- `rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md`
  - Add a short Phase 7 note describing production-grade Python fact extraction behavior.

Create:

- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/mod.rs`
  - Public API, diagnostics, extraction result types.
- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/ids.rs`
  - Deterministic ID helpers matching legacy Python ID formats.
- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`
  - RustPython AST extraction implementation and extractor tests.
- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`
  - Discovery-to-facts pipeline integration and pipeline tests.

---

### Task 1: Add Result Model Support for Facts

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/model/static_result.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/fixtures.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/reporting.rs`

**Interfaces:**
- Consumes: existing `Fact` enum from `crate::model`.
- Produces: `StaticAnalysisResult { facts: Vec<Fact>, ... }` and `StaticAnalysisSummary { fact_count: usize, ... }`.

- [ ] **Step 1: Add failing model assertions**

Update `static_analysis_json_preserves_three_line_results` in `rust/crates/mcp-sec-audit-core/src/model/static_result.rs` to assert the new fields:

```rust
assert!(value.get("facts").is_some());
assert!(value["summary"].get("fact_count").is_some());
```

- [ ] **Step 2: Run the focused model test and confirm failure**

Run from `/home/xiao/Project/mcp-sec-audit/rust`:

```bash
cargo test -p mcp-sec-audit-core static_analysis_json_preserves_three_line_results
```

Expected: compile failure or assertion failure because `facts` and `fact_count` do not exist yet.

- [ ] **Step 3: Add facts to static result structs**

In `rust/crates/mcp-sec-audit-core/src/model/static_result.rs`, import `Fact`:

```rust
use super::{Confidence, Fact, FindingStatus, Severity};
```

Change `StaticAnalysisSummary`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticAnalysisSummary {
    pub target: String,
    pub fact_count: usize,
    pub rule_result_count: usize,
    pub taint_result_count: usize,
    pub agent_result_count: usize,
    pub fused_finding_count: usize,
    pub highest_severity: Option<Severity>,
    pub risk_level: String,
}
```

Change `StaticAnalysisResult`:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaticAnalysisResult {
    pub facts: Vec<Fact>,
    pub rule_results: Vec<RuleAnalysisResult>,
    pub taint_results: Vec<TaintAnalysisResult>,
    pub agent_results: Vec<AgentAnalysisResult>,
    pub fused_findings: Vec<FusedFinding>,
    pub summary: StaticAnalysisSummary,
    pub config_snapshot: ConfigSnapshot,
}
```

- [ ] **Step 4: Add a synthetic source fact fixture**

In `rust/crates/mcp-sec-audit-core/src/fixtures.rs`, extend the imports to include the fact structs used below:

```rust
use crate::model::{
    AgentAnalysisResult, CapabilityFinding, Confidence, ConfigSnapshot, DetectionResult,
    EntryPointKind, EvidenceSource, Fact, FactBase, FindingFact, FindingStatus, FusedFinding,
    SourceFact, RuleAnalysisResult, Severity, StaticAnalysisResult, StaticAnalysisSummary,
    TaintAnalysisResult,
};
```

Add this function near the existing synthetic fact helpers:

```rust
pub fn synthetic_source_fact() -> Fact {
    Fact::Source(SourceFact {
        base: FactBase {
            id: "source:server.py:tool_handler:command".to_string(),
            file: "server.py".to_string(),
            line: 40,
            extractor: "phase7_fixture".to_string(),
        },
        kind: "mcp_tool_parameter".to_string(),
        function_id: "python:server.py:tool_handler".to_string(),
        name: "command".to_string(),
        confidence: Confidence::High,
    })
}
```

Remove `EntryPointKind` from the import if the compiler reports it is unused.

- [ ] **Step 5: Update synthetic static result**

In `synthetic_static_analysis_result()`, add facts and fact count:

```rust
StaticAnalysisResult {
    facts: vec![synthetic_source_fact()],
    rule_results: vec![synthetic_rule_analysis_result()],
    // existing fields...
    summary: StaticAnalysisSummary {
        target: "demo-mcp-server".to_string(),
        fact_count: 1,
        rule_result_count: 1,
        taint_result_count: 1,
        agent_result_count: 1,
        fused_finding_count: 1,
        highest_severity: Some(Severity::High),
        risk_level: "high".to_string(),
    },
    // existing config_snapshot...
}
```

- [ ] **Step 6: Update JSON renderer test**

In `rust/crates/mcp-sec-audit-core/src/reporting.rs`, update `json_renderer_preserves_full_static_result`:

```rust
assert!(value.get("facts").is_some());
assert_eq!(value["facts"].as_array().expect("facts array").len(), 1);
```

- [ ] **Step 7: Run focused tests**

Run:

```bash
cargo test -p mcp-sec-audit-core static_analysis_result_roundtrips_json static_analysis_json_preserves_three_line_results json_renderer_preserves_full_static_result
```

Expected: tests pass after fixture updates.

---

### Task 2: Add Fact Reporting Options

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/reporting.rs`

**Interfaces:**
- Consumes: `StaticAnalysisResult.facts` and `ReportConfig.include_facts`.
- Produces: `MarkdownRenderOptions.include_facts`, `JsonlRenderOptions.include_facts`, JSONL `fact` events, and Markdown fact summary.

- [ ] **Step 1: Add failing JSONL and Markdown tests**

In `reporting.rs`, update `jsonl_renderer_emits_expected_events` expected lines from 5 to 6 and assert the fact event:

```rust
assert_eq!(lines.len(), 6);
assert!(lines[0].contains(r#"\"event\":\"summary\""#));
assert!(lines[1].contains(r#"\"event\":\"fact\""#));
assert!(lines[2].contains(r#"\"event\":\"fused_finding\""#));
assert!(lines[3].contains(r#"\"event\":\"rule_result\""#));
assert!(lines[4].contains(r#"\"event\":\"taint_result\""#));
assert!(lines[5].contains(r#"\"event\":\"agent_result\""#));
```

Add a new Markdown test:

```rust
#[test]
fn markdown_can_include_fact_summary() {
    let result = crate::fixtures::synthetic_static_analysis_result();
    let markdown = render_markdown(
        &result,
        &MarkdownRenderOptions {
            include_fused_results: true,
            include_raw_rule_results: false,
            include_raw_taint_results: false,
            include_raw_agent_results: false,
            include_facts: true,
        },
    );

    assert!(markdown.contains("- Facts: 1"));
    assert!(markdown.contains("## Facts"));
    assert!(markdown.contains("- source: 1"));
}
```

- [ ] **Step 2: Run reporting tests and confirm failure**

Run:

```bash
cargo test -p mcp-sec-audit-core jsonl_renderer_emits_expected_events markdown_can_include_fact_summary
```

Expected: compile failure because render options do not have `include_facts`, or test failure because facts are not rendered.

- [ ] **Step 3: Extend render option structs**

In `reporting.rs`, add `include_facts` to both option structs:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkdownRenderOptions {
    pub include_fused_results: bool,
    pub include_raw_rule_results: bool,
    pub include_raw_taint_results: bool,
    pub include_raw_agent_results: bool,
    pub include_facts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonlRenderOptions {
    pub include_fused_results: bool,
    pub include_raw_rule_results: bool,
    pub include_raw_taint_results: bool,
    pub include_raw_agent_results: bool,
    pub include_facts: bool,
}
```

Update `From<&ReportConfig>` for both:

```rust
include_facts: config.include_facts,
```

Update defaults:

```rust
impl Default for MarkdownRenderOptions {
    fn default() -> Self {
        Self {
            include_fused_results: true,
            include_raw_rule_results: false,
            include_raw_taint_results: false,
            include_raw_agent_results: false,
            include_facts: false,
        }
    }
}

impl Default for JsonlRenderOptions {
    fn default() -> Self {
        Self {
            include_fused_results: true,
            include_raw_rule_results: true,
            include_raw_taint_results: true,
            include_raw_agent_results: true,
            include_facts: true,
        }
    }
}
```

- [ ] **Step 4: Emit JSONL fact events**

In `render_jsonl()`, after the summary event and before fused findings:

```rust
if options.include_facts {
    for fact in &result.facts {
        lines.push(serde_json::to_string(&JsonlRecord {
            event: "fact",
            data: fact,
        })?);
    }
}
```

- [ ] **Step 5: Add Markdown fact summary helpers**

At the top of `reporting.rs`, add:

```rust
use std::collections::BTreeMap;
```

Add helper functions before tests:

```rust
fn fact_type_name(fact: &crate::Fact) -> &'static str {
    match fact {
        crate::Fact::Function(_) => "function",
        crate::Fact::Import(_) => "import",
        crate::Fact::Entrypoint(_) => "entrypoint",
        crate::Fact::Call(_) => "call",
        crate::Fact::Sink(_) => "sink",
        crate::Fact::Source(_) => "source",
        crate::Fact::Assign(_) => "assign",
        crate::Fact::Dataflow(_) => "dataflow",
        crate::Fact::RuntimeEvent(_) => "runtime_event",
        crate::Fact::Finding(_) => "finding",
    }
}

fn fact_type_counts(result: &StaticAnalysisResult) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for fact in &result.facts {
        *counts.entry(fact_type_name(fact)).or_insert(0) += 1;
    }
    counts
}
```

- [ ] **Step 6: Render Markdown fact counts**

In the summary list, add:

```rust
format!("- Facts: {}", result.summary.fact_count),
```

After the highest severity block and before fused findings, add:

```rust
if options.include_facts {
    lines.push(String::new());
    lines.push("## Facts".to_string());
    if result.facts.is_empty() {
        lines.push("- None".to_string());
    } else {
        for (kind, count) in fact_type_counts(result) {
            lines.push(format!("- {kind}: {count}"));
        }
    }
}
```

- [ ] **Step 7: Update raw section tests with include_facts field**

Every `MarkdownRenderOptions { ... }` literal in tests must include:

```rust
include_facts: false,
```

- [ ] **Step 8: Run reporting tests**

Run:

```bash
cargo test -p mcp-sec-audit-core reporting::tests
```

Expected: all reporting tests pass.

---

### Task 3: Add Dependencies and Fact Module Skeleton

**Files:**
- Modify: `rust/Cargo.toml`
- Modify: `rust/crates/mcp-sec-audit-core/Cargo.toml`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/lib.rs`
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/mod.rs`
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/ids.rs`
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`

**Interfaces:**
- Produces:
  - `ExtractionDiagnostic`
  - `PythonExtractionResult`
  - `extract_python_facts(root: &Path, file: &Path, source: &str) -> PythonExtractionResult`
  - `extract_static_facts(ctx: &StaticScanContext) -> Result<Vec<Fact>>`
  - deterministic ID helpers in `ids.rs`.

- [ ] **Step 1: Add parser dependency**

In `rust/Cargo.toml`, add:

```toml
rustpython-parser = "0.4"
```

under `[workspace.dependencies]`.

In `rust/crates/mcp-sec-audit-core/Cargo.toml`, add:

```toml
rustpython-parser.workspace = true
```

- [ ] **Step 2: Create facts module root**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/mod.rs`:

```rust
use std::path::Path;

use crate::Fact;

mod ids;
mod pipeline;
mod python;

pub use ids::{
    make_assign_id, make_call_id, make_entrypoint_id, make_fact_id, make_function_id,
    make_import_id, make_sink_id, make_source_id,
};
pub use pipeline::extract_static_facts;
pub use python::extract_python_facts;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionDiagnostic {
    pub file: String,
    pub line: u32,
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PythonExtractionResult {
    pub facts: Vec<Fact>,
    pub diagnostics: Vec<ExtractionDiagnostic>,
}

impl PythonExtractionResult {
    pub fn empty() -> Self {
        Self {
            facts: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}

pub(crate) fn display_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}
```

- [ ] **Step 3: Create ID helpers**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/ids.rs`:

```rust
use std::path::Path;

fn rel_posix(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn make_fact_id(type_prefix: &str, root: &Path, file: &Path, qualifier: &str) -> String {
    format!("{type_prefix}:{}:{qualifier}", rel_posix(root, file))
}

pub fn make_function_id(language: &str, root: &Path, file: &Path, name: &str) -> String {
    make_fact_id(language, root, file, name)
}

pub fn make_import_id(root: &Path, file: &Path, line: u32, imported: &str) -> String {
    format!("import:{}:{line}:{imported}", rel_posix(root, file))
}

pub fn make_entrypoint_id(root: &Path, file: &Path, name: &str) -> String {
    make_fact_id("entry", root, file, name)
}

pub fn make_call_id(root: &Path, file: &Path, line: u32, column: u32) -> String {
    format!("call:{}:{line}:{column}", rel_posix(root, file))
}

pub fn make_sink_id(category: &str, root: &Path, file: &Path, line: u32) -> String {
    format!("sink:{category}:{}:{line}", rel_posix(root, file))
}

pub fn make_source_id(root: &Path, file: &Path, function_name: &str, param_name: &str) -> String {
    format!("source:{}:{function_name}:{param_name}", rel_posix(root, file))
}

pub fn make_assign_id(root: &Path, file: &Path, line: u32, target: &str) -> String {
    format!("assign:{}:{line}:{target}", rel_posix(root, file))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn ids_match_legacy_python_format() {
        let root = Path::new("/repo");
        let file = Path::new("/repo/src/server.py");

        assert_eq!(
            make_function_id("python", root, file, "tool_handler"),
            "python:src/server.py:tool_handler"
        );
        assert_eq!(
            make_import_id(root, file, 3, "subprocess"),
            "import:src/server.py:3:subprocess"
        );
        assert_eq!(
            make_entrypoint_id(root, file, "tool_handler"),
            "entry:src/server.py:tool_handler"
        );
        assert_eq!(make_call_id(root, file, 8, 4), "call:src/server.py:8:4");
        assert_eq!(
            make_sink_id("rce", root, file, 8),
            "sink:rce:src/server.py:8"
        );
        assert_eq!(
            make_source_id(root, file, "tool_handler", "command"),
            "source:src/server.py:tool_handler:command"
        );
        assert_eq!(
            make_assign_id(root, file, 7, "runner"),
            "assign:src/server.py:7:runner"
        );
    }
}
```

- [ ] **Step 4: Create temporary compile-safe Python extractor shell with explicit diagnostic behavior**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`:

```rust
use std::path::Path;

use crate::Fact;

use super::{ExtractionDiagnostic, PythonExtractionResult, display_path};

pub fn extract_python_facts(root: &Path, file: &Path, source: &str) -> PythonExtractionResult {
    let _ = root;
    let _ = source;
    PythonExtractionResult {
        facts: Vec::<Fact>::new(),
        diagnostics: vec![ExtractionDiagnostic {
            file: display_path(file),
            line: 1,
            kind: "not_implemented".to_string(),
            message: "Python fact extraction implementation is added in the following tasks".to_string(),
        }],
    }
}
```

This shell is allowed only inside Task 3 so later test-driven tasks can compile. It must not remain by the end of Task 8.

- [ ] **Step 5: Create static facts pipeline shell**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`:

```rust
use anyhow::Result;

use crate::{Fact, static_analysis::pipeline::StaticScanContext};

pub fn extract_static_facts(_ctx: &StaticScanContext) -> Result<Vec<Fact>> {
    Ok(Vec::new())
}
```

This shell is allowed only until Task 9 wires the real pipeline. It must not remain as the final implementation.

- [ ] **Step 6: Register facts module**

In `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`, add:

```rust
pub mod facts;
```

In `rust/crates/mcp-sec-audit-core/src/lib.rs`, extend the static analysis re-exports:

```rust
pub use static_analysis::{
    DiscoveredFile, DiscoverySummary, ExtractionDiagnostic, PythonExtractionResult, ScanLanguage,
    StaticScanContext, detect_language, discover_files, extract_python_facts, extract_static_facts,
    run_static_scan,
};
```

If the compiler requires different module paths, re-export through `static_analysis/mod.rs` first:

```rust
pub use facts::{
    ExtractionDiagnostic, PythonExtractionResult, extract_python_facts, extract_static_facts,
};
```

- [ ] **Step 7: Run module compile tests**

Run:

```bash
cargo test -p mcp-sec-audit-core ids_match_legacy_python_format
```

Expected: ID test passes, project compiles with the temporary extractor shell.

---

### Task 4: Implement Python Imports and Function Facts

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: RustPython parser API:
  - `rustpython_parser::{Parse, ast}`
  - `ast::Suite::parse(source, path)` or `rustpython_parser::parse_program(source, path)` if the trait form is awkward.
- Produces real `ImportFact` and `FunctionFact` extraction.

- [ ] **Step 1: Replace shell tests with failing import and function tests**

In `python.rs`, replace the temporary shell-only implementation tests with these tests:

```rust
#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{Fact, ImportKind};

    use super::*;

    fn extract(source: &str) -> PythonExtractionResult {
        extract_python_facts(Path::new("/repo"), Path::new("/repo/server.py"), source)
    }

    fn import_facts(result: &PythonExtractionResult) -> Vec<&crate::ImportFact> {
        result
            .facts
            .iter()
            .filter_map(|fact| match fact {
                Fact::Import(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn function_facts(result: &PythonExtractionResult) -> Vec<&crate::FunctionFact> {
        result
            .facts
            .iter()
            .filter_map(|fact| match fact {
                Fact::Function(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn extracts_import_facts_and_aliases() {
        let result = extract(
            r#"
import subprocess
import os as operating_system
from pathlib import Path
from subprocess import run as subprocess_run
"#,
        );

        assert!(result.diagnostics.is_empty());
        let imports = import_facts(&result);
        assert_eq!(imports.len(), 4);
        assert_eq!(imports[0].module, "subprocess");
        assert_eq!(imports[0].kind, ImportKind::Import);
        assert_eq!(imports[1].module, "os");
        assert_eq!(imports[1].alias.as_deref(), Some("operating_system"));
        assert_eq!(imports[1].kind, ImportKind::ImportAs);
        assert_eq!(imports[2].module, "pathlib");
        assert_eq!(imports[2].imported_name.as_deref(), Some("Path"));
        assert_eq!(imports[2].kind, ImportKind::FromImport);
        assert_eq!(imports[3].module, "subprocess");
        assert_eq!(imports[3].imported_name.as_deref(), Some("run"));
        assert_eq!(imports[3].alias.as_deref(), Some("subprocess_run"));
        assert_eq!(imports[3].kind, ImportKind::FromImportAs);
    }

    #[test]
    fn extracts_functions_async_methods_nested_and_docstrings() {
        let result = extract(
            r#"
def top_level(command: str, timeout=30):
    """Run a command."""
    return command

async def async_tool(path):
    return path

class Server:
    def method(self, value: int):
        def nested(inner):
            return inner
        return nested(value)
"#,
        );

        assert!(result.diagnostics.is_empty());
        let functions = function_facts(&result);
        let names = functions
            .iter()
            .map(|item| item.qualified_name.as_str())
            .collect::<Vec<_>>();

        assert!(names.contains(&"top_level"));
        assert!(names.contains(&"async_tool"));
        assert!(names.contains(&"Server.method"));
        assert!(names.contains(&"Server.method.nested"));

        let top = functions
            .iter()
            .find(|item| item.qualified_name == "top_level")
            .expect("top_level function");
        assert_eq!(top.params[0].name, "command");
        assert_eq!(top.params[0].annotation.as_deref(), Some("str"));
        assert_eq!(top.params[1].name, "timeout");
        assert_eq!(top.params[1].default.as_deref(), Some("30"));
        assert_eq!(top.docstring.as_deref(), Some("Run a command."));

        let method = functions
            .iter()
            .find(|item| item.qualified_name == "Server.method")
            .expect("method fact");
        assert_eq!(method.enclosing_class.as_deref(), Some("Server"));
    }
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
cargo test -p mcp-sec-audit-core extracts_import_facts_and_aliases extracts_functions_async_methods_nested_and_docstrings
```

Expected: tests fail because the extractor still returns no facts.

- [ ] **Step 3: Implement extractor state and parsing**

In `python.rs`, replace the shell implementation with an extractor struct. Use this structure and adapt RustPython AST field names after checking compiler errors:

```rust
use std::{collections::BTreeMap, path::{Path, PathBuf}};

use rustpython_parser::{Parse, ast};

use crate::{
    Fact, FactBase, FunctionFact, ImportFact, ImportKind, ParamInfo,
};

use super::{
    ExtractionDiagnostic, PythonExtractionResult, display_path,
    make_function_id, make_import_id,
};

const EXTRACTOR_NAME: &str = "rust_python_ast_phase7";

pub fn extract_python_facts(root: &Path, file: &Path, source: &str) -> PythonExtractionResult {
    let mut extractor = PythonFactExtractor::new(root, file, source);
    extractor.extract()
}

struct PythonFactExtractor<'a> {
    root: PathBuf,
    file: PathBuf,
    source: &'a str,
    facts: Vec<Fact>,
    diagnostics: Vec<ExtractionDiagnostic>,
    import_aliases: BTreeMap<String, String>,
    assignment_aliases: BTreeMap<String, String>,
    scope: Vec<String>,
    class_stack: Vec<String>,
}

impl<'a> PythonFactExtractor<'a> {
    fn new(root: &Path, file: &Path, source: &'a str) -> Self {
        Self {
            root: root.to_path_buf(),
            file: file.to_path_buf(),
            source,
            facts: Vec::new(),
            diagnostics: Vec::new(),
            import_aliases: BTreeMap::new(),
            assignment_aliases: BTreeMap::new(),
            scope: Vec::new(),
            class_stack: Vec::new(),
        }
    }

    fn extract(&mut self) -> PythonExtractionResult {
        let path = display_path(&self.file);
        let suite = match ast::Suite::parse(self.source, &path) {
            Ok(suite) => suite,
            Err(err) => {
                self.diagnostics.push(ExtractionDiagnostic {
                    file: path,
                    line: 1,
                    kind: "syntax_error".to_string(),
                    message: err.to_string(),
                });
                return PythonExtractionResult {
                    facts: Vec::new(),
                    diagnostics: std::mem::take(&mut self.diagnostics),
                };
            }
        };

        self.visit_suite(&suite);
        self.facts.sort_by_key(fact_sort_key);

        PythonExtractionResult {
            facts: std::mem::take(&mut self.facts),
            diagnostics: std::mem::take(&mut self.diagnostics),
        }
    }
}

fn fact_sort_key(fact: &Fact) -> String {
    match fact {
        Fact::Function(item) => item.base.id.clone(),
        Fact::Import(item) => item.base.id.clone(),
        Fact::Entrypoint(item) => item.base.id.clone(),
        Fact::Call(item) => item.base.id.clone(),
        Fact::Sink(item) => item.base.id.clone(),
        Fact::Source(item) => item.base.id.clone(),
        Fact::Assign(item) => item.base.id.clone(),
        Fact::Dataflow(item) => item.base.id.clone(),
        Fact::RuntimeEvent(item) => item.base.id.clone(),
        Fact::Finding(item) => item.base.id.clone(),
    }
}
```

- [ ] **Step 4: Implement statement traversal for imports/classes/functions**

Add methods to `impl PythonFactExtractor`:

```rust
fn visit_suite(&mut self, suite: &[ast::Stmt]) {
    for stmt in suite {
        self.visit_stmt(stmt);
    }
}

fn visit_stmt(&mut self, stmt: &ast::Stmt) {
    match stmt {
        ast::Stmt::Import(import) => self.visit_import(import),
        ast::Stmt::ImportFrom(import) => self.visit_import_from(import),
        ast::Stmt::FunctionDef(function) => self.visit_function_def(
            &function.name.to_string(),
            &function.args,
            &function.body,
            &function.decorator_list,
            function.range.start().to_u32(),
            function.range.end().to_u32(),
        ),
        ast::Stmt::AsyncFunctionDef(function) => self.visit_function_def(
            &function.name.to_string(),
            &function.args,
            &function.body,
            &function.decorator_list,
            function.range.start().to_u32(),
            function.range.end().to_u32(),
        ),
        ast::Stmt::ClassDef(class_def) => {
            let name = class_def.name.to_string();
            self.class_stack.push(name.clone());
            self.scope.push(name);
            self.visit_suite(&class_def.body);
            self.scope.pop();
            self.class_stack.pop();
        }
        _ => self.visit_child_statements(stmt),
    }
}
```

If RustPython 0.4 AST variants use slightly different wrapper names, inspect the compiler errors and map to the corresponding generated structs. Keep the public behavior identical to the tests.

- [ ] **Step 5: Implement line/column helpers using RustPython ranges**

Add source position helpers. RustPython `TextSize` offsets are byte offsets, so convert offsets to line/column from source text:

```rust
fn line_col_for_offset(source: &str, offset: u32) -> (u32, u32) {
    let offset = offset as usize;
    let prefix = &source[..offset.min(source.len())];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() as u32 + 1;
    let column = prefix
        .rsplit('\n')
        .next()
        .map(|item| item.chars().count() as u32)
        .unwrap_or(0);
    (line, column)
}
```

Use this helper for `FactBase.line`. For end line, call it on `range.end()`.

- [ ] **Step 6: Implement expression string rendering for parameters and decorators**

Add a conservative expression renderer:

```rust
fn expr_to_string(expr: &ast::Expr) -> String {
    match expr {
        ast::Expr::Name(name) => name.id.to_string(),
        ast::Expr::Attribute(attr) => format!("{}.{}", expr_to_string(&attr.value), attr.attr),
        ast::Expr::Call(call) => expr_to_string(&call.func),
        ast::Expr::Constant(constant) => format_constant(&constant.value),
        ast::Expr::Subscript(subscript) => {
            format!("{}[{}]", expr_to_string(&subscript.value), expr_to_string(&subscript.slice))
        }
        ast::Expr::Tuple(tuple) => tuple.elts.iter().map(expr_to_string).collect::<Vec<_>>().join(", "),
        ast::Expr::List(list) => format!("[{}]", list.elts.iter().map(expr_to_string).collect::<Vec<_>>().join(", ")),
        _ => format!("{:?}", expr),
    }
}

fn format_constant(value: &ast::Constant) -> String {
    match value {
        ast::Constant::Str(item) => item.clone(),
        ast::Constant::Int(item) => item.to_string(),
        ast::Constant::Bool(item) => item.to_string(),
        ast::Constant::None => "None".to_string(),
        _ => format!("{:?}", value),
    }
}
```

Adjust enum names if RustPython 0.4 generated constants differ. The test expectations must stay stable for `str` and `30`.

- [ ] **Step 7: Implement imports**

Add import handlers:

```rust
fn visit_import(&mut self, import: &ast::StmtImport) {
    let (line, _) = line_col_for_offset(self.source, import.range.start().to_u32());
    for alias in &import.names {
        let module = alias.name.to_string();
        let alias_name = alias.asname.as_ref().map(|item| item.to_string());
        if let Some(alias_name) = &alias_name {
            self.import_aliases.insert(alias_name.clone(), module.clone());
        } else {
            let root_name = module.split('.').next().unwrap_or(&module).to_string();
            self.import_aliases.insert(root_name, module.clone());
        }
        self.facts.push(Fact::Import(ImportFact {
            base: FactBase {
                id: make_import_id(&self.root, &self.file, line, &module),
                file: display_path(&self.file),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            language: "python".to_string(),
            module,
            imported_name: None,
            alias: alias_name.clone(),
            kind: if alias_name.is_some() { ImportKind::ImportAs } else { ImportKind::Import },
        }));
    }
}

fn visit_import_from(&mut self, import: &ast::StmtImportFrom) {
    let (line, _) = line_col_for_offset(self.source, import.range.start().to_u32());
    let module = import.module.as_ref().map(|item| item.to_string()).unwrap_or_default();
    for alias in &import.names {
        let imported_name = alias.name.to_string();
        let alias_name = alias.asname.as_ref().map(|item| item.to_string());
        let normalized = if module.is_empty() {
            imported_name.clone()
        } else {
            format!("{module}.{imported_name}")
        };
        self.import_aliases
            .insert(alias_name.clone().unwrap_or_else(|| imported_name.clone()), normalized);
        self.facts.push(Fact::Import(ImportFact {
            base: FactBase {
                id: make_import_id(&self.root, &self.file, line, &imported_name),
                file: display_path(&self.file),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            language: "python".to_string(),
            module: module.clone(),
            imported_name: Some(imported_name),
            alias: alias_name.clone(),
            kind: if alias_name.is_some() { ImportKind::FromImportAs } else { ImportKind::FromImport },
        }));
    }
}
```

- [ ] **Step 8: Implement function facts**

Add function handler:

```rust
fn visit_function_def(
    &mut self,
    name: &str,
    args: &ast::Arguments,
    body: &[ast::Stmt],
    decorators: &[ast::Expr],
    start: u32,
    end: u32,
) {
    self.scope.push(name.to_string());
    let qualified_name = self.scope.join(".");
    let (line, _) = line_col_for_offset(self.source, start);
    let (end_line, _) = line_col_for_offset(self.source, end);
    let function_id = make_function_id("python", &self.root, &self.file, &qualified_name);
    let params = params_from_arguments(args);
    let decorator_texts = decorators.iter().map(expr_to_string).collect::<Vec<_>>();
    let enclosing_class = self.class_stack.last().cloned();

    self.facts.push(Fact::Function(FunctionFact {
        base: FactBase {
            id: function_id,
            file: display_path(&self.file),
            line,
            extractor: EXTRACTOR_NAME.to_string(),
        },
        language: "python".to_string(),
        name: name.to_string(),
        qualified_name: qualified_name.clone(),
        end_line,
        params,
        decorators: decorator_texts,
        docstring: docstring_from_body(body),
        enclosing_class,
    }));

    self.visit_suite(body);
    self.scope.pop();
}
```

Add `params_from_arguments()` and `docstring_from_body()` helpers. For RustPython 0.4 arguments, map positional args, kw-only args, vararg, and kwarg if present. Defaults should align from the end of positional args.

- [ ] **Step 9: Run import/function tests**

Run:

```bash
cargo test -p mcp-sec-audit-core extracts_import_facts_and_aliases extracts_functions_async_methods_nested_and_docstrings
```

Expected: both tests pass. If RustPython AST names differ, adjust implementation while preserving test behavior.

---

### Task 5: Implement MCP Entrypoints and Source Facts

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: function facts and decorator rendering from Task 4.
- Produces: `EntryPointFact` and `SourceFact` for MCP-decorated Python functions.

- [ ] **Step 1: Add failing entrypoint/source tests**

Add to `python.rs` tests:

```rust
fn entrypoint_facts(result: &PythonExtractionResult) -> Vec<&crate::EntryPointFact> {
    result
        .facts
        .iter()
        .filter_map(|fact| match fact {
            Fact::Entrypoint(item) => Some(item),
            _ => None,
        })
        .collect()
}

fn source_facts(result: &PythonExtractionResult) -> Vec<&crate::SourceFact> {
    result
        .facts
        .iter()
        .filter_map(|fact| match fact {
            Fact::Source(item) => Some(item),
            _ => None,
        })
        .collect()
}

#[test]
fn extracts_mcp_entrypoints_and_parameter_sources() {
    let result = extract(
        r#"
@mcp.tool()
def run_command(command: str, timeout=30):
    return command

@server.resource("file://{path}")
def read_resource(path):
    return path

@mcp.prompt
def build_prompt(topic):
    return topic

class Tools:
    @server.tool()
    def method_tool(self, value):
        return value
"#,
    );

    assert!(result.diagnostics.is_empty());
    let entries = entrypoint_facts(&result);
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].name, "run_command");
    assert_eq!(entries[0].kind, crate::EntryPointKind::McpTool);
    assert_eq!(entries[1].kind, crate::EntryPointKind::McpResource);
    assert_eq!(entries[2].kind, crate::EntryPointKind::McpPrompt);

    let sources = source_facts(&result);
    let names = sources.iter().map(|item| item.name.as_str()).collect::<Vec<_>>();
    assert!(names.contains(&"command"));
    assert!(names.contains(&"timeout"));
    assert!(names.contains(&"path"));
    assert!(names.contains(&"topic"));
    assert!(names.contains(&"value"));
    assert!(!names.contains(&"self"));
}
```

- [ ] **Step 2: Run the new test and confirm failure**

Run:

```bash
cargo test -p mcp-sec-audit-core extracts_mcp_entrypoints_and_parameter_sources
```

Expected: test fails because entrypoint and source facts are not implemented.

- [ ] **Step 3: Add MCP decorator constants and classifier**

In `python.rs`, add:

```rust
use crate::{Confidence, EntryPointEvidence, EntryPointFact, EntryPointKind, SourceFact};
use super::{make_entrypoint_id, make_source_id};

const MCP_DECORATOR_PATTERNS: &[&str] = &[
    "mcp.tool",
    "mcp.resource",
    "mcp.prompt",
    "server.tool",
    "server.resource",
    "server.prompt",
    "mcp_tools",
    "mcp_tool",
    "server_tools",
];

fn classify_mcp_decorator(decorator: &str) -> Option<EntryPointKind> {
    let normalized = decorator.trim_end_matches("()");
    if !MCP_DECORATOR_PATTERNS
        .iter()
        .any(|pattern| normalized == *pattern || normalized.starts_with(&format!("{pattern}.")))
    {
        return None;
    }
    if normalized.contains("resource") {
        Some(EntryPointKind::McpResource)
    } else if normalized.contains("prompt") {
        Some(EntryPointKind::McpPrompt)
    } else {
        Some(EntryPointKind::McpTool)
    }
}
```

- [ ] **Step 4: Emit entrypoint and source facts from function handler**

Inside `visit_function_def()`, after pushing the `FunctionFact` and before visiting the body:

```rust
if let Some((kind, evidence_text)) = decorator_texts
    .iter()
    .find_map(|decorator| classify_mcp_decorator(decorator).map(|kind| (kind, decorator.clone())))
{
    let entry_id = make_entrypoint_id(&self.root, &self.file, &qualified_name);
    let param_names = params
        .iter()
        .map(|param| param.name.clone())
        .filter(|name| name != "self" && name != "cls")
        .collect::<Vec<_>>();

    self.facts.push(Fact::Entrypoint(EntryPointFact {
        base: FactBase {
            id: entry_id.clone(),
            file: display_path(&self.file),
            line,
            extractor: EXTRACTOR_NAME.to_string(),
        },
        kind,
        name: name.to_string(),
        function_id: make_function_id("python", &self.root, &self.file, &qualified_name),
        evidence: Some(EntryPointEvidence {
            kind: "decorator".to_string(),
            text: evidence_text,
        }),
        params: param_names.clone(),
        confidence: Confidence::High,
    }));

    for param in param_names {
        self.facts.push(Fact::Source(SourceFact {
            base: FactBase {
                id: make_source_id(&self.root, &self.file, &qualified_name, &param),
                file: display_path(&self.file),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            kind: "mcp_tool_parameter".to_string(),
            function_id: make_function_id("python", &self.root, &self.file, &qualified_name),
            name: param,
            confidence: Confidence::High,
        }));
    }
}
```

- [ ] **Step 5: Run entrypoint/source tests**

Run:

```bash
cargo test -p mcp-sec-audit-core extracts_mcp_entrypoints_and_parameter_sources
```

Expected: test passes.

---

### Task 6: Implement Calls, Arguments, and Alias Normalization

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: import alias map and assignment alias map.
- Produces: `CallFact` with callee, normalized callee, caller, args, kwargs, snippet, resolution.

- [ ] **Step 1: Add failing call extraction tests**

Add to tests:

```rust
fn call_facts(result: &PythonExtractionResult) -> Vec<&crate::CallFact> {
    result
        .facts
        .iter()
        .filter_map(|fact| match fact {
            Fact::Call(item) => Some(item),
            _ => None,
        })
        .collect()
}

#[test]
fn extracts_calls_with_args_kwargs_and_alias_resolution() {
    let result = extract(
        r#"
import subprocess as sp
from os import system as shell

def run(command, path):
    runner = sp.run
    runner(command, shell=True)
    shell(command)
    helper(path, mode="read")
"#,
    );

    assert!(result.diagnostics.is_empty());
    let calls = call_facts(&result);
    let normalized = calls
        .iter()
        .filter_map(|item| item.normalized_callee.as_deref())
        .collect::<Vec<_>>();

    assert!(normalized.contains(&"subprocess.run"));
    assert!(normalized.contains(&"os.system"));
    assert!(normalized.contains(&"helper"));

    let runner = calls
        .iter()
        .find(|item| item.normalized_callee.as_deref() == Some("subprocess.run"))
        .expect("runner call");
    assert_eq!(runner.caller, "python:server.py:run");
    assert_eq!(runner.args[0].index, 0);
    assert_eq!(runner.args[0].expr, "command");
    assert!(runner.kwargs.contains_key("shell"));
    assert!(runner.snippet.contains("runner(command"));
}
```

- [ ] **Step 2: Run test and confirm failure**

Run:

```bash
cargo test -p mcp-sec-audit-core extracts_calls_with_args_kwargs_and_alias_resolution
```

Expected: test fails because calls are not implemented.

- [ ] **Step 3: Add imports for call types**

In `python.rs`, add:

```rust
use serde_json::Value;
use crate::{CallArg, CallFact, CallKwarg, CallResolution};
use super::make_call_id;
```

- [ ] **Step 4: Implement child traversal and call detection**

Add traversal methods that visit statements inside function bodies and find expressions:

```rust
fn visit_child_statements(&mut self, stmt: &ast::Stmt) {
    match stmt {
        ast::Stmt::Return(item) => {
            if let Some(value) = &item.value {
                self.visit_expr(value);
            }
        }
        ast::Stmt::Expr(item) => self.visit_expr(&item.value),
        ast::Stmt::Assign(item) => {
            self.visit_assignment(&item.targets, &item.value, item.range.start().to_u32());
            self.visit_expr(&item.value);
        }
        ast::Stmt::AnnAssign(item) => {
            if let Some(value) = &item.value {
                self.visit_assignment(std::slice::from_ref(&item.target), value, item.range.start().to_u32());
                self.visit_expr(value);
            }
        }
        ast::Stmt::If(item) => {
            self.visit_expr(&item.test);
            self.visit_suite(&item.body);
            self.visit_suite(&item.orelse);
        }
        ast::Stmt::For(item) => {
            self.visit_expr(&item.iter);
            self.visit_suite(&item.body);
            self.visit_suite(&item.orelse);
        }
        ast::Stmt::While(item) => {
            self.visit_expr(&item.test);
            self.visit_suite(&item.body);
            self.visit_suite(&item.orelse);
        }
        ast::Stmt::With(item) => {
            for with_item in &item.items {
                self.visit_expr(&with_item.context_expr);
            }
            self.visit_suite(&item.body);
        }
        _ => {}
    }
}

fn visit_expr(&mut self, expr: &ast::Expr) {
    match expr {
        ast::Expr::Call(call) => self.visit_call(call),
        ast::Expr::Attribute(attr) => self.visit_expr(&attr.value),
        ast::Expr::BoolOp(item) => item.values.iter().for_each(|value| self.visit_expr(value)),
        ast::Expr::BinOp(item) => {
            self.visit_expr(&item.left);
            self.visit_expr(&item.right);
        }
        ast::Expr::UnaryOp(item) => self.visit_expr(&item.operand),
        ast::Expr::Compare(item) => {
            self.visit_expr(&item.left);
            item.comparators.iter().for_each(|value| self.visit_expr(value));
        }
        ast::Expr::List(item) => item.elts.iter().for_each(|value| self.visit_expr(value)),
        ast::Expr::Tuple(item) => item.elts.iter().for_each(|value| self.visit_expr(value)),
        ast::Expr::Dict(item) => {
            for key in item.keys.iter().flatten() {
                self.visit_expr(key);
            }
            item.values.iter().for_each(|value| self.visit_expr(value));
        }
        _ => {}
    }
}
```

Adjust AST field names as compiler requires.

- [ ] **Step 5: Implement callee normalization**

Add:

```rust
fn normalize_callee(&self, callee: &str) -> (String, Option<String>, Confidence) {
    if let Some(alias) = self.assignment_aliases.get(callee) {
        return (alias.clone(), Some(callee.to_string()), Confidence::High);
    }
    let mut parts = callee.split('.').collect::<Vec<_>>();
    if let Some(first) = parts.first().copied() {
        if let Some(resolved) = self.import_aliases.get(first) {
            parts[0] = resolved;
            return (parts.join("."), Some(first.to_string()), Confidence::High);
        }
    }
    (callee.to_string(), None, Confidence::Medium)
}
```

- [ ] **Step 6: Implement call fact builder**

Add:

```rust
fn visit_call(&mut self, call: &ast::ExprCall) {
    let callee = expr_to_string(&call.func);
    let (normalized, import_alias, confidence) = self.normalize_callee(&callee);
    let (line, column) = line_col_for_offset(self.source, call.range.start().to_u32());
    let (end_line, _) = line_col_for_offset(self.source, call.range.end().to_u32());
    let call_id = make_call_id(&self.root, &self.file, line, column);
    let caller = self
        .scope
        .last()
        .map(|_| make_function_id("python", &self.root, &self.file, &self.scope.join(".")))
        .unwrap_or_else(|| make_function_id("python", &self.root, &self.file, "<module>"));

    let args = call
        .args
        .iter()
        .enumerate()
        .map(|(index, expr)| CallArg {
            index: index as u32,
            expr: expr_to_string(expr),
            kind: "positional".to_string(),
        })
        .collect::<Vec<_>>();

    let kwargs = call
        .keywords
        .iter()
        .filter_map(|keyword| {
            keyword.arg.as_ref().map(|name| {
                (
                    name.to_string(),
                    CallKwarg {
                        expr: expr_to_string(&keyword.value),
                        value: Value::String(expr_to_string(&keyword.value)),
                    },
                )
            })
        })
        .collect();

    self.facts.push(Fact::Call(CallFact {
        base: FactBase {
            id: call_id,
            file: display_path(&self.file),
            line,
            extractor: EXTRACTOR_NAME.to_string(),
        },
        caller,
        callee,
        normalized_callee: Some(normalized),
        column: Some(column),
        end_line: Some(end_line),
        snippet: snippet_for_line(self.source, line),
        args,
        kwargs,
        resolution: Some(CallResolution {
            import_alias,
            confidence,
        }),
    }));

    self.visit_expr(&call.func);
    call.args.iter().for_each(|expr| self.visit_expr(expr));
    call.keywords.iter().for_each(|keyword| self.visit_expr(&keyword.value));
}

fn snippet_for_line(source: &str, line: u32) -> String {
    source
        .lines()
        .nth(line.saturating_sub(1) as usize)
        .unwrap_or_default()
        .trim()
        .to_string()
}
```

- [ ] **Step 7: Run call tests**

Run:

```bash
cargo test -p mcp-sec-audit-core extracts_calls_with_args_kwargs_and_alias_resolution
```

Expected: test passes.

---

### Task 7: Implement Assign Facts and Assignment Alias Resolution

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: traversal from Task 6.
- Produces: `AssignFact` and assignment alias map used by `normalize_callee()`.

- [ ] **Step 1: Add failing assignment tests**

Add to tests:

```rust
fn assign_facts(result: &PythonExtractionResult) -> Vec<&crate::AssignFact> {
    result
        .facts
        .iter()
        .filter_map(|fact| match fact {
            Fact::Assign(item) => Some(item),
            _ => None,
        })
        .collect()
}

#[test]
fn extracts_assignments_and_uses_assignment_aliases() {
    let result = extract(
        r#"
import subprocess

def run(command):
    value = command
    runner = subprocess.run
    runner(value)
"#,
    );

    assert!(result.diagnostics.is_empty());
    let assigns = assign_facts(&result);
    assert_eq!(assigns.len(), 2);
    assert!(assigns.iter().any(|item| item.target == "value" && item.value == "command"));
    assert!(assigns.iter().any(|item| item.target == "runner" && item.value == "subprocess.run"));

    let calls = call_facts(&result);
    assert!(calls
        .iter()
        .any(|item| item.normalized_callee.as_deref() == Some("subprocess.run")));
}
```

- [ ] **Step 2: Run test and confirm failure**

Run:

```bash
cargo test -p mcp-sec-audit-core extracts_assignments_and_uses_assignment_aliases
```

Expected: assignment fact assertions fail.

- [ ] **Step 3: Add assignment imports**

In `python.rs`, add:

```rust
use crate::AssignFact;
use super::make_assign_id;
```

- [ ] **Step 4: Implement target extraction helper**

Add:

```rust
fn assignment_targets(expr: &ast::Expr) -> Vec<String> {
    match expr {
        ast::Expr::Name(name) => vec![name.id.to_string()],
        ast::Expr::Attribute(attr) => vec![expr_to_string(&ast::Expr::Attribute(attr.clone()))],
        ast::Expr::Tuple(tuple) => tuple.elts.iter().flat_map(assignment_targets).collect(),
        ast::Expr::List(list) => list.elts.iter().flat_map(assignment_targets).collect(),
        _ => Vec::new(),
    }
}
```

If cloning `ast::ExprAttribute` is awkward, replace the attribute branch with `vec![format!("{}.{}", expr_to_string(&attr.value), attr.attr)]`.

- [ ] **Step 5: Implement assignment handler**

Add method:

```rust
fn visit_assignment(&mut self, targets: &[ast::Expr], value: &ast::Expr, start: u32) {
    if self.scope.is_empty() {
        return;
    }
    let (line, _) = line_col_for_offset(self.source, start);
    let value_text = expr_to_string(value);
    let normalized_value = self.normalize_callee(&value_text).0;
    let function_id = make_function_id("python", &self.root, &self.file, &self.scope.join("."));

    for target in targets.iter().flat_map(assignment_targets) {
        if normalized_value != value_text || value_text.contains('.') {
            self.assignment_aliases.insert(target.clone(), normalized_value.clone());
        }
        self.facts.push(Fact::Assign(AssignFact {
            base: FactBase {
                id: make_assign_id(&self.root, &self.file, line, &target),
                file: display_path(&self.file),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            function_id: function_id.clone(),
            target,
            value: normalized_value.clone(),
            snippet: snippet_for_line(self.source, line),
        }));
    }
}
```

- [ ] **Step 6: Run assignment tests**

Run:

```bash
cargo test -p mcp-sec-audit-core extracts_assignments_and_uses_assignment_aliases
```

Expected: test passes.

---

### Task 8: Implement Sink Facts and Syntax Diagnostics

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: `CallFact` generation and normalized callees.
- Produces: `SinkFact` for dangerous calls and syntax diagnostics for invalid Python source.

- [ ] **Step 1: Add failing sink and diagnostics tests**

Add to tests:

```rust
fn sink_facts(result: &PythonExtractionResult) -> Vec<&crate::SinkFact> {
    result
        .facts
        .iter()
        .filter_map(|fact| match fact {
            Fact::Sink(item) => Some(item),
            _ => None,
        })
        .collect()
}

#[test]
fn extracts_sink_facts_for_rce_file_and_network_calls() {
    let result = extract(
        r#"
import subprocess
import os
import requests
import socket

def run(command, path, url):
    subprocess.run(command)
    os.system(command)
    eval(command)
    open(path, "w")
    requests.get(url)
    socket.create_connection(("127.0.0.1", 80))
"#,
    );

    assert!(result.diagnostics.is_empty());
    let sinks = sink_facts(&result);
    let rules = sinks.iter().map(|item| item.rule_id.as_str()).collect::<Vec<_>>();
    assert!(rules.contains(&"rce_subprocess"));
    assert!(rules.contains(&"rce_os"));
    assert!(rules.contains(&"rce_dynamic"));
    assert!(rules.contains(&"file_access"));
    assert!(rules.contains(&"network_access"));
    assert!(rules.contains(&"network_socket"));
    assert!(sinks.iter().all(|item| !item.call_id.is_empty()));
}

#[test]
fn syntax_errors_return_diagnostics_without_facts() {
    let result = extract("def broken(:\n    pass\n");

    assert!(result.facts.is_empty());
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].kind, "syntax_error");
    assert!(result.diagnostics[0].message.contains("error") || !result.diagnostics[0].message.is_empty());
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
cargo test -p mcp-sec-audit-core extracts_sink_facts_for_rce_file_and_network_calls syntax_errors_return_diagnostics_without_facts
```

Expected: sink test fails; syntax diagnostics may already pass if Task 4 parse error handling is complete.

- [ ] **Step 3: Add sink rule struct and constants**

In `python.rs`, add:

```rust
use crate::{JsonMap, Severity, SinkFact};
use super::make_sink_id;

#[derive(Debug, Clone, Copy)]
struct SinkRule {
    patterns: &'static [&'static str],
    category: &'static str,
    rule_id: &'static str,
    severity: Severity,
    reason: &'static str,
}

const SINK_RULES: &[SinkRule] = &[
    SinkRule {
        patterns: &["subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.exec", "subprocess.check_output"],
        category: "rce",
        rule_id: "rce_subprocess",
        severity: Severity::High,
        reason: "Executes external commands",
    },
    SinkRule {
        patterns: &["os.system", "os.popen", "os.exec", "os.spawn"],
        category: "rce",
        rule_id: "rce_os",
        severity: Severity::High,
        reason: "Executes external commands via os module",
    },
    SinkRule {
        patterns: &["eval", "exec", "compile"],
        category: "rce",
        rule_id: "rce_dynamic",
        severity: Severity::High,
        reason: "Dynamic code execution",
    },
    SinkRule {
        patterns: &["open", "builtins.open", "io.open", "pathlib.Path.open", "__builtins__"],
        category: "file",
        rule_id: "file_access",
        severity: Severity::Medium,
        reason: "File system access",
    },
    SinkRule {
        patterns: &["requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch", "urllib.request", "urllib3", "http.client"],
        category: "network",
        rule_id: "network_access",
        severity: Severity::Medium,
        reason: "Network access",
    },
    SinkRule {
        patterns: &["socket.create_connection", "socket.connect"],
        category: "network",
        rule_id: "network_socket",
        severity: Severity::Medium,
        reason: "Socket connection",
    },
];

fn matching_sink_rule(callee: &str) -> Option<SinkRule> {
    SINK_RULES.iter().copied().find(|rule| {
        rule.patterns
            .iter()
            .any(|pattern| callee == *pattern || callee.starts_with(&format!("{pattern}.")))
    })
}
```

- [ ] **Step 4: Emit sink facts from call handler**

In `visit_call()`, after creating the call id and normalized callee, clone the call id into a local variable before pushing the call fact:

```rust
let call_id = make_call_id(&self.root, &self.file, line, column);
let normalized_for_sink = normalized.clone();
```

After pushing the `CallFact`, add:

```rust
if let Some(rule) = matching_sink_rule(&normalized_for_sink) {
    self.facts.push(Fact::Sink(SinkFact {
        base: FactBase {
            id: make_sink_id(rule.category, &self.root, &self.file, line),
            file: display_path(&self.file),
            line,
            extractor: EXTRACTOR_NAME.to_string(),
        },
        call_id,
        category: rule.category.to_string(),
        rule_id: rule.rule_id.to_string(),
        sink_name: normalized_for_sink,
        severity_base: rule.severity,
        reason: rule.reason.to_string(),
        conditions: JsonMap::new(),
        confidence: Confidence::High,
    }));
}
```

- [ ] **Step 5: Ensure the temporary not_implemented diagnostic is gone**

Search `python.rs` manually or with:

```bash
rg -n "not_implemented|Python fact extraction implementation is added" rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs
```

Expected: no matches. Any match means the Task 3 shell is still present and must be removed.

- [ ] **Step 6: Run full Python extractor tests**

Run:

```bash
cargo test -p mcp-sec-audit-core static_analysis::facts::python::tests
```

Expected: all Python extractor tests pass.

---

### Task 9: Wire Fact Extraction into Static Scan Pipeline

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`

**Interfaces:**
- Consumes: `extract_python_facts(root, file, source)`.
- Produces: real `extract_static_facts(ctx) -> Result<Vec<Fact>>` and populated `StaticAnalysisResult.facts`.

- [ ] **Step 1: Add failing facts pipeline tests**

In `facts/pipeline.rs`, add tests:

```rust
#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

    use crate::{RuntimeConfig, static_analysis::{DiscoveredFile, ScanLanguage, StaticScanContext}};

    use super::*;

    #[test]
    fn static_fact_pipeline_extracts_only_python_files() {
        let root = temp_dir("facts-pipeline");
        let python = root.join("server.py");
        let rust = root.join("server.rs");
        fs::write(&python, "import subprocess\ndef run(command):\n    subprocess.run(command)\n").expect("write python");
        fs::write(&rust, "fn main() {}\n").expect("write rust");

        let ctx = StaticScanContext {
            config: RuntimeConfig::default(),
            rulebook_paths: Vec::new(),
            discovered_files: vec![
                DiscoveredFile { path: python, language: ScanLanguage::Python },
                DiscoveredFile { path: rust, language: ScanLanguage::Rust },
            ],
        };

        let facts = extract_static_facts(&ctx).expect("extract facts");
        assert!(!facts.is_empty());
        assert!(facts.iter().all(|fact| match fact {
            crate::Fact::Function(item) => item.language == "python",
            crate::Fact::Import(item) => item.language == "python",
            _ => true,
        }));

        fs::remove_dir_all(root).expect("cleanup");
    }

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mcp-sec-audit-{name}-{suffix}"));
        fs::create_dir_all(&root).expect("create temp dir");
        root
    }
}
```

- [ ] **Step 2: Run facts pipeline test and confirm failure**

Run:

```bash
cargo test -p mcp-sec-audit-core static_fact_pipeline_extracts_only_python_files
```

Expected: test fails because `extract_static_facts()` still returns empty facts.

- [ ] **Step 3: Implement real static facts pipeline**

Replace `facts/pipeline.rs` implementation with:

```rust
use std::{fs, path::Path};

use anyhow::{Context, Result};

use crate::{Fact, static_analysis::{ScanLanguage, pipeline::StaticScanContext}};

use super::extract_python_facts;

pub fn extract_static_facts(ctx: &StaticScanContext) -> Result<Vec<Fact>> {
    if !ctx.config.static_.save_facts {
        return Ok(Vec::new());
    }

    let root = scan_root(ctx);
    let mut facts = Vec::new();

    for file in &ctx.discovered_files {
        if file.language != ScanLanguage::Python {
            continue;
        }
        let source = fs::read_to_string(&file.path)
            .with_context(|| format!("read Python source for fact extraction {}", file.path.display()))?;
        let result = extract_python_facts(root, &file.path, &source);
        facts.extend(result.facts);
    }

    facts.sort_by_key(fact_sort_key);
    Ok(facts)
}

fn scan_root(ctx: &StaticScanContext) -> &Path {
    ctx.config
        .scan
        .targets
        .first()
        .map(Path::new)
        .unwrap_or_else(|| Path::new("."))
}

fn fact_sort_key(fact: &Fact) -> String {
    match fact {
        Fact::Function(item) => item.base.id.clone(),
        Fact::Import(item) => item.base.id.clone(),
        Fact::Entrypoint(item) => item.base.id.clone(),
        Fact::Call(item) => item.base.id.clone(),
        Fact::Sink(item) => item.base.id.clone(),
        Fact::Source(item) => item.base.id.clone(),
        Fact::Assign(item) => item.base.id.clone(),
        Fact::Dataflow(item) => item.base.id.clone(),
        Fact::RuntimeEvent(item) => item.base.id.clone(),
        Fact::Finding(item) => item.base.id.clone(),
    }
}
```

- [ ] **Step 4: Add failing static scan integration assertions**

In `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`, update `enabled_static_scan_runs_rule_line`:

```rust
assert!(!result.facts.is_empty());
assert_eq!(result.summary.fact_count, result.facts.len());
```

- [ ] **Step 5: Run static scan integration test and confirm failure**

Run:

```bash
cargo test -p mcp-sec-audit-core enabled_static_scan_runs_rule_line
```

Expected: compile failure or assertion failure because `run_static_scan()` does not yet populate facts.

- [ ] **Step 6: Wire facts into run_static_scan**

In `static_analysis/pipeline.rs`, update imports:

```rust
use super::{DiscoveredFile, discover_files, facts, lines};
```

After `ctx` is created and before line analyzers:

```rust
let facts = facts::extract_static_facts(&ctx)?;
```

Update summary:

```rust
fact_count: facts.len(),
```

Update result construction:

```rust
Ok(StaticAnalysisResult {
    facts,
    rule_results,
    taint_results,
    agent_results,
    fused_findings: Vec::new(),
    summary,
    config_snapshot: ConfigSnapshot {
        runtime: effective_config,
        rulebook_paths: ctx.rulebook_paths,
    },
})
```

Update `empty_result()`:

```rust
facts: Vec::new(),
summary: StaticAnalysisSummary {
    target,
    fact_count: 0,
    rule_result_count: 0,
    taint_result_count: 0,
    agent_result_count: 0,
    fused_finding_count: 0,
    highest_severity: None,
    risk_level: "none".to_string(),
},
```

- [ ] **Step 7: Run pipeline tests**

Run:

```bash
cargo test -p mcp-sec-audit-core static_fact_pipeline_extracts_only_python_files enabled_static_scan_runs_rule_line disabled_static_scan_returns_empty_result
```

Expected: all pass.

---

### Task 10: Guard Taint Line and Update Default Config

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`
- Modify: `rust/config/default.toml`

**Interfaces:**
- Consumes: `StaticTaintConfig.enabled`.
- Produces: disabled taint returns empty, enabled unimplemented taint returns clear error, default config keeps scan usable.

- [ ] **Step 1: Add failing taint guard test**

In `static_analysis/pipeline.rs` tests, add:

```rust
#[test]
fn enabled_taint_line_fails_until_taint_phase_is_implemented() {
    let root = temp_dir("taint-enabled");
    let rules = write_rulebook(&root, "rules.toml", "command_exec");
    fs::write(root.join("server.py"), "def run(command):\n    return command\n").expect("write file");
    let mut config = RuntimeConfig::default();
    config.static_.taint.enabled = true;

    let err = run_static_scan(&config, &[rules], Some(&[root.clone()]))
        .expect_err("enabled taint should fail before Phase 10/11");
    assert!(err.to_string().contains("taint analysis line is enabled but not implemented"));

    fs::remove_dir_all(root).expect("cleanup");
}
```

- [ ] **Step 2: Run test and confirm failure mode**

Run:

```bash
cargo test -p mcp-sec-audit-core enabled_taint_line_fails_until_taint_phase_is_implemented
```

Expected: test fails because current `run_taint_line()` returns `Ok(Vec::new())`.

- [ ] **Step 3: Update taint line implementation**

In `rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs`, replace `run_taint_line()` with:

```rust
pub fn run_taint_line(ctx: &StaticScanContext) -> Result<Vec<TaintAnalysisResult>> {
    if !ctx.config.static_.taint.enabled {
        return Ok(Vec::new());
    }

    bail!(
        "taint analysis line is enabled but not implemented until Phase 10/11; disable [static.taint].enabled or continue the refactor roadmap"
    )
}
```

- [ ] **Step 4: Update default config**

In `rust/config/default.toml`, change:

```toml
[static.taint]
enabled = false
```

Leave the other taint options in place so Phase 10/11 can re-enable them.

- [ ] **Step 5: Update tests that use RuntimeConfig::default**

Because `RuntimeConfig::default()` currently sets taint enabled to true in code, decide whether to change the Rust default too. To keep default behavior consistent across config file and code, update `StaticTaintConfig::default()` in `config.rs`:

```rust
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
```

Update any config default tests that expected taint enabled. If there is no such test, add this assertion to the config default test area:

```rust
assert!(!RuntimeConfig::default().static_.taint.enabled);
```

- [ ] **Step 6: Run taint guard and pipeline tests**

Run:

```bash
cargo test -p mcp-sec-audit-core enabled_taint_line_fails_until_taint_phase_is_implemented enabled_static_scan_runs_rule_line
```

Expected: enabled taint explicitly fails; default static scan still passes.

---

### Task 11: Expose Public API and Update Phase Constant

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/lib.rs`

**Interfaces:**
- Produces public API exports:
  - `ExtractionDiagnostic`
  - `PythonExtractionResult`
  - `extract_python_facts`
  - `extract_static_facts`
- Produces `CURRENT_PHASE = "phase7-python-fact-extraction"`.

- [ ] **Step 1: Add failing public API test**

In `lib.rs` tests, update `exposes_current_phase`:

```rust
assert_eq!(CURRENT_PHASE, "phase7-python-fact-extraction");
```

Add:

```rust
#[test]
fn exposes_phase7_fact_extraction_api() {
    let result = extract_python_facts(
        std::path::Path::new("/repo"),
        std::path::Path::new("/repo/server.py"),
        "def run(command):\n    return command\n",
    );
    assert!(result.diagnostics.is_empty());
    assert!(!result.facts.is_empty());
}
```

- [ ] **Step 2: Run lib tests and confirm failure**

Run:

```bash
cargo test -p mcp-sec-audit-core exposes_current_phase exposes_phase7_fact_extraction_api
```

Expected: phase constant test fails and API may fail to compile if exports are missing.

- [ ] **Step 3: Re-export facts API through static_analysis**

In `static_analysis/mod.rs`, ensure these lines exist:

```rust
pub mod facts;

pub use facts::{
    ExtractionDiagnostic, PythonExtractionResult, extract_python_facts, extract_static_facts,
};
```

- [ ] **Step 4: Re-export facts API from crate root**

In `lib.rs`, update static analysis exports:

```rust
pub use static_analysis::{
    DiscoveredFile, DiscoverySummary, ExtractionDiagnostic, PythonExtractionResult, ScanLanguage,
    StaticScanContext, detect_language, discover_files, extract_python_facts, extract_static_facts,
    run_static_scan,
};
```

Update phase constant:

```rust
pub const CURRENT_PHASE: &str = "phase7-python-fact-extraction";
```

- [ ] **Step 5: Run public API tests**

Run:

```bash
cargo test -p mcp-sec-audit-core exposes_current_phase exposes_phase7_fact_extraction_api
```

Expected: tests pass.

---

### Task 12: Update Documentation for Phase 7 Completion

**Files:**
- Modify: `rust/docs/REFACTOR_PLAN.md`
- Modify: `rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md`

**Interfaces:**
- Consumes: implemented Phase 7 behavior.
- Produces: Chinese documentation reflecting completed production-grade Python fact extraction and no-empty taint guard.

- [ ] **Step 1: Update roadmap status**

In `rust/docs/REFACTOR_PLAN.md`, change Phase 7 row status from `未开始` to `完成`:

```markdown
| Phase 7：Python fact 提取 | 完成 | 从 Python 源码中提取核心静态 facts。                                  | Python fixtures 可以产出预期的函数、导入、调用、入口、sink 和相关基础 facts。                |
```

- [ ] **Step 2: Add concise Phase 7 design note**

In `rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md`, after the existing Phase 6 note in section `6.1` or near section `6.2`, add this Chinese paragraph:

```markdown
Phase 7 的 Python fact extraction 采用 Rust 原生 Python AST parser，产出真实 `FunctionFact`、`ImportFact`、`EntryPointFact`、`SourceFact`、`CallFact`、`SinkFact` 和 `AssignFact`。该阶段覆盖 MCP decorator 入口识别、参数 source、import/from-import/assignment alias resolution、危险 sink 标记和语法错误 diagnostics，并通过 `StaticAnalysisResult.facts` 保留 JSON 可审查输出。Phase 7 不声明 call graph 或 taint propagation 已完成；在 Phase 10/11 前显式启用 taint line 会返回明确错误，默认配置保持未实现 taint 关闭。
```

- [ ] **Step 3: Review documentation wording**

Run:

```bash
rg -n "Phase 7|Python fact|taint line|空实现|StaticAnalysisResult.facts" rust/docs/REFACTOR_PLAN.md rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md
```

Expected: output shows Phase 7 completion and explicit no-empty behavior.

---

### Task 13: End-to-End Verification

**Files:**
- Validate: entire Rust workspace.

**Interfaces:**
- Consumes: completed Tasks 1-12.
- Produces: verified Phase 7 implementation.

- [ ] **Step 1: Format check**

Run from `/home/xiao/Project/mcp-sec-audit/rust`:

```bash
cargo fmt --all -- --check
```

Expected: pass. If it fails, run `cargo fmt --all`, then rerun the check.

- [ ] **Step 2: Full test suite**

Run:

```bash
cargo test
```

Expected: all tests pass.

- [ ] **Step 3: Verify CLI status**

Run:

```bash
cargo run -p mcp-sec-audit-cli -- status
```

Expected: output includes `phase7-python-fact-extraction`.

- [ ] **Step 4: Verify rules still validate**

Run:

```bash
cargo run -p mcp-sec-audit-cli -- rules validate --rules ../detection/detection/rules/keywords.toml
```

Expected: rules validate successfully.

- [ ] **Step 5: Create a temporary Phase 7 fixture**

Create a temporary fixture directory outside the repo, for example `/tmp/mcp-sec-audit-phase7-fixture`, with `server.py`:

```python
import subprocess as sp
import requests

@mcp.tool()
def run_command(command: str, url: str):
    runner = sp.run
    runner(command, shell=True)
    requests.get(url)
```

Use a normal editor or shell redirection for this temporary file. Do not add it to the repository.

- [ ] **Step 6: Verify JSON scan contains facts**

Run:

```bash
cargo run -p mcp-sec-audit-cli -- scan static \
  --config config/default.toml \
  --target /tmp/mcp-sec-audit-phase7-fixture \
  --rules ../detection/detection/rules/keywords.toml \
  --format json
```

Expected output properties:

- Contains top-level `"facts"`.
- `facts` is non-empty.
- Contains function/import/entrypoint/source/call/sink/assign facts.
- Contains `"fact_count"` in `summary`.
- Does not fail due to taint because default taint is disabled.

- [ ] **Step 7: Verify JSONL fact events**

Run:

```bash
cargo run -p mcp-sec-audit-cli -- scan static \
  --config config/default.toml \
  --target /tmp/mcp-sec-audit-phase7-fixture \
  --rules ../detection/detection/rules/keywords.toml \
  --format jsonl
```

Expected: includes at least one line with `"event":"fact"`.

- [ ] **Step 8: Verify Markdown remains concise by default**

Run:

```bash
cargo run -p mcp-sec-audit-cli -- scan static \
  --config config/default.toml \
  --target /tmp/mcp-sec-audit-phase7-fixture \
  --rules ../detection/detection/rules/keywords.toml \
  --format markdown
```

Expected: Markdown summary includes `Facts: <count>` but does not dump every fact unless `report.include_facts = true` is configured.

- [ ] **Step 9: Verify explicit taint enable fails clearly**

Create a temporary config copied from `rust/config/default.toml` with `[static.taint].enabled = true`, then run the same scan.

Expected: command fails with message containing:

```text
taint analysis line is enabled but not implemented until Phase 10/11
```

- [ ] **Step 10: Inspect git diff without reverting user changes**

Run:

```bash
git diff -- rust/Cargo.toml rust/crates/mcp-sec-audit-core/Cargo.toml rust/crates/mcp-sec-audit-core/src rust/config/default.toml rust/docs/REFACTOR_PLAN.md rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md docs/superpowers/specs/2026-08-03-phase-7-python-fact-extraction-design.md docs/superpowers/plans/2026-08-03-phase-7-python-fact-extraction.md
```

Expected: diff contains only Phase 7 implementation, report/model integration, default taint disable, and Phase 7 docs/plan/spec updates.

---

## Self-Review

- **Spec coverage:** This plan implements the approved方案 A design: production-grade Python fact extraction, deterministic IDs, imports/functions/entrypoints/sources/calls/sinks/assignments, JSON facts, report integration, taint guard, default taint disable, docs, and verification.
- **Placeholder scan:** The plan contains no `TBD`, `TODO`, `implement later`, or unspecified “add tests” steps. Temporary shells are explicitly bounded to early tasks and removed by Task 8.
- **Type consistency:** Public functions are consistently named `extract_python_facts` and `extract_static_facts`; result types are consistently `PythonExtractionResult` and `ExtractionDiagnostic`; model fields are consistently `facts` and `fact_count`.
- **Scope control:** Phase 7 does not implement JS/TS/Rust facts, call graph, taint propagation, Agent analysis, fusion, or dynamic analysis. Unimplemented taint is guarded by explicit error instead of empty output.
