# Phase 7 Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Phase 7 Rust-native Python fact extraction and integrate extracted facts into static scan results without claiming later taint/fusion phases.

**Architecture:** Extend the existing RustPython AST extractor in `python.rs` to emit assign and sink facts, then connect the extractor through `facts/pipeline.rs` into `run_static_scan`. Keep taint disabled by default and make explicit taint enablement fail clearly until later phases implement it.

**Tech Stack:** Rust, Cargo workspace under `rust/Cargo.toml`, RustPython parser `rustpython-parser = "0.4"`, serde/serde_json, anyhow, TOML runtime config.

## Global Constraints

- Phase 7 is Rust-native Python fact extraction only.
- Do not implement JavaScript, TypeScript, or Rust fact extraction.
- Do not implement full assignment/dataflow semantics.
- Do not implement full Python scoping or shadowing semantics.
- Do not implement taint propagation.
- Do not implement call graph construction.
- Do not implement agent analysis.
- Do not implement finding fusion.
- Do not claim Phase 10/11 functionality exists.
- Enabled-but-unimplemented taint analysis must return an explicit error, not `Ok(Vec::new())`.
- Default taint config must be disabled.
- Commit, push, merge, or branch deletion require explicit user instruction at finish time; do not commit during plan execution unless the user explicitly asks.

---

## File Structure

- Modify `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`
  - Add assign fact tests and implementation.
  - Add sink fact tests and implementation.
  - Add syntax diagnostic tests.
  - Add intermediate print tests for Task 7 and Task 8.
- Modify `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/ids.rs`
  - Reuse existing ID helpers; only adjust if formatting requires it.
- Modify `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`
  - Implement real Python static fact extraction over discovered files.
  - Add focused pipeline tests.
- Modify `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`
  - Call `extract_static_facts` from `run_static_scan`.
  - Populate `facts` and `summary.fact_count`.
  - Add pipeline-level static scan tests.
- Modify `rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs`
  - Make enabled taint fail clearly.
  - Add taint behavior tests.
- Modify `rust/crates/mcp-sec-audit-core/src/config.rs`
  - Make Rust and serde defaults for taint enabled equal `false`.
  - Add config default tests if no existing test covers this behavior.
- Modify `rust/config/default.toml`
  - Set `[static.taint].enabled = false`.
- Modify `rust/crates/mcp-sec-audit-core/src/lib.rs`
  - Update `CURRENT_PHASE` and test after the rest passes.
- Modify `rust/docs/PHASE7_STATUS.md`
  - Mark remaining Phase 7 items completed after implementation.
- Modify `rust/docs/REFACTOR_PLAN.md`
  - Mark Phase 7 complete while preserving later-phase boundaries.
- Modify `rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md`
  - Document RustPython fact extraction and the Phase 7 boundary.

---

### Task 1: Add assign fact tests

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: existing `extract(source)` test helper, `Fact::Assign`, `AssignFact`, `Fact::Call`, Task 6 call alias behavior.
- Produces: failing tests for `Fact::Assign` and annotated assignment alias behavior.

- [ ] **Step 1: Add an assign facts helper in the test module**

Add this helper near the existing `call_facts` helper:

```rust
fn assign_facts(result: &PythonExtractionResult) -> Vec<&AssignFact> {
    result
        .facts
        .iter()
        .filter_map(|fact| match fact {
            Fact::Assign(item) => Some(item),
            _ => None,
        })
        .collect()
}
```

If `AssignFact` is not imported in the local test module scope, add it to the existing `use crate::model::{...}` list or qualify it as `crate::model::AssignFact`.

- [ ] **Step 2: Add the focused assign fact test**

Add this test in `python.rs` under the existing tests:

```rust
#[test]
fn extracts_assign_facts_and_assignment_aliases() {
    let result = extract(
        r#"
import subprocess as sp
from typing import Callable

@mcp.tool()
def run_command(command: str):
    runner: Callable = sp.run
    command_text = command.strip()
    output = runner(command_text, shell=True)
    return output
"#,
    );

    assert!(result.diagnostics.is_empty());
    let assigns = assign_facts(&result);
    assert_eq!(assigns.len(), 3);

    let runner_assign = assigns
        .iter()
        .find(|item| item.target == "runner")
        .expect("runner assignment fact");
    assert_eq!(runner_assign.value, "sp.run");
    assert_eq!(runner_assign.function_id, "python:server.py:run_command");
    assert!(runner_assign.snippet.contains("runner: Callable = sp.run"));
    assert!(runner_assign.base.id.starts_with("assign:server.py:"));

    let command_assign = assigns
        .iter()
        .find(|item| item.target == "command_text")
        .expect("command_text assignment fact");
    assert_eq!(command_assign.value, "command.strip()");

    let calls = call_facts(&result);
    let assignment_alias_call = calls
        .iter()
        .find(|item| item.callee == "runner")
        .expect("assignment alias call");
    assert_eq!(
        assignment_alias_call.normalized_callee.as_deref(),
        Some("subprocess.run")
    );
}
```

- [ ] **Step 3: Add the Task 7 printable intermediate test**

Add:

```rust
#[test]
fn prints_phase7_task7_intermediate_facts() {
    let result = extract(
        r#"
import subprocess as sp

@mcp.tool()
def run_command(command: str):
    runner = sp.run
    command_text = command.strip()
    return runner(command_text, shell=True)
"#,
    );

    assert!(result.diagnostics.is_empty());
    println!(
        "{}",
        serde_json::to_string_pretty(&result.facts).expect("serialize intermediate facts")
    );
    assert!(!assign_facts(&result).is_empty());
    assert!(!call_facts(&result).is_empty());
}
```

- [ ] **Step 4: Run assign tests and verify they fail before implementation**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core extracts_assign_facts_and_assignment_aliases
```

Expected: FAIL because `Fact::Assign` is not emitted yet.

---

### Task 2: Implement assign facts

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: `make_assign_id(root, file, line, target)`, `AssignFact`, existing `expr_to_string`, `snippet_for_range`, `caller_function_id`, `visit_assignment_alias`.
- Produces: `Fact::Assign` entries and richer assignment alias behavior for `Assign` and `AnnAssign`.

- [ ] **Step 1: Add imports for assign facts and ID helper**

At the top of `python.rs`, add `AssignFact` to the `crate::model::{...}` import and `make_assign_id` to the `super::{...}` import.

The imports should include these names:

```rust
use crate::model::{
    AssignFact, CallArg, CallFact, CallKwarg, CallResolution, Confidence, EntryPointEvidence,
    EntryPointFact, EntryPointKind, Fact, FactBase, FunctionFact, ImportFact, ImportKind,
    ParamInfo, SourceFact,
};

use super::{
    ExtractionDiagnostic, PythonExtractionResult, display_path, make_assign_id, make_call_id,
    make_entrypoint_id, make_function_id, make_import_id, make_source_id,
};
```

- [ ] **Step 2: Replace assignment statement handling**

In `visit_stmt`, replace the `Assign` arm body with:

```rust
ast::Stmt::Assign(assign) => {
    self.visit_assign_stmt(assign);
}
```

Replace the `AnnAssign` arm body with:

```rust
ast::Stmt::AnnAssign(assign) => {
    self.visit_ann_assign_stmt(assign);
}
```

Keep the `AugAssign` arm as traversal-only:

```rust
ast::Stmt::AugAssign(assign) => {
    self.visit_expr(&assign.target);
    self.visit_expr(&assign.value);
}
```

- [ ] **Step 3: Add `visit_assign_stmt`**

Add this method inside `impl PythonFactExtractor` near `visit_assignment_alias`:

```rust
fn visit_assign_stmt(&mut self, assign: &ast::StmtAssign) {
    self.visit_assignment_alias(&assign.targets, &assign.value);
    for target in &assign.targets {
        self.emit_assign_fact(target, &assign.value, assign.range.start().to_u32(), assign.range.end().to_u32());
    }
    self.visit_expr(&assign.value);
    for target in &assign.targets {
        self.visit_expr(target);
    }
}
```

If `cargo fmt` wraps the long line, accept the formatter output.

- [ ] **Step 4: Add `visit_ann_assign_stmt`**

Add:

```rust
fn visit_ann_assign_stmt(&mut self, assign: &ast::StmtAnnAssign) {
    if let Some(value) = &assign.value {
        self.visit_assignment_alias(std::slice::from_ref(&assign.target), value);
        self.emit_assign_fact(
            &assign.target,
            value,
            assign.range.start().to_u32(),
            assign.range.end().to_u32(),
        );
        self.visit_expr(value);
    }
    self.visit_expr(&assign.target);
}
```

- [ ] **Step 5: Add `emit_assign_fact`**

Add:

```rust
fn emit_assign_fact(&mut self, target: &ast::Expr, value: &ast::Expr, start: u32, end: u32) {
    if matches!(target, ast::Expr::Tuple(_) | ast::Expr::List(_)) {
        return;
    }

    let target_text = expr_to_string(target);
    if target_text.is_empty() {
        return;
    }

    let (line, _) = line_col_for_offset(self.source, start);
    self.facts.push(Fact::Assign(AssignFact {
        base: FactBase {
            id: make_assign_id(&self.root, &self.file, line, &target_text),
            file: display_path(&self.file),
            line,
            extractor: EXTRACTOR_NAME.to_string(),
        },
        function_id: self.caller_function_id().unwrap_or_default(),
        target: target_text,
        value: expr_to_string(value),
        snippet: snippet_for_range(self.source, start, end),
    }));
}
```

- [ ] **Step 6: Run assign tests**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core extracts_assign_facts_and_assignment_aliases
```

Expected: PASS.

- [ ] **Step 7: Print Task 7 intermediate facts**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core prints_phase7_task7_intermediate_facts -- --nocapture
```

Expected: PASS and JSON output includes `"type": "assign"`.

---

### Task 3: Add sink fact tests

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: existing call extraction and normalized callee behavior.
- Produces: failing tests for deterministic sink classification.

- [ ] **Step 1: Add a sink facts helper in the test module**

Add near other fact helpers:

```rust
fn sink_facts(result: &PythonExtractionResult) -> Vec<&SinkFact> {
    result
        .facts
        .iter()
        .filter_map(|fact| match fact {
            Fact::Sink(item) => Some(item),
            _ => None,
        })
        .collect()
}
```

If `SinkFact` is not imported in the local test module scope, add it to the existing `use crate::model::{...}` list or qualify it as `crate::model::SinkFact`.

- [ ] **Step 2: Add the focused sink test**

Add:

```rust
#[test]
fn extracts_sink_facts_from_dangerous_python_calls() {
    let result = extract(
        r#"
import importlib
import os
import subprocess as sp
from pathlib import Path
import requests

@mcp.tool()
def run_command(command: str, url: str, path: str):
    sp.run(command, shell=True)
    subprocess.Popen(command)
    os.system(command)
    open(path, "w").write(command)
    Path(path).write_text(command)
    requests.get(url)
    eval(command)
    importlib.import_module(command)
"#,
    );

    assert!(result.diagnostics.is_empty());
    let sinks = sink_facts(&result);
    let sink_names = sinks
        .iter()
        .map(|item| item.sink_name.as_str())
        .collect::<Vec<_>>();

    assert!(sink_names.contains(&"subprocess.run"));
    assert!(sink_names.contains(&"subprocess.Popen"));
    assert!(sink_names.contains(&"os.system"));
    assert!(sink_names.contains(&"open"));
    assert!(sink_names.contains(&"Path.write_text"));
    assert!(sink_names.contains(&"requests.get"));
    assert!(sink_names.contains(&"eval"));
    assert!(sink_names.contains(&"importlib.import_module"));

    let command_sink = sinks
        .iter()
        .find(|item| item.sink_name == "subprocess.run")
        .expect("subprocess.run sink");
    assert_eq!(command_sink.category, "command_execution");
    assert_eq!(command_sink.rule_id, "python.command_execution");
    assert!(command_sink.call_id.starts_with("call:server.py:"));
    assert!(command_sink.reason.contains("command execution"));
    assert_eq!(command_sink.confidence, Confidence::High);
}
```

- [ ] **Step 3: Add Task 8 printable intermediate test**

Add:

```rust
#[test]
fn prints_phase7_task8_intermediate_facts() {
    let result = extract(
        r#"
import os
import subprocess as sp

@mcp.tool()
def run_command(command: str):
    sp.run(command, shell=True)
    os.system(command)
"#,
    );

    assert!(result.diagnostics.is_empty());
    println!(
        "{}",
        serde_json::to_string_pretty(&result.facts).expect("serialize intermediate facts")
    );
    assert!(!call_facts(&result).is_empty());
    assert!(!sink_facts(&result).is_empty());
}
```

- [ ] **Step 4: Run sink test and verify it fails before implementation**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core extracts_sink_facts_from_dangerous_python_calls
```

Expected: FAIL because `Fact::Sink` is not emitted yet.

---

### Task 4: Implement sink facts

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: `CallFact`, `make_sink_id`, `Severity`, `SinkFact`, call normalized callee.
- Produces: `Fact::Sink` entries linked to call IDs.

- [ ] **Step 1: Add imports for sink facts**

At the top of `python.rs`, add `Severity` and `SinkFact` to the `crate::model::{...}` import and `make_sink_id` to the `super::{...}` import.

The imports should include these names:

```rust
use crate::model::{
    AssignFact, CallArg, CallFact, CallKwarg, CallResolution, Confidence, EntryPointEvidence,
    EntryPointFact, EntryPointKind, Fact, FactBase, FunctionFact, ImportFact, ImportKind,
    ParamInfo, Severity, SinkFact, SourceFact,
};

use super::{
    ExtractionDiagnostic, PythonExtractionResult, display_path, make_assign_id, make_call_id,
    make_entrypoint_id, make_function_id, make_import_id, make_sink_id, make_source_id,
};
```

- [ ] **Step 2: Change `visit_call_expr` to build and reuse the call fact**

Inside `visit_call_expr`, instead of pushing `Fact::Call(CallFact { ... })` directly, create local variables for `call_id`, `line`, `column`, `callee`, `normalized_callee`, `args`, `kwargs`, and then build a `CallFact` value:

```rust
let call_id = make_call_id(&self.root, &self.file, line, column);
let call_fact = CallFact {
    base: FactBase {
        id: call_id,
        file: display_path(&self.file),
        line,
        extractor: EXTRACTOR_NAME.to_string(),
    },
    caller: self.caller_function_id().unwrap_or_default(),
    callee: callee.clone(),
    normalized_callee: Some(normalized_callee),
    column: Some(column),
    end_line: Some(end_line),
    snippet: snippet_for_range(
        self.source,
        call.range.start().to_u32(),
        call.range.end().to_u32(),
    ),
    args,
    kwargs,
    resolution: import_alias.map(|alias| CallResolution {
        import_alias: Some(alias),
        confidence: Confidence::High,
    }),
};
self.emit_sink_for_call(&call_fact);
self.facts.push(Fact::Call(call_fact));
```

- [ ] **Step 3: Add `emit_sink_for_call`**

Add this method in `impl PythonFactExtractor`:

```rust
fn emit_sink_for_call(&mut self, call: &CallFact) {
    let sink_name = call
        .normalized_callee
        .as_deref()
        .unwrap_or(call.callee.as_str())
        .to_string();

    let Some(classification) = classify_sink(&sink_name, call) else {
        return;
    };

    let mut conditions = BTreeMap::new();
    conditions.insert(
        "callee".to_string(),
        serde_json::Value::String(call.callee.clone()),
    );
    conditions.insert(
        "normalized_callee".to_string(),
        serde_json::Value::String(sink_name.clone()),
    );
    conditions.insert(
        "snippet".to_string(),
        serde_json::Value::String(call.snippet.clone()),
    );

    self.facts.push(Fact::Sink(SinkFact {
        base: FactBase {
            id: make_sink_id(classification.category, &self.root, &self.file, call.base.line),
            file: call.base.file.clone(),
            line: call.base.line,
            extractor: EXTRACTOR_NAME.to_string(),
        },
        call_id: call.base.id.clone(),
        category: classification.category.to_string(),
        rule_id: format!("python.{}", classification.category),
        sink_name,
        severity_base: classification.severity,
        reason: classification.reason.to_string(),
        conditions,
        confidence: classification.confidence,
    }));
}
```

- [ ] **Step 4: Add sink classification structs and function**

Outside `impl PythonFactExtractor`, add:

```rust
#[derive(Debug, Clone, Copy)]
struct SinkClassification {
    category: &'static str,
    severity: Severity,
    reason: &'static str,
    confidence: Confidence,
}

fn classify_sink(callee: &str, call: &CallFact) -> Option<SinkClassification> {
    match callee {
        "subprocess.run" | "subprocess.Popen" | "os.system" | "os.popen" => Some(
            SinkClassification {
                category: "command_execution",
                severity: Severity::High,
                reason: "Python command execution call can execute attacker-controlled commands",
                confidence: Confidence::High,
            },
        ),
        "Path.write_text" | "Path.write_bytes" => Some(SinkClassification {
            category: "file_write",
            severity: Severity::Medium,
            reason: "Python file write call can modify filesystem contents",
            confidence: Confidence::High,
        }),
        "open" if open_call_writes(call) => Some(SinkClassification {
            category: "file_write",
            severity: Severity::Medium,
            reason: "Python open call uses a write-capable file mode",
            confidence: Confidence::High,
        }),
        "eval" | "exec" => Some(SinkClassification {
            category: "dynamic_execution",
            severity: Severity::Critical,
            reason: "Python dynamic execution call can execute attacker-controlled code",
            confidence: Confidence::High,
        }),
        "requests.get" | "requests.post" | "requests.request" | "httpx.get" | "httpx.post"
        | "httpx.request" | "urllib.request.urlopen" => Some(SinkClassification {
            category: "network_request",
            severity: Severity::Medium,
            reason: "Python network request call can reach attacker-controlled URLs",
            confidence: Confidence::Medium,
        }),
        "importlib.import_module" | "__import__" => Some(SinkClassification {
            category: "dynamic_import",
            severity: Severity::Medium,
            reason: "Python dynamic import call can load attacker-controlled modules",
            confidence: Confidence::Medium,
        }),
        _ => None,
    }
}
```

- [ ] **Step 5: Add write-mode helper functions**

Add:

```rust
fn open_call_writes(call: &CallFact) -> bool {
    if let Some(mode) = call.kwargs.get("mode") {
        return file_mode_writes(&mode.expr);
    }
    call.args
        .get(1)
        .map(|arg| file_mode_writes(&arg.expr))
        .unwrap_or(false)
}

fn file_mode_writes(mode: &str) -> bool {
    let trimmed = mode.trim_matches(|ch| ch == '\'' || ch == '"');
    trimmed.contains('w') || trimmed.contains('a') || trimmed.contains('x') || trimmed.contains('+')
}
```

- [ ] **Step 6: Run sink tests**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core extracts_sink_facts_from_dangerous_python_calls
```

Expected: PASS.

- [ ] **Step 7: Print Task 8 intermediate facts**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core prints_phase7_task8_intermediate_facts -- --nocapture
```

Expected: PASS and JSON output includes `"type": "sink"`.

---

### Task 5: Add syntax diagnostic tests

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: `extract(source)` test helper and current `ExtractionDiagnostic` behavior.
- Produces: test coverage that parser failures are visible and do not forge facts.

- [ ] **Step 1: Add syntax diagnostic test**

Add:

```rust
#[test]
fn syntax_errors_return_diagnostic_without_facts() {
    let result = extract("def broken(:\n    pass\n");

    assert!(result.facts.is_empty());
    assert_eq!(result.diagnostics.len(), 1);
    let diagnostic = &result.diagnostics[0];
    assert_eq!(diagnostic.file, "server.py");
    assert_eq!(diagnostic.kind, "syntax_error");
    assert!(diagnostic.line >= 1);
    assert!(!diagnostic.message.is_empty());
}
```

- [ ] **Step 2: Run syntax diagnostic test**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core syntax_errors_return_diagnostic_without_facts
```

Expected: PASS. If `line` is still always `1`, this test accepts that current behavior while confirming visibility.

---

### Task 6: Implement static facts pipeline

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`

**Interfaces:**
- Consumes: `StaticScanContext`, `DiscoveredFile`, `ScanLanguage::Python`, `extract_python_facts`.
- Produces: real `extract_static_facts(ctx) -> Result<Vec<Fact>>` implementation.

- [ ] **Step 1: Replace placeholder imports**

Replace the contents of `facts/pipeline.rs` imports with:

```rust
use std::fs;

use anyhow::{Context, Result, bail};

use crate::{Fact, ScanLanguage, static_analysis::pipeline::StaticScanContext};

use super::extract_python_facts;
```

- [ ] **Step 2: Replace placeholder function**

Replace:

```rust
pub fn extract_static_facts(_ctx: &StaticScanContext) -> Result<Vec<Fact>> {
    Ok(Vec::new())
}
```

with:

```rust
pub fn extract_static_facts(ctx: &StaticScanContext) -> Result<Vec<Fact>> {
    let mut facts = Vec::new();
    let mut diagnostics = Vec::new();

    for file in &ctx.discovered_files {
        if file.language != ScanLanguage::Python {
            continue;
        }

        let source = fs::read_to_string(&file.path)
            .with_context(|| format!("read Python source for fact extraction: {}", file.path.display()))?;
        let root = file.path.parent().unwrap_or_else(|| file.path.as_path());
        let result = extract_python_facts(root, &file.path, &source);
        facts.extend(result.facts);
        diagnostics.extend(result.diagnostics);
    }

    if !diagnostics.is_empty() {
        let summary = diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "{}:{} {}: {}",
                    diagnostic.file, diagnostic.line, diagnostic.kind, diagnostic.message
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        bail!("Python fact extraction produced diagnostics: {summary}");
    }

    Ok(facts)
}
```

- [ ] **Step 3: Add tests module to `facts/pipeline.rs`**

Add below the function:

```rust
#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{RuntimeConfig, static_analysis::DiscoveredFile};

    #[test]
    fn extract_static_facts_reads_python_discovered_files() {
        let root = temp_dir("facts-pipeline");
        let file = root.join("server.py");
        fs::write(
            &file,
            r#"
import subprocess as sp

@mcp.tool()
def run_command(command: str):
    runner = sp.run
    return runner(command, shell=True)
"#,
        )
        .expect("write Python file");

        let ctx = StaticScanContext {
            config: RuntimeConfig::default(),
            rulebook_paths: Vec::new(),
            discovered_files: vec![DiscoveredFile {
                path: file,
                language: ScanLanguage::Python,
            }],
        };

        let facts = extract_static_facts(&ctx).expect("extract facts");
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Import(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Function(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Entrypoint(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Source(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Call(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Assign(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Sink(_))));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn extract_static_facts_reports_python_diagnostics() {
        let root = temp_dir("facts-diagnostic");
        let file = root.join("broken.py");
        fs::write(&file, "def broken(:\n    pass\n").expect("write Python file");

        let ctx = StaticScanContext {
            config: RuntimeConfig::default(),
            rulebook_paths: Vec::new(),
            discovered_files: vec![DiscoveredFile {
                path: file,
                language: ScanLanguage::Python,
            }],
        };

        let err = extract_static_facts(&ctx).expect_err("diagnostics should fail extraction");
        assert!(err.to_string().contains("Python fact extraction produced diagnostics"));
        assert!(err.to_string().contains("syntax_error"));

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

- [ ] **Step 4: Run facts pipeline tests**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::facts::pipeline::tests
```

Expected: PASS.

---

### Task 7: Wire facts into static scan

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`

**Interfaces:**
- Consumes: `extract_static_facts(&ctx) -> Result<Vec<Fact>>` from Task 6.
- Produces: `StaticAnalysisResult.facts` and `summary.fact_count` populated in normal static scan.

- [ ] **Step 1: Import `extract_static_facts`**

Change the `use super::{...};` line from:

```rust
use super::{DiscoveredFile, discover_files, lines};
```

to:

```rust
use super::{DiscoveredFile, discover_files, extract_static_facts, lines};
```

- [ ] **Step 2: Call `extract_static_facts` before lines**

In `run_static_scan`, after constructing `ctx` and before `run_rule_line`, add:

```rust
let facts = extract_static_facts(&ctx)?;
```

- [ ] **Step 3: Use real fact count in summary**

Change:

```rust
fact_count: 0,
```

to:

```rust
fact_count: facts.len(),
```

- [ ] **Step 4: Store real facts in result**

Change:

```rust
facts: Vec::new(),
```

to:

```rust
facts,
```

- [ ] **Step 5: Update existing static scan test for default taint behavior**

The existing `enabled_static_scan_runs_rule_line` test should continue to assert:

```rust
assert_eq!(result.summary.taint_result_count, 0);
```

Add these assertions to it:

```rust
assert!(!result.facts.is_empty());
assert_eq!(result.summary.fact_count, result.facts.len());
assert!(result.facts.iter().any(|fact| matches!(fact, Fact::Call(_))));
assert!(result.facts.iter().any(|fact| matches!(fact, Fact::Sink(_))));
```

If `Fact` is not in scope in the tests module, add `use crate::Fact;`.

- [ ] **Step 6: Add a pipeline-level all-fact-types test**

Add this test in `static_analysis/pipeline.rs` tests:

```rust
#[test]
fn enabled_static_scan_includes_python_facts_and_fact_count() {
    let root = temp_dir("scan-facts");
    let rules = write_rulebook(&root, "rules.toml", "command_exec");
    fs::write(
        root.join("server.py"),
        r#"
import subprocess as sp

@mcp.tool()
def run_command(command: str):
    runner = sp.run
    command_text = command.strip()
    return runner(command_text, shell=True)
"#,
    )
    .expect("write file");

    let result = run_static_scan(&RuntimeConfig::default(), &[rules], Some(&[root.clone()]))
        .expect("run scan");

    assert!(!result.facts.is_empty());
    assert_eq!(result.summary.fact_count, result.facts.len());
    assert!(result.facts.iter().any(|fact| matches!(fact, Fact::Import(_))));
    assert!(result.facts.iter().any(|fact| matches!(fact, Fact::Function(_))));
    assert!(result.facts.iter().any(|fact| matches!(fact, Fact::Entrypoint(_))));
    assert!(result.facts.iter().any(|fact| matches!(fact, Fact::Source(_))));
    assert!(result.facts.iter().any(|fact| matches!(fact, Fact::Call(_))));
    assert!(result.facts.iter().any(|fact| matches!(fact, Fact::Assign(_))));
    assert!(result.facts.iter().any(|fact| matches!(fact, Fact::Sink(_))));
    assert_eq!(result.summary.taint_result_count, 0);

    fs::remove_dir_all(root).expect("cleanup");
}
```

- [ ] **Step 7: Run static pipeline tests**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::pipeline::tests
```

Expected: PASS after default taint is disabled in Task 8. If this fails before Task 8 because taint is still enabled, continue to Task 8 and rerun.

---

### Task 8: Disable taint by default and error when enabled

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/config.rs`
- Modify: `rust/config/default.toml`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs`

**Interfaces:**
- Consumes: `RuntimeConfig::default`, `parse_runtime_config_toml`, `run_taint_line`.
- Produces: default disabled taint and clear enabled-taint error.

- [ ] **Step 1: Add a false default helper in config**

In `config.rs`, near `default_true`, add:

```rust
fn default_false() -> bool {
    false
}
```

If a false helper already exists, reuse it instead.

- [ ] **Step 2: Change `StaticTaintConfig.enabled` serde default**

Change:

```rust
#[serde(default = "default_true")]
pub enabled: bool,
```

to:

```rust
#[serde(default = "default_false")]
pub enabled: bool,
```

- [ ] **Step 3: Change Rust default taint enabled**

In `impl Default for StaticTaintConfig`, change:

```rust
enabled: true,
```

to:

```rust
enabled: false,
```

- [ ] **Step 4: Add config tests**

If no config tests module exists, add one at the bottom of `config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_taint_is_disabled() {
        assert!(!RuntimeConfig::default().static_.taint.enabled);
    }

    #[test]
    fn missing_taint_enabled_defaults_to_disabled() {
        let config = parse_runtime_config_toml(
            r#"
[static]
enabled = true

[static.taint]
forward = true
"#,
        )
        .expect("parse config");

        assert!(!config.static_.taint.enabled);
    }
}
```

If a tests module already exists, add these tests inside it.

- [ ] **Step 5: Update default TOML**

In `rust/config/default.toml`, change:

```toml
[static.taint]
enabled = true
```

to:

```toml
[static.taint]
enabled = false
```

- [ ] **Step 6: Change enabled taint behavior**

In `lines.rs`, replace:

```rust
Ok(Vec::new())
```

inside `run_taint_line` with:

```rust
bail!(
    "taint analysis line is enabled but not implemented until Phase 10/11; disable [static.taint].enabled or continue the refactor roadmap"
)
```

Keep disabled behavior returning `Ok(Vec::new())`.

- [ ] **Step 7: Add taint line tests**

In `lines.rs` tests module, add:

```rust
#[test]
fn disabled_taint_line_returns_empty() {
    let mut config = RuntimeConfig::default();
    config.static_.taint.enabled = false;
    let ctx = StaticScanContext {
        config,
        rulebook_paths: Vec::new(),
        discovered_files: Vec::<DiscoveredFile>::new(),
    };

    let results = run_taint_line(&ctx).expect("disabled taint should be empty");
    assert!(results.is_empty());
}

#[test]
fn enabled_taint_line_reports_unimplemented_error() {
    let mut config = RuntimeConfig::default();
    config.static_.taint.enabled = true;
    let ctx = StaticScanContext {
        config,
        rulebook_paths: Vec::new(),
        discovered_files: Vec::<DiscoveredFile>::new(),
    };

    let err = run_taint_line(&ctx).expect_err("enabled taint should fail clearly");
    assert!(err.to_string().contains("taint analysis line is enabled but not implemented"));
}
```

- [ ] **Step 8: Run config and line tests**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core default_taint_is_disabled missing_taint_enabled_defaults_to_disabled disabled_taint_line_returns_empty enabled_taint_line_reports_unimplemented_error
```

Expected: PASS. If Cargo does not accept multiple filters in this form, run each filter separately.

---

### Task 9: Update phase constant

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/lib.rs`

**Interfaces:**
- Consumes: completed Phase 7 behavior from previous tasks.
- Produces: public phase constant and test updated to Phase 7.

- [ ] **Step 1: Update `CURRENT_PHASE`**

In `lib.rs`, change:

```rust
pub const CURRENT_PHASE: &str = "phase6-traditional-rule-analysis";
```

to:

```rust
pub const CURRENT_PHASE: &str = "phase7-python-fact-extraction";
```

- [ ] **Step 2: Update phase test**

Change:

```rust
assert_eq!(CURRENT_PHASE, "phase6-traditional-rule-analysis");
```

to:

```rust
assert_eq!(CURRENT_PHASE, "phase7-python-fact-extraction");
```

- [ ] **Step 3: Run phase test**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core exposes_current_phase
```

Expected: PASS.

---

### Task 10: Update Phase 7 documentation

**Files:**
- Modify: `rust/docs/PHASE7_STATUS.md`
- Modify: `rust/docs/REFACTOR_PLAN.md`
- Modify: `rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md`

**Interfaces:**
- Consumes: completed implementation and verification results.
- Produces: Chinese docs that truthfully mark Phase 7 complete and preserve later-phase boundaries.

- [ ] **Step 1: Update `PHASE7_STATUS.md`**

Edit `rust/docs/PHASE7_STATUS.md` so it states:

```markdown
第七阶段已经完成：Rust-native Python fact extraction 已经接入静态扫描结果。
```

Ensure the completed list includes:

```markdown
- Python assign facts。
- Python sink facts。
- syntax diagnostics 测试。
- `extract_static_facts` 真实 pipeline。
- `run_static_scan` 接入 facts。
- taint line 默认禁用，显式启用时报错。
- phase 常量更新为 `phase7-python-fact-extraction`。
- end-to-end JSON 验证。
```

Ensure the document still states:

```markdown
第七阶段不是完整 taint propagation、完整 call graph、Agent 分析、finding fusion 或动态分析。
```

- [ ] **Step 2: Update `REFACTOR_PLAN.md`**

Find the Phase 7 section or row. Change it to state Phase 7 is complete and summarize:

```markdown
Phase 7 完成 Rust-native Python fact extraction：imports、functions、MCP entrypoints、sources、calls、assigns、sinks，JSON 保存 facts，Markdown/JSONL 可配置展示 facts。
```

Also state later work remains in later phases:

```markdown
完整 taint propagation、call graph、fusion、agent line 和 dynamic correlation 仍属于后续阶段。
```

- [ ] **Step 3: Update `STATIC_ANALYSIS_REFACTOR_DESIGN.md`**

Add or update a Phase 7 note explaining:

```markdown
Phase 7 使用 RustPython AST 在 Rust core 中提取 Python facts，并通过 `extract_static_facts` / `run_static_scan` 写入 `StaticAnalysisResult.facts` 和 `summary.fact_count`。
```

Mention supported fact types:

```markdown
import、function、entrypoint、source、call、assign、sink
```

Mention taint boundary:

```markdown
taint line 默认禁用；显式启用时在 Phase 10/11 前返回明确错误，避免空实现伪装成功。
```

- [ ] **Step 4: Review docs for premature claims**

Search the edited doc sections manually and ensure they do not claim that Phase 7 implements:

- full taint propagation,
- complete call graph,
- finding fusion,
- agent analysis,
- dynamic analysis.

---

### Task 11: Run focused Phase 7 tests

**Files:**
- Test only.

**Interfaces:**
- Consumes: all implementation tasks.
- Produces: focused verification before full suite.

- [ ] **Step 1: Run Python fact extractor tests**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::facts::python::tests
```

Expected: PASS.

- [ ] **Step 2: Run facts pipeline tests**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::facts::pipeline::tests
```

Expected: PASS.

- [ ] **Step 3: Run static scan pipeline tests**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::pipeline::tests
```

Expected: PASS.

- [ ] **Step 4: Run taint/config/phase focused tests**

Run these if the combined filter is not supported:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core default_taint_is_disabled
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core missing_taint_enabled_defaults_to_disabled
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core disabled_taint_line_returns_empty
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core enabled_taint_line_reports_unimplemented_error
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core exposes_current_phase
```

Expected: all PASS.

---

### Task 12: Run formatting, full tests, and static scan JSON verification

**Files:**
- Test only.

**Interfaces:**
- Consumes: all implementation and docs tasks.
- Produces: final verification before finishing branch workflow.

- [ ] **Step 1: Run formatter check**

Run:

```bash
cargo fmt --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml --all -- --check
```

Expected: PASS. If it fails, run:

```bash
cargo fmt --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml --all
```

Then rerun the check.

- [ ] **Step 2: Run full core tests**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml -p mcp-sec-audit-core
```

Expected: PASS.

- [ ] **Step 3: Create a temporary Phase 7 Python fixture for manual JSON verification**

Use an existing temp directory or create a project-local untracked fixture under `targets/phase7-e2e/server.py` with this content:

```python
import os
import subprocess as sp

@mcp.tool()
def run_command(command: str):
    runner = sp.run
    command_text = command.strip()
    os.system(command_text)
    return runner(command_text, shell=True)
```

- [ ] **Step 4: Run static scan JSON output**

Run:

```bash
cargo run --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-cli -- scan static \
  --config /home/xiao/Project/mcp-sec-audit/rust/config/default.toml \
  --target /home/xiao/Project/mcp-sec-audit/targets/phase7-e2e \
  --rules /home/xiao/Project/mcp-sec-audit/detection/detection/rules/keywords.toml \
  --format json
```

Expected JSON properties:

- top-level `facts` is non-empty,
- `summary.fact_count` equals `facts.length`,
- `rule_results` remains present if rules match,
- `taint_results` is empty by default.

- [ ] **Step 5: Verify explicit taint enablement fails clearly**

Create a temporary config by copying `rust/config/default.toml` and setting `[static.taint].enabled = true`, or use an existing test fixture if available. Run static scan with that config.

Expected: command fails with:

```text
taint analysis line is enabled but not implemented until Phase 10/11
```

- [ ] **Step 6: Capture final git status**

Run:

```bash
git status --short
```

Expected: working tree contains Phase 7 changes and pre-existing untracked docs/targets as applicable. Do not commit or merge until the user confirms the finishing branch step.

---

## Self-review notes

- Spec coverage: all accepted spec sections map to Tasks 1-12.
- Placeholder scan: no TBD/TODO placeholders are present.
- Type consistency: plan uses existing model names `AssignFact`, `SinkFact`, `CallFact`, `Fact`, `Confidence`, `Severity`, `RuntimeConfig`, `StaticScanContext`, and `ScanLanguage` from the current codebase.
- Boundary check: the plan explicitly avoids taint propagation, call graph, fusion, agent analysis, and dynamic analysis.
