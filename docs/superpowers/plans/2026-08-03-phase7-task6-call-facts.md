# Phase 7 Task 6 Call Facts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Python `Fact::Call` extraction with import alias normalization and narrow assignment alias normalization for Phase 7 Task 6.

**Architecture:** Extend the existing RustPython AST visitor in `python.rs` without changing the public result model or pipeline wiring. Add expression traversal that emits `CallFact` records, then layer deterministic normalization helpers over the extractor's existing import alias map and a renamed assignment alias map.

**Tech Stack:** Rust, RustPython parser `rustpython-parser = "0.4"`, existing `mcp-sec-audit-core` model types, Cargo tests.

## Global Constraints

- This task only implements Phase 7 Task 6.
- Do not generate `Fact::Assign` in this task.
- Do not implement sink facts, call graph construction, taint propagation, static pipeline integration, phase constant updates, final documentation updates, or Phase 7 completion marking.
- Keep syntax error behavior unchanged: return a `syntax_error` diagnostic, return no facts, and do not panic.
- Unknown or unsupported alias cases must fall back to the original rendered callee.
- Follow the current single-file extractor style in `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`.

---

## File Structure

- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`
  - Import `CallArg`, `CallFact`, `CallKwarg`, `CallResolution`, and `make_call_id`.
  - Rename `_assignment_aliases` to `assignment_aliases`.
  - Add statement/expression traversal for calls.
  - Add narrow assignment alias tracking for `name = callable_expr`.
  - Add callee normalization helpers.
  - Add snippet extraction helper.
  - Add Task 6 tests.
- No model file changes are planned. `CallFact`, `CallArg`, `CallKwarg`, and `CallResolution` already exist in `rust/crates/mcp-sec-audit-core/src/model/facts.rs`.
- No changes to `ids.rs` are planned. `make_call_id(root, file, line, column)` already exists.

---

### Task 1: Add Failing Call Fact Tests

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: Existing `extract(source: &str) -> PythonExtractionResult` test helper.
- Produces: A failing test that defines the exact Task 6 behavior before implementation.

- [ ] **Step 1: Update test imports**

In the `#[cfg(test)] mod tests` import list, change:

```rust
use crate::model::{
    EntryPointFact, EntryPointKind, Fact, FunctionFact, ImportFact, ImportKind, SourceFact,
};
```

to:

```rust
use crate::model::{
    CallFact, EntryPointFact, EntryPointKind, Fact, FunctionFact, ImportFact, ImportKind,
    SourceFact,
};
```

- [ ] **Step 2: Add a call facts test helper**

After the existing `source_facts` helper, add:

```rust
fn call_facts(result: &PythonExtractionResult) -> Vec<&CallFact> {
    result
        .facts
        .iter()
        .filter_map(|fact| match fact {
            Fact::Call(item) => Some(item),
            _ => None,
        })
        .collect()
}
```

- [ ] **Step 3: Add the failing focused Task 6 test**

Add this test before `prints_phase7_task5_intermediate_facts`:

```rust
#[test]
fn extracts_calls_with_args_kwargs_and_alias_resolution() {
    let result = extract(
        r#"
import subprocess as sp
from subprocess import run

@mcp.tool()
def run_command(command: str, timeout=30):
    direct = subprocess.run(command)
    aliased = sp.run(command, shell=True, timeout=timeout)
    imported = run(command)
    runner = sp.run
    return runner(command, shell=True)
"#,
    );

    assert!(result.diagnostics.is_empty());
    let calls = call_facts(&result);
    let normalized = calls
        .iter()
        .map(|item| item.normalized_callee.as_deref().unwrap_or(item.callee.as_str()))
        .collect::<Vec<_>>();

    assert!(normalized.contains(&"subprocess.run"));
    assert_eq!(
        normalized
            .iter()
            .filter(|callee| **callee == "subprocess.run")
            .count(),
        4
    );

    let shell_call = calls
        .iter()
        .find(|item| item.kwargs.contains_key("shell"))
        .expect("call with shell kwarg");
    assert_eq!(shell_call.callee, "sp.run");
    assert_eq!(shell_call.normalized_callee.as_deref(), Some("subprocess.run"));
    assert_eq!(shell_call.args[0].index, 0);
    assert_eq!(shell_call.args[0].expr, "command");
    assert_eq!(shell_call.kwargs["shell"].expr, "True");
    assert_eq!(shell_call.caller, "python:server.py:run_command");
    assert!(shell_call.column.is_some());
    assert!(shell_call.snippet.contains("sp.run"));
    assert_eq!(
        shell_call
            .resolution
            .as_ref()
            .and_then(|item| item.import_alias.as_deref()),
        Some("sp")
    );

    let assignment_alias_call = calls
        .iter()
        .find(|item| item.callee == "runner")
        .expect("assignment alias call");
    assert_eq!(
        assignment_alias_call.normalized_callee.as_deref(),
        Some("subprocess.run")
    );
    assert_eq!(
        assignment_alias_call
            .resolution
            .as_ref()
            .and_then(|item| item.import_alias.as_deref()),
        Some("runner")
    );
}
```

- [ ] **Step 4: Add the failing printable intermediate test**

Add this test immediately after the focused Task 6 test:

```rust
#[test]
fn prints_phase7_task6_intermediate_facts() {
    let result = extract(
        r#"
import subprocess as sp
from subprocess import run

@mcp.tool()
def run_command(command: str, timeout=30):
    runner = sp.run
    direct = subprocess.run(command)
    aliased = sp.run(command, shell=True, timeout=timeout)
    imported = run(command)
    return runner(command, shell=True)
"#,
    );

    assert!(result.diagnostics.is_empty());
    println!(
        "{}",
        serde_json::to_string_pretty(&result.facts).expect("serialize intermediate facts")
    );
    assert!(!import_facts(&result).is_empty());
    assert!(!function_facts(&result).is_empty());
    assert!(!entrypoint_facts(&result).is_empty());
    assert!(!source_facts(&result).is_empty());
    assert!(!call_facts(&result).is_empty());
}
```

- [ ] **Step 5: Run the focused test and verify it fails**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core extracts_calls_with_args_kwargs_and_alias_resolution
```

Expected: FAIL because `Fact::Call` extraction has not been implemented yet, so `call_facts(&result)` is empty.

- [ ] **Step 6: Commit the failing tests**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs
git commit -m "test: add phase 7 python call fact expectations"
```

---

### Task 2: Add Call Fact Model Imports and Alias State

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: Existing model structs from `crate::model` and existing `make_call_id` from `facts::ids`.
- Produces: Compile-ready imports and assignment alias state for later traversal.

- [ ] **Step 1: Extend model imports**

At the top of `python.rs`, replace:

```rust
use crate::model::{
    Confidence, EntryPointEvidence, EntryPointFact, EntryPointKind, Fact, FactBase, FunctionFact,
    ImportFact, ImportKind, ParamInfo, SourceFact,
};
```

with:

```rust
use crate::model::{
    CallArg, CallFact, CallKwarg, CallResolution, Confidence, EntryPointEvidence, EntryPointFact,
    EntryPointKind, Fact, FactBase, FunctionFact, ImportFact, ImportKind, ParamInfo, SourceFact,
};
```

- [ ] **Step 2: Import `make_call_id`**

Replace:

```rust
use super::{
    ExtractionDiagnostic, PythonExtractionResult, display_path, make_entrypoint_id, make_function_id,
    make_import_id, make_source_id,
};
```

with:

```rust
use super::{
    ExtractionDiagnostic, PythonExtractionResult, display_path, make_call_id, make_entrypoint_id,
    make_function_id, make_import_id, make_source_id,
};
```

- [ ] **Step 3: Rename assignment alias field**

In `PythonFactExtractor`, replace:

```rust
_assignment_aliases: BTreeMap<String, String>,
```

with:

```rust
assignment_aliases: BTreeMap<String, String>,
```

In `new`, replace:

```rust
_assignment_aliases: BTreeMap::new(),
```

with:

```rust
assignment_aliases: BTreeMap::new(),
```

- [ ] **Step 4: Run tests to verify no behavior changed**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::facts::python::tests
```

Expected: Existing tests pass except the new Task 6 tests still fail because call extraction is not implemented.

- [ ] **Step 5: Commit import and state setup**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs
git commit -m "refactor: prepare python extractor call fact state"
```

---

### Task 3: Add Statement and Expression Traversal for Calls

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: Existing `visit_stmt`, `visit_suite`, `expr_to_string`, and `line_col_for_offset`.
- Produces: New methods `visit_expr`, `visit_call_expr`, `visit_assignment_alias`, `visit_stmt_expressions`, `caller_function_id`, `normalize_callee`, `resolve_alias`, and helper functions used by call extraction.

- [ ] **Step 1: Add expression traversal hooks in `visit_stmt`**

Replace the `_` arm at the end of `visit_stmt`:

```rust
_ => self.visit_child_statements(stmt),
```

with:

```rust
ast::Stmt::Assign(assign) => {
    self.visit_assignment_alias(&assign.targets, &assign.value);
    self.visit_expr(&assign.value);
    for target in &assign.targets {
        self.visit_expr(target);
    }
}
ast::Stmt::AnnAssign(assign) => {
    if let Some(value) = &assign.value {
        self.visit_assignment_alias(std::slice::from_ref(&assign.target), value);
        self.visit_expr(value);
    }
    self.visit_expr(&assign.target);
}
ast::Stmt::AugAssign(assign) => {
    self.visit_expr(&assign.target);
    self.visit_expr(&assign.value);
}
ast::Stmt::Expr(expr_stmt) => self.visit_expr(&expr_stmt.value),
ast::Stmt::Return(return_stmt) => {
    if let Some(value) = &return_stmt.value {
        self.visit_expr(value);
    }
}
_ => self.visit_child_statements(stmt),
```

- [ ] **Step 2: Extend `visit_child_statements` to visit condition expressions**

Replace the existing `visit_child_statements` method with:

```rust
fn visit_child_statements(&mut self, stmt: &ast::Stmt) {
    match stmt {
        ast::Stmt::For(item) => {
            self.visit_expr(&item.target);
            self.visit_expr(&item.iter);
            self.visit_suite(&item.body);
            self.visit_suite(&item.orelse);
        }
        ast::Stmt::AsyncFor(item) => {
            self.visit_expr(&item.target);
            self.visit_expr(&item.iter);
            self.visit_suite(&item.body);
            self.visit_suite(&item.orelse);
        }
        ast::Stmt::While(item) => {
            self.visit_expr(&item.test);
            self.visit_suite(&item.body);
            self.visit_suite(&item.orelse);
        }
        ast::Stmt::If(item) => {
            self.visit_expr(&item.test);
            self.visit_suite(&item.body);
            self.visit_suite(&item.orelse);
        }
        ast::Stmt::With(item) => {
            for with_item in &item.items {
                self.visit_expr(&with_item.context_expr);
                if let Some(optional_vars) = &with_item.optional_vars {
                    self.visit_expr(optional_vars);
                }
            }
            self.visit_suite(&item.body);
        }
        ast::Stmt::AsyncWith(item) => {
            for with_item in &item.items {
                self.visit_expr(&with_item.context_expr);
                if let Some(optional_vars) = &with_item.optional_vars {
                    self.visit_expr(optional_vars);
                }
            }
            self.visit_suite(&item.body);
        }
        ast::Stmt::Try(item) => {
            self.visit_suite(&item.body);
            for handler in &item.handlers {
                match handler {
                    ast::ExceptHandler::ExceptHandler(handler) => self.visit_suite(&handler.body),
                }
            }
            self.visit_suite(&item.orelse);
            self.visit_suite(&item.finalbody);
        }
        ast::Stmt::TryStar(item) => {
            self.visit_suite(&item.body);
            for handler in &item.handlers {
                match handler {
                    ast::ExceptHandler::ExceptHandler(handler) => self.visit_suite(&handler.body),
                }
            }
            self.visit_suite(&item.orelse);
            self.visit_suite(&item.finalbody);
        }
        ast::Stmt::Match(item) => {
            self.visit_expr(&item.subject);
            for case in &item.cases {
                if let Some(guard) = &case.guard {
                    self.visit_expr(guard);
                }
                self.visit_suite(&case.body);
            }
        }
        _ => {}
    }
}
```

- [ ] **Step 3: Add `visit_expr` method**

Inside `impl PythonFactExtractor<'a>`, before `visit_function_def`, add:

```rust
fn visit_expr(&mut self, expr: &ast::Expr) {
    match expr {
        ast::Expr::Call(call) => {
            self.visit_call_expr(call);
            self.visit_expr(&call.func);
            for arg in &call.args {
                self.visit_expr(arg);
            }
            for keyword in &call.keywords {
                self.visit_expr(&keyword.value);
            }
        }
        ast::Expr::Attribute(attr) => self.visit_expr(&attr.value),
        ast::Expr::Subscript(subscript) => {
            self.visit_expr(&subscript.value);
            self.visit_expr(&subscript.slice);
        }
        ast::Expr::BoolOp(bool_op) => {
            for value in &bool_op.values {
                self.visit_expr(value);
            }
        }
        ast::Expr::BinOp(bin_op) => {
            self.visit_expr(&bin_op.left);
            self.visit_expr(&bin_op.right);
        }
        ast::Expr::UnaryOp(unary) => self.visit_expr(&unary.operand),
        ast::Expr::Compare(compare) => {
            self.visit_expr(&compare.left);
            for comparator in &compare.comparators {
                self.visit_expr(comparator);
            }
        }
        ast::Expr::IfExp(if_exp) => {
            self.visit_expr(&if_exp.test);
            self.visit_expr(&if_exp.body);
            self.visit_expr(&if_exp.orelse);
        }
        ast::Expr::List(list) => {
            for item in &list.elts {
                self.visit_expr(item);
            }
        }
        ast::Expr::Tuple(tuple) => {
            for item in &tuple.elts {
                self.visit_expr(item);
            }
        }
        ast::Expr::Set(set) => {
            for item in &set.elts {
                self.visit_expr(item);
            }
        }
        ast::Expr::Dict(dict) => {
            for key in dict.keys.iter().flatten() {
                self.visit_expr(key);
            }
            for value in &dict.values {
                self.visit_expr(value);
            }
        }
        ast::Expr::ListComp(comp) => {
            self.visit_expr(&comp.elt);
            for generator in &comp.generators {
                self.visit_expr(&generator.target);
                self.visit_expr(&generator.iter);
                for condition in &generator.ifs {
                    self.visit_expr(condition);
                }
            }
        }
        ast::Expr::SetComp(comp) => {
            self.visit_expr(&comp.elt);
            for generator in &comp.generators {
                self.visit_expr(&generator.target);
                self.visit_expr(&generator.iter);
                for condition in &generator.ifs {
                    self.visit_expr(condition);
                }
            }
        }
        ast::Expr::DictComp(comp) => {
            self.visit_expr(&comp.key);
            self.visit_expr(&comp.value);
            for generator in &comp.generators {
                self.visit_expr(&generator.target);
                self.visit_expr(&generator.iter);
                for condition in &generator.ifs {
                    self.visit_expr(condition);
                }
            }
        }
        ast::Expr::GeneratorExp(comp) => {
            self.visit_expr(&comp.elt);
            for generator in &comp.generators {
                self.visit_expr(&generator.target);
                self.visit_expr(&generator.iter);
                for condition in &generator.ifs {
                    self.visit_expr(condition);
                }
            }
        }
        ast::Expr::Await(await_expr) => self.visit_expr(&await_expr.value),
        ast::Expr::Yield(yield_expr) => {
            if let Some(value) = &yield_expr.value {
                self.visit_expr(value);
            }
        }
        ast::Expr::YieldFrom(yield_from) => self.visit_expr(&yield_from.value),
        ast::Expr::Lambda(lambda) => self.visit_expr(&lambda.body),
        _ => {}
    }
}
```

- [ ] **Step 4: Add call extraction and alias helper methods**

Inside `impl PythonFactExtractor<'a>`, after `visit_expr`, add:

```rust
fn visit_call_expr(&mut self, call: &ast::ExprCall) {
    let (line, column) = line_col_for_offset(self.source, call.range.start().to_u32());
    let (end_line, _) = line_col_for_offset(self.source, call.range.end().to_u32());
    let callee = expr_to_string(&call.func);
    let (normalized_callee, import_alias) = self.normalize_callee(&callee);
    let args = call
        .args
        .iter()
        .enumerate()
        .map(|(index, arg)| CallArg {
            index: index as u32,
            expr: expr_to_string(arg),
            kind: "positional".to_string(),
        })
        .collect::<Vec<_>>();
    let kwargs = call
        .keywords
        .iter()
        .map(|keyword| {
            let key = keyword
                .arg
                .as_ref()
                .map(|item| item.to_string())
                .unwrap_or_else(|| "**".to_string());
            (
                key,
                CallKwarg {
                    expr: expr_to_string(&keyword.value),
                    value: serde_json::Value::Null,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    self.facts.push(Fact::Call(CallFact {
        base: FactBase {
            id: make_call_id(&self.root, &self.file, line, column),
            file: display_path(&self.file),
            line,
            extractor: EXTRACTOR_NAME.to_string(),
        },
        caller: self.caller_function_id().unwrap_or_default(),
        callee: callee.clone(),
        normalized_callee: Some(normalized_callee),
        column: Some(column),
        end_line: Some(end_line),
        snippet: snippet_for_range(self.source, call.range.start().to_u32(), call.range.end().to_u32()),
        args,
        kwargs,
        resolution: import_alias.map(|alias| CallResolution {
            import_alias: Some(alias),
            confidence: Confidence::High,
        }),
    }));
}

fn visit_assignment_alias(&mut self, targets: &[ast::Expr], value: &ast::Expr) {
    if targets.len() != 1 {
        return;
    }
    let ast::Expr::Name(target) = &targets[0] else {
        return;
    };
    let value_text = expr_to_string(value);
    let (normalized, _) = self.normalize_callee(&value_text);
    if normalized != value_text || looks_like_callable_reference(&value_text) {
        self.assignment_aliases
            .insert(target.id.to_string(), normalized);
    }
}

fn caller_function_id(&self) -> Option<String> {
    if self.scope.is_empty() {
        None
    } else {
        Some(make_function_id(
            "python",
            &self.root,
            &self.file,
            &self.scope.join("."),
        ))
    }
}

fn normalize_callee(&self, callee: &str) -> (String, Option<String>) {
    if let Some(target) = self.assignment_aliases.get(callee) {
        return (target.clone(), Some(callee.to_string()));
    }
    self.resolve_alias(callee)
}

fn resolve_alias(&self, callee: &str) -> (String, Option<String>) {
    if let Some(target) = self.import_aliases.get(callee) {
        return (target.clone(), Some(callee.to_string()));
    }
    if let Some((head, tail)) = callee.split_once('.') {
        if let Some(target) = self.import_aliases.get(head) {
            return (format!("{target}.{tail}"), Some(head.to_string()));
        }
    }
    (callee.to_string(), None)
}
```

- [ ] **Step 5: Add helper functions outside the impl**

After `line_col_for_offset`, add:

```rust
fn snippet_for_range(source: &str, start: u32, end: u32) -> String {
    let start = start as usize;
    let end = end as usize;
    source
        .get(start.min(source.len())..end.min(source.len()))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn looks_like_callable_reference(value: &str) -> bool {
    value.contains('.') || value.chars().all(|item| item == '_' || item.is_ascii_alphanumeric())
}
```

- [ ] **Step 6: Run the focused Task 6 test**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core extracts_calls_with_args_kwargs_and_alias_resolution
```

Expected: PASS if RustPython AST field names match this plan. If compilation fails because an AST field name differs, inspect the compiler error and replace only that field access with the correct RustPython 0.4 field name.

- [ ] **Step 7: Commit traversal implementation**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs
git commit -m "feat: extract python call facts"
```

---

### Task 4: Tune Normalized Callee and Resolution Semantics

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: `normalize_callee(&self, callee: &str) -> (String, Option<String>)` from Task 3.
- Produces: Stable semantics where `normalized_callee` is always the best available callee string and `resolution` is present only when an alias was resolved.

- [ ] **Step 1: Add direct call assertion to the focused test**

Inside `extracts_calls_with_args_kwargs_and_alias_resolution`, after `let calls = call_facts(&result);`, add:

```rust
let direct_call = calls
    .iter()
    .find(|item| item.callee == "subprocess.run")
    .expect("direct subprocess.run call");
assert_eq!(direct_call.normalized_callee.as_deref(), Some("subprocess.run"));
assert!(direct_call.resolution.is_none());
```

- [ ] **Step 2: Add from-import assertion to the focused test**

After the direct call assertion, add:

```rust
let from_import_call = calls
    .iter()
    .find(|item| item.callee == "run")
    .expect("from import run call");
assert_eq!(from_import_call.normalized_callee.as_deref(), Some("subprocess.run"));
assert_eq!(
    from_import_call
        .resolution
        .as_ref()
        .and_then(|item| item.import_alias.as_deref()),
    Some("run")
);
```

- [ ] **Step 3: Run the focused test**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core extracts_calls_with_args_kwargs_and_alias_resolution
```

Expected: PASS.

- [ ] **Step 4: Run all Python fact extractor tests**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::facts::python::tests
```

Expected: PASS.

- [ ] **Step 5: Commit normalization semantics**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs
git commit -m "test: cover python call normalization semantics"
```

---

### Task 5: Verify Intermediate JSON Output

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

**Interfaces:**
- Consumes: `prints_phase7_task6_intermediate_facts` from Task 1 and implementation from Tasks 3-4.
- Produces: Human-checkable JSON output for Task 6 facts.

- [ ] **Step 1: Run the printable Task 6 test**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core prints_phase7_task6_intermediate_facts -- --nocapture
```

Expected: PASS and stdout contains JSON with at least one object where:

```json
{
  "type": "call",
  "callee": "sp.run",
  "normalized_callee": "subprocess.run"
}
```

The actual JSON object includes additional fields such as `id`, `file`, `line`, `caller`, `column`, `end_line`, `snippet`, `args`, `kwargs`, and `resolution`.

- [ ] **Step 2: Run all Python fact extractor tests again**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::facts::python::tests
```

Expected: PASS.

- [ ] **Step 3: Run formatter check for the Rust workspace**

Run:

```bash
cargo fmt --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml --all -- --check
```

Expected: PASS. If it fails with formatting diffs, run:

```bash
cargo fmt --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml --all
```

Then rerun the formatter check.

- [ ] **Step 4: Commit verification adjustments if formatting changed**

If `cargo fmt` changed `python.rs`, run:

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs
git commit -m "style: format python fact extractor"
```

If `cargo fmt --check` passed without changing files, skip this commit.

---

### Task 6: Update Phase 7 Status for Task 6 Only

**Files:**
- Modify: `rust/docs/PHASE7_STATUS.md`

**Interfaces:**
- Consumes: Passing Task 6 tests from Tasks 3-5.
- Produces: Status documentation that records Task 6 completion but still states Phase 7 is not complete.

- [ ] **Step 1: Change the Task 6 section from incomplete to completed**

In `rust/docs/PHASE7_STATUS.md`, replace the current section beginning with:

```markdown
### 1. Call facts 尚未实现
```

through the Task 6 recommended command block ending with:

```markdown
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core prints_phase7_task6_intermediate_facts -- --nocapture
```

with:

```markdown
### 1. Call facts 已实现

已实现：

- 遍历 Python 表达式中的 `ast::Expr::Call`。
- 生成 `Fact::Call`。
- 提取 callee。
- 提取 normalized callee。
- 提取 positional args。
- 提取 kwargs。
- 提取 caller function ID。
- 提取 call snippet。
- 使用 `make_call_id(root, file, line, column)` 生成 call ID。

已新增并通过测试：

- `extracts_calls_with_args_kwargs_and_alias_resolution`
- `prints_phase7_task6_intermediate_facts`

已验证命令：

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core extracts_calls_with_args_kwargs_and_alias_resolution
```

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core prints_phase7_task6_intermediate_facts -- --nocapture
```
```

- [ ] **Step 2: Change alias normalization section from incomplete to completed**

Replace the heading:

```markdown
### 2. Call alias normalization 尚未完成
```

with:

```markdown
### 2. Call alias normalization 已完成
```

Then replace the sentence:

```markdown
当前 import alias map 已经存在，但还没有用于 call facts。
```

with:

```markdown
当前 import alias map 已用于 call facts normalized callee 解析。
```

- [ ] **Step 3: Change assignment alias section to partial completion**

Replace the heading:

```markdown
### 3. Assignment alias resolution 尚未完成
```

with:

```markdown
### 3. Assignment alias resolution 已完成 Task 6 窄实现
```

Replace the sentence:

```markdown
当前 extractor 中有 `_assignment_aliases` 字段，但还没有实现真实逻辑。
```

with:

```markdown
当前 extractor 已支持 Task 6 所需的简单函数别名解析，例如 `runner = sp.run` 后续 `runner(...)` 可归一化为 `subprocess.run`。本阶段尚未生成 `Fact::Assign`，完整 assignment facts 仍属于 Task 7。
```

- [ ] **Step 4: Update the current next step**

Replace the block under `## 当前下一步` that says:

```markdown
清理上下文后，应该从 Phase 7 Task 6 继续。

当前下一步任务：

```text
Implement Phase 7 Task 6 calls and aliases
```
```

with:

```markdown
清理上下文后，应该从 Phase 7 Task 7 继续。

当前下一步任务：

```text
Implement Phase 7 Task 7 assign facts and richer assignment aliases
```
```

- [ ] **Step 5: Keep Phase 7 marked partial**

Verify the document still says Phase 7 is partially complete and still lists these as unfinished:

```markdown
- assign facts。
- sink facts。
- syntax diagnostics 最终测试。
- `extract_static_facts` 真实 pipeline。
- `run_static_scan` 接入 facts。
- taint 空实现修复。
- 默认配置禁用 taint。
- phase 常量更新。
- 中文文档最终更新。
- end-to-end 验证。
```

- [ ] **Step 6: Commit status update**

```bash
git add rust/docs/PHASE7_STATUS.md
git commit -m "docs: record phase 7 task 6 status"
```

---

### Task 7: Final Verification for Task 6

**Files:**
- No source modifications expected.

**Interfaces:**
- Consumes: Code and docs from Tasks 1-6.
- Produces: Final evidence that Task 6 works and Phase 7 remains incomplete.

- [ ] **Step 1: Run focused Task 6 test**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core extracts_calls_with_args_kwargs_and_alias_resolution
```

Expected: PASS.

- [ ] **Step 2: Run printable Task 6 test**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core prints_phase7_task6_intermediate_facts -- --nocapture
```

Expected: PASS and JSON output includes call facts.

- [ ] **Step 3: Run all Python fact extractor tests**

Run:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::facts::python::tests
```

Expected: PASS.

- [ ] **Step 4: Run formatter check**

Run:

```bash
cargo fmt --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml --all -- --check
```

Expected: PASS.

- [ ] **Step 5: Inspect git diff**

Run:

```bash
git diff --stat
```

Expected: Only intended files changed for Task 6 implementation and status tracking:

```text
rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs
rust/docs/PHASE7_STATUS.md
```

- [ ] **Step 6: Report completion accurately**

Report this exact status in the implementation summary:

```text
Phase 7 Task 6 is complete: Python call facts, call args/kwargs, import alias normalization, and simple assignment alias normalization are implemented and tested. Phase 7 overall is still incomplete; next step is Task 7 assign facts and richer assignment alias handling.
```

---

## Self-Review

### Spec Coverage

- `Fact::Call` extraction: covered by Tasks 1, 3, 4, and 7.
- Original and normalized callee: covered by Tasks 1, 3, and 4.
- Positional args and kwargs: covered by Tasks 1 and 3.
- Caller function identity: covered by Tasks 1 and 3.
- Location and snippet evidence: covered by Tasks 1 and 3.
- Import alias normalization: covered by Tasks 1, 3, and 4.
- Narrow assignment alias normalization: covered by Tasks 1 and 3.
- No `Fact::Assign`: covered by Global Constraints and Task 6 status wording.
- Intermediate JSON output: covered by Tasks 1, 5, and 7.
- Existing tests and formatting: covered by Tasks 4, 5, and 7.

### Placeholder Scan

The plan contains no TBD/TODO placeholders. Each task includes exact files, concrete code snippets, exact commands, and expected outcomes.

### Type Consistency

The plan uses existing model types from `facts.rs`:

- `CallFact.caller: String`
- `CallFact.callee: String`
- `CallFact.normalized_callee: Option<String>`
- `CallFact.column: Option<u32>`
- `CallFact.end_line: Option<u32>`
- `CallFact.snippet: String`
- `CallFact.args: Vec<CallArg>`
- `CallFact.kwargs: BTreeMap<String, CallKwarg>`
- `CallFact.resolution: Option<CallResolution>`

The plan uses existing ID helper `make_call_id(root, file, line, column)` and existing function ID helper `make_function_id("python", root, file, qualified_name)`.
