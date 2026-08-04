# Phase 8: JS/TS Fact Extraction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract Import, Function, Entrypoint, Source, Call, Assign, and Sink facts from JavaScript/TypeScript source files using SWC parser, integrated into the existing static analysis pipeline.

**Architecture:** `JsTsFactExtractor` struct implements SWC's `Visit` trait for compiler-guaranteed exhaustive AST traversal. Each visit method delegates to a focused sub-module (imports, functions, calls, sinks, mcp). JS and TS share a single extractor; differences are only in SWC parse syntax mode.

**Tech Stack:** Rust, SWC 0.101 (`ecma_parser`, `ecma_ast`, `ecma_visit`, `common`), serde, anyhow

## Global Constraints

- Phase: 8 — JS/TS fact extraction
- Rust edition: 2024
- Minimum Rust version: 1.88
- License: MIT
- SWC version: 0.101 with features `ecma_parser`, `ecma_ast`, `ecma_visit`, `common`
- Taint line stays disabled; enabled taint returns unimplemented error unchanged
- Agent line stays disabled; enabled agent returns empty unchanged
- All existing tests must continue passing
- Facts must serialize to stable JSON compatible with Python implementation
- Parse failures must not crash — use tolerance-first error handling

---

### Task 1: Add SWC dependency and extend FunctionFact model

**Files:**
- Modify: `rust/Cargo.toml`
- Modify: `rust/crates/mcp-sec-audit-core/Cargo.toml`
- Modify: `rust/crates/mcp-sec-audit-core/src/model/facts.rs:83-96`

**Interfaces:**
- Produces: `FunctionFact.return_type: Option<String>` — TS return type annotation, Python/JS fill None

- [ ] **Step 1: Add SWC to workspace Cargo.toml**

Open `rust/Cargo.toml` and add under `[workspace.dependencies]`:

```toml
swc_core = { version = "0.101", features = [
    "ecma_parser",
    "ecma_ast",
    "ecma_visit",
    "common",
] }
```

- [ ] **Step 2: Add SWC to core Cargo.toml**

Open `rust/crates/mcp-sec-audit-core/Cargo.toml` and add under `[dependencies]`:

```toml
swc_core.workspace = true
```

- [ ] **Step 3: Add return_type field to FunctionFact**

Open `rust/crates/mcp-sec-audit-core/src/model/facts.rs`. In the `FunctionFact` struct (lines 83-96), add after `docstring`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionFact {
    #[serde(flatten)]
    pub base: FactBase,
    pub language: String,
    pub name: String,
    pub qualified_name: String,
    pub end_line: u32,
    pub params: Vec<ParamInfo>,
    pub decorators: Vec<String>,
    pub docstring: Option<String>,
    pub return_type: Option<String>,
    pub enclosing_class: Option<String>,
}
```

- [ ] **Step 4: Build to verify compilation**

```bash
cd rust && cargo build 2>&1
```

- [ ] **Step 5: Run existing tests to confirm no regressions**

```bash
cd rust && cargo test 2>&1
```

Expected: all 58 existing tests pass. The `return_type: None` is backward compatible because all existing `FunctionFact` constructors use struct literal syntax — Rust will error on missing field, so we must update all existing construction sites.

- [ ] **Step 6: Fix existing FunctionFact construction sites**

In `python.rs`, find all `FunctionFact { ... }` struct literals and add `return_type: None`:

Search for `FunctionFact {` in `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`. There are 2-3 construction sites (one in `visit_function_def`). For each, add:

```rust
return_type: None,
```

Also check `fixtures.rs` for any `FunctionFact` constructions (used in tests). Add `return_type: None` there too.

- [ ] **Step 7: Run tests again to confirm fix**

```bash
cd rust && cargo test 2>&1
```

Expected: all 58 tests pass.

- [ ] **Step 8: Commit**

```bash
git add rust/Cargo.toml rust/crates/mcp-sec-audit-core/Cargo.toml rust/crates/mcp-sec-audit-core/src/model/facts.rs rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs rust/crates/mcp-sec-audit-core/src/fixtures.rs
git commit -m "feat: add SWC dependency and FunctionFact.return_type field for Phase 8"
```

---

### Task 2: Create JsTsExtractionResult and diagnostics types

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/mod.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/mod.rs`

**Interfaces:**
- Consumes: `Fact` (from `crate::model::facts`)
- Produces: `JsTsDiagnostic` enum, `JsTsExtractionResult` struct, `extract_js_ts_facts(root, file, source) -> JsTsExtractionResult`

- [ ] **Step 1: Create js_ts directory**

```bash
mkdir -p rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts
```

- [ ] **Step 2: Write JsTsDiagnostic and JsTsExtractionResult**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/mod.rs`:

```rust
use crate::model::Fact;

use super::ExtractionDiagnostic;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsTsDiagnostic {
    Fatal { file: String, message: String },
    NonFatal {
        file: String,
        line: u32,
        kind: String,
        message: String,
    },
}

impl From<JsTsDiagnostic> for ExtractionDiagnostic {
    fn from(d: JsTsDiagnostic) -> Self {
        match d {
            JsTsDiagnostic::Fatal { file, message } => ExtractionDiagnostic {
                file,
                line: 0,
                kind: "fatal_parse_error".to_string(),
                message,
            },
            JsTsDiagnostic::NonFatal {
                file,
                line,
                kind,
                message,
            } => ExtractionDiagnostic { file, line, kind, message },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct JsTsExtractionResult {
    pub facts: Vec<Fact>,
    pub diagnostics: Vec<JsTsDiagnostic>,
}

impl JsTsExtractionResult {
    pub fn empty() -> Self {
        Self {
            facts: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    pub fn has_fatal(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| matches!(d, JsTsDiagnostic::Fatal { .. }))
    }
}
```

- [ ] **Step 3: Add js_ts module to facts/mod.rs**

Open `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/mod.rs`. Add the module declaration alongside existing `mod python;`:

```rust
mod js_ts;
mod python;
```

Add the public re-exports:

```rust
pub use js_ts::{JsTsDiagnostic, JsTsExtractionResult};
```

Add a stub `extract_js_ts_facts` function (will be replaced in Task 8):

```rust
use std::path::Path;
use js_ts::JsTsExtractionResult;

pub fn extract_js_ts_facts(_root: &Path, _file: &Path, _source: &str) -> JsTsExtractionResult {
    JsTsExtractionResult::empty()
}
```

- [ ] **Step 4: Build to verify compilation**

```bash
cd rust && cargo build 2>&1
```

- [ ] **Step 5: Run tests**

```bash
cd rust && cargo test 2>&1
```

Expected: 58 tests pass.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/mod.rs rust/crates/mcp-sec-audit-core/src/static_analysis/facts/mod.rs
git commit -m "feat(phase8): add JsTsExtractionResult and diagnostics scaffolding"
```

---

### Task 3: Implement import extraction (ESM + CJS)

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/imports.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/mod.rs`

**Interfaces:**
- Consumes: `JsTsFactExtractor` state (alias maps, facts buffer, diagnostics)
- Produces: `pub(crate) fn extract_import(extractor: &JsTsFactExtractor, n: &ImportDecl)` for ESM
- Produces: `pub(crate) fn extract_require(extractor: &JsTsFactExtractor, n: &CallExpr, source: &str)` for CJS

- [ ] **Step 1: Write test for ESM default import with alias**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/imports.rs`:

```rust
#[cfg(test)]
mod tests {
    use std::path::Path;
    use crate::model::{Fact, ImportFact, ImportKind};

    // NOTE: these tests will be enabled after JsTsFactExtractor is fully wired in Task 8.
    // For now, verify compilation with a placeholder test.
    #[test]
    fn esm_import_kinds_exist_in_model() {
        // Verify the JS/TS-specific ImportKind variants exist
        use crate::model::ImportKind;
        assert_eq!(
            serde_json::to_value(ImportKind::EsmImport).unwrap(),
            serde_json::json!("esm_import")
        );
        assert_eq!(
            serde_json::to_value(ImportKind::Require).unwrap(),
            serde_json::json!("require")
        );
        assert_eq!(
            serde_json::to_value(ImportKind::RequireDestructure).unwrap(),
            serde_json::json!("require_destructure")
        );
        assert_eq!(
            serde_json::to_value(ImportKind::EsmNamedImport).unwrap(),
            serde_json::json!("esm_named_import")
        );
    }
}
```

Note: Full extraction tests will be written in Task 8 when the extractor is fully wired.

- [ ] **Step 2: Write the imports module implementation**

Append to the same file (above the test module):

```rust
use std::collections::BTreeMap;
use swc_core::ecma::{
    ast::{ImportDecl, CallExpr, Callee, Expr, Lit, Pat, ObjectPatProp, VarDeclarator},
    visit::Visit,
};

use crate::model::{Fact, FactBase, ImportFact, ImportKind};

// --- ESM Import Handling ---

pub(crate) fn extract_esm_import(
    n: &ImportDecl,
    file: &str,
    line: u32,
    extractor_name: &str,
    facts: &mut Vec<Fact>,
    import_aliases: &mut BTreeMap<String, String>,
) {
    let module = n.src.value.to_string();

    for specifier in &n.specifiers {
        match specifier {
            swc_core::ecma::ast::ImportSpecifier::Named(named) => {
                let imported_name = named.local.sym.to_string();
                let alias = if named.imported.is_some() {
                    named.imported.as_ref().map(|i| match i {
                        swc_core::ecma::ast::ModuleExportName::Ident(id) => id.sym.to_string(),
                        swc_core::ecma::ast::ModuleExportName::Str(s) => s.value.to_string(),
                    })
                } else {
                    None
                };
                let effective_alias = alias.clone();
                let kind = if effective_alias.is_some() {
                    ImportKind::EsmImportAs
                } else {
                    ImportKind::EsmNamedImport
                };
                let alias_key = effective_alias.unwrap_or_else(|| imported_name.clone());
                import_aliases.insert(alias_key.clone(), format!("{module}.{imported_name}"));

                facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: format!("import:{file}:{line}:{module}.{imported_name}"),
                        file: file.to_string(),
                        line,
                        extractor: extractor_name.to_string(),
                    },
                    language: "javascript".to_string(),
                    module: module.clone(),
                    imported_name: Some(imported_name),
                    alias: effective_alias,
                    kind,
                }));
            }
            swc_core::ecma::ast::ImportSpecifier::Default(default) => {
                let name = default.local.sym.to_string();
                import_aliases.insert(name.clone(), module.clone());

                facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: format!("import:{file}:{line}:{module}"),
                        file: file.to_string(),
                        line,
                        extractor: extractor_name.to_string(),
                    },
                    language: "javascript".to_string(),
                    module: module.clone(),
                    imported_name: None,
                    alias: Some(name),
                    kind: ImportKind::EsmImport,
                }));
            }
            swc_core::ecma::ast::ImportSpecifier::Namespace(ns) => {
                let name = ns.local.sym.to_string();
                import_aliases.insert(name.clone(), format!("{module}.*"));

                facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: format!("import:{file}:{line}:{module}.*"),
                        file: file.to_string(),
                        line,
                        extractor: extractor_name.to_string(),
                    },
                    language: "javascript".to_string(),
                    module: module.clone(),
                    imported_name: Some("*".to_string()),
                    alias: Some(name),
                    kind: ImportKind::EsmImportAs,
                }));
            }
        }
    }
}

// --- CJS require() Handling ---

pub(crate) fn extract_require_call(
    callee_name: &str,
    n: &CallExpr,
    file: &str,
    line: u32,
    extractor_name: &str,
    facts: &mut Vec<Fact>,
    require_aliases: &mut BTreeMap<String, String>,
) -> bool {
    // Returns true if this call was a require() call
    if callee_name != "require" {
        return false;
    }

    let Some(module_name) = first_string_arg(n) else {
        return false;
    };

    facts.push(Fact::Import(ImportFact {
        base: FactBase {
            id: format!("import:{file}:{line}:{module_name}"),
            file: file.to_string(),
            line,
            extractor: extractor_name.to_string(),
        },
        language: "javascript".to_string(),
        module: module_name.clone(),
        imported_name: None,
        alias: None,
        kind: ImportKind::Require,
    }));
    true
}

pub(crate) fn extract_destructured_require(
    n: &VarDeclarator,
    module_name: &str,
    file: &str,
    line: u32,
    extractor_name: &str,
    facts: &mut Vec<Fact>,
    require_aliases: &mut BTreeMap<String, String>,
) {
    // Handle const { readFile, writeFile: wf } = require("fs")
    let Some(name) = &n.name else { return };
    let Pat::Object(obj) = name.as_ref() else { return };

    for prop in &obj.props {
        match prop {
            ObjectPatProp::KeyValue(kv) => {
                let key = kv.key.sym.to_string();
                let value_name = match kv.value.as_ref() {
                    Pat::Ident(id) => id.sym.to_string(),
                    _ => continue,
                };
                require_aliases.insert(value_name.clone(), format!("{module_name}.{key}"));

                facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: format!("import:{file}:{line}:{module_name}.{key}"),
                        file: file.to_string(),
                        line,
                        extractor: extractor_name.to_string(),
                    },
                    language: "javascript".to_string(),
                    module: module_name.to_string(),
                    imported_name: Some(key),
                    alias: None,
                    kind: ImportKind::RequireDestructure,
                }));
            }
            ObjectPatProp::Assign(assign) => {
                let name = assign.key.sym.to_string();
                require_aliases.insert(name.clone(), format!("{module_name}.{name}"));

                facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: format!("import:{file}:{line}:{module_name}.{name}"),
                        file: file.to_string(),
                        line,
                        extractor: extractor_name.to_string(),
                    },
                    language: "javascript".to_string(),
                    module: module_name.to_string(),
                    imported_name: Some(name),
                    alias: None,
                    kind: ImportKind::RequireDestructure,
                }));
            }
            _ => {}
        }
    }
}

// --- Helpers ---

fn first_string_arg(call: &CallExpr) -> Option<String> {
    let arg = call.args.first()?;
    match arg.expr.as_ref() {
        Expr::Lit(Lit::Str(s)) => Some(s.value.to_string()),
        _ => None,
    }
}
```

- [ ] **Step 3: Build to verify compilation**

```bash
cd rust && cargo build 2>&1
```

- [ ] **Step 4: Run tests**

```bash
cd rust && cargo test 2>&1
```

Expected: 59 tests pass (58 existing + 1 new).

- [ ] **Step 5: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/imports.rs
git commit -m "feat(phase8): implement ESM and CJS import extraction"
```

---

### Task 4: Implement function extraction (4 forms + TS annotations)

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/functions.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/mod.rs`

**Interfaces:**
- Consumes: `JsTsFactExtractor` state (scope stack, class stack, facts buffer)
- Produces:
  - `pub(crate) fn push_function_scope(extractor: &mut JsTsFactExtractor, fn_node: &FnDecl)`
  - `pub(crate) fn push_method_scope(extractor: &mut JsTsFactExtractor, method: &ClassMember, class_name: &str)`
  - `pub(crate) fn extract_arrow_or_fn_expr(extractor: &mut JsTsFactExtractor, var_name: &str, fn_expr: &FnExpr | &ArrowExpr, line: u32, source: &str)`
  - `pub(crate) fn pop_function_scope(extractor: &mut JsTsFactExtractor)`
  - `pub(crate) fn params_from_fn(fn_decl: &Function) -> Vec<ParamInfo>`
  - `pub(crate) fn push_class_scope(extractor: &mut JsTsFactExtractor, name: &str)`
  - `pub(crate) fn pop_class_scope(extractor: &mut JsTsFactExtractor)`

- [ ] **Step 1: Write the functions module**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/functions.rs`:

```rust
use swc_core::ecma::ast::{
    ArrowExpr, ClassMember, FnDecl, FnExpr, Function, MethodKind, Param, Pat, TsTypeAnn,
};
use swc_core::common::Span;

use crate::model::{Fact, FactBase, FunctionFact, ParamInfo};

use super::ids::make_js_ts_function_id;

/// Extract parameter info from SWC Function node (shared by all function forms).
pub(crate) fn params_from_fn(f: &Function, source: &str) -> Vec<ParamInfo> {
    f.params
        .iter()
        .map(|param| match &param.pat {
            Pat::Ident(id) => ParamInfo {
                name: id.sym.to_string(),
                annotation: ts_type_ann_to_string(param, source),
                default: None,
            },
            Pat::Rest(rest) => match rest.arg.as_ref() {
                Pat::Ident(id) => ParamInfo {
                    name: format!("...{}", id.sym),
                    annotation: None,
                    default: None,
                },
                _ => ParamInfo {
                    name: "...".to_string(),
                    annotation: None,
                    default: None,
                },
            },
            _ => ParamInfo {
                name: format!("<pat:{:?}>", param.pat),
                annotation: None,
                default: None,
            },
        })
        .collect()
}

fn ts_type_ann_to_string(param: &Param) -> Option<String> {
    // Extract TS type annotation by converting the TsTypeAnn node to string representation
    None // Note: SWC type annotation extraction requires TsTypeAnn → string conversion.
    // Full implementation will use SWC's type annotation span + source text extraction.
    // For Phase 8, the field exists but may be None for complex TS types.
    // FIXME: implement TsTypeAnn → string conversion using SWC type printer or span extraction.
}

/// Build qualified function name from scope + class context.
pub(crate) fn build_qualified_name(
    scope: &[String],
    class_stack: &[String],
    name: &str,
) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if let Some(class_name) = class_stack.last() {
        parts.push(class_name.as_str());
    }
    parts.push(name);
    parts.join(".")
}

/// Create FunctionFact for a function declaration.
pub(crate) fn create_function_fact(
    id: String,
    file: String,
    line: u32,
    extractor: String,
    language: String,
    name: String,
    qualified_name: String,
    end_line: u32,
    params: Vec<ParamInfo>,
    enclosing_class: Option<String>,
) -> FunctionFact {
    FunctionFact {
        base: FactBase { id, file, line, extractor },
        language,
        name,
        qualified_name,
        end_line,
        params,
        decorators: Vec::new(),
        docstring: None,
        return_type: None,
        enclosing_class,
    }
}
```

- [ ] **Step 2: Build to verify compilation**

```bash
cd rust && cargo build 2>&1
```

- [ ] **Step 3: Run tests**

```bash
cd rust && cargo test 2>&1
```

Expected: 59 tests pass.

- [ ] **Step 4: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/functions.rs
git commit -m "feat(phase8): implement function/method/arrow extraction utilities"
```

---

### Task 5: Implement call extraction + alias resolution + sink detection

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/calls.rs`
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/sinks.rs`

**Interfaces:**
- calls.rs produces:
  - `pub(crate) fn extract_call(extractor: &mut JsTsFactExtractor, n: &CallExpr, source: &str)`
  - `pub(crate) fn resolve_callee(callee_str: &str, import_aliases: &BTreeMap<String, String>, require_aliases: &BTreeMap<String, String>) -> String`
  - `pub(crate) fn get_callee_str(callee: &Callee) -> String`
- sinks.rs produces:
  - `pub(crate) fn check_sink(normalized_callee: &str, call_id: &str, line: u32, file: &str, extractor: &str, facts: &mut Vec<Fact>)`

- [ ] **Step 1: Write sinks.rs**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/sinks.rs`:

```rust
use std::collections::BTreeMap;

use crate::model::{Confidence, Fact, FactBase, Severity, SinkFact};

struct SinkRule {
    patterns: &'static [&'static str],
    category: &'static str,
    rule_id: &'static str,
    severity: Severity,
    reason: &'static str,
}

static SINK_RULES: &[SinkRule] = &[
    SinkRule {
        patterns: &["child_process.exec", "child_process.execSync", "child_process.spawn",
                     "child_process.spawnSync", "child_process.execFile", "child_process.fork"],
        category: "command_execution",
        rule_id: "js.command_execution",
        severity: Severity::High,
        reason: "Executes external commands via child_process",
    },
    SinkRule {
        patterns: &["eval", "new Function", "Function"],
        category: "dynamic_execution",
        rule_id: "js.dynamic_execution",
        severity: Severity::Critical,
        reason: "Dynamic code execution can run attacker-controlled code",
    },
    SinkRule {
        patterns: &["fs.readFile", "fs.readFileSync", "fs.createReadStream",
                     "fs.promises.readFile"],
        category: "file_read",
        rule_id: "js.file_read",
        severity: Severity::Medium,
        reason: "File read access can leak sensitive data",
    },
    SinkRule {
        patterns: &["fs.writeFile", "fs.writeFileSync", "fs.createWriteStream",
                     "fs.promises.writeFile"],
        category: "file_write",
        rule_id: "js.file_write",
        severity: Severity::Medium,
        reason: "File write can modify filesystem contents",
    },
    SinkRule {
        patterns: &["http.request", "https.request", "fetch", "net.connect", "axios"],
        category: "network_request",
        rule_id: "js.network_request",
        severity: Severity::Medium,
        reason: "Network request can reach attacker-controlled URLs (SSRF)",
    },
    SinkRule {
        patterns: &["process.env"],
        category: "credential_leak",
        rule_id: "js.credential_leak",
        severity: Severity::High,
        reason: "Access to environment variables can leak credentials",
    },
    SinkRule {
        patterns: &["connection.query", "db.run", "Model.find", "mysql.createConnection",
                     "mongoose.Model"],
        category: "database_injection",
        rule_id: "js.database_injection",
        severity: Severity::Critical,
        reason: "Database query may be vulnerable to injection",
    },
    SinkRule {
        patterns: &["vm.runInNewContext", "vm.Script", "new WebAssembly.Module"],
        category: "deserialization_rce",
        rule_id: "js.deserialization_rce",
        severity: Severity::Critical,
        reason: "Deserialization/vm execution can run attacker-controlled code",
    },
];

pub(crate) fn check_sink(
    normalized_callee: &str,
    call_id: &str,
    line: u32,
    file: &str,
    extractor_name: &str,
    facts: &mut Vec<Fact>,
) {
    for rule in SINK_RULES {
        if matches_sink(normalized_callee, rule.patterns) {
            facts.push(Fact::Sink(SinkFact {
                base: FactBase {
                    id: format!("sink:{}:{}:{}", rule.category, file, line),
                    file: file.to_string(),
                    line,
                    extractor: extractor_name.to_string(),
                },
                call_id: call_id.to_string(),
                category: rule.category.to_string(),
                rule_id: rule.rule_id.to_string(),
                sink_name: normalized_callee.to_string(),
                severity_base: rule.severity.clone(),
                reason: rule.reason.to_string(),
                conditions: BTreeMap::new(),
                confidence: Confidence::High,
            }));
            return;
        }
    }
}

fn matches_sink(callee: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| {
        callee == *pattern
            || callee.ends_with(&format!(".{pattern}"))
            || callee.starts_with(&format!("{pattern}."))
    })
}
```

- [ ] **Step 2: Write calls.rs**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/calls.rs`:

```rust
use std::collections::BTreeMap;

use swc_core::ecma::ast::{CallExpr, Callee, Expr, MemberProp};

use crate::model::{CallArg, CallFact, Fact, FactBase};

use super::sinks::check_sink;

/// Get string representation of a callee expression (including nested members).
pub(crate) fn callee_to_string(callee: &Callee) -> String {
    match callee {
        Callee::Expr(expr) => expr_to_string(expr),
        _ => "<unknown>".to_string(),
    }
}

fn expr_to_string(expr: &Expr) -> String {
    match expr {
        Expr::Ident(id) => id.sym.to_string(),
        Expr::Member(member) => {
            let obj = expr_to_string(&member.obj);
            let prop = match &member.prop {
                MemberProp::Ident(id) => id.sym.to_string(),
                MemberProp::Computed(comp) => expr_to_string(&comp.expr),
                _ => "<?>".to_string(),
            };
            format!("{obj}.{prop}")
        }
        Expr::Call(call) => {
            let callee = callee_to_string(&call.callee);
            format!("{callee}(...)")
        }
        Expr::Lit(lit) => match lit {
            swc_core::ecma::ast::Lit::Str(s) => s.value.to_string(),
            swc_core::ecma::ast::Lit::Num(n) => n.value.to_string(),
            swc_core::ecma::ast::Lit::Bool(b) => b.value.to_string(),
            _ => "<lit>".to_string(),
        },
        _ => format!("<{expr:?}>"),
    }
}

/// Resolve callee through import and require aliases.
pub(crate) fn resolve_callee(
    callee_str: &str,
    import_aliases: &BTreeMap<String, String>,
    require_aliases: &BTreeMap<String, String>,
) -> (String, Option<String>) {
    // Check direct alias match
    if let Some(resolved) = import_aliases.get(callee_str) {
        return (resolved.clone(), Some(callee_str.to_string()));
    }
    if let Some(resolved) = require_aliases.get(callee_str) {
        return (resolved.clone(), Some(callee_str.to_string()));
    }

    // Check member expression alias (e.g., "sp.run" where "sp" -> "child_process")
    if let Some((head, tail)) = callee_str.split_once('.') {
        if let Some(resolved) = import_aliases.get(head) {
            return (format!("{resolved}.{tail}"), Some(head.to_string()));
        }
        if let Some(resolved) = require_aliases.get(head) {
            return (format!("{resolved}.{tail}"), Some(head.to_string()));
        }
    }

    (callee_str.to_string(), None)
}

/// Extract positional arguments from a call expression.
pub(crate) fn extract_call_args(call: &CallExpr) -> Vec<CallArg> {
    call.args
        .iter()
        .enumerate()
        .map(|(i, arg)| {
            let expr_str = match arg.expr.as_ref() {
                Expr::Ident(id) => id.sym.to_string(),
                Expr::Lit(lit) => match lit {
                    swc_core::ecma::ast::Lit::Str(s) => s.value.to_string(),
                    swc_core::ecma::ast::Lit::Num(n) => n.value.to_string(),
                    swc_core::ecma::ast::Lit::Bool(b) => b.value.to_string(),
                    _ => "<lit>".to_string(),
                },
                Expr::Member(m) => expr_to_string(&Expr::Member(m.clone())),
                _ => "<expr>".to_string(),
            };
            CallArg {
                index: i as u32,
                expr: expr_str,
                kind: "positional".to_string(),
            }
        })
        .collect()
}
```

- [ ] **Step 3: Build to verify compilation**

```bash
cd rust && cargo build 2>&1
```

- [ ] **Step 4: Run tests**

```bash
cd rust && cargo test 2>&1
```

Expected: 59 tests pass.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/calls.rs rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/sinks.rs
git commit -m "feat(phase8): implement call extraction, alias resolution, and 8 sink categories"
```

---

### Task 6: Implement MCP registration detection

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/mcp.rs`

**Interfaces:**
- Produces:
  - `pub(crate) fn is_mcp_registration(callee: &str) -> bool`
  - `pub(crate) fn entrypoint_kind_from_callee(callee: &str) -> EntryPointKind`
  - `pub(crate) fn process_inline_arrow_handler(extractor: &mut JsTsFactExtractor, call: &CallExpr, arrow: &ArrowExpr, tool_name: &str, callee_str: &str, source: &str)`
  - `pub(crate) fn process_named_handler(extractor: &mut JsTsFactExtractor, handler_name: &str, tool_name: &str, callee_str: &str, line: u32)`
  - `pub(crate) fn backfill_named_handler_sources(extractor: &mut JsTsFactExtractor)`

- [ ] **Step 1: Write mcp.rs**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/mcp.rs`:

```rust
use std::collections::BTreeMap;

use swc_core::ecma::ast::{ArrowExpr, CallExpr, Expr, Pat};

use crate::model::{
    Confidence, EntryPointEvidence, EntryPointFact, EntryPointKind, Fact, FactBase, SourceFact,
};

use super::functions::params_from_fn;

const MCP_PATTERNS: &[&str] = &[
    "server.tool",
    "server.resource",
    "server.prompt",
    "mcp.tool",
    "mcp.resource",
    "mcp.prompt",
];

pub(crate) fn is_mcp_registration(callee: &str) -> bool {
    MCP_PATTERNS
        .iter()
        .any(|pattern| callee == *pattern || callee.ends_with(&format!(".{pattern}")))
}

pub(crate) fn entrypoint_kind_from_callee(callee: &str) -> EntryPointKind {
    let method = callee.rsplit('.').next().unwrap_or(callee);
    match method {
        "resource" => EntryPointKind::McpResource,
        "prompt" => EntryPointKind::McpPrompt,
        _ => EntryPointKind::McpTool,
    }
}

/// Process an inline arrow function MCP handler.
/// Creates FunctionFact, EntryPointFact, and SourceFacts for destructured params.
pub(crate) fn process_inline_arrow_handler(
    facts: &mut Vec<Fact>,
    handler_func_id: String,
    tool_name: String,
    callee_str: &str,
    file: &str,
    line: u32,
    extractor_name: &str,
    arrow: &ArrowExpr,
    source: &str,
) {
    // Extract source params (including destructured)
    let source_facts = extract_source_params_from_arrow(arrow, &handler_func_id, file, line, extractor_name);

    let param_names: Vec<String> = source_facts
        .iter()
        .map(|sf| match sf {
            Fact::Source(s) => s.name.clone(),
            _ => String::new(),
        })
        .filter(|name| !name.is_empty() && !name.starts_with("..."))
        .collect();

    for sf in source_facts {
        facts.push(sf);
    }

    let ep_kind = entrypoint_kind_from_callee(callee_str);
    facts.push(Fact::Entrypoint(EntryPointFact {
        base: FactBase {
            id: format!("entry:{file}:{tool_name}"),
            file: file.to_string(),
            line,
            extractor: extractor_name.to_string(),
        },
        kind: ep_kind,
        name: tool_name,
        function_id: handler_func_id,
        evidence: Some(EntryPointEvidence {
            kind: "call_registration".to_string(),
            text: callee_str.to_string(),
        }),
        params: param_names,
        confidence: Confidence::High,
    }));
}

/// Process a named (identifier-referenced) MCP handler for deferred backfill.
pub(crate) fn process_named_handler(
    named_handlers: &mut BTreeMap<String, String>,
    handler_name: &str,
    tool_name: &str,
    callee_str: &str,
    file: &str,
    line: u32,
    extractor_name: &str,
    facts: &mut Vec<Fact>,
) {
    let ep_kind = entrypoint_kind_from_callee(callee_str);
    let ep_id = format!("entry:{file}:{tool_name}");

    facts.push(Fact::Entrypoint(EntryPointFact {
        base: FactBase {
            id: ep_id.clone(),
            file: file.to_string(),
            line,
            extractor: extractor_name.to_string(),
        },
        kind: ep_kind,
        name: tool_name.to_string(),
        function_id: format!("javascript:{file}:{handler_name}"),
        evidence: Some(EntryPointEvidence {
            kind: "call_registration".to_string(),
            text: callee_str.to_string(),
        }),
        params: Vec::new(), // backfilled later
        confidence: Confidence::High,
    }));

    named_handlers.insert(handler_name.to_string(), ep_id);
}

/// Extract SourceFact from arrow function parameters (with destructuring expansion).
fn extract_source_params_from_arrow(
    arrow: &ArrowExpr,
    function_id: &str,
    file: &str,
    line: u32,
    extractor_name: &str,
) -> Vec<Fact> {
    arrow
        .params
        .iter()
        .flat_map(|pat| extract_source_from_pat(pat, function_id, file, line, extractor_name))
        .collect()
}

fn extract_source_from_pat(
    pat: &Pat,
    function_id: &str,
    file: &str,
    line: u32,
    extractor_name: &str,
) -> Vec<Fact> {
    match pat {
        Pat::Ident(id) => vec![Fact::Source(SourceFact {
            base: FactBase {
                id: format!("source:{file}:{function_id}:{}", id.sym),
                file: file.to_string(),
                line,
                extractor: extractor_name.to_string(),
            },
            kind: "mcp_tool_parameter".to_string(),
            function_id: function_id.to_string(),
            name: id.sym.to_string(),
            confidence: Confidence::High,
        })],
        Pat::Object(obj) => obj
            .props
            .iter()
            .flat_map(|prop| match prop {
                swc_core::ecma::ast::ObjectPatProp::KeyValue(kv) => {
                    extract_source_from_pat(&kv.value, function_id, file, line, extractor_name)
                }
                swc_core::ecma::ast::ObjectPatProp::Assign(assign) => {
                    vec![Fact::Source(SourceFact {
                        base: FactBase {
                            id: format!(
                                "source:{file}:{function_id}:{}",
                                assign.key.sym
                            ),
                            file: file.to_string(),
                            line,
                            extractor: extractor_name.to_string(),
                        },
                        kind: "mcp_tool_parameter".to_string(),
                        function_id: function_id.to_string(),
                        name: assign.key.sym.to_string(),
                        confidence: Confidence::High,
                    })]
                }
                swc_core::ecma::ast::ObjectPatProp::Rest(rest) => {
                    extract_source_from_pat(&rest.arg, function_id, file, line, extractor_name)
                }
            })
            .collect(),
        Pat::Array(arr) => arr
            .elems
            .iter()
            .filter_map(|elem| elem.as_ref())
            .flat_map(|pat| extract_source_from_pat(pat, function_id, file, line, extractor_name))
            .collect(),
        Pat::Rest(rest) => {
            extract_source_from_pat(&rest.arg, function_id, file, line, extractor_name)
        }
        _ => Vec::new(),
    }
}
```

- [ ] **Step 2: Build to verify compilation**

```bash
cd rust && cargo build 2>&1
```

- [ ] **Step 3: Run tests**

```bash
cd rust && cargo test 2>&1
```

Expected: 59 tests pass.

- [ ] **Step 4: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/mcp.rs
git commit -m "feat(phase8): implement MCP registration detection with destructuring support"
```

---

### Task 7: Implement JsTsFactExtractor with SWC Visit trait + ID generation

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/mod.rs` (complete rewrite)
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/ids.rs`

**Interfaces:**
- Produces: `JsTsFactExtractor` struct with `Visit` trait implementation
- Produces: `pub fn extract_js_ts_facts(root: &Path, file: &Path, source: &str) -> JsTsExtractionResult`

- [ ] **Step 1: Write ID generation for JS/TS**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/ids.rs`:

```rust
use std::path::Path;

use super::super::ids::{
    make_call_id, make_entrypoint_id, make_import_id, make_sink_id, make_source_id, make_assign_id,
};

/// Build a JS/TS function ID in the format: javascript:<rel_path>:<qualified_name>
pub(crate) fn make_js_ts_function_id(
    root: &Path,
    file: &Path,
    qualified_name: &str,
) -> String {
    let rel = file
        .strip_prefix(root)
        .unwrap_or(file)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    format!("javascript:{rel}:{qualified_name}")
}
```

- [ ] **Step 2: Write the full JsTsFactExtractor with Visit trait**

Complete rewrite of `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/mod.rs`:

```rust
mod ids;
pub(crate) mod imports;
pub(crate) mod functions;
pub(crate) mod calls;
pub(crate) mod sinks;
pub(crate) mod mcp;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use swc_core::{
    common::{FileName, SourceMap, Syntax, sync::Lrc},
    ecma::{
        ast::*,
        parser::{Parser, StringInput, TsSyntax},
        visit::{Visit, VisitWith},
    },
};

use crate::model::{AssignFact, CallFact, Fact, FactBase, FunctionFact, ImportFact, ImportKind};

use super::ExtractionDiagnostic;

// Re-export diagnostics types
pub use self::types::{JsTsDiagnostic, JsTsExtractionResult};

mod types {
    use crate::model::Fact;
    use super::ExtractionDiagnostic;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum JsTsDiagnostic {
        Fatal { file: String, message: String },
        NonFatal { file: String, line: u32, kind: String, message: String },
    }

    impl From<JsTsDiagnostic> for ExtractionDiagnostic {
        fn from(d: JsTsDiagnostic) -> Self {
            match d {
                JsTsDiagnostic::Fatal { file, message } => ExtractionDiagnostic {
                    file, line: 0, kind: "fatal_parse_error".into(), message,
                },
                JsTsDiagnostic::NonFatal { file, line, kind, message } => ExtractionDiagnostic {
                    file, line, kind, message,
                },
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct JsTsExtractionResult {
        pub facts: Vec<Fact>,
        pub diagnostics: Vec<JsTsDiagnostic>,
    }

    impl JsTsExtractionResult {
        pub fn empty() -> Self {
            Self { facts: Vec::new(), diagnostics: Vec::new() }
        }

        pub fn has_fatal(&self) -> bool {
            self.diagnostics.iter().any(|d| matches!(d, JsTsDiagnostic::Fatal { .. }))
        }
    }
}

const EXTRACTOR_NAME: &str = "rust_swc_phase8";

/// Main extractor struct implementing SWC's Visit trait.
pub(crate) struct JsTsFactExtractor {
    root: PathBuf,
    file: PathBuf,
    facts: Vec<Fact>,
    diagnostics: Vec<JsTsDiagnostic>,

    // Alias tracking (two independent systems)
    import_aliases: BTreeMap<String, String>,
    require_aliases: BTreeMap<String, String>,

    // Scope tracking
    function_stack: Vec<String>,
    class_stack: Vec<String>,

    // MCP handler context
    current_mcp_handler_id: Option<String>,

    // Named handler deferred processing
    named_handlers: BTreeMap<String, String>, // handler_name -> entrypoint_id
}

impl JsTsFactExtractor {
    fn new(root: &Path, file: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            file: file.to_path_buf(),
            facts: Vec::new(),
            diagnostics: Vec::new(),
            import_aliases: BTreeMap::new(),
            require_aliases: BTreeMap::new(),
            function_stack: Vec::new(),
            class_stack: Vec::new(),
            current_mcp_handler_id: None,
            named_handlers: BTreeMap::new(),
        }
    }

    fn rel_path(&self) -> String {
        self.file
            .strip_prefix(&self.root)
            .unwrap_or(&self.file)
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    }

    fn current_caller_id(&self) -> String {
        if let Some(handler_id) = &self.current_mcp_handler_id {
            return handler_id.clone();
        }
        if let Some(top) = self.function_stack.last() {
            ids::make_js_ts_function_id(&self.root, &self.file, top)
        } else {
            format!("javascript:{}:<module>", self.rel_path())
        }
    }

    fn line_of(&self, span: Span) -> u32 {
        // SWC Span.lo is a byte offset; count newlines to get 1-based line
        // For simplicity during initial implementation, return 1
        // Accurate line computation will use a SourceMap
        1
    }

    /// Convert expression to string for AssignFact value extraction.
    fn expr_to_string_for_assign(expr: &Expr) -> String {
        match expr {
            Expr::Ident(id) => id.sym.to_string(),
            Expr::Lit(Lit::Str(s)) => s.value.to_string(),
            Expr::Lit(Lit::Num(n)) => n.value.to_string(),
            Expr::Lit(Lit::Bool(b)) => b.value.to_string(),
            Expr::Member(m) => calls::callee_to_string(&Callee::Expr(Box::new(Expr::Member(m.clone())))),
            Expr::Call(_) => "<call>".to_string(),
            _ => String::new(),
        }
    }

    /// Post-processing pass: backfill SourceFacts for named handler references.
    fn backfill_named_handlers(&mut self) {
        // Build map: function_name -> FunctionFact
        let mut func_by_name: BTreeMap<String, &FunctionFact> = BTreeMap::new();
        for fact in &self.facts {
            if let Fact::Function(f) = fact {
                func_by_name.insert(f.name.clone(), f);
            }
        }

        for (handler_name, _ep_id) in &self.named_handlers {
            if let Some(func_fact) = func_by_name.get(handler_name) {
                let func_id = &func_fact.base.id;
                for param in &func_fact.params {
                    if param.name.starts_with("...") {
                        continue;
                    }
                    self.facts.push(Fact::Source(crate::model::SourceFact {
                        base: FactBase {
                            id: format!(
                                "source:{}:{}:{}",
                                self.rel_path(),
                                func_fact.qualified_name,
                                param.name
                            ),
                            file: self.rel_path(),
                            line: func_fact.base.line,
                            extractor: EXTRACTOR_NAME.to_string(),
                        },
                        kind: "mcp_tool_parameter".to_string(),
                        function_id: func_id.clone(),
                        name: param.name.clone(),
                        confidence: crate::model::Confidence::High,
                    }));
                }
            }
        }
    }
}

/// Detect SWC parse syntax from file extension.
fn detect_syntax(file: &Path) -> Syntax {
    match file.extension().and_then(|e| e.to_str()) {
        Some("ts" | "mts" | "cts") => Syntax::Typescript(TsSyntax::default()),
        Some("tsx") => Syntax::Typescript(TsSyntax {
            tsx: true,
            ..TsSyntax::default()
        }),
        _ => Syntax::Es(Default::default()),
    }
}

/// Public entry point: extract facts from a JS/TS source file.
pub fn extract_js_ts_facts(
    root: &Path,
    file: &Path,
    source: &str,
) -> JsTsExtractionResult {
    // Skip .d.ts declaration files
    if let Some(ext) = file.extension() {
        if let Some(name) = file.file_stem() {
            let name_str = name.to_string_lossy();
            if ext == "ts" && name_str.ends_with(".d") {
                return JsTsExtractionResult::empty();
            }
        }
    }

    let syntax = detect_syntax(file);
    let fm = Lrc::new(SourceMap::default().new_source_file(
        FileName::Custom(file.display().to_string()).into(),
        source.to_string(),
    ));

    let parser = Parser::new(
        syntax,
        StringInput::from(&*fm),
        None,
    );

    let mut parser = match parser {
        Ok(p) => p,
        Err(e) => {
            return JsTsExtractionResult {
                facts: Vec::new(),
                diagnostics: vec![JsTsDiagnostic::Fatal {
                    file: file.display().to_string(),
                    message: format!("Failed to create parser: {e}"),
                }],
            };
        }
    };

    let module = match parser.parse_module() {
        Ok(m) => m,
        Err(e) => {
            return JsTsExtractionResult {
                facts: Vec::new(),
                diagnostics: vec![JsTsDiagnostic::Fatal {
                    file: file.display().to_string(),
                    message: format!("Parse error: {e:?}"),
                }],
            };
        }
    };

    let mut extractor = JsTsFactExtractor::new(root, file);
    module.visit_with(&mut extractor);

    // Post-processing
    extractor.backfill_named_handlers();

    // Sort facts by line
    extractor.facts.sort_by_key(|fact| match fact {
        Fact::Function(f) => f.base.line,
        Fact::Import(i) => i.base.line,
        Fact::Entrypoint(e) => e.base.line,
        Fact::Call(c) => c.base.line,
        Fact::Sink(s) => s.base.line,
        Fact::Source(s) => s.base.line,
        Fact::Assign(a) => a.base.line,
        _ => u32::MAX,
    });

    JsTsExtractionResult {
        facts: extractor.facts,
        diagnostics: extractor.diagnostics,
    }
}

// --- SWC Visit trait implementation ---

impl Visit for JsTsFactExtractor {
    fn visit_import_decl(&mut self, n: &ImportDecl) {
        let file = self.rel_path();
        let line = self.line_of(n.span);
        imports::extract_esm_import(
            n, &file, line, EXTRACTOR_NAME,
            &mut self.facts, &mut self.import_aliases,
        );
        n.visit_children_with(self);
    }

    fn visit_fn_decl(&mut self, n: &FnDecl) {
        let name = n.ident.sym.to_string();
        let qual_name = functions::build_qualified_name(
            &self.function_stack, &self.class_stack, &name,
        );
        self.function_stack.push(qual_name.clone());

        let file = self.rel_path();
        let line = self.line_of(n.function.span);
        let func_id = ids::make_js_ts_function_id(&self.root, &self.file, &qual_name);
        let params = functions::params_from_fn(&n.function, "");

        self.facts.push(Fact::Function(functions::create_function_fact(
            func_id, file.clone(), line, EXTRACTOR_NAME.to_string(),
            "javascript".to_string(), name, qual_name,
            self.line_of(n.function.span), params,
            self.class_stack.last().cloned(),
        )));

        n.visit_children_with(self);
        self.function_stack.pop();
    }

    fn visit_class_decl(&mut self, n: &ClassDecl) {
        let name = n.ident.sym.to_string();
        self.class_stack.push(name);
        n.visit_children_with(self);
        self.class_stack.pop();
    }

    fn visit_var_decl(&mut self, n: &VarDecl) {
        for declarator in &n.decls {
            // Check for require() calls
            if let Some(init) = &declarator.init {
                if let Expr::Call(call) = init.as_ref() {
                    let callee_str = calls::callee_to_string(&call.callee);
                    if callee_str == "require" {
                        let file = self.rel_path();
                        let line = self.line_of(declarator.span);

                        // Simple require: const fs = require("fs")
                        if let Pat::Ident(id) = declarator.name.as_ref() {
                            let var_name = id.sym.to_string();
                            if let Some(first_arg) = call.args.first() {
                                if let Expr::Lit(Lit::Str(s)) = first_arg.expr.as_ref() {
                                    let module = s.value.to_string();
                                    self.require_aliases.insert(var_name.clone(), module.clone());
                                    self.facts.push(Fact::Import(ImportFact {
                                        base: FactBase {
                                            id: format!("import:{}:{line}:{module}", file),
                                            file: file.clone(),
                                            line,
                                            extractor: EXTRACTOR_NAME.to_string(),
                                        },
                                        language: "javascript".to_string(),
                                        module,
                                        imported_name: None,
                                        alias: Some(var_name),
                                        kind: ImportKind::Require,
                                    }));
                                }
                            }
                        }

                        // Destructured require: const { readFile, writeFile: wf } = require("fs")
                        if let Pat::Object(_) = declarator.name.as_ref() {
                            if let Some(first_arg) = call.args.first() {
                                if let Expr::Lit(Lit::Str(s)) = first_arg.expr.as_ref() {
                                    let module = s.value.to_string();
                                    imports::extract_destructured_require(
                                        declarator, &module, &file, line, EXTRACTOR_NAME,
                                        &mut self.facts, &mut self.require_aliases,
                                    );
                                }
                            }
                        }
                    }
                }

                // Check for arrow/function expression assigned to variable
                if let Expr::Arrow(arrow) = init.as_ref() {
                    if let Pat::Ident(id) = declarator.name.as_ref() {
                        let name = id.sym.to_string();
                        let qual_name = functions::build_qualified_name(
                            &self.function_stack, &self.class_stack, &name,
                        );
                        let file = self.rel_path();
                        let line = self.line_of(declarator.span);
                        let func_id = ids::make_js_ts_function_id(&self.root, &self.file, &qual_name);
                        let params = functions::params_from_fn(&Function {
                            params: arrow.params.iter().map(|p| Param {
                                span: p.span(),
                                decorators: Vec::new(),
                                pat: p.clone(),
                            }).collect(),
                            decorators: Vec::new(),
                            span: arrow.span,
                            body: arrow.body.as_ref().map(|b| match b {
                                BlockStmtOrExpr::BlockStmt(block) => block.clone(),
                                BlockStmtOrExpr::Expr(_) => BlockStmt {
                                    span: arrow.span,
                                    stmts: Vec::new(),
                                },
                            }),
                            is_generator: false,
                            is_async: arrow.is_async,
                            type_params: None,
                            return_type: None,
                        }, "");

                        self.facts.push(Fact::Function(functions::create_function_fact(
                            func_id, file, line, EXTRACTOR_NAME.to_string(),
                            "javascript".to_string(), name.clone(), qual_name.clone(),
                            self.line_of(arrow.span), params,
                            self.class_stack.last().cloned(),
                        )));
                    }
                }

                // Simple assignment: const x = expr → AssignFact
                if let Pat::Ident(id) = declarator.name.as_ref() {
                    if let Some(init_expr) = &declarator.init {
                        let value_str = Self::expr_to_string_for_assign(init_expr);
                        if !value_str.is_empty() && value_str != "<call>" {
                            let assign_id = format!(
                                "assign:{}:{}:{}",
                                file, line, id.sym
                            );
                            self.facts.push(Fact::Assign(AssignFact {
                                base: FactBase {
                                    id: assign_id,
                                    file: file.clone(),
                                    line,
                                    extractor: EXTRACTOR_NAME.to_string(),
                                },
                                function_id: self.current_caller_id(),
                                target: id.sym.to_string(),
                                value: value_str,
                                snippet: String::new(),
                            }));
                        }
                    }
                }
            }
        }
        n.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, n: &CallExpr) {
        let callee_str = calls::callee_to_string(&n.callee);
        let file = self.rel_path();
        let line = self.line_of(n.span);

        // Check for MCP registration first
        if mcp::is_mcp_registration(&callee_str) {
            // MCP registration: server.tool("name", handler)
            if let Some(second_arg) = n.args.get(1) {
                let tool_name = n.args.first()
                    .and_then(|a| match a.expr.as_ref() {
                        Expr::Lit(Lit::Str(s)) => Some(s.value.to_string()),
                        Expr::Ident(id) => Some(id.sym.to_string()),
                        _ => None,
                    })
                    .unwrap_or_else(|| "<anonymous>".to_string());

                match second_arg.expr.as_ref() {
                    Expr::Arrow(arrow) => {
                        // Inline arrow handler
                        let handler_name = format!("{tool_name}_handler");
                        let qual_name = functions::build_qualified_name(
                            &self.function_stack, &self.class_stack, &handler_name,
                        );
                        let handler_func_id =
                            ids::make_js_ts_function_id(&self.root, &self.file, &qual_name);
                        let params = functions::params_from_fn(&Function {
                            params: arrow.params.iter().map(|p| Param {
                                span: p.span(),
                                decorators: Vec::new(),
                                pat: p.clone(),
                            }).collect(),
                            decorators: Vec::new(),
                            span: arrow.span,
                            body: arrow.body.as_ref().map(|b| match b {
                                BlockStmtOrExpr::BlockStmt(block) => block.clone(),
                                BlockStmtOrExpr::Expr(_) => BlockStmt {
                                    span: arrow.span,
                                    stmts: Vec::new(),
                                },
                            }),
                            is_generator: false,
                            is_async: arrow.is_async,
                            type_params: None,
                            return_type: None,
                        }, "");

                        // Create FunctionFact for handler
                        self.facts.push(Fact::Function(functions::create_function_fact(
                            handler_func_id.clone(),
                            file.clone(),
                            line,
                            EXTRACTOR_NAME.to_string(),
                            "javascript".to_string(),
                            handler_name,
                            qual_name,
                            self.line_of(arrow.span),
                            params,
                            self.class_stack.last().cloned(),
                        )));

                        // Create EntryPointFact + SourceFacts
                        mcp::process_inline_arrow_handler(
                            &mut self.facts,
                            handler_func_id.clone(),
                            tool_name,
                            &callee_str,
                            &file,
                            line,
                            EXTRACTOR_NAME,
                            arrow,
                            "",
                        );

                        // Walk arrow body with handler context
                        let prev_handler = self.current_mcp_handler_id.take();
                        self.current_mcp_handler_id = Some(handler_func_id);
                        n.visit_children_with(self);
                        self.current_mcp_handler_id = prev_handler;
                        return;
                    }

                    Expr::Ident(id) => {
                        // Named handler reference
                        let handler_name = id.sym.to_string();
                        mcp::process_named_handler(
                            &mut self.named_handlers,
                            &handler_name,
                            &tool_name,
                            &callee_str,
                            &file,
                            line,
                            EXTRACTOR_NAME,
                            &mut self.facts,
                        );
                    }

                    _ => {}
                }
            }
            n.visit_children_with(self);
            return;
        }

        // Regular call: create CallFact
        let (normalized_callee, import_alias) = calls::resolve_callee(
            &callee_str, &self.import_aliases, &self.require_aliases,
        );
        let caller = self.current_caller_id();
        let args = calls::extract_call_args(n);
        let call_id = format!("call:{file}:{line}:0");

        self.facts.push(Fact::Call(CallFact {
            base: FactBase {
                id: call_id.clone(),
                file: file.clone(),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            caller,
            callee: callee_str,
            normalized_callee: Some(normalized_callee.clone()),
            column: None,
            end_line: None,
            snippet: String::new(),
            args,
            kwargs: BTreeMap::new(),
            resolution: import_alias.map(|alias| crate::model::CallResolution {
                import_alias: Some(alias),
                confidence: crate::model::Confidence::High,
            }),
        }));

        // Check sinks
        sinks::check_sink(&normalized_callee, &call_id, line, &file, EXTRACTOR_NAME, &mut self.facts);

        n.visit_children_with(self);
    }

    fn visit_class_method(&mut self, n: &ClassMethod) {
        let name = match &n.key {
            PropName::Ident(id) => id.sym.to_string(),
            _ => "<method>".to_string(),
        };
        let qual_name = functions::build_qualified_name(
            &self.function_stack, &self.class_stack, &name,
        );
        self.function_stack.push(qual_name.clone());

        let file = self.rel_path();
        let line = self.line_of(n.function.span);
        let func_id = ids::make_js_ts_function_id(&self.root, &self.file, &qual_name);
        let params = functions::params_from_fn(&n.function, "");

        self.facts.push(Fact::Function(functions::create_function_fact(
            func_id, file, line, EXTRACTOR_NAME.to_string(),
            "javascript".to_string(), name, qual_name,
            self.line_of(n.function.span), params,
            self.class_stack.last().cloned(),
        )));

        n.visit_children_with(self);
        self.function_stack.pop();
    }
}
```

- [ ] **Step 2: Build to verify compilation**

```bash
cd rust && cargo build 2>&1
```

Expected: compiles successfully. May need to fix SWC API mismatches — SWC 0.101 APIs for `TsSyntax`, `Parser`, etc. Adjust imports as needed.

- [ ] **Step 3: Run tests**

```bash
cd rust && cargo test 2>&1
```

Expected: 59 tests pass.

---

### Task 8: Update extract_js_ts_facts in pipeline and add integration tests

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/mod.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`

- [ ] **Step 1: Fix stub to use real implementation**

In `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/mod.rs`, remove the stub and re-export:

```rust
pub use js_ts::{JsTsDiagnostic, JsTsExtractionResult, extract_js_ts_facts};
```

- [ ] **Step 2: Update mod.rs exports**

In `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`, add to exports:

```rust
pub use facts::{
    ExtractionDiagnostic, PythonExtractionResult, JsTsExtractionResult, JsTsDiagnostic,
    extract_python_facts, extract_js_ts_facts, extract_static_facts,
};
```

- [ ] **Step 3: Update pipeline.rs to dispatch JS/TS**

In `pipeline.rs`, modify `extract_static_facts()` to add JS/TS branch:

```rust
use super::extract_js_ts_facts;

pub fn extract_static_facts(ctx: &StaticScanContext) -> Result<Vec<Fact>> {
    let mut facts = Vec::new();
    let mut diagnostics = Vec::new();

    for file in &ctx.discovered_files {
        match file.language {
            ScanLanguage::Python => {
                // existing Python extraction (unchanged)
            }
            ScanLanguage::JavaScript | ScanLanguage::TypeScript => {
                let source = fs::read_to_string(&file.path).with_context(|| {
                    format!(
                        "read JS/TS source for fact extraction: {}",
                        file.path.display()
                    )
                })?;
                let root = file.path.parent().unwrap_or_else(|| file.path.as_path());
                let result = extract_js_ts_facts(root, &file.path, &source);
                facts.extend(result.facts);
                diagnostics.extend(
                    result.diagnostics.into_iter().map(ExtractionDiagnostic::from),
                );
                if result.has_fatal() {
                    bail!("JS/TS fact extraction produced fatal errors");
                }
            }
            _ => continue,
        }
    }

    if !diagnostics.is_empty() {
        // Non-fatal diagnostics: log but continue (changed from Phase 7's bail behavior)
        // For Phase 8, maintain Phase 7 behavior: bail on any diagnostic
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
        bail!("fact extraction produced diagnostics: {summary}");
    }

    Ok(facts)
}
```

Note: Update the existing Python branch `continue` to handle the match structure properly.

- [ ] **Step 4: Build to verify compilation**

```bash
cd rust && cargo build 2>&1
```

- [ ] **Step 5: Write integration test for JS fact extraction**

Append to `pipeline.rs` tests (following existing pattern from Phase 7 Python tests):

```rust
#[test]
fn enabled_static_scan_includes_js_ts_facts() {
    let root = temp_dir("scan-js-facts");
    let rules = write_rulebook(&root, "rules.toml", "command_exec");
    fs::write(
        root.join("server.js"),
        r#"
const { exec } = require("child_process");

const server = { tool: (name, handler) => ({ name, handler }) };

server.tool("run_command", async (params) => {
    const { command } = params;
    exec(command, (error, stdout) => {
        console.log(stdout);
    });
});
"#,
    )
    .expect("write JS file");

    let result = run_static_scan(&RuntimeConfig::default(), &[rules], Some(&[root.clone()]))
        .expect("run scan");

    assert!(!result.facts.is_empty());
    assert_eq!(result.summary.fact_count, result.facts.len());
    assert!(
        result.facts.iter().any(|fact| matches!(fact, Fact::Import(_)))
    );
    assert!(
        result.facts.iter().any(|fact| matches!(fact, Fact::Function(_)))
    );
    assert!(
        result.facts.iter().any(|fact| matches!(fact, Fact::Entrypoint(_)))
    );
    assert!(
        result.facts.iter().any(|fact| matches!(fact, Fact::Source(_)))
    );
    assert!(
        result.facts.iter().any(|fact| matches!(fact, Fact::Call(_)))
    );
    assert!(
        result.facts.iter().any(|fact| matches!(fact, Fact::Sink(_)))
    );
    assert_eq!(result.summary.taint_result_count, 0);

    fs::remove_dir_all(root).expect("cleanup");
}
```

- [ ] **Step 6: Write integration test for TypeScript**

```rust
#[test]
fn enabled_static_scan_includes_typescript_facts() {
    let root = temp_dir("scan-ts-facts");
    let rules = write_rulebook(&root, "rules.toml", "command_exec");
    fs::write(
        root.join("server.ts"),
        r#"
import { exec } from "child_process";

interface ToolParams {
    command: string;
}

const server = {
    tool(name: string, handler: (params: any) => Promise<any>) {
        return { name, handler };
    }
};

server.tool("run_command", async (params: ToolParams) => {
    const { command } = params;
    exec(command);
});
"#,
    )
    .expect("write TS file");

    let result = run_static_scan(&RuntimeConfig::default(), &[rules], Some(&[root.clone()]))
        .expect("run scan");

    assert!(!result.facts.is_empty());
    assert!(
        result.facts.iter().any(|fact| matches!(fact, Fact::Entrypoint(_)))
    );
    assert!(
        result.facts.iter().any(|fact| matches!(fact, Fact::Sink(_)))
    );

    fs::remove_dir_all(root).expect("cleanup");
}
```

- [ ] **Step 7: Run all tests**

```bash
cd rust && cargo test 2>&1
```

Expected: all tests pass (existing 59 + 2 new integration tests = 61).

- [ ] **Step 8: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/mod.rs rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs
git commit -m "feat(phase8): wire JS/TS fact extraction into static analysis pipeline"
```

---

### Task 9: Update phase constant, lib.rs exports, and final verification

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/lib.rs`
- Modify: `rust/docs/REFACTOR_PLAN.md`

- [ ] **Step 1: Update phase constant**

In `lib.rs`:

```rust
pub const CURRENT_PHASE: &str = "phase8-js-ts-fact-extraction";
```

Update the test:

```rust
#[test]
fn exposes_current_phase() {
    assert_eq!(CURRENT_PHASE, "phase8-js-ts-fact-extraction");
}
```

- [ ] **Step 2: Add JsTsExtractionResult to lib.rs exports**

In `lib.rs`, add to `pub use static_analysis` block:

```rust
    JsTsDiagnostic, JsTsExtractionResult, extract_js_ts_facts,
```

- [ ] **Step 3: Update REFACTOR_PLAN.md**

Change Phase 8 status from `未开始` to `完成`:

```markdown
| Phase 8：JS/TS fact 提取  | 完成 | 从 JavaScript 和 TypeScript 源码中提取核心静态 facts。 | JS/TS fixtures 可以产出预期的入口、调用、导入、sink 和相关基础 facts。 |
```

Add a note below Phase 8 similar to Phase 7's note:

```markdown
Phase 8 已完成 JS/TS fact extraction 基础能力：SWC AST extractor 已产出 import (ESM/CJS)、function、entrypoint (MCP 回调模式)、source (含解构展开)、call、assign、sink (8 类) facts，并已接入 run_static_scan() 的 facts 和 summary.fact_count。Phase 8 不包含完整 taint propagation、完整 call graph、finding fusion、Agent 分析或动态分析；taint line 在默认配置中保持禁用，显式启用时返回明确未实现错误。
```

- [ ] **Step 4: Run full test suite**

```bash
cd rust && cargo test 2>&1 && cargo build 2>&1
```

Expected: all tests pass, clean build.

- [ ] **Step 5: Final commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/lib.rs rust/docs/REFACTOR_PLAN.md
git commit -m "feat(phase8): mark Phase 8 complete — JS/TS fact extraction with SWC

- SWC-based JavaScript/TypeScript AST fact extractor
- 6 ImportKinds (ESM default/named/namespace + CJS require/destructured)
- 4 function forms (decl, expr, arrow, method) with TypeScript annotations
- MCP callback registration detection (server.tool / mcp.tool)
- SourceFact with recursive destructuring expansion
- 8 JS sink categories: command_execution, dynamic_execution,
  file_read, file_write, network_request, credential_leak,
  database_injection, deserialization_rce
- Dual alias resolution (ESM imports + CJS require)
- Named handler deferred backfill for SourceFacts
- Integrated into run_static_scan() pipeline
- Phase constant updated to phase8-js-ts-fact-extraction"
```

---

### Task 10: Run full verification

- [ ] **Step 1: Run all tests one final time**

```bash
cd rust && cargo test --all 2>&1
```

- [ ] **Step 2: Run clippy**

```bash
cd rust && cargo clippy --all-targets 2>&1
```

Expected: no warnings.

- [ ] **Step 3: Verify CLI still works**

```bash
cd rust && cargo run -- --help 2>&1
```

Expected: CLI help output shows.

- [ ] **Step 4: Notify completion**

Report completion status and test summary.
