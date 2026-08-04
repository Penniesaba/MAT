# Phase 8: JS/TS Fact Extraction — Design

**Date:** 2026-08-04
**Status:** Approved
**Ref:** `rust/docs/REFACTOR_PLAN.md` Phase 8

## Scope

从 JavaScript 和 TypeScript 源码中提取核心静态 facts，接入 Rust 静态分析 pipeline。

## Non-Scope

- 不包含 taint propagation（Phase 10/11）
- 不包含 call graph（Phase 10）
- 不包含 finding fusion（Phase 13）
- 不包含 Agent 分析（Phase 12）
- 不包含动态分析（Phase 15+）
- taint line 保持禁用，显式启用时继续报未实现错误

---

## 1. Architecture

```
                    run_static_scan()
                          │
                          ▼
                 extract_static_facts()
                          │
            ┌─────────────┼─────────────┐
            ▼             ▼             ▼
     Python files    JS/TS files    (future: Rust)
            │             │
            ▼             ▼
     extract_python    extract_js_ts
     _facts()          _facts()
            │             │
            ▼             ▼
     PythonExtraction  JsTsExtraction
     Result            Result
            │             │
            └──────┬──────┘
                   ▼
            Vec<Fact>  →  StaticAnalysisResult
```

`extract_static_facts()` dispatches by file language. JS/TS files route to the new `extract_js_ts_facts()`. Both languages produce identical `Vec<Fact>`, making downstream rule/taint/agent lines and report outputs unchanged.

### JS/TS Internal Architecture

Uses SWC Visit trait for compiler-guaranteed exhaustive traversal, with module-level decomposition:

```
facts/
├── mod.rs              # JsTsExtractionResult + exports
├── ids.rs              # Reused from Phase 7
├── pipeline.rs         # Extended: JS/TS dispatch
├── python.rs           # Existing
└── js_ts/
    ├── mod.rs          # JsTsFactExtractor state + Visit trait impl (dispatch)
    ├── imports.rs      # ESM + CJS import extraction
    ├── functions.rs    # 4 function forms + TS type annotations
    ├── calls.rs        # Call expressions + alias resolution
    ├── sinks.rs        # 8 sink categories
    └── mcp.rs          # MCP registration detection (server.tool / mcp.tool)
```

- `JsTsFactExtractor` holds shared state (alias maps, scope stack, facts buffer, diagnostics)
- It implements SWC's `Visit` trait, each `visit_*` method delegates to a pure function in the corresponding module
- Each module independently unit-testable (construct virtual AST nodes + state, verify produced facts)
- SWC Visit trait ensures exhaustive traversal; module decomposition ensures testability

JS and TS share a single extractor. Differences are only in the SWC parse syntax mode: `Syntax::Es` / `Syntax::Typescript` / `Syntax::Tsx`.

---

## 2. Fact Type Coverage

All fact enum variants from Phase 7. JS/TS-specific details:

| Fact Type | JS/TS Coverage | Key Differences vs Python |
|-----------|---------------|--------------------------|
| **Import** | ESM default/named/namespace, CJS `require()`, destructured require, aliased destructured require | 6 ImportKinds (Python: 4), two alias systems (import_aliases + require_aliases) |
| **Function** | function decl, function expr, arrow, class method, variable-assigned function | Arrow has no own name; method needs class for enclosing_class; TS annotation on params + return type |
| **Entrypoint** | `server.tool/resource/prompt("name", handler)`, `mcp.tool(...)` | Callback registration pattern (not decorator); handler may be inline arrow or identifier reference |
| **Source** | MCP handler params (from arrow params or named function params) | Inline arrow: immediate extraction. Named reference: deferred via post-processing pass. Destructured params fully expanded |
| **Call** | All call expressions including member `a.b.c()`, optional chaining `a?.b()` | Member calls more common than Python; callee resolution more complex |
| **Sink** | 8 categories (see below) | JS-specific sink patterns |
| **Assign** | Intra-function `const x = expr;` | Same as Phase 7, foundation for taint-lite |
| **Dataflow** | Not implemented | Phase 10/11 |
| **RuntimeEvent** | Not applicable | Dynamic analysis only |
| **Finding** | Not implemented | Phase 13 fusion |

### TypeScript Extras

- `ParamInfo.annotation` — TS type annotation (`: string`, `: number`, etc.)
- Function return type annotation (`return_type: Option<String>` on `FunctionFact`, added to model; Python/JS fill `None`)
- No new fact variants (InterfaceFact, EnumFact) — not security-relevant

### 2.1 Sink Categories (8 total)

| Category | Sink Patterns | Severity |
|----------|--------------|----------|
| `command_execution` | `child_process.exec/spawn/fork/execSync/spawnSync/execFile` | High |
| `dynamic_execution` | `eval`, `new Function`, `Function()` | Critical |
| `file_write` | `fs.writeFile/Sync`, `fs.createWriteStream`, `fs.promises.writeFile` | Medium |
| `file_read` | `fs.readFile/Sync`, `fs.createReadStream`, `fs.promises.readFile` | Medium |
| `network_request` | `http.request`, `https.request`, `fetch`, `net.connect`, `axios` | Medium |
| `credential_leak` | `process.env[expr]`, `fs.readFileSync(".env")` | High |
| `database_injection` | `connection.query()`, `db.run()`, `Model.find()`, `mongoose...exec()`, `mysql...query()` | Critical |
| `deserialization_rce` | `vm.runInNewContext()`, `vm.Script()`, `new WebAssembly.Module()` | Critical |

### 2.2 Source Fact Expansion for Destructured Params

```typescript
// Before (Phase 7 Python behavior): only identifiers
server.tool("deploy", (command) => ...)  // ✅ command extracted

// After (Phase 8): recursive destructuring expansion
server.tool("deploy", ({ command, env: { HOME } }) => ...)
// ✅ command extracted
// ✅ HOME extracted
```

---

## 3. Extraction Flow

### 3.1 Main Flow

```
extract_js_ts_facts(root, file, source)
        │
        ├─ 1. Detect language: .js/.mjs/.cjs → Syntax::Es
        │                       .ts/.mts/.cts → Syntax::Typescript
        │                       .tsx           → Syntax::Tsx
        │   Skip: .d.ts (declaration files, no executable code)
        │
        ├─ 2. SWC parse → Module (success) | diagnostic error (failure)
        │
        ├─ 3. JsTsFactExtractor::extract(module)
        │       │
        │       ├─ Pass 1: Visit traversal
        │       │   ├─ visit_import_decl()     → ImportFact + import_aliases
        │       │   ├─ visit_call_expr()       → check require() → ImportFact + require_aliases
        │       │   ├─ visit_fn_decl()         → FunctionFact + scope push
        │       │   ├─ visit_var_decl()        → arrow/function/require/AssignFact
        │       │   ├─ visit_class_decl()      → class stack push
        │       │   ├─ visit_call_expr()       → CallFact + MCP detection + Sink detection
        │       │   └─ ...
        │       │
        │       ├─ Pass 2: Post-processing
        │       │   └─ process_named_handlers()
        │       │       For identifier-referenced MCP handlers,
        │       │       backfill SourceFact from recorded FunctionFact
        │       │
        │       └─ Return Vec<Fact> (sorted by line)
        │
        └─ 4. Wrap as JsTsExtractionResult { facts, diagnostics }
```

### 3.2 Dual Alias Resolution

JS/TS has two independent alias paths:

```rust
struct JsTsFactExtractor {
    // ESM: import { fs } from "fs"      → "fs"      → "fs"
    // ESM: import fs from "fs"          → "fs"      → "fs"
    // ESM: import { readFile }          → "readFile" → "fs.readFile"
    import_aliases: BTreeMap<String, String>,

    // CJS: const fs = require("fs")             → "fs"       → "fs"
    // CJS: const { readFile } = require("fs")   → "readFile" → "fs.readFile"
    // CJS: const { exec: ex } = require(...)     → "ex"      → "child_process.exec"
    require_aliases: BTreeMap<String, String>,
}
```

Resolution order: `import_aliases` first, then `require_aliases`, then fallback to raw callee (global function).

### 3.3 MCP Registration Detection (Different from Python Decorator)

```
visit_call_expr(node):
    │
    ├─ Check if callee matches MCP registration patterns:
    │   "server.tool" / "mcp.tool" / "server.resource" / "mcp.resource"
    │   "server.prompt" / "mcp.prompt"
    │
    ├─ Match → MCP handler processing:
    │   │
    │   ├─ Handler is arrow function → inline processing:
    │   │   ├─ Generate FunctionFact (with _handler suffix)
    │   │   ├─ Extract params recursively → SourceFact (including destructuring)
    │   │   ├─ Generate EntryPointFact
    │   │   └─ Continue traversing body with handler's function_id as context
    │   │       → body CallFact attributed to handler
    │   │
    │   └─ Handler is identifier → deferred processing:
    │       ├─ Generate EntryPointFact (params empty initially)
    │       ├─ Record to pending_named_handlers
    │       └─ Post-processing: find matching FunctionFact → backfill SourceFact
    │
    └─ No match → normal CallFact processing + Sink detection
```

### 3.4 Source Destructuring Expansion

```rust
fn extract_source_params(pattern: &Pat, func_id: &str) -> Vec<SourceFact> {
    match pattern {
        Pat::Ident(id) => vec![source_fact(id.sym, func_id)],
        Pat::Object(obj) => obj.props.iter().flat_map(|prop| {
            match prop {
                ObjectPatProp::KeyValue(kv) => extract_source_params(&kv.value, func_id),
                ObjectPatProp::Assign(assign) => vec![source_fact(assign.key.sym, func_id)],
                ObjectPatProp::Rest(rest) => vec![source_fact(format!("...{}", rest.arg.sym), func_id)],
            }
        }).collect(),
        Pat::Array(arr) => arr.elems.iter().filter_map(|elem| {
            elem.as_ref().map(|pat| extract_source_params(pat, func_id))
        }).flatten().collect(),
        Pat::Rest(rest) => extract_source_params(&rest.arg, func_id),
        _ => vec![],
    }
}
```

Nested destructuring like `({ command, env: { HOME } })` correctly extracts both `command` and `HOME`.

---

## 4. Error Handling & Diagnostics

### 4.1 Three-Layer Fault Tolerance

| Layer | Scope | Behavior |
|-------|-------|----------|
| **File-level** | SWC parse failure | File skipped, 1 FatalDiagnostic. `.gitkeep` / minified: silently skipped |
| **Expression-level** | Single callee unresolvable | Placeholder `"<unknown>"`. Single pattern unexpanded: skip that SourceFact. Path not under root: NonFatal + continue |
| **Module-level** | Post-processing: handler reference not found | NonFatal. Accumulated errors > threshold (50) → bail |

Phase 8 uses **tolerance-first** strategy (different from Phase 7 Python's fail-fast). Real-world JS/TS code contains minified files, dynamic require(), and unusual DSLs. One parse error must not block other file extractions.

### 4.2 Diagnostic Types

```rust
enum JsTsDiagnostic {
    Fatal { file: String, message: String },
    NonFatal { file: String, line: u32, kind: String, message: String },
}

// Convert to pipeline-compatible ExtractionDiagnostic (same as Phase 7)
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
```

### 4.3 Parser Selection

```rust
fn detect_syntax(file: &Path) -> Syntax {
    match file.extension().and_then(|e| e.to_str()) {
        Some("ts" | "mts" | "cts") => Syntax::Typescript(TsSyntaxConfig::default()),
        Some("tsx")                 => Syntax::Tsx(TsSyntaxConfig::default()),
        _                           => Syntax::Es(EsSyntaxConfig::default()),
    }
}
```

`.d.ts` declaration files are skipped — no executable code, no security facts.

---

## 5. Pipeline Integration

### 5.1 Changes to `extract_static_facts()` (pipeline.rs)

Add JS/TS branch alongside existing Python branch:

```rust
for file in &ctx.discovered_files {
    match file.language {
        ScanLanguage::Python => {
            // existing: bail on any diagnostic
        }
        ScanLanguage::JavaScript | ScanLanguage::TypeScript => {
            let source = fs::read_to_string(&file.path)?;
            let result = extract_js_ts_facts(root, &file.path, &source);
            facts.extend(result.facts);
            // Convert JsTsDiagnostic → ExtractionDiagnostic
            // NonFatal: logged, continues to next file
            // Fatal: logged, file skipped (no facts from this file)
            diagnostics.extend(
                result.diagnostics.into_iter().map(ExtractionDiagnostic::from)
            );
            // For now: bail if any fatal diagnostic (consistent with Python behavior)
            // Future: can relax to tolerance-first once pipeline supports it
            if result.diagnostics.iter().any(|d| matches!(d, JsTsDiagnostic::Fatal { .. })) {
                bail!("JS/TS fact extraction had fatal errors");
            }
        }
        _ => continue,
    }
}
```

### 5.2 Changes to `mod.rs`

```rust
pub use facts::{
    ExtractionDiagnostic, PythonExtractionResult, JsTsExtractionResult,
    extract_python_facts, extract_js_ts_facts, extract_static_facts,
};
```

### 5.3 Integration Verification

The existing test `enabled_static_scan_includes_python_facts_and_fact_count` pattern is extended with a mixed JS/TS test verifying:
- `ScanLanguage::JavaScript` and `ScanLanguage::TypeScript` files are discovered
- Facts flow into `StaticAnalysisResult.facts`
- `summary.fact_count` reflects combined Python + JS/TS facts
- Taint line remains disabled (returns empty), enabled taint line still errors

---

## 6. Dependencies

Add to workspace `Cargo.toml`:

```toml
swc_core = { version = "0.101", features = [
    "ecma_parser",
    "ecma_ast",
    "ecma_visit",
    "common",
] }
```

Add to `mcp-sec-audit-core/Cargo.toml`:

```toml
swc_core.workspace = true
```

SWC 0.101 is the latest stable. Uses `ecma_parser` (parsing), `ecma_ast` (AST types), `ecma_visit` (Visit trait). `common` provides `Syntax`, `SourceMap`, `FileName` types.

---

## 7. Testing Strategy

### 7.1 Unit Tests (per module)

**imports.rs:**
- `esm_default_import_with_alias`
- `esm_named_imports_multiple`
- `esm_namespace_import`
- `cjs_bare_require`
- `cjs_destructured_require`
- `cjs_aliased_destructured_require`

**functions.rs:**
- `function_declaration_top_level`
- `function_expression_variable`
- `arrow_function_assigned`
- `class_method_with_enclosing_class`
- `nested_functions_qualified_names`
- `ts_type_annotations_on_params`
- `ts_return_type_annotation`

**calls.rs:**
- `simple_call_with_positional_args`
- `member_expression_call_recursive_callee`
- `optional_chaining_call`
- `alias_resolution_esm_import`
- `alias_resolution_cjs_require`

**mcp.rs:**
- `server_tool_with_arrow_handler`
- `server_resource_with_named_handler`
- `mcp_tool_direct_call`
- `destructured_params_as_source_facts`
- `nested_destructured_params_expanded`

**sinks.rs:**
- `child_process_exec_detected` (command_execution)
- `eval_and_new_function_detected` (dynamic_execution)
- `fs_read_write_detected` (file_read, file_write)
- `http_fetch_network_detected` (network_request)
- `credential_leak_process_env` (credential_leak)
- `database_injection_mysql_query` (database_injection)
- `deserialization_vm_runinnewcontext` (deserialization_rce)

### 7.2 Integration Tests (extract_js_ts_facts entry)

- `full_mcp_server_js_fixture` — CJS + server.tool pattern
- `full_mcp_server_ts_fixture` — TypeScript MCP server
- `tsx_file_with_mcp_tools` — TSX with JSX + MCP registration
- `syntax_error_returns_diagnostics` — broken JS produces diagnostics
- `minified_file_graceful_degradation` — large minified files don't crash

### 7.3 Pipeline Integration Tests (extract_static_facts)

- `mixed_python_js_ts_discovery` — files with different languages all extracted
- `js_ts_facts_flow_to_run_static_scan` — facts appear in StaticAnalysisResult
- `js_ts_facts_populate_summary_fact_count` — fact_count is accurate

### 7.4 Fixture Files

```
rust/crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/
└── tests/
    └── fixtures/
        ├── basic_server.js       # CJS require + server.tool
        ├── esm_server.mjs        # ESM import + mcp.tool
        ├── full_server.ts        # TypeScript MCP server
        ├── react_tool.tsx        # TSX with MCP tools
        ├── destructured.ts       # Nested destructured params
        ├── sinks_all.js          # All 8 sink categories
        └── broken.js             # Syntax error for diagnostics
```

---

## 8. Acceptance Criteria

From `REFACTOR_PLAN.md` Phase 8: "JS/TS fixtures 可以产出预期的入口、调用、导入、sink 和相关基础 facts"

| Criteria | Verification |
|----------|-------------|
| Import facts: 6 ImportKinds (ESM + CJS) extracted correctly | `imports.rs` unit tests |
| Function facts: 4 function forms + TS annotations | `functions.rs` unit tests |
| Entrypoint facts: MCP callback registration pattern | `mcp.rs` unit tests + integration fixtures |
| Source facts: params from inline arrow + named handlers, destructuring expanded | `mcp.rs` destructured tests |
| Call facts: member expression callee + dual alias resolution | `calls.rs` unit tests |
| Sink facts: 8 JS sink categories detected | `sinks.rs` unit tests |
| Assign facts: intra-function assignments extracted | `calls.rs` fixture tests |
| Pipeline integration: facts flow into `run_static_scan()` | pipeline integration tests |
| Taint line disabled by default, enabled → error | Existing test unchanged |
| All tests pass: `cargo test` | CI gate |

---

## 9. Deltas to Existing Model

### 9.1 FunctionFact: add `return_type`

```rust
pub struct FunctionFact {
    // ... existing fields ...
    pub return_type: Option<String>,  // NEW: TS return type annotation
}
```

Python/JS fill `None`. TS fills when type annotation present.

### 9.2 JsTsExtractionResult

```rust
pub struct JsTsExtractionResult {
    pub facts: Vec<Fact>,
    pub diagnostics: Vec<JsTsDiagnostic>,
}
```

Analogous to `PythonExtractionResult` but uses `JsTsDiagnostic` with severity levels.

### 9.3 Phase constant

Update `exposes_current_phase` test to reflect Phase 8 status when `extract_static_facts` handles JS/TS.

---

## 10. Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| SWC parse failure on edge case JS/TS syntax | Tolerance-first error handling; skip file, not crash |
| Callee resolution ambiguity (global vs module) | Two-stage alias lookup; `<unknown>` fallback never panics |
| Minified files exploding parse time | SWC is optimized for large files; `.min.js` exclusion rule if needed |
| Duplicate facts from inline + named handler | Call ID dedup via `processed_handler_call_ids` set |
| TS-specific syntax not handled | `.d.ts` skip + `TsSyntaxConfig` default tolerant settings |
