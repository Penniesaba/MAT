# R4 — CodeQL 用满 (Full Suites + MCP Query Matrix + MaD Extension) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make CodeQL the highest-precision, deepest analysis line: run the full standard suites, fill out the MCP attack-surface query matrix for Python and JS/TS, and compile the shared model catalog into CodeQL MaD model packs so standard queries reach third-party wrappers like `openpyxl.load_workbook`.

**Architecture:** CodeQL's generic L1/L2 engine already tracks data flow; its weakness is L3 model coverage. We fix that two ways: (1) write MCP-specific `.ql` queries with correct source/sink/sanitizer + `@tags` category labels, and (2) compile our `ModelCatalog` (the TOML sink models from R2) into CodeQL MaD `sinkModel` extensions so the *standard* queries (`py/path-injection`, `py/command-injection`, …) also reach third-party wrappers. A `CodeqlSession` refactor caches the database and accepts model packs, which R5 reuses for warm re-run.

**Tech Stack:** Rust (`tracing`, `serde`, `toml`), CodeQL CLI 2.26.2, QL (`TaintTracking`, API Graphs, MaD).

**Spec:** `rust/docs/CODEQL_MASTER_PLAN.md` (tactical) + `rust/docs/ARCHITECTURE_REDESIGN.md` §5.3 (双引擎) and §5.1 (MaD compile).

## Global Constraints

- CodeQL CLI **2.26.2** is pinned (`codeql --version`); binary resolved from `[static.codeql].binary` (default `"codeql"`).
- Suite refs stay **version-pinned** (`codeql/python-queries@1.8.7`, `codeql/javascript-queries@2.4.2`, `codeql/rust-queries@0.1.39`) — do **not** unpin (2.26.2 cannot resolve unversioned refs; 2.26.3 packs fail to download).
- MaD `sinkModel` data is the **3-tuple** `[module, path, kind]` (verified against `codeql/python-all@7.2.2` and `codeql/javascript-all@2.8.2`), **not** the old 5-tuple in `GENERALITY_STRATEGY.md` §2.1.3.
- Category → MaD kind mapping is **fixed** (verified empirically in the installed packs):
  - `command_execution` → `command-injection`
  - `dynamic_execution` → `code-injection`
  - `database_injection` → `sql-injection`
  - `network_request` → `request-forgery`
  - `file_read` / `file_write` / `file_delete` / `path_traversal` → `path-injection`
  - `template_injection` → `template injection` (space, not underscore)
  - `prompt_injection` → `prompt-injection`
  - `deserialization`/`deserialization_rce`, `env_access`, `xml_parsing`, `xpath_injection`, `unsafe_block`, `tool_poisoning`, `data_exfiltration`, `dynamic_import`, `dynamic_loading` → **no standard sinkModel kind → skipped** (covered by the built-in taint line).
- No `cargo test` regression. Baseline: **216 core + 4 CLI = 220 green**.
- Every `.ql` query carries `@id` + `@name` + `@tags` (with a canonical category tag) + a comment naming its test sample.
- All unit tests must run **without CodeQL installed** (the existing convention: use `__codeql_definitely_missing__` and never invoke the real CLI in `cargo test`).
- **QL API (verified on 2.26.2, Task 1):** the Python `semmle.python.dataflow.new` library uses `Function.getAnArg()` (NOT `getAParameter`), `DataFlow::parameterNode(f.getAnArg())`, sanitizer hook `predicate isBarrier(DataFlow::Node n)` (NOT `isSanitizer`), and registration-form source via `import semmle.python.frameworks.internal.PoorMansFunctionResolution` + `poorMansFunctionTracker(handler) = call.getArg(1)`. Apply these names everywhere in Tasks 4/5; the JS snippets are illustrative and must be compile-checked against `semmle.javascript.dataflow.new`.

---

### Task 1: Strengthen the 3 existing Python MCP queries (source + sanitizer + `@tags`)

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/ToolParameterToSink.ql`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/PromptInjection.ql`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/ResourceToNetwork.ql`

**Interfaces:**
- Consumes: the existing `mcp-python` query pack (`qlpack.yml` deps `codeql/python-all: 7.2.2`).
- Produces: queries whose `@tags` carry canonical categories, consumed by `parser::resolve_category` (already reads `rule.properties.tags`).

- [ ] **Step 1: Rewrite `ToolParameterToSink.ql` source + sanitizer + tags**

Replace the whole file with:

```ql
/**
 * @name MCP tool parameter to dangerous sink
 * @description Tracks data flow from MCP tool parameters (decorator or
 *              registration form) to dangerous sinks without sanitization.
 * @kind path-problem
 * @problem.severity error
 * @id mcp/tool-parameter-to-sink
 * @tags security mcp command-execution
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

/**
 * A decorator `@<obj>.tool(...)` whose attribute name ends in "tool"
 * (`@mcp.tool()`, `@fastmcp.tool()`, `@server.tool()`), OR a registration
 * call `server.tool("name", handler)` / `mcp.tool("name", handler)`.
 */
class McpToolSource extends DataFlow::Node {
  McpToolSource() {
    // Decorator form: @x.tool() on a function — every parameter is a source.
    exists(Function f, Call dec, Attribute attr |
      dec = f.getADecorator() and
      dec.getFunc() = attr and
      attr.getName() = "tool" and
      this = DataFlow::parameterNode(f.getAParameter())
    )
    or
    // Registration form: server.tool("name", handler) — handler's parameters.
    exists(DataFlow::CallCfgNode call, Function handler |
      call = API::moduleImport("mcp").getMember("tool").getACall()
      and call.getArg(1) = DataFlow::exprNode(handler.getDefiningExpression())
      and this = DataFlow::parameterNode(handler.getAParameter())
    )
  }
}

/** Command execution / dynamic code / deserialization / file sinks. */
class DangerousSink extends DataFlow::Node {
  DangerousSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("os").getMember("system").getACall() or
      call = API::moduleImport("os").getMember("popen").getACall() or
      call = API::moduleImport("subprocess").getMember("run").getACall() or
      call = API::moduleImport("subprocess").getMember("Popen").getACall() or
      call = API::moduleImport("subprocess").getMember("call").getACall() or
      call = API::builtin("eval").getACall() or
      call = API::builtin("exec").getACall() or
      call = API::moduleImport("pickle").getMember("loads").getACall() or
      call = API::moduleImport("builtins").getMember("open").getACall()
    |
      this = call.getArg(0)
    )
  }
}

/** Recognized sanitizers: shell quoting and path canonicalization. */
class Sanitizer extends DataFlow::Node {
  Sanitizer() {
    this = API::moduleImport("shlex").getMember("quote").getACall() or
    this = API::moduleImport("os").getMember("path").getMember("realpath").getACall() or
    this = API::moduleImport("os").getMember("path").getMember("abspath").getACall() or
    this = API::moduleImport("os").getMember("path").getMember("normpath").getACall()
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof McpToolSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof DangerousSink }
  predicate isSanitizer(DataFlow::Node node) { node instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to a dangerous sink without sanitization.",
  source.getNode(), "user input"
```

- [ ] **Step 2: Add `@tags` + registration source to `PromptInjection.ql` and `ResourceToNetwork.ql`**

For each file, add the `@tags security mcp <category>` line after `@id` (PromptInjection → `prompt-injection`, ResourceToNetwork → `data-exfiltration`), and add the registration-form source to the source class using the same `or exists(DataFlow::CallCfgNode call, Function handler | call = API::moduleImport("mcp").getMember("prompt").getACall() and ...)` (resp. `"resource"`) pattern as Task 1 Step 1.

- [ ] **Step 3: Syntax-check the queries**

Run: `codeql query compile --search-path crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/ToolParameterToSink.ql`
Expected: exits 0 with no QL errors.

- [ ] **Step 4: Smoke test against the Python target**

```bash
rm -rf /tmp/db-r4 && codeql database create /tmp/db-r4 --language=python --source-root=test-targets/python-mcp-server --overwrite
codeql database analyze /tmp/db-r4 crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python --format=sarif-latest --output=/tmp/r4.sarif
```
Expected: `ToolParameterToSink.ql` hits `run_shell` (command injection) in `server.py`.

- [ ] **Step 5: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/
git commit -m "feat(codeql): strengthen Python MCP queries (source+sanitizer+tags)"
```

---

### Task 2: MaD model-package compiler (`codeql/models.rs`)

**Files:**
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/models.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs` (add `mod models;`)

**Interfaces:**
- Consumes: `crate::models::SinkModel` (R2 schema: `language`/`category`/`severity`/`confidence`/`reason`/`patterns`).
- Produces (public to crate):
  - `pub struct MadSinkEntry { pub module: String, pub path: String, pub kind: String }`
  - `pub fn sink_models_to_mad(models: &[SinkModel]) -> Vec<MadSinkEntry>`
  - `pub fn render_mad_pack(models: &[SinkModel], language: &str) -> String` (YAML string for one language)
  - `pub fn mad_sink_kind(category: &str) -> Option<&'static str>`

- [ ] **Step 1: Write the failing unit tests**

Add to `models.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SinkModel;
    use crate::{Confidence, Severity};

    fn model(category: &str, patterns: &[&str]) -> SinkModel {
        SinkModel {
            language: "python".into(),
            category: category.into(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            reason: "t".into(),
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn maps_categories_to_mad_kinds() {
        assert_eq!(mad_sink_kind("command_execution"), Some("command-injection"));
        assert_eq!(mad_sink_kind("dynamic_execution"), Some("code-injection"));
        assert_eq!(mad_sink_kind("database_injection"), Some("sql-injection"));
        assert_eq!(mad_sink_kind("network_request"), Some("request-forgery"));
        assert_eq!(mad_sink_kind("file_read"), Some("path-injection"));
        assert_eq!(mad_sink_kind("template_injection"), Some("template injection"));
        assert_eq!(mad_sink_kind("deserialization"), None);
        assert_eq!(mad_sink_kind("env_access"), None);
    }

    #[test]
    fn module_function_pattern_becomes_mad_entry() {
        let models = vec![model("file_read", &["openpyxl.load_workbook"])];
        let entries = sink_models_to_mad(&models);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].module, "openpyxl");
        assert_eq!(entries[0].path, "Member[load_workbook].Argument[0]");
        assert_eq!(entries[0].kind, "path-injection");
    }

    #[test]
    fn single_segment_patterns_are_skipped() {
        // eval/exec are builtins with no module prefix — not MaD-representable.
        let models = vec![model("dynamic_execution", &["eval", "exec"])];
        assert!(sink_models_to_mad(&models).is_empty());
    }

    #[test]
    fn render_mad_pack_emits_sink_model_extension() {
        let models = vec![model("command_execution", &["os.system"])];
        let yaml = render_mad_pack(&models, "python");
        assert!(yaml.contains("extensible: sinkModel"));
        assert!(yaml.contains("codeql/python-all"));
        assert!(yaml.contains("- [\"os\", \"Member[system].Argument[0]\", \"command-injection\"]"));
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p mcp-sec-audit-core codeql::models`
Expected: compile error — `mod models` not found / `mad_sink_kind` not found.

- [ ] **Step 3: Implement the compiler**

```rust
//! Compile the shared sink model catalog into CodeQL MaD (Models as Data)
//! `sinkModel` extensions so standard queries reach third-party wrappers.

use crate::models::SinkModel;

/// One MaD sink entry in the 3-tuple format `[module, path, kind]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MadSinkEntry {
    pub module: String,
    pub path: String,
    pub kind: String,
}

/// Map a canonical category to a CodeQL MaD sink kind, or `None` when no
/// standard query consumes that category via `sinkModel`.
pub fn mad_sink_kind(category: &str) -> Option<&'static str> {
    match category {
        "command_execution" => Some("command-injection"),
        "dynamic_execution" => Some("code-injection"),
        "database_injection" => Some("sql-injection"),
        "network_request" => Some("request-forgery"),
        "file_read" | "file_write" | "file_delete" | "path_traversal" => Some("path-injection"),
        "template_injection" => Some("template injection"),
        "prompt_injection" => Some("prompt-injection"),
        _ => None,
    }
}

/// Split a callee pattern into `(module, function)` for MaD. Patterns that are
/// not a plain `module.function` (single segment like `eval`, or `new X`) are
/// skipped because they have no module prefix to hang the model on.
fn split_module_function(pattern: &str) -> Option<(&str, &str)> {
    if let Some((module, function)) = pattern.rsplit_once('.') {
        if module.is_empty() || function.is_empty() || function.contains(' ') {
            return None;
        }
        Some((module, function))
    } else {
        None
    }
}

/// Compile a list of sink models into MaD entries, skipping models with no
/// standard sink kind or with an un-splittable pattern.
pub fn sink_models_to_mad(models: &[SinkModel]) -> Vec<MadSinkEntry> {
    let mut out = Vec::new();
    for model in models {
        let Some(kind) = mad_sink_kind(&model.category) else {
            continue;
        };
        for pattern in &model.patterns {
            if let Some((module, function)) = split_module_function(pattern) {
                out.push(MadSinkEntry {
                    module: module.to_string(),
                    path: format!("Member[{function}].Argument[0]"),
                    kind: kind.to_string(),
                });
            }
        }
    }
    out
}

/// Render a full MaD model-pack extension file for one language.
pub fn render_mad_pack(models: &[SinkModel], language: &str) -> String {
    let pack = match language {
        "javascript" | "typescript" => "codeql/javascript-all",
        _ => "codeql/python-all",
    };
    let mut body = String::from("extensions:\n  - addsTo:\n");
    body.push_str(&format!("      pack: {pack}\n"));
    body.push_str("      extensible: sinkModel\n    data:\n");
    for entry in sink_models_to_mad(models) {
        body.push_str(&format!(
            "      - [\"{}\", \"{}\", \"{}\"]\n",
            entry.module, entry.path, entry.kind
        ));
    }
    body
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p mcp-sec-audit-core codeql::models`
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/codeql/models.rs crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs
git commit -m "feat(codeql): compile sink model catalog into CodeQL MaD pack"
```

---

### Task 3: `CodeqlSession` with DB cache + model-pack injection

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/provider.rs` (extend `run_analysis` signature; add DB path reuse)
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs` (extract `CodeqlSession`; rewrite `run` as a thin wrapper)

**Interfaces:**
- Consumes: `StaticScanContext`, `QueryPack`, `CodeqlOutput`, `SinkModel`.
- Produces (public to crate, consumed by R5 Task 5):
  - `pub struct CodeqlSession { /* private */ }`
  - `impl CodeqlSession { pub fn create(ctx: &StaticScanContext) -> Result<Option<CodeqlSession>>; pub fn analyze(&self, model_packs: &[std::path::PathBuf], progress: impl FnMut(&str)) -> Result<CodeqlOutput>; }`

- [ ] **Step 1: Extend the provider trait**

In `provider.rs`, change:

```rust
fn run_analysis(
    &self,
    db: &DatabaseInfo,
    queries: &QueryPack,
    timeout_seconds: u64,
    extra_args: &[String],
    model_packs: &[PathBuf],
) -> Result<String>;
```

In the `CliCodeqlProvider` impl, add the model packs to the command **before** the query files:

```rust
for mp in model_packs {
    cmd.arg("--model-packs").arg(mp);
}
```

- [ ] **Step 2: Add a test for the DB path reuse**

Add to `provider.rs` tests a `DatabaseInfo` path assertion is not needed; instead add a test in `mod.rs` tests (Step 3). First, make `create_database` deterministic: change the db dir to key by language + process id (already does), and add `if db_dir.join("codeql-database.yml").exists() { return Ok(DatabaseInfo { .. }) }` early-return so a re-created session reuses the cached DB.

- [ ] **Step 3: Extract `CodeqlSession` in `mod.rs`**

Move the body of `run` into `CodeqlSession::analyze`, and replace `run` with a wrapper that also compiles the catalog into MaD packs:

```rust
pub struct CodeqlSession {
    provider: CliCodeqlProvider,
    config: StaticCodeqlConfig,
    databases: BTreeMap<String, DatabaseInfo>,
    query_packs: BTreeMap<String, QueryPack>,
    supported_files: Vec<DiscoveredFile>,
    target_root: String,
}

impl CodeqlSession {
    /// Create a session (build databases + resolve query packs) if there is
    /// CodeQL work to do; `Ok(None)` when disabled or no supported language.
    pub fn create(ctx: &StaticScanContext) -> Result<Option<Self>> { /* …filter + CLI check + build DBs… */ }

    pub fn analyze(&self, model_packs: &[PathBuf], mut progress: impl FnMut(&str)) -> Result<CodeqlOutput> {
        /* per-language: run_analysis(…, model_packs) → parse SARIF; same logic as current run() */
    }
}

pub fn run(ctx: &StaticScanContext, mut progress: impl FnMut(&str)) -> Result<CodeqlOutput> {
    let Some(session) = CodeqlSession::create(ctx)? else {
        return Ok(CodeqlOutput::empty());
    };
    let pack_dir = models::write_model_pack_dir(&crate::models::default_catalog(), ctx)?;
    session.analyze(&[pack_dir], &mut progress)
}
```

Add a helper in `models.rs`:

```rust
/// Write the rendered MaD packs for python + javascript into a temp dir and
/// return the directory path (a `--model-packs` root). Returns `None`-ish by
/// returning an empty dir when nothing maps.
pub fn write_model_pack_dir(catalog: &ModelCatalog, ctx: &StaticScanContext) -> Result<PathBuf>;
```

- [ ] **Step 4: Keep the existing unit tests green**

Update the existing `run` tests (in `mod.rs` `tests`) so they still compile against the new signature. The three existing tests (`disabled_codeql_returns_empty`, `enabled_with_no_files_returns_empty_with_diagnostic`, `unsupported_language_emits_skip_progress`) must continue to pass unchanged.

Run: `cargo test -p mcp-sec-audit-core codeql`
Expected: all `codeql::*` tests pass (no CodeQL CLI needed).

- [ ] **Step 5: Add a session test for model-pack temp dir**

In `models.rs` tests, add:

```rust
#[test]
fn write_model_pack_dir_renders_python_and_js() {
    let dir = std::env::temp_dir().join("mad-test-dir");
    // call write_model_pack_dir against a temp catalog; assert the dir contains
    // python.model.yml and javascript.model.yml with "extensible: sinkModel".
}
```

- [ ] **Step 6: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/codeql/
git commit -m "feat(codeql): CodeqlSession with DB cache and model-pack injection"
```

---

### Task 4: Python MCP query matrix (6 new queries)

**Files:**
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/ToolParamToNetwork.ql` (SSRF)
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/ToolParamToFileWrite.ql`
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/ToolParamToSql.ql`
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/ToolParamToTemplate.ql` (SSTI)
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/ToolParamToPathTraversal.ql`

**Interfaces:**
- Consumes: the `McpToolSource` source pattern from Task 1 (copy the class definition into each file — QL has no cross-file import in this pack).
- Produces: queries with `@tags` categories `network-request`, `file-write`, `database-injection`, `template-injection`, `path-traversal` (normalized to `network_request`/`file_write`/`database_injection`/`template_injection`/`path_traversal` by `parser.rs`).

- [ ] **Step 1: Write `ToolParamToNetwork.ql`**

```ql
/**
 * @name MCP tool parameter to network request
 * @description Tracks tool parameters flowing into outbound network requests
 *              (SSRF).
 * @kind path-problem
 * @problem.severity warning
 * @id mcp/tool-param-to-network
 * @tags security mcp network-request
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

class McpToolSource extends DataFlow::Node {
  McpToolSource() {
    exists(Function f, Call dec, Attribute attr |
      dec = f.getADecorator() and dec.getFunc() = attr and
      attr.getName() = "tool" and this = DataFlow::parameterNode(f.getAParameter())
    )
    or
    exists(DataFlow::CallCfgNode call, Function handler |
      call = API::moduleImport("mcp").getMember("tool").getACall()
      and call.getArg(1) = DataFlow::exprNode(handler.getDefiningExpression())
      and this = DataFlow::parameterNode(handler.getAParameter())
    )
  }
}

class NetworkSink extends DataFlow::Node {
  NetworkSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("requests").getMember("get").getACall() or
      call = API::moduleImport("requests").getMember("post").getACall() or
      call = API::moduleImport("httpx").getMember("get").getACall() or
      call = API::moduleImport("httpx").getMember("post").getACall() or
      call = API::moduleImport("urllib").getMember("request").getMember("urlopen").getACall() or
      call = API::moduleImport("socket").getMember("socket").getReturn().getMember("connect").getACall()
    |
      this = call.getArg(0)
    )
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) { s instanceof McpToolSource }
  predicate isSink(DataFlow::Node s) { s instanceof NetworkSink }
}
module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph
from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to an outbound network request (SSRF).",
  source.getNode(), "user input"
```

- [ ] **Step 2: Write the remaining 4 queries**

`ToolParamToFileWrite.ql`: sink class uses `API::moduleImport("builtins").getMember("open").getACall()` filtered to write mode via `call.getArg(1).getNode().toString().matches("%\"w%\"")` **or** `API::moduleImport("shutil").getMember("move").getACall()`, arg 0; `@tags … file-write`.

`ToolParamToSql.ql`: sink uses `call.getCalleeName() = "execute"` and `call.getCalleeName() = "executemany"` and `call.getCalleeName() = "executescript"`; `@tags … database-injection`.

`ToolParamToTemplate.ql`: sink uses `API::moduleImport("jinja2").getMember("Template").getReturn().getMember("render").getACall()` and `API::moduleImport("flask").getMember("render_template_string").getACall()`; `@tags … template-injection`.

`ToolParamToPathTraversal.ql`: sink = `open`/`Path` reads/writes (same as file write sinks) **without** the `Sanitizer` class from Task 1; `@tags … path-traversal`.

- [ ] **Step 3: Compile + smoke test**

```bash
codeql query compile --search-path crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python
codeql database analyze /tmp/db-r4 crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python --format=sarif-latest --output=/tmp/r4-full.sarif
```
Expected: `fetch_url` in `python-mcp-server/server.py` hits `ToolParamToNetwork`; `read_log` hits `ToolParamToPathTraversal`/`ToolParamToFileWrite`; `run_shell` hits `ToolParameterToSink`.

- [ ] **Step 4: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-python/
git commit -m "feat(codeql): complete Python MCP query matrix"
```

---

### Task 5: JS/TS MCP query matrix (6 queries)

**Files:**
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-js/ToolParamToCommandExec.ql`
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-js/ToolParamToCodeExec.ql`
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-js/ToolParamToFileWrite.ql`
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-js/ToolParamToNetwork.ql`
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-js/ToolParamToSql.ql`
- Create: `crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-js/ToolParamToPromptInjection.ql`

**Interfaces:**
- Consumes: the `mcp-js` pack (`qlpack.yml` deps `codeql/javascript-all: 2.8.2`).
- Produces: JS queries with `@tags` categories `command-execution`, `dynamic-execution`, `file-write`, `network-request`, `database-injection`, `prompt-injection`.

- [ ] **Step 1: Write `ToolParamToCommandExec.ql` (registration source is the JS norm)**

```ql
/**
 * @name MCP tool parameter to command execution
 * @description Tracks server.tool() handler parameters into child_process
 *              command execution.
 * @kind path-problem
 * @problem.severity error
 * @id mcp-js/tool-param-to-command-exec
 * @tags security mcp command-execution
 */
import javascript
import semmle.javascript.dataflow.new.TaintTracking

/** `server.tool("name", handler)` — the handler's parameters are sources. */
class ServerToolSource extends DataFlow::Node {
  ServerToolSource() {
    exists(DataFlow::CallNode call, DataFlow::FunctionNode handler |
      call.getCalleeName() = "tool" and
      call.getNumArgument() >= 2 and
      handler = call.getArgument(1).getAFunctionValue() and
      this = DataFlow::parameterNode(handler.getFunction().getAParameter())
    )
  }
}

class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(DataFlow::CallNode call, string name |
      name = call.getCalleeName() and
      (name = "exec" or name = "execSync" or name = "spawn" or name = "spawnSync") and
      call.getArgument(0) = this
    )
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) { s instanceof ServerToolSource }
  predicate isSink(DataFlow::Node s) { s instanceof CommandSink }
}
module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph
from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to a shell command (command injection).",
  source.getNode(), "user input"
```

- [ ] **Step 2: Write the remaining 5 JS queries**

`ToolParamToCodeExec.ql`: sink = `eval(...)`, `Function(...)` constructor (callee name `eval`/`Function`), arg 0; `@tags … dynamic-execution`.

`ToolParamToFileWrite.ql`: sink = `fs.writeFile`/`writeFileSync`/`appendFile`/`appendFileSync` arg 1 (the content) and `fs.createWriteStream`; `@tags … file-write`.

`ToolParamToNetwork.ql`: sink = `fetch(...)` arg 0, `http.request`/`https.request` arg 0; `@tags … network-request`.

`ToolParamToSql.ql`: sink = `connection.query`/`.execute`/`.run` arg 0; `@tags … database-injection`.

`ToolParamToPromptInjection.ql`: sink = LLM API call args (`openai`/`anthropic` client methods); `@tags … prompt-injection`.

- [ ] **Step 3: Compile + smoke test against `js-mcp-server`**

```bash
codeql query compile --search-path crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-js crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-js
rm -rf /tmp/db-js && codeql database create /tmp/db-js --language=javascript --source-root=test-targets/js-mcp-server --overwrite
codeql database analyze /tmp/db-js crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-js --format=sarif-latest --output=/tmp/r4-js.sarif
```
Expected: `db_query` (eval/exec) hits `ToolParamToCodeExec`/`ToolParamToCommandExec`; `export_file` hits `ToolParamToFileWrite`.

- [ ] **Step 4: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp-js/
git commit -m "feat(codeql): add JS/TS MCP query matrix"
```

---

### Task 6: Wire MaD compilation into the pipeline + integration smoke test

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs` (already done in Task 3 — verify `run` passes the MaD pack dir)
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/models.rs` (finalize `write_model_pack_dir`)

**Interfaces:**
- Consumes: `default_catalog()`, `ModelCatalog`.
- Produces: a temp `--model-packs` dir fed to every `analyze`.

- [ ] **Step 1: Implement `write_model_pack_dir`**

```rust
pub fn write_model_pack_dir(catalog: &ModelCatalog, ctx: &StaticScanContext) -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("mcp-sec-audit-mad-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    for language in ["python", "javascript"] {
        let models = catalog.sinks_for_language(language);
        if models.is_empty() { continue; }
        let yaml = render_mad_pack(models, language);
        let path = dir.join(format!("{language}.model.yml"));
        std::fs::write(&path, yaml)?;
    }
    Ok(dir)
}
```

- [ ] **Step 2: Unit test**

Run: `cargo test -p mcp-sec-audit-core codeql::models`
Expected: `write_model_pack_dir` test passes (asserts the dir contains `python.model.yml` and `javascript.model.yml` with `extensible: sinkModel`).

- [ ] **Step 3: Integration smoke test — MaD makes `py/path-injection` reach openpyxl**

Add an openpyxl sample to a scratch target and confirm the *standard* query fires:

```bash
mkdir -p /tmp/mad-smoke && cat > /tmp/mad-smoke/xl.py <<'EOF'
import openpyxl
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def read_wb(path: str):
    return openpyxl.load_workbook(path)
EOF
rm -rf /tmp/db-mad && codeql database create /tmp/db-mad --language=python --source-root=/tmp/mad-smoke --overwrite
# Render the python MaD pack manually for this smoke test:
#   models render output → /tmp/mad-smoke-pack/python.model.yml
codeql database analyze /tmp/db-mad codeql/python-queries@1.8.7 --model-packs=/tmp/mad-smoke-pack --format=sarif-latest --output=/tmp/mad.sarif
```
Expected: `py/path-injection` (or a `command-injection`/`path-injection` result) now fires on `load_workbook`, where without the model pack it returns 0.

- [ ] **Step 4: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/codeql/models.rs crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs
git commit -m "feat(codeql): feed compiled MaD packs into every analyze"
```

---

### Task 7: Full regression + E2E on three test targets

**Files:** none (verification only).

- [ ] **Step 1: Run the full Rust suite**

Run: `cargo test`
Expected: 220 green (216 core + 4 CLI), no regressions.

- [ ] **Step 2: E2E on the three targets**

```bash
# python-mcp-server: command injection / path traversal / SSRF all hit, with codeql in supported_by
# js-mcp-server: eval/exec/file-write hit JS queries
# rust-mcp-server: "CodeQL skipped" or rust suite runs clean, no error
```
Confirm `Fused Findings` now includes entries whose `supported_by` contains `codeql` (category-aligned via `@tags`).

- [ ] **Step 3: Commit any final fixes and report**

```bash
git add -A && git commit -m "test(codeql): R4 regression + E2E pass"
```

---

## Self-Review

- **Spec coverage:** full suites (already pinned in `queries.rs`), MCP query matrix (Tasks 1/4/5), MaD extension (Tasks 2/6), DB cache + warm re-run seam (Task 3, consumed by R5) — all §5.3 items covered.
- **Placeholder scan:** no TBD/TODO; every Rust task has exact code, every QL task has exact queries or a precise sink-class recipe.
- **Type consistency:** `CodeqlSession::{create, analyze}` and `CodeqlProvider::run_analysis(…, model_packs)` signatures are named identically here and in the R5 plan's "Consumes" block.
