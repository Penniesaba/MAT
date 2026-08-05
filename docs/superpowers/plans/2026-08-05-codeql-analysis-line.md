# CodeQL Analysis Line — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fourth parallel static analysis line that invokes CodeQL CLI for professional taint analysis, producing structured `CodeqlAnalysisResult` items and raw SARIF audit artifacts.

**Architecture:** Independent peer to rule/taint/agent lines. No data dependencies. `codeql::run(ctx)` → filters to Python/JS/TS → shell out to `codeql` CLI (database create → analyze) → parse SARIF → `CodeqlOutput`.

**Tech Stack:** Rust, `std::process::Command`, `serde_json`, SARIF v2.1.0

## Global Constraints

- Three existing lines (rule, taint, agent) must remain untouched — no cross-line imports, no shared mutable state
- New line lives in `static_analysis/codeql/` with a single `pub fn run(ctx: &StaticScanContext) -> Result<CodeqlOutput>` entry point
- All model types must round-trip JSON via serde
- No new external crate dependencies (use `std::process::Command`, `serde_json`, `anyhow`)
- Hardcoded constants stay in `mod.rs`, not in config
- CodeQL CLI not found → panic (hard error per design)
- Rust targets → skip with diagnostic
- Built-in `.ql` query files live under `static_analysis/codeql/queries/` directory
- Follow existing patterns: `AgentProvider`→`CodeqlProvider`, `agent/mod.rs`→`codeql/mod.rs`

---

### Task 1: Config + Model — types, enums, and config struct

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/config.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/model/static_result.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/model/mod.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/fixtures.rs`
- Modify: `rust/config/default.toml`

**Interfaces:**
- Produces: `StaticCodeqlConfig`, `CodeqlAnalysisResult`, `Location`, `DataFlowPath`, `CodeqlOutput`, `synthetic_codeql_analysis_result()`

- [ ] **Step 1: Add `StaticCodeqlConfig` to `config.rs`**

Insert after the `StaticAgentConfig` block (around line 85):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCodeqlConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub query_pack_path: Option<String>,
    #[serde(default = "default_codeql_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub extra_args: Vec<String>,
}

fn default_codeql_timeout() -> u64 {
    1200
}
```

Add `impl Default for StaticCodeqlConfig` block:

```rust
impl Default for StaticCodeqlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            query_pack_path: None,
            timeout_seconds: default_codeql_timeout(),
            extra_args: Vec::new(),
        }
    }
}
```

Add `codeql: StaticCodeqlConfig` field to `StaticConfig` struct (under the `agent` field):

```rust
#[serde(default)]
pub codeql: StaticCodeqlConfig,
```

Add serde default for the new field in existing `Default for StaticConfig` impl:

```rust
codeql: StaticCodeqlConfig::default(),
```

- [ ] **Step 2: Add `Location` and `DataFlowPath` to `static_result.rs`**

Insert before `RuleAnalysisResult`:

```rust
/// Source location with file path and line number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub line: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// A single step in a CodeQL dataflow path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFlowPathStep {
    pub location: Location,
    pub snippet: Option<String>,
}

/// CodeQL codeFlows representation — a full taint path through the program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFlowPath {
    pub steps: Vec<DataFlowPathStep>,
}
```

- [ ] **Step 3: Add `CodeqlAnalysisResult` to `static_result.rs`**

Insert after `AgentAnalysisResult`:

```rust
/// Result from the CodeQL analysis line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeqlAnalysisResult {
    pub result_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub message: String,
    pub severity: Severity,
    pub locations: Vec<Location>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataflow_path: Option<DataFlowPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sarif_snippet: Option<String>,
    #[serde(default)]
    pub related_rule_ids: Vec<String>,
    #[serde(default)]
    pub related_taint_ids: Vec<String>,
    #[serde(default)]
    pub related_agent_ids: Vec<String>,
    #[serde(default = "default_verification_status")]
    pub verification_status: String,
    #[serde(default)]
    pub limitations: Vec<String>,
}

fn default_verification_status() -> String {
    "uncorroborated".to_string()
}
```

- [ ] **Step 4: Add `CodeqlOutput` to `static_result.rs`**

Insert after `CodeqlAnalysisResult`:

```rust
/// Composite output from the CodeQL line — structured results + raw SARIF + diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeqlOutput {
    pub results: Vec<CodeqlAnalysisResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_sarif: Option<String>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

impl CodeqlOutput {
    pub fn empty() -> Self {
        Self {
            results: Vec::new(),
            raw_sarif: None,
            diagnostics: Vec::new(),
        }
    }
}
```

- [ ] **Step 5: Add `codeql_results` + `codeql_result_count` to result types**

In `StaticAnalysisResult`, add field after `agent_results`:

```rust
pub codeql_results: Vec<CodeqlAnalysisResult>,
```

In `StaticAnalysisSummary`, add field after `agent_result_count`:

```rust
pub codeql_result_count: usize,
```

- [ ] **Step 6: Update `model/mod.rs` exports**

Add to the `pub use static_result::` block:

```rust
CodeqlAnalysisResult, CodeqlOutput, DataFlowPath, DataFlowPathStep, Location,
```

- [ ] **Step 7: Update `fixtures.rs`**

Add a synthetic CodeQL result function:

```rust
use super::model::{CodeqlAnalysisResult, CodeqlOutput, Location};

pub fn synthetic_codeql_analysis_result() -> CodeqlAnalysisResult {
    CodeqlAnalysisResult {
        result_id: "codeql:py/command-injection:server.py:42".to_string(),
        rule_id: "py/command-injection".to_string(),
        rule_name: "Uncontrolled command line".to_string(),
        message: "This command line depends on a user-provided value.".to_string(),
        severity: Severity::High,
        locations: vec![Location {
            file: "server.py".to_string(),
            line: 42,
            column: Some(5),
            message: Some("sink".to_string()),
        }],
        dataflow_path: None,
        sarif_snippet: None,
        related_rule_ids: Vec::new(),
        related_taint_ids: Vec::new(),
        related_agent_ids: Vec::new(),
        verification_status: "uncorroborated".to_string(),
        limitations: vec!["Synthetic fixture only".to_string()],
    }
}
```

Update `synthetic_static_analysis_result()`:

```rust
codeql_results: vec![synthetic_codeql_analysis_result()],
```

And in the summary:

```rust
codeql_result_count: 1,
```

Also update `empty_result()` in `pipeline.rs`:

```rust
codeql_results: Vec::new(),
```
and in summary:

```rust
codeql_result_count: 0,
```

- [ ] **Step 8: Update `default.toml`**

Append after `[static.agent]` block:

```toml
[static.codeql]
enabled = false
# query_pack_path = "/path/to/custom/queries"  # optional
timeout_seconds = 1200
extra_args = []
```

- [ ] **Step 9: Add config test**

In `config.rs` tests, add assertions in `runtime_config_parses_three_line_switches`:

```rust
// CodeQL config defaults
assert!(!config.static_.codeql.enabled);
assert_eq!(config.static_.codeql.timeout_seconds, default_codeql_timeout());
assert_eq!(config.static_.codeql.query_pack_path, None);
assert!(config.static_.codeql.extra_args.is_empty());
```

- [ ] **Step 10: Add model JSON round-trip test**

In `static_result.rs` tests:

```rust
#[test]
fn static_analysis_json_preserves_codeql_results() {
    let result = crate::fixtures::synthetic_static_analysis_result();
    let value = serde_json::to_value(&result).expect("serialize static result");
    assert!(value.get("codeql_results").is_some());
    assert!(value["summary"].get("codeql_result_count").is_some());
    assert_eq!(
        value["summary"]["codeql_result_count"].as_u64(),
        Some(1)
    );
}
```

- [ ] **Step 11: Run tests and commit**

```bash
cd rust && cargo test -p mcp-sec-audit-core
```
Expected: ~115 tests pass (110 existing + ~5 new/updated).

```bash
git add rust/crates/mcp-sec-audit-core/src/config.rs \
        rust/crates/mcp-sec-audit-core/src/model/static_result.rs \
        rust/crates/mcp-sec-audit-core/src/model/mod.rs \
        rust/crates/mcp-sec-audit-core/src/fixtures.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs \
        rust/config/default.toml
git commit -m "feat(codeql): add StaticCodeqlConfig, CodeqlAnalysisResult, and model types

Add CodeqlAnalysisResult, CodeqlOutput, Location, DataFlowPath to the
static analysis model. Add StaticCodeqlConfig with timeout and query
pack path. Update fixtures, pipeline empty_result, and default.toml.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 2: CodeQL queries — built-in .ql files + query pack resolution

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp/ToolParameterToSink.ql`
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp/ResourceToNetwork.ql`
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp/PromptInjection.ql`
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/queries.rs`

**Interfaces:**
- Produces: `QueryPack`, `resolve_query_pack()`, `builtin_mcp_query_dir()`

- [ ] **Step 1: Create `queries/mcp/ToolParameterToSink.ql`**

Reference: GitHub Security Lab — `MCPToolParameterToSink.ql` adapted from `Security/CWE-078/CommandInjection.ql` pattern.

```ql
/**
 * @name MCP Tool Parameter to Dangerous Sink
 * @description Tracks data flow from MCP tool parameters to dangerous sinks
 *              (command execution, file write, code evaluation).
 * @kind path-problem
 * @problem.severity error
 * @id mcp/tool-parameter-to-sink
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

// MCP tool entrypoints — decorated with @mcp.tool() or server.tool()
class McpToolEntrypoint extends DataFlow::Node {
  McpToolEntrypoint() {
    exists(Function f |
      f.getADecorator().(Call).getFunc().(Attribute).getObject().(Name).getId() = "mcp" and
      f.getADecorator().(Call).getFunc().(Attribute).getName() = "tool" and
      this = f.getArg(0)
    )
  }
}

// Dangerous sinks for MCP context
class DangerousSink extends DataFlow::Node {
  DangerousSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("os").getMember("system").getACall() or
      call = API::moduleImport("subprocess").getMember("run").getACall() or
      call = API::moduleImport("subprocess").getMember("Popen").getACall() or
      call = API::moduleImport("subprocess").getMember("call").getACall() or
      call = API::moduleImport("os").getMember("popen").getACall() or
      call = API::builtin("eval").getACall() or
      call = API::builtin("exec").getACall() or
      call = API::moduleImport("pickle").getMember("loads").getACall() or
      call = API::moduleImport("builtins").getMember("open").getACall()
    |
      this = call.getArg(0)
    )
  }
}

module McpToolToSinkConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof McpToolEntrypoint }
  predicate isSink(DataFlow::Node sink) { sink instanceof DangerousSink }
}

module McpToolToSinkFlow = TaintTracking::Global<McpToolToSinkConfig>;

from McpToolToSinkFlow::PathNode source, McpToolToSinkFlow::PathNode sink
where McpToolToSinkFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows to $@ without sanitization.",
  sink.getNode(), sink.getNode().toString()
```

- [ ] **Step 2: Create `queries/mcp/ResourceToNetwork.ql`**

```ql
/**
 * @name MCP Resource Read to Network Outbound
 * @description Detects MCP resource/content reads that flow into outbound
 *              network calls, indicating potential data exfiltration.
 * @kind path-problem
 * @problem.severity warning
 * @id mcp/resource-to-network
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

// MCP resource handlers
class McpResourceSource extends DataFlow::Node {
  McpResourceSource() {
    exists(Function f |
      f.getADecorator().(Call).getFunc().(Attribute).getObject().(Name).getId() = "mcp" and
      f.getADecorator().(Call).getFunc().(Attribute).getName() = "resource" and
      this = f.getArg(0)
    )
  }
}

// Network outbound sinks
class NetworkSink extends DataFlow::Node {
  NetworkSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("requests").getMember("get").getACall() or
      call = API::moduleImport("requests").getMember("post").getACall() or
      call = API::moduleImport("httpx").getMember("Client").getReturn().getMember("get").getACall() or
      call = API::moduleImport("httpx").getMember("Client").getReturn().getMember("post").getACall() or
      call = API::moduleImport("aiohttp").getMember("ClientSession").getReturn().getMember("get").getACall() or
      call = API::moduleImport("aiohttp").getMember("ClientSession").getReturn().getMember("post").getACall() or
      call = API::moduleImport("urllib").getMember("request").getMember("urlopen").getACall() or
      call = API::moduleImport("socket").getMember("socket").getReturn().getMember("connect").getACall()
    |
      this = call.getArg(0)
    )
  }
}

module ResourceToNetworkConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof McpResourceSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof NetworkSink }
}

module ResourceToNetworkFlow = TaintTracking::Global<ResourceToNetworkConfig>;

from ResourceToNetworkFlow::PathNode source, ResourceToNetworkFlow::PathNode sink
where ResourceToNetworkFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP resource data flows to outbound network $@ without sanitization.",
  sink.getNode(), sink.getNode().toString()
```

- [ ] **Step 3: Create `queries/mcp/PromptInjection.ql`**

```ql
/**
 * @name MCP Prompt Parameter to LLM API Call
 * @description Tracks user-supplied prompt parameters flowing into LLM API
 *              calls, which may enable prompt injection attacks.
 * @kind path-problem
 * @problem.severity warning
 * @id mcp/prompt-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

// MCP prompt entrypoints
class McpPromptSource extends DataFlow::Node {
  McpPromptSource() {
    exists(Function f |
      f.getADecorator().(Call).getFunc().(Attribute).getObject().(Name).getId() = "mcp" and
      f.getADecorator().(Call).getFunc().(Attribute).getName() = "prompt" and
      this = f.getArg(0)
    )
  }
}

// LLM API call sinks
class LlmApiSink extends DataFlow::Node {
  LlmApiSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("openai").getMember("ChatCompletion").getMember("create").getACall() or
      call = API::moduleImport("openai").getMember("Completion").getMember("create").getACall() or
      call = API::moduleImport("anthropic").getMember("messages").getMember("create").getACall() or
      call = API::moduleImport("google").getMember("generativeai").getMember("GenerativeModel").getReturn().getMember("generate_content").getACall()
    |
      this = call.getArg(0)
    )
  }
}

module PromptInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof McpPromptSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof LlmApiSink }
}

module PromptInjectionFlow = TaintTracking::Global<PromptInjectionConfig>;

from PromptInjectionFlow::PathNode source, PromptInjectionFlow::PathNode sink
where PromptInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP prompt parameter flows to LLM API $@, enabling prompt injection.",
  sink.getNode(), sink.getNode().toString()
```

- [ ] **Step 4: Create `queries.rs`**

```rust
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// Represents a resolved query pack ready for CodeQL analysis.
#[derive(Debug, Clone)]
pub struct QueryPack {
    /// Paths to .ql files or .qlref references.
    pub query_files: Vec<PathBuf>,
    /// Additional CodeQL query pack references (e.g. "codeql/python-queries").
    pub suite_refs: Vec<String>,
}

impl QueryPack {
    /// Build the default query pack: built-in MCP queries + standard security suites.
    pub fn default() -> Result<Self> {
        let mcp_dir = builtin_mcp_query_dir()?;
        let mut query_files = Vec::new();
        for entry in std::fs::read_dir(&mcp_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("ql") {
                query_files.push(path);
            }
        }
        Ok(Self {
            query_files,
            suite_refs: vec![
                "codeql/python-queries".to_string(),
                "codeql/javascript-queries".to_string(),
            ],
        })
    }

    /// Load a user-specified query pack directory.
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
        })
    }
}

/// Resolve the active query pack: user override or built-in default.
pub fn resolve_query_pack(custom_path: Option<&str>) -> Result<QueryPack> {
    match custom_path {
        Some(p) => QueryPack::from_path(Path::new(p)),
        None => QueryPack::default(),
    }
}

/// Directory containing built-in MCP CodeQL queries.
fn builtin_mcp_query_dir() -> Result<PathBuf> {
    // Relative to the crate source at build/run time
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("static_analysis")
        .join("codeql")
        .join("queries")
        .join("mcp");
    if !dir.exists() {
        bail!(
            "Built-in CodeQL query directory not found: {}. \
             Ensure the crate is built from the correct directory.",
            dir.display()
        );
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_query_pack_includes_mcp_queries() {
        let pack = QueryPack::default().expect("default query pack");
        assert!(
            !pack.query_files.is_empty(),
            "Expected at least one built-in .ql file"
        );
        assert!(pack.query_files.iter().any(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |n| n.contains("ToolParameterToSink"))
        }));
        assert_eq!(
            pack.suite_refs,
            vec!["codeql/python-queries", "codeql/javascript-queries"]
        );
    }

    #[test]
    fn resolve_custom_path_overrides_default() {
        let tmp = std::env::temp_dir().join("codeql-test-queries");
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        std::fs::write(tmp.join("test.ql"), "// test query").expect("write test file");

        let pack = resolve_query_pack(Some(tmp.to_str().unwrap()))
            .expect("resolve custom pack");
        assert!(!pack.query_files.is_empty());
        assert!(pack.suite_refs.is_empty());

        std::fs::remove_dir_all(&tmp).expect("cleanup");
    }

    #[test]
    fn missing_custom_path_returns_error() {
        let err = resolve_query_pack(Some("/nonexistent/path/xyz"))
            .expect_err("nonexistent path should fail");
        assert!(err.to_string().contains("does not exist"));
    }
}
```

- [ ] **Step 5: Run tests and commit**

```bash
cd rust && cargo test -p mcp-sec-audit-core
```
Expected: ~118 tests pass.

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/
git commit -m "feat(codeql): add built-in MCP CodeQL queries and QueryPack resolution

Three MCP-focused CodeQL queries: ToolParameterToSink, ResourceToNetwork,
PromptInjection. QueryPack with default (built-in + standard suites) and
custom path resolution.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 3: CodeQL provider — trait + CliCodeqlProvider

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/provider.rs`

**Interfaces:**
- Consumes: `QueryPack` from Task 2
- Produces: `CodeqlProvider` trait, `CliCodeqlProvider`, `DatabaseInfo`

- [ ] **Step 1: Write `provider.rs`**

```rust
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use super::queries::QueryPack;

/// CLI binary name for CodeQL.
const CODEQL_BIN: &str = "codeql";

/// Info about a successfully created CodeQL database.
#[derive(Debug, Clone)]
pub struct DatabaseInfo {
    pub path: PathBuf,
    pub language: String,
}

/// Pluggable CodeQL backend.
pub trait CodeqlProvider {
    /// Check whether the CodeQL CLI is available on PATH.
    fn check_available(&self) -> bool;

    /// Create a CodeQL database from source files.
    fn create_database(&self, source_dir: &Path, language: &str) -> Result<DatabaseInfo>;

    /// Run CodeQL analysis on a database and return SARIF JSON.
    fn run_analysis(
        &self,
        db: &DatabaseInfo,
        queries: &QueryPack,
        timeout_seconds: u64,
        extra_args: &[String],
    ) -> Result<String>;
}

/// Default provider: shells out to the `codeql` CLI.
pub struct CliCodeqlProvider;

impl CodeqlProvider for CliCodeqlProvider {
    fn check_available(&self) -> bool {
        Command::new(CODEQL_BIN)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn create_database(&self, source_dir: &Path, language: &str) -> Result<DatabaseInfo> {
        let db_dir = std::env::temp_dir()
            .join("mcp-sec-audit-codeql")
            .join(format!("db-{}", std::process::id()))
            .join(language);

        std::fs::create_dir_all(&db_dir)?;

        let output = Command::new(CODEQL_BIN)
            .arg("database")
            .arg("create")
            .arg(&db_dir)
            .arg("--language")
            .arg(language)
            .arg("--source-root")
            .arg(source_dir)
            .arg("--overwrite")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    anyhow::anyhow!(
                        "codeql CLI not found in PATH. Install CodeQL: \
                         https://github.com/github/codeql-cli-binaries/releases"
                    )
                } else {
                    anyhow::anyhow!("failed to spawn codeql: {}", e)
                }
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "codeql database create failed for language '{}': {}",
                language,
                stderr.trim()
            );
        }

        Ok(DatabaseInfo {
            path: db_dir,
            language: language.to_string(),
        })
    }

    fn run_analysis(
        &self,
        db: &DatabaseInfo,
        queries: &QueryPack,
        timeout_seconds: u64,
        extra_args: &[String],
    ) -> Result<String> {
        let mut cmd = Command::new(CODEQL_BIN);
        cmd.arg("database")
            .arg("analyze")
            .arg(&db.path)
            .arg("--format=sarif-latest")
            .arg("--output=-");

        // Add query files
        for qf in &queries.query_files {
            cmd.arg(qf);
        }

        // Add suite references
        for suite in &queries.suite_refs {
            cmd.arg(suite);
        }

        // Extra args from config
        for arg in extra_args {
            cmd.arg(arg);
        }

        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            anyhow::anyhow!("failed to spawn codeql analyze: {}", e)
        })?;

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut stdout = String::new();
            let mut stderr = String::new();
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

        let timeout = Duration::from_secs(timeout_seconds);
        match rx.recv_timeout(timeout) {
            Ok((stdout, _stderr, _exit_code)) => Ok(stdout),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                bail!("codeql analyze timed out after {}s", timeout_seconds)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("codeql analyze process communication channel disconnected")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "codeql CLI not found in PATH")]
    fn missing_codeql_cli_panics_on_database_create() {
        // This test assumes codeql is NOT installed.
        // If codeql IS installed, this test is skipped via #[ignore].
        if CliCodeqlProvider.check_available() {
            return; // codeql is installed — skip the panic test
        }
        let provider = CliCodeqlProvider;
        let tmp = std::env::temp_dir().join("mcp-sec-audit-codeql-test-missing");
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        provider
            .create_database(&tmp, "python")
            .expect("codeql database create should fail when CLI not found");
    }
}
```

- [ ] **Step 2: Run tests and commit**

```bash
cd rust && cargo test -p mcp-sec-audit-core
```
Expected: ~119 tests pass.

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/provider.rs
git commit -m "feat(codeql): add CodeqlProvider trait and CliCodeqlProvider

Pluggable CodeQL backend with create_database and run_analysis steps.
Timeout via mpsc channel, following agent/provider.rs pattern.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: SARIF parser — SARIF v2.1.0 → Vec<CodeqlAnalysisResult>

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/parser.rs`

**Interfaces:**
- Consumes: `CodeqlAnalysisResult`, `Location`, `DataFlowPath`, `DataFlowPathStep` from Task 1
- Produces: `parse_sarif(sarif_json: &str, metadata: &CodeqlMetadata) -> Result<Vec<CodeqlAnalysisResult>>`

- [ ] **Step 1: Write `parser.rs`**

```rust
use anyhow::{Result, bail};

use crate::model::{CodeqlAnalysisResult, DataFlowPath, DataFlowPathStep, Location, Severity};

/// Metadata attached to every result from this CodeQL run.
#[derive(Debug, Clone)]
pub struct CodeqlMetadata {
    pub query_source: String, // "built-in" or custom path
    pub languages: Vec<String>,
}

/// Parse SARIF v2.1.0 JSON output from CodeQL into structured results.
pub fn parse_sarif(sarif_json: &str, metadata: &CodeqlMetadata) -> Result<Vec<CodeqlAnalysisResult>> {
    let root: serde_json::Value =
        serde_json::from_str(sarif_json).map_err(|e| anyhow::anyhow!("invalid SARIF JSON: {}", e))?;

    let runs = root["runs"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("SARIF missing 'runs' array"))?;

    let mut results = Vec::new();

    for (run_idx, run) in runs.iter().enumerate() {
        let tool_name = run["tool"]["driver"]["name"]
            .as_str()
            .unwrap_or("CodeQL");

        let rule_index: std::collections::HashMap<&str, &serde_json::Value> = run["tool"]["driver"]["rules"]
            .as_array()
            .map(|rules| {
                rules
                    .iter()
                    .filter_map(|r| r["id"].as_str().map(|id| (id, r)))
                    .collect()
            })
            .unwrap_or_default();

        let sarif_results = match run["results"].as_array() {
            Some(arr) => arr,
            None => continue,
        };

        for (result_idx, sr) in sarif_results.iter().enumerate() {
            let rule_id = match sr["ruleId"].as_str() {
                Some(id) => id.to_string(),
                None => continue, // skip results without ruleId
            };

            let rule_name = rule_index
                .get(rule_id.as_str())
                .and_then(|r| r["name"].as_str())
                .unwrap_or(&rule_id)
                .to_string();

            let message = sr["message"]["text"]
                .as_str()
                .unwrap_or("")
                .to_string();

            if message.is_empty() {
                continue;
            }

            let severity = parse_severity(
                sr.get("level").and_then(|l| l.as_str()),
                rule_index
                    .get(rule_id.as_str())
                    .and_then(|r| r["defaultConfiguration"]["level"].as_str()),
            );

            let locations = parse_locations(sr.get("locations"));

            if locations.is_empty() {
                continue; // must have at least one location
            }

            let dataflow_path = parse_code_flows(sr.get("codeFlows"));

            // Extract the raw SARIF snippet for this result
            let sarif_snippet = serde_json::to_string_pretty(sr).ok();

            let result_id = format!(
                "codeql:{}:{}:r{}:{}",
                tool_name, rule_id, run_idx, result_idx
            );

            results.push(CodeqlAnalysisResult {
                result_id,
                rule_id,
                rule_name,
                message,
                severity,
                locations,
                dataflow_path,
                sarif_snippet,
                related_rule_ids: Vec::new(),
                related_taint_ids: Vec::new(),
                related_agent_ids: Vec::new(),
                verification_status: "uncorroborated".to_string(),
                limitations: Vec::new(),
            });
        }
    }

    Ok(results)
}

fn parse_severity(
    result_level: Option<&str>,
    rule_level: Option<&str>,
) -> Severity {
    let level = result_level.or(rule_level).unwrap_or("warning");
    match level {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "note" => Severity::Low,
        _ => Severity::Medium,
    }
}

fn parse_locations(locations_val: Option<&serde_json::Value>) -> Vec<Location> {
    let arr = match locations_val.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };

    arr.iter()
        .filter_map(|loc| {
            let pl = &loc["physicalLocation"];
            let artifact = pl["artifactLocation"]["uri"].as_str()?;
            let region = &pl["region"];
            let line = region["startLine"].as_u64().map(|l| l as u32).unwrap_or(1);
            let column = region["startColumn"].as_u64().map(|c| c as u32);
            let message = loc["message"]["text"].as_str().map(|s| s.to_string());
            Some(Location {
                file: artifact.to_string(),
                line,
                column,
                message,
            })
        })
        .collect()
}

fn parse_code_flows(code_flows_val: Option<&serde_json::Value>) -> Option<DataFlowPath> {
    let flows = code_flows_val?.as_array()?;
    if flows.is_empty() {
        return None;
    }

    // Take the first codeFlow's threadFlows
    let thread_flows = flows[0]["threadFlows"].as_array()?;
    if thread_flows.is_empty() {
        return None;
    }

    let mut steps = Vec::new();
    for tf in thread_flows {
        let locations = tf["locations"].as_array()?;
        for loc in locations {
            let pl = &loc["location"]["physicalLocation"];
            let artifact = pl["artifactLocation"]["uri"].as_str()?;
            let region = &pl["region"];
            let line = region["startLine"].as_u64().map(|l| l as u32).unwrap_or(1);
            let column = region["startColumn"].as_u64().map(|c| c as u32);
            let snippet = loc["location"]["message"]["text"]
                .as_str()
                .map(|s| s.to_string());

            steps.push(DataFlowPathStep {
                location: Location {
                    file: artifact.to_string(),
                    line,
                    column,
                    message: None,
                },
                snippet,
            });
        }
    }

    if steps.is_empty() {
        None
    } else {
        Some(DataFlowPath { steps })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_sarif_with_result() -> String {
        r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "rules": [{
          "id": "py/command-injection",
          "name": "Uncontrolled command line"
        }]
      }
    },
    "results": [{
      "ruleId": "py/command-injection",
      "message": { "text": "This command depends on user input." },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "server.py" },
          "region": { "startLine": 42, "startColumn": 10 }
        }
      }]
    }]
  }]
}"#.to_string()
    }

    fn metadata() -> CodeqlMetadata {
        CodeqlMetadata {
            query_source: "built-in".to_string(),
            languages: vec!["python".to_string()],
        }
    }

    #[test]
    fn parse_valid_sarif_returns_result() {
        let sarif = minimal_sarif_with_result();
        let results = parse_sarif(&sarif, &metadata()).expect("parse SARIF");
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.rule_id, "py/command-injection");
        assert_eq!(r.rule_name, "Uncontrolled command line");
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.locations.len(), 1);
        assert_eq!(r.locations[0].file, "server.py");
        assert_eq!(r.locations[0].line, 42);
        assert_eq!(r.verification_status, "uncorroborated");
    }

    #[test]
    fn empty_runs_returns_empty() {
        let sarif = r#"{"version": "2.1.0", "runs": []}"#;
        let results = parse_sarif(sarif, &metadata()).expect("parse empty SARIF");
        assert!(results.is_empty());
    }

    #[test]
    fn invalid_json_returns_error() {
        let err = parse_sarif("not json", &metadata()).expect_err("invalid JSON should fail");
        assert!(err.to_string().contains("invalid SARIF JSON"));
    }

    #[test]
    fn missing_runs_key_returns_error() {
        let sarif = r#"{"version": "2.1.0"}"#;
        let err = parse_sarif(sarif, &metadata()).expect_err("missing runs should fail");
        assert!(err.to_string().contains("missing 'runs'"));
    }

    #[test]
    fn skips_results_without_rule_id() {
        let sarif = r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "CodeQL", "rules": [] } },
    "results": [{
      "message": { "text": "No rule here." },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "server.py" },
          "region": { "startLine": 1 }
        }
      }]
    }]
  }]
}"#;
        let results = parse_sarif(sarif, &metadata()).expect("parse SARIF");
        assert!(results.is_empty(), "results without ruleId should be skipped");
    }

    #[test]
    fn skips_results_with_empty_message() {
        let sarif = r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "CodeQL", "rules": [{ "id": "x/t", "name": "Test" }] } },
    "results": [{
      "ruleId": "x/t",
      "message": { "text": "" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "server.py" },
          "region": { "startLine": 1 }
        }
      }]
    }]
  }]
}"#;
        let results = parse_sarif(sarif, &metadata()).expect("parse SARIF");
        assert!(results.is_empty(), "results with empty message should be skipped");
    }

    #[test]
    fn parse_code_flows_when_present() {
        let sarif = r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "rules": [{ "id": "py/test", "name": "Test" }]
      }
    },
    "results": [{
      "ruleId": "py/test",
      "message": { "text": "Data flows to sink." },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "server.py" },
          "region": { "startLine": 42 }
        }
      }],
      "codeFlows": [{
        "threadFlows": [{
          "locations": [
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "server.py" },
                  "region": { "startLine": 10 }
                },
                "message": { "text": "source" }
              }
            },
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "server.py" },
                  "region": { "startLine": 42 }
                },
                "message": { "text": "sink" }
              }
            }
          ]
        }]
      }]
    }]
  }]
}"#;
        let results = parse_sarif(sarif, &metadata()).expect("parse SARIF");
        let r = &results[0];
        assert!(r.dataflow_path.is_some());
        let dfp = r.dataflow_path.as_ref().unwrap();
        assert_eq!(dfp.steps.len(), 2);
        assert_eq!(dfp.steps[0].location.line, 10);
        assert_eq!(dfp.steps[1].location.line, 42);
    }

    #[test]
    fn multiple_results_are_all_parsed() {
        let sarif = r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "rules": [
          { "id": "py/a", "name": "A" },
          { "id": "py/b", "name": "B" }
        ]
      }
    },
    "results": [
      {
        "ruleId": "py/a",
        "message": { "text": "Issue A." },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "a.py" },
            "region": { "startLine": 1 }
          }
        }]
      },
      {
        "ruleId": "py/b",
        "message": { "text": "Issue B." },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "b.py" },
            "region": { "startLine": 2 }
          }
        }]
      }
    ]
  }]
}"#;
        let results = parse_sarif(sarif, &metadata()).expect("parse SARIF");
        assert_eq!(results.len(), 2);
    }
}
```

- [ ] **Step 2: Run tests and commit**

```bash
cd rust && cargo test -p mcp-sec-audit-core
```
Expected: ~127 tests pass.

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/parser.rs
git commit -m "feat(codeql): add SARIF v2.1.0 parser

Parse codeql database analyze output into CodeqlAnalysisResult items.
Handles codeFlows→DataFlowPath, severity mapping, location extraction.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5: CodeQL orchestration — mod.rs entry point

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs`

**Interfaces:**
- Consumes: `provider.rs`, `parser.rs`, `queries.rs` from Tasks 2-4; `StaticScanContext` from pipeline
- Produces: `pub fn run(ctx: &StaticScanContext) -> Result<CodeqlOutput>`

- [ ] **Step 1: Write `mod.rs`**

```rust
mod parser;
mod provider;
mod queries;

use anyhow::Result;

use crate::model::CodeqlOutput;

use super::pipeline::StaticScanContext;
use provider::{CliCodeqlProvider, CodeqlProvider};
use queries::resolve_query_pack;

/// Hardcoded constants (not user-configurable).
/// Languages CodeQL supports — Rust is NOT a first-class CodeQL language.
const SUPPORTED_LANGUAGES: &[&str] = &["python", "javascript", "typescript"];

/// CodeQL line entry point.
///
/// Filters to Python/JS/TS targets, creates CodeQL databases per language,
/// runs analysis with built-in or custom queries, and parses SARIF output
/// into structured results.
pub fn run(ctx: &StaticScanContext) -> Result<CodeqlOutput> {
    let codeql_config = &ctx.config.static_.codeql;

    if !codeql_config.enabled {
        return Ok(CodeqlOutput::empty());
    }

    let provider = CliCodeqlProvider;

    // Hard-error if CodeQL CLI is not installed
    if !provider.check_available() {
        panic!(
            "CodeQL CLI ('codeql') not found in PATH. \
             Install it from: https://github.com/github/codeql-cli-binaries/releases"
        );
    }

    // Filter discovered files to CodeQL-supported languages only
    let supported_files: Vec<_> = ctx
        .discovered_files
        .iter()
        .filter(|df| {
            let lang = df.language.config_keys()[0].as_str();
            SUPPORTED_LANGUAGES.contains(&lang)
        })
        .collect();

    if supported_files.is_empty() {
        let mut output = CodeqlOutput::empty();
        output.diagnostics.push(
            "No Python/JS/TS files found — CodeQL line skipped.".to_string(),
        );
        return Ok(output);
    }

    // Group files by language to create one database per language
    let mut languages = std::collections::BTreeSet::new();
    for df in &supported_files {
        let lang = df.language.config_keys()[0].to_string();
        languages.insert(lang);
    }

    // Determine source root from the first file
    let target_root = ctx
        .discovered_files
        .first()
        .and_then(|df| df.path.parent())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| ".".to_string());

    // Resolve query pack
    let query_pack = resolve_query_pack(codeql_config.query_pack_path.as_deref())?;

    let mut all_results = Vec::new();
    let mut all_diagnostics = Vec::new();
    let mut raw_sarif_parts = Vec::new();

    for language in &languages {
        // Create database
        let db = match provider.create_database(
            std::path::Path::new(&target_root),
            language,
        ) {
            Ok(db) => db,
            Err(e) => {
                all_diagnostics.push(format!(
                    "CodeQL database create failed for {}: {}",
                    language, e
                ));
                continue;
            }
        };

        // Run analysis
        match provider.run_analysis(
            &db,
            &query_pack,
            codeql_config.timeout_seconds,
            &codeql_config.extra_args,
        ) {
            Ok(sarif) => {
                let metadata = parser::CodeqlMetadata {
                    query_source: codeql_config
                        .query_pack_path
                        .clone()
                        .unwrap_or_else(|| "built-in".to_string()),
                    languages: vec![language.clone()],
                };

                match parser::parse_sarif(&sarif, &metadata) {
                    Ok(results) => {
                        all_results.extend(results);
                        raw_sarif_parts.push(sarif);
                    }
                    Err(e) => {
                        all_diagnostics.push(format!(
                            "SARIF parse failed for {}: {}",
                            language, e
                        ));
                    }
                }
            }
            Err(e) => {
                all_diagnostics.push(format!(
                    "CodeQL analyze failed for {}: {}",
                    language, e
                ));
            }
        }
    }

    let raw_sarif = if raw_sarif_parts.is_empty() {
        None
    } else {
        Some(raw_sarif_parts.join("\n"))
    };

    Ok(CodeqlOutput {
        results: all_results,
        raw_sarif,
        diagnostics: all_diagnostics,
    })
}

// Integration tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeConfig;

    #[test]
    fn disabled_codeql_returns_empty() {
        let ctx = StaticScanContext {
            config: RuntimeConfig::default(), // codeql disabled by default
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        let output = run(&ctx).expect("run disabled codeql");
        assert!(output.results.is_empty());
        assert!(output.raw_sarif.is_none());
        assert!(output.diagnostics.is_empty());
    }

    #[test]
    fn enabled_with_no_files_returns_empty_with_diagnostic() {
        let mut config = RuntimeConfig::default();
        config.static_.codeql.enabled = true;
        let ctx = StaticScanContext {
            config,
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        let output = run(&ctx).expect("run codeql with no files");
        assert!(output.results.is_empty());
        // We still panic on CLI not found, but no files means we return early
        // before the CLI check. Actually, re-reading the code, the CLI check
        // happens before the file check. So this test will panic if codeql
        // is not installed. We need to handle this.
    }
}
```

Wait — there's a problem. The CLI availability check happens before the file emptiness check, so the `enabled_with_no_files_returns_empty` test will **panic** if CodeQL is not installed. We need to reorder: check files first, then CLI.

Fix the ordering in `run()`:

```rust
pub fn run(ctx: &StaticScanContext) -> Result<CodeqlOutput> {
    let codeql_config = &ctx.config.static_.codeql;

    if !codeql_config.enabled {
        return Ok(CodeqlOutput::empty());
    }

    // Filter to supported languages first
    let supported_files: Vec<_> = ctx
        .discovered_files
        .iter()
        .filter(|df| {
            let lang = df.language.config_keys()[0].as_str();
            SUPPORTED_LANGUAGES.contains(&lang)
        })
        .collect();

    if supported_files.is_empty() {
        let mut output = CodeqlOutput::empty();
        let total = ctx.discovered_files.len();
        output.diagnostics.push(format!(
            "No Python/JS/TS files among {} discovered files — CodeQL line skipped.",
            total
        ));
        return Ok(output);
    }

    // Now check CLI availability — hard error
    let provider = CliCodeqlProvider;
    if !provider.check_available() {
        panic!(
            "CodeQL CLI ('codeql') not found in PATH. \
             Install it from: https://github.com/github/codeql-cli-binaries/releases"
        );
    }

    // ... rest of the implementation
}
```

And the test becomes safe:

```rust
#[test]
fn enabled_with_no_files_returns_empty_with_diagnostic() {
    let mut config = RuntimeConfig::default();
    config.static_.codeql.enabled = true;
    let ctx = StaticScanContext {
        config,
        rulebook_paths: Vec::new(),
        discovered_files: Vec::new(),
    };
    // Safe even without CodeQL CLI: no files → returns before CLI check
    let output = run(&ctx).expect("run codeql with no files");
    assert!(output.results.is_empty());
    assert!(!output.diagnostics.is_empty());
}
```

- [ ] **Step 2: Run tests and commit**

```bash
cd rust && cargo test -p mcp-sec-audit-core
```
Expected: ~129 tests pass.

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs
git commit -m "feat(codeql): add CodeQL line orchestration entry point

Per-language database create + analyze + SARIF parse. Filters to
Python/JS/TS only. Early return before CLI check when no supported
files, so unit tests work without CodeQL installed.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 6: Integration — module declaration, pipeline wiring, docs

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`
- Modify: `rust/docs/REFACTOR_PLAN.md`

- [ ] **Step 1: Add `mod codeql;` to `static_analysis/mod.rs`**

Insert after `mod agent;`:

```rust
mod codeql;
```

- [ ] **Step 2: Wire codeql into pipeline.rs**

In the use statement (line 14), add `codeql`:

```rust
use super::{agent, codeql, rule, taint, DiscoveredFile, discover_files};
```

After `agent_results` line (~line 77):

```rust
let codeql_output = codeql::run(&ctx)?;
```

Use codeql_output fields in the result assembly:

```rust
let summary = StaticAnalysisSummary {
    target: target_label(&targets),
    fact_count: all_facts.len(),
    rule_result_count: rule_results.len(),
    taint_result_count: taint_results.len(),
    agent_result_count: agent_results.len(),
    codeql_result_count: codeql_output.results.len(),  // NEW
    fused_finding_count: 0,
    highest_severity: None,
    risk_level: "none".to_string(),
};

Ok(StaticAnalysisResult {
    facts: all_facts,
    rule_results,
    taint_results,
    agent_results,
    codeql_results: codeql_output.results,  // NEW
    fused_findings: Vec::new(),
    summary,
    config_snapshot: ConfigSnapshot {
        runtime: effective_config,
        rulebook_paths: ctx.rulebook_paths,
    },
})
```

- [ ] **Step 3: Add pipeline test**

Add a test in the `pipeline.rs` tests module:

```rust
#[test]
fn enabled_static_scan_includes_codeql_result_count() {
    let root = temp_dir("codeql-count");
    let rules = write_rulebook(&root, "rules.toml", "command_exec");
    fs::write(root.join("server.py"), "print('ok')").expect("write file");

    let mut config = RuntimeConfig::default();
    config.static_.taint.enabled = true;
    // codeql is disabled by default — count should be 0
    let result = run_static_scan(&config, &[rules], Some(&[root.clone()]))
        .expect("run scan");
    assert_eq!(result.summary.codeql_result_count, 0);
    assert!(result.codeql_results.is_empty());
    assert!(result.summary.taint_result_count > 0);

    fs::remove_dir_all(root).expect("cleanup");
}
```

- [ ] **Step 4: Run full test suite**

```bash
cd rust && cargo test
```
Expected: ~130 tests pass (111 existing + ~19 new, minus any overlap).

Then check the `static_analysis_json_preserves_three_line_results` test still passes — it now also checks for `codeql_results`.

- [ ] **Step 5: Update REFACTOR_PLAN.md**

Insert a new row after Phase 12 in the status table:

```
| Phase 12.5：CodeQL 分析线 | 完成 | 作为第四条并行静态分析线，调用 CodeQL CLI 进行专业级污点分析。 | CodeQL 线独立产出 CodeqlAnalysisResult + SARIF 审计原始数据。 |
```

And add a completion note below the Phase 12 note.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs \
        rust/docs/REFACTOR_PLAN.md
git commit -m "feat(codeql): wire CodeQL line into static analysis pipeline

Add codeql::run() as fourth parallel line in run_static_scan().
Update StaticAnalysisSummary with codeql_result_count. Mark Phase 12.5
complete in REFACTOR_PLAN.md.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task Summary

| # | Task | Files | Test impact |
|---|---|---|---|
| 1 | Config + Model | `config.rs`, `static_result.rs`, `model/mod.rs`, `fixtures.rs`, `pipeline.rs`, `default.toml` | +5 tests |
| 2 | Queries | `queries.rs` + 3 `.ql` files | +3 tests |
| 3 | Provider | `provider.rs` | +1 test |
| 4 | Parser | `parser.rs` | +8 tests |
| 5 | Orchestration | `mod.rs` | +2 tests |
| 6 | Integration | `mod.rs`, `pipeline.rs`, `REFACTOR_PLAN.md` | +1 test |
