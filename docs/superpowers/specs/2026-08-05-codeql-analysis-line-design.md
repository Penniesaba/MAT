# CodeQL Analysis Line — Design Spec

**Status:** Approved  
**Date:** 2026-08-05

## Goal

Add a fourth static analysis line that invokes CodeQL CLI as a subprocess for
professional-grade taint analysis. The line runs fully independent and parallel
to the existing rule, taint, and agent lines.

## Architecture

```
pipeline.rs
  ├─ rule::run(&ctx, rulebook)      → Vec<RuleAnalysisResult>
  ├─ taint::run(&ctx)               → (Vec<TaintAnalysisResult>, Vec<Fact>)
  ├─ agent::run(&ctx)               → Vec<AgentAnalysisResult>
  └─ codeql::run(&ctx)              → CodeqlOutput          ← NEW
```

The CodeQL line consumes **only** `StaticScanContext` — no facts, no rulebook,
no results from other lines. It is a pure peer.

## Directory Structure

```
static_analysis/codeql/
├── mod.rs           # pub fn run(ctx) -> Result<CodeqlOutput>
├── provider.rs      # CodeqlProvider trait + CliCodeqlProvider
├── queries.rs       # Built-in MCP queries + path resolution
└── parser.rs        # SARIF v2.1.0 → Vec<CodeqlAnalysisResult>
```

## Data Flow

1. **Language filter**: Python/JS/TS only — Rust targets are skipped with a
   diagnostic.
2. **Enabled guard**: return empty `CodeqlOutput` if disabled.
3. **CLI availability check**: panic if `codeql` is not on PATH (hard error,
   per design decision).
4. **Database creation**: `codeql database create <tmpdir> --language=<lang>`
   — per-language granularity; a failing language records a diagnostic and
   steps to the next.
5. **Query pack resolution**: load custom pack if `query_pack_path` is set,
   otherwise use built-in MCP queries + CodeQL standard security suites.
6. **Analysis run**: `codeql database analyze <db> <queries> --format=sarif-latest`
   — timeout per `timeout_seconds` config.
7. **SARIF parse**: extract `CodeqlAnalysisResult` items; keep raw SARIF JSON
   as audit artifact.
8. **Assembly**: `CodeqlOutput { results, raw_sarif, diagnostics }`.

## Configuration

```toml
[static.codeql]
enabled = false
# query_pack_path = "/path/to/custom/queries"  # optional
timeout_seconds = 1200
extra_args = []
```

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCodeqlConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub query_pack_path: Option<String>,
    #[serde(default = "default_codeql_timeout")]
    pub timeout_seconds: u64,              // default: 1200
    #[serde(default)]
    pub extra_args: Vec<String>,
}
```

## Models

### CodeqlOutput

```rust
pub struct CodeqlOutput {
    pub results: Vec<CodeqlAnalysisResult>,
    pub raw_sarif: Option<String>,          // Original SARIF JSON
    pub diagnostics: Vec<String>,           // Warnings / skip notices
}
```

### CodeqlAnalysisResult

```rust
pub struct CodeqlAnalysisResult {
    pub result_id: String,
    pub rule_id: String,                    // e.g. "py/command-injection"
    pub rule_name: String,                  // e.g. "Uncontrolled command line"
    pub message: String,
    pub severity: Severity,
    pub locations: Vec<Location>,
    pub dataflow_path: Option<DataFlowPath>, // CodeQL codeFlows
    pub sarif_snippet: Option<String>,       // Raw SARIF fragment
    pub related_rule_ids: Vec<String>,       // Phase 13
    pub related_taint_ids: Vec<String>,      // Phase 13
    pub related_agent_ids: Vec<String>,      // Phase 13
    pub verification_status: String,         // Phase 13
    pub limitations: Vec<String>,
}
```

## Provider

```rust
pub trait CodeqlProvider {
    fn check_available(&self) -> bool;
    fn create_database(&self, source_dir: &Path, language: &str) -> Result<DatabaseInfo>;
    fn run_analysis(&self, db: &DatabaseInfo, queries: &QueryPack, timeout_secs: u64) -> Result<String>;
}

pub struct CliCodeqlProvider; // Default: shell out to `codeql` CLI
```

Reuses the `mpsc::channel` + `recv_timeout` pattern from `agent::provider`.

## Built-in Queries

### MCP-specific (authored by us, references from GitHub Security Lab / Trail of Bits)

| Query | What it detects |
|---|---|
| `ToolParameterToSink.ql` | MCP tool parameter reaches dangerous sink (exec, eval, file write) |
| `ResourceToNetwork.ql` | MCP resource/content read reaches outbound network call |
| `PromptInjection.ql` | User-supplied prompt data flows into LLM API calls without sanitization |

### Standard security queries

Use CodeQL's published query packs (`codeql/python-queries`, `codeql/javascript-queries`)
— no vendored copies needed.

### Loading strategy

- `query_pack_path` set → only the user's queries run.
- `query_pack_path` not set → built-in MCP queries + standard packs.

## Model Integration

`StaticAnalysisResult` gains:

```rust
pub codeql_results: Vec<CodeqlAnalysisResult>,
```

`StaticAnalysisSummary` gains:

```rust
pub codeql_result_count: usize,
```

## Testing

| Module | Tests | Requires CodeQL? |
|---|---|---|
| `queries.rs` | Built-in .ql files exist, query pack resolution | No |
| `parser.rs` | SARIF → results, empty/invalid/missing fields, codeFlows | No |
| `provider.rs` | CLI-not-found panic, timeout (sleep mock) | No |
| `mod.rs` | Disabled → empty, no matching language → empty + diag, Rust skip | No |
| Integration | Full python sink detection (ignored by default) | Yes |

## Risk Assessment

| Risk | Mitigation |
|---|---|
| CodeQL CLI not installed | Hard error with install instructions in panic message |
| Syntax errors in target source | Per-language skip, diagnostic recorded |
| Large project timeout | Configurable `timeout_seconds` (default 1200) |
| Query quality | Reference authoritative repos (GitHub Security Lab, Trail of Bits); cite sources |
| Duplicate findings with taint line (Phase 13) | Deduplicate by `rule_id` + location during fusion |
| SARIF format drift | Parse only standard SARIF v2.1.0 schema; version-independent |

## Non-Goals (out of scope)

- Rust CodeQL support (CodeQL has no official Rust support; Rust targets are skipped)
- Docker/container bundling of CodeQL CLI (defer to Phase 17)
- Auto-install of CodeQL CLI
- CodeQL query compilation/packaging (queries are run as source `.ql` files)
