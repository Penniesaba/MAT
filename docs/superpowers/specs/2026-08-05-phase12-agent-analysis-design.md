# Phase 12: Agent Analysis Line — Design Spec

**Date:** 2026-08-05
**Status:** Approved
**Scope:** Agent 辅助源码分析线 + 三线工程化解耦重构

## Overview

实现可配置的 Agent 辅助源码分析线（Phase 12），同时对静态分析模块进行工程化解耦重构。Agent 线通过 CLI 子进程调用外部 Agent 工具（如 Claude Code），传入设计良好的安全审计 prompt，Agent 自主使用工具探索源码并产出结构化漏洞发现。三条分析线（rule/taint/agent）完全并行独立，各自从源文件出发，互不依赖。

## Non-Goals

- 不实现 HTTP API 直调 Agent（后续可加）
- 不实现 `evidence_aware` 或 `hypothesis_then_verify` 模式（依赖其他线结果，违反三线并行原则）
- Agent 线不消费 rule_results 或 taint_results
- Phase 13 融合层不在此范围

## Architecture: Three-Line Decoupling

### Before

```
Source Files
     │
     ├── Fact Extraction (above all lines)
     │   └── Vec<Fact>
     │       ├── Rule Line (ignores facts)
     │       ├── Taint Line (consumes facts)
     │       └── Agent Line (stub, empty)
     │
     └── Problem: facts only serve taint line, but sit above all three
```

### After

```
Source Files (DiscoveredFile[])
     │
     ├── rule/run()     ── source text ── regex matching ── Vec<RuleAnalysisResult>
     │
     ├── taint/run()    ── source text ── fact extraction ── graph ── BFS ── (Vec<TaintAnalysisResult>, Vec<Fact>)
     │
     └── agent/run()    ── source text ── CLI agent ── Vec<AgentAnalysisResult>
```

All three lines are equal peers. Each reads source files independently. Facts become an internal implementation detail of the taint line.

## Module Structure

```
static_analysis/
├── mod.rs              # module declarations + public re-exports
├── pipeline.rs         # StaticScanContext + run_static_scan() — pure orchestrator
├── discovery.rs        # DiscoveredFile, ScanLanguage, file discovery (shared)
│
├── rule/               # ── Rule Line ──
│   └── mod.rs          # pub fn run() -> Vec<RuleAnalysisResult>
│
├── taint/              # ── Taint Line ──
│   ├── mod.rs          # pub fn run() -> (Vec<TaintAnalysisResult>, Vec<Fact>)
│   ├── graph.rs        # Node, Edge, Graph
│   ├── builder.rs      # build_graph(&[Fact]) -> Graph
│   ├── propagation.rs  # BFS forward/backward
│   └── result.rs       # paths → TaintAnalysisResult + DataFlowFact
│
├── facts/              # Fact extraction — called ONLY by taint line
│   ├── mod.rs
│   ├── pipeline.rs     # extract_static_facts()
│   ├── python/
│   ├── js_ts/
│   └── rust/
│
└── agent/              # ── Agent Line ──
    ├── mod.rs          # pub fn run() -> Vec<AgentAnalysisResult>
    ├── provider.rs     # AgentProvider trait + CliAgentProvider
    ├── prompt.rs       # template loading + rendering
    └── parser.rs       # JSON extraction → AgentAnalysisResult mapping
```

### Design Rules

- Each line is an independent directory
- Each directory has exactly one `pub fn run()` entry point
- Lines do NOT import from each other
- Shared types live in `pipeline.rs` / `discovery.rs`
- All internal implementation details are `pub(crate)` or private
- `lines.rs` is deleted — dispatchers move into their respective line directories

## Agent Line Design

### Invocation Model: CLI Subprocess

```
agent::run(ctx, config)
  │
  ├── 1. enabled check → false: return Ok(Vec::new())
  │
  ├── 2. Collect file info from ctx.discovered_files
  │       → Vec<FileInfo> { path, language, line_count }
  │
  ├── 3. prompt::render(template, &file_info)
  │       - Load template: config.prompt_template_path OR built-in default
  │       - Substitute: {file_list}, {language}, {target_root}
  │
  ├── 4. provider.run(AgentRunConfig { working_dir, prompt, ... })
  │       → $ claude -p "$PROMPT" --max-turns 30 --output-format text
  │
  └── 5. parser::parse(stdout) → Vec<AgentAnalysisResult>
          - Extract JSON block from stdout
          - Validate required fields
          - Filter low confidence (hardcoded threshold)
          - Attach metadata (agent_id, prompt_profile)
```

### Configuration (StaticAgentConfig)

```rust
pub struct StaticAgentConfig {
    pub enabled: bool,                       // default: false
    pub provider: String,                    // CLI binary name, default: "claude"
    pub prompt_template_path: Option<String>, // custom template path, None = built-in
    pub max_turns: u32,                      // default: 30
    pub timeout_seconds: u64,                // default: 600
    pub extra_args: Vec<String>,             // extra CLI args, e.g. ["--model", "sonnet"]
}
```

TOML:
```toml
[static.agent]
enabled = true
provider = "claude"
prompt_template_path = "/path/to/custom-prompt.md"
max_turns = 30
timeout_seconds = 600
extra_args = ["--model", "sonnet"]
```

### Hardcoded Constants (NOT in config)

```rust
const PROMPT_PROFILE: &str = "mcp_security_audit";
const AGENT_MODE: &str = "source_only";   // three-line parallel, no cross-line deps
const MAX_FILES: u32 = 80;
const INCLUDE_LOW_CONFIDENCE: bool = false;
const DEFAULT_MAX_TURNS: u32 = 30;
const DEFAULT_TIMEOUT_SECONDS: u64 = 600;
const DEFAULT_PROVIDER: &str = "claude";
```

### AgentProvider Trait

```rust
pub trait AgentProvider {
    fn run(&self, config: &AgentRunConfig) -> Result<AgentRunOutput>;
}

pub struct AgentRunConfig {
    pub working_dir: PathBuf,
    pub prompt: String,
    pub provider_binary: String,
    pub max_turns: u32,
    pub timeout_seconds: u64,
    pub extra_args: Vec<String>,
}

pub struct AgentRunOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration: Duration,
}
```

### CliAgentProvider

Uses `std::process::Command` to spawn agent CLI. Captures stdout/stderr. Implements timeout via thread + channel.

| Scenario | Behavior |
|---|---|
| CLI binary not in PATH | Error: "agent provider 'claude' not found" |
| Timeout | Kill process, parse partial stdout, add limitation |
| Non-zero exit | Log stderr, attempt to parse stdout for JSON |
| No valid JSON in stdout | Error: "no valid JSON output from agent" |
| Agent returns empty findings | Ok(Vec::new()) |

### Prompt Template (built-in default)

Structured as markdown with variable placeholders:

- **Role**: MCP security auditor
- **Vulnerability Taxonomy**: 7 MCP-specific categories (tool poisoning, prompt injection, command injection, path traversal, credential leaks, capability over-exposure, context over-sharing)
- **Target Overview**: `{language}`, `{file_list}`
- **Instructions**: Read files, identify risks beyond pattern matching, focus on MCP attack surfaces
- **Output Format**: JSON schema with `{ "findings": [...] }`

### Output Parser (parser.rs)

```
parse_agent_output(stdout) -> Vec<AgentAnalysisResult>
  1. Locate JSON block: ```json ... ``` fence OR bare { "findings": ... }
  2. Deserialize to RawFindings { findings: Vec<RawFinding> }
  3. Map to AgentAnalysisResult, attach metadata
  4. Validate: candidate_title non-empty, affected_locations ≥ 1, reasoning_summary non-empty
  5. Filter: discard low confidence below threshold
```

AgentAnalysisResult fields populated:
- `result_id`: `"agent:{agent_id}:{seq}"`
- `agent_id`: from provider binary name
- `prompt_profile`: hardcoded constant
- `model_provider`: `Some(provider_binary)`
- `input_scope`: file paths analyzed
- `candidate_title`: from agent output
- `affected_locations`: from agent output
- `reasoning_summary`: from agent output
- `evidence_snippets`: from agent output
- `related_rule_result_ids`: `vec![]` (Phase 13)
- `related_taint_result_ids`: `vec![]` (Phase 13)
- `confidence`: from agent output, filtered
- `verification_status`: `"uncorroborated"` (Phase 13)
- `limitations`: from agent output + runtime notes

### Prompt Template: Variable Substitution

| Placeholder | Source |
|---|---|
| `{language}` | Primary language from discovered files |
| `{file_list}` | Bullet list: `- path (language, N lines)` |
| `{target_root}` | Absolute path to project root |
| `{mcp_taxonomy}` | Embedded MCP vulnerability taxonomy text |

## Pipeline Changes

### Before (pipeline.rs)

```rust
use super::{DiscoveredFile, discover_files, extract_static_facts, lines};

let facts = extract_static_facts(&ctx)?;
let rule_results = lines::run_rule_line(&ctx, loaded_rulebook.as_ref())?;
let (taint_results, dataflow_facts) = lines::run_taint_line(&ctx, &facts)?;
let agent_results = lines::run_agent_line(&ctx)?;

let mut all_facts = facts;
all_facts.extend(dataflow_facts);
```

### After (pipeline.rs)

```rust
use super::{rule, taint, agent, discovery};

// No extract_static_facts call here — taint line handles it internally

let rule_results = rule::run(&ctx, loaded_rulebook.as_ref())?;
let (taint_results, all_facts) = taint::run(&ctx)?;
let agent_results = agent::run(&ctx)?;

// No fact merging needed — taint::run() returns all facts + dataflow facts
```

### `rule::run()` signature

```rust
pub fn run(ctx: &StaticScanContext, rulebook: Option<&RuleBook>) -> Result<Vec<RuleAnalysisResult>>
```

### `taint::run()` signature

```rust
pub fn run(ctx: &StaticScanContext) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)>
```
Internally calls `extract_static_facts(ctx)?` then `run_taint_analysis(&facts, &config)`.

### `agent::run()` signature

```rust
pub fn run(ctx: &StaticScanContext) -> Result<Vec<AgentAnalysisResult>>
```

## Files Changed

| File | Operation | Summary |
|---|---|---|
| `static_analysis/lines.rs` | **Delete** | Dispatchers move into line directories |
| `static_analysis/rule.rs` → `rule/mod.rs` | **Move** | Content preserved, becomes `rule::run()` |
| `static_analysis/mod.rs` | Modify | Remove `mod lines`, add `mod agent`, update re-exports |
| `static_analysis/pipeline.rs` | Modify | Import from `rule`/`taint`/`agent` directly, remove `extract_static_facts` call |
| `static_analysis/agent/mod.rs` | Create | `run()` orchestration entry point |
| `static_analysis/agent/provider.rs` | Create | `AgentProvider` trait + `CliAgentProvider` |
| `static_analysis/agent/prompt.rs` | Create | Built-in template + render function |
| `static_analysis/agent/parser.rs` | Create | JSON extraction + validation |
| `config.rs` | Modify | `StaticAgentConfig` field changes |
| `rust/docs/REFACTOR_PLAN.md` | Modify | Update Phase 12 status |

## Error Handling

| Scenario | Behavior |
|---|---|
| Agent config disabled | Return empty Vec, no error |
| CLI binary not found | `bail!("agent provider '{}' not found in PATH", name)` |
| Prompt template file not found | `bail!("prompt template not found: {}", path)` |
| Agent timeout | Kill process, parse partial stdout, add `"timeout after {N}s"` to limitations |
| Agent crash (non-zero exit) | Log stderr, attempt parse, return partial results if possible |
| No JSON in stdout | `bail!("no valid JSON output from agent provider")` |
| JSON parse failure | `bail!("failed to parse agent output: {details}")` |
| Empty findings in JSON | Ok(Vec::new()), not an error |
| Missing required fields | Skip that finding, log warning, continue with others |

## Edge Cases

| Scenario | Behavior |
|---|---|
| Zero discovered files | Return empty results (nothing to analyze) |
| Single file > MAX_FILES | Still include it (cap is on count, not size) |
| Mixed language project | `{language}` shows primary language, file list shows all |
| Agent output has extra fields | Ignore unknown fields (serde `deny_unknown_fields = false`) |
| Duplicate finding titles | Keep all, dedup is Phase 13's job |
| Concurrent agent runs | Not supported — agent line runs once per scan |

## Testing Strategy

### Unit Tests

- **parser.rs**: JSON extraction from various formats (fenced, bare, malformed, empty)
- **prompt.rs**: Template rendering, variable substitution, missing template file
- **provider.rs**: Binary not found, mock provider for success/failure/timeout

### Integration Tests

- **agent/mod.rs**: `run()` with disabled config, enabled but no files
- **pipeline.rs**: End-to-end with agent disabled (existing tests should pass unchanged)
- **pipeline.rs**: End-to-end with mock agent provider

### Mock Provider for Testing

A `MockAgentProvider` that returns pre-crafted JSON output, enabling tests without a real CLI agent installed.

## Dependencies

No new external crate dependencies. Uses `std::process::Command`, `std::sync::mpsc` (for timeout), and existing `serde`/`serde_json`.

## Risks

- **Agent output format fragility**: Mitigated by JSON schema in prompt + lenient parser (handles both fenced and bare JSON)
- **Prompt quality determines results**: Mitigated by externalized template — can be iterated without code changes
- **CLI binary version differences**: Mitigated by `extra_args` config for version-specific flags
