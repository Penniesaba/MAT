# Phase 10/11: Unified Taint Analysis — Design Spec

**Date:** 2026-08-05
**Status:** Approved
**Scope:** Call graph construction + lightweight data flow analysis delivered as a single taint analysis module

## Overview

Replace the current `run_taint_line()` bail-with-error stub with a production-grade taint analysis module. Build a unified cross-file program graph from all language facts (Python, JS/TS, Rust), then run configurable forward/backward BFS propagation to find source-to-sink paths. Output `TaintAnalysisResult` and `DataFlowFact` values integrated into the existing static analysis pipeline.

## Non-Goals

- Full abstract interpretation or symbolic execution
- Type-level precision (field-sensitive, points-to analysis)
- Control-flow sensitivity (branches, loops)
- Replacing or modifying existing fact extractors
- Agent line or fusion — those are later phases

## Module Structure

New directory `static_analysis/taint/` with five files:

```
rust/crates/mcp-sec-audit-core/src/static_analysis/taint/
├── mod.rs          # public API: run_taint_analysis(&[Fact], &StaticTaintConfig) -> (Vec<TaintAnalysisResult>, Vec<Fact>)
├── graph.rs        # unified graph: Node enum, Edge enum, Graph struct
├── builder.rs      # graph construction from Vec<Fact>
├── propagation.rs  # forward/backward BFS with depth limiting
└── result.rs       # path → TaintAnalysisResult + DataFlowFact generation
```

Integration point in `lines.rs`:

- `run_taint_line()` calls `taint::run_taint_analysis(ctx.discovered_files_facts, &ctx.config.static_.taint)`
- Returns `Vec<TaintAnalysisResult>` plus `Vec<Fact>` (DataFlowFact values to append to the facts list)

## Graph Data Model

### Nodes

| Node variant | ID source | Key fields |
|---|---|---|
| `Function` | `FunctionFact.base.id` | name, qualified_name, file, params |
| `Source` | `SourceFact.base.id` | name, kind, function_id |
| `Sink` | `SinkFact.base.id` | category, severity_base, call_id |
| `Call` | `CallFact.base.id` | callee, normalized_callee, args |
| `Variable` | `{function_id}::{var_name}` | name, function_id |

### Edges

| Edge | From | To | Source fact | Critical for |
|---|---|---|---|---|
| `SourceInFunction` | Source | Function | SourceFact | Link source to its function |
| `CallInFunction` | Call | Function | CallFact.caller | Calls within a function |
| `CallToFunction` | Call | Function | CallFact.normalized_callee + FunctionFact.qualified_name match | Cross-file call resolution |
| `ArgToParam` | Call | Variable | CallFact.args + FunctionFact.params | Parameter binding |
| `VarToArg` | Variable | Call | CallFact.args[].expr matches AssignFact.target | Variable flows into call |
| `ValToVar` | Variable | Variable | AssignFact: x = y | Assignment propagation |
| `CallToSink` | Call | Sink | SinkFact.call_id | Dangerous call classification |
| `ReturnToVar` | Call | Variable | AssignFact: x = foo() | Return value flow |
| `SourceToArg` | Source | Call | SourceFact name matches CallFact.args[].expr | Direct parameter to arg |

### Callee Resolution (Cross-File)

The critical cross-file edge is `CallToFunction`. Resolution strategy:

1. Build a `HashMap<String, Vec<String>>` from all `FunctionFact` facts: qualified_name → [function_id] (multiple files may define same name — use file path to disambiguate)
2. For each `CallFact` with `normalized_callee`:
   - Exact match on qualified_name → `CallToFunction` with `Confidence::High`
   - Partial match (last segment matches) in same file → `Confidence::Medium`
3. No match → callee is external; still create Call node but set `is_external: true`; sink edges still work

External calls do NOT block analysis. A sink on an external call (e.g. `subprocess.run(...)`) still generates results — the path ends at the Call node itself, annotated with `has_external_call: true`.

### Graph Structure

```rust
pub struct Graph {
    pub nodes: HashMap<String, Node>,              // node_id → Node
    pub outgoing: HashMap<String, Vec<Edge>>,      // forward edges
    pub incoming: HashMap<String, Vec<Edge>>,      // reverse edges (for backward propagation)
    pub functions: HashMap<String, FunctionMeta>,   // function_id → params, file, etc.
    pub source_to_function: HashMap<String, String>, // source_id → function_id
    pub entrypoint_to_function: HashMap<String, String>, // entrypoint_id → function_id
}
```

Both `outgoing` and `incoming` are built during graph construction to support both forward and backward BFS without edge reversal at query time.

## Propagation Algorithm

Single BFS implementation parameterized by direction:

```rust
pub struct PropagationConfig {
    pub direction: Direction,  // Forward | Backward
    pub max_depth: u32,
    pub entrypoint_required: bool,
}

pub struct PropagationPath {
    pub source_id: String,
    pub sink_id: String,
    pub entrypoint_id: Option<String>,
    pub steps: Vec<PathStep>,
    pub confidence: Confidence,
    pub has_external_call: bool,
}
```

### Forward Propagation

**Start nodes:** All `Node::Source` that belong to entrypoint functions (if `entrypoint_required`) or all sources.

**BFS queue:** `(current_node_id, path_so_far, depth)`

**Per-step logic:**
1. Look up `outgoing[current_node_id]`
2. For each edge, push `(edge.target, path + edge, depth + 1)` if `depth < max_depth` and target not visited in current path
3. On reaching `Node::Sink` → emit `PropagationPath`, continue exploring siblings
4. On reaching `Call` with `is_external: true` → check if it has a `CallToSink` edge; if so, include it in path and emit

### Backward Propagation

**Start nodes:** All `Node::Sink`

**BFS queue:** Same structure, using `incoming` edges instead of `outgoing`

**Termination:** Reaching `Node::Source` (especially MCP entrypoint params) → emit path

### Confidence Calculation

| Condition | Confidence |
|---|---|
| All call edges are resolved (no external) | `High` |
| One external call in path | `Medium` |
| Two or more external calls, or assignment alias used | `Low` |
| Source tracked through variable alias (not direct) | `Medium` (downgraded from `High`) |

### Deduplication

- Same `(source_id, sink_id)` with identical call chain → keep shortest path
- Same `(source_id, sink_id)` with different call chains → keep all (different routes through the codebase)

## Result Generation

### TaintAnalysisResult

Each `PropagationPath` produces one `TaintAnalysisResult`:

| Field | Source |
|---|---|
| `result_id` | `format!("taint:{}:{}", path.source_id, path.sink_id)` |
| `source_id` | `path.source_id` |
| `source_kind` | Source node's `kind` field |
| `entrypoint_id` | Lookup via `source_to_function` then `entrypoint_to_function` |
| `sink_id` | `path.sink_id` |
| `sink_kind` | Sink node's `category` field |
| `call_chain` | Function names from path steps of kind `CallArg`/`Return`, in order |
| `dataflow_path` | Snipet text from path steps with non-empty snippet |
| `evidence` | Key steps with file:line + snippet |
| `taint_confidence` | `path.confidence` |
| `entrypoint_is_mcp` | Check entrypoint kind (McpTool/McpResource/McpPrompt) |
| `backward_trace_found_root` | True if backward path reaches an entrypoint parameter |

### DataFlowFact

Each path also produces a `Fact::Dataflow(DataFlowFact)` for persistence into the universal facts list:

| Field | Source |
|---|---|
| `base.id` | `format!("dataflow:{}:{}", source_id, sink_id)` |
| `base.file` | Source or sink file |
| `base.line` | First step's line |
| `base.extractor` | `"rust_taint_phase10_11"` |
| `source_id` | `path.source_id` |
| `sink_id` | `path.sink_id` |
| `path` | `path.steps` (all PathStep values) |
| `confidence` | `path.confidence` |

## Pipeline Integration

`lines.rs` change from:

```rust
pub fn run_taint_line(ctx: &StaticScanContext) -> Result<Vec<TaintAnalysisResult>> {
    if !ctx.config.static_.taint.enabled {
        return Ok(Vec::new());
    }
    bail!("taint analysis line is enabled but not implemented...")
}
```

To:

```rust
pub fn run_taint_line(
    ctx: &StaticScanContext,
    facts: &[Fact],
) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)> {
    if !ctx.config.static_.taint.enabled {
        return Ok((Vec::new(), Vec::new()));
    }
    taint::run_taint_analysis(facts, &ctx.config.static_.taint)
}
```

`pipeline.rs` updated to pass `facts` into `run_taint_line` and append DataFlowFact results:

```rust
let (taint_results, dataflow_facts) = lines::run_taint_line(&ctx, &facts)?;
facts.extend(dataflow_facts);
```

## Edge Cases and Error Handling

| Scenario | Behavior |
|---|---|
| No entrypoint facts in scan | Return empty results (not an error) |
| No sink facts in scan | Return empty results |
| Callee resolution fails (external lib) | Mark `is_external`, path continues if sink is on the call itself |
| `max_depth` reached before sink | Path discarded |
| Cycle in call graph (recursion/mutual recursion) | Visited set prevents infinite loop; path recorded up to max_depth |
| Empty facts list | Return empty results |
| Config has `entrypoint_required: false` | All sources considered, not just MCP entrypoint params |
| Source parameter not directly in any call arg | Still tracked through VarToArg/ValToVar chains |
| Multiple files with same function name | Disambiguate via file path in qualified_name |

## Testing Strategy

### Unit Tests (per module)

- **graph.rs**: Node/Edge creation, Graph building from synthetic facts
- **builder.rs**: Each step (1-6) tested with focused fixture facts
- **propagation.rs**: BFS on small hand-crafted graphs, depth limit, cycle handling
- **result.rs**: Path → TaintAnalysisResult mapping correctness

### Integration Tests (per language)

Each language gets a test fixture that exercises:
1. Simple direct: entrypoint param → sink in same function
2. One-hop: entrypoint → helper function → sink
3. Multi-hop: entrypoint → A → B → sink
4. Cross-file: entrypoint in file_a, sink in file_b
5. Assignment alias: param → local var → sink
6. No-entrypoint source (for `entrypoint_required: false`)

### End-to-End Pipeline Tests

Reuse existing `pipeline.rs` tests by enabling taint config and verifying `TaintAnalysisResult` output.

### Fixture Examples

**Python — direct:**
```python
@mcp.tool()
def run_cmd(cmd: str):
    os.system(cmd)  # cmd (source) → os.system (sink) — direct
```

**Python — one-hop:**
```python
@mcp.tool()
def run_cmd(cmd: str):
    execute(cmd)  # passes source to helper

def execute(command):
    os.system(command)  # sink in helper
```

**JS — assignment alias:**
```javascript
server.tool("delete", async (params) => {
    const command = params.path;  // assignment
    exec(command);                 // var → sink
});
```

## File Plan

Files to create:

1. `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/mod.rs`
2. `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/graph.rs`
3. `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/builder.rs`
4. `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/propagation.rs`
5. `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/result.rs`

Files to modify:

6. `rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs` — integrate taint module
7. `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs` — pass facts to taint line
8. `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs` — add `taint` module declaration
9. `rust/docs/REFACTOR_PLAN.md` — update Phase 10/11 status
