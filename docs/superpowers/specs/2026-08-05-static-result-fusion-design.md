# Phase 13: Static Result Fusion — Design Spec

## Overview

Merge four parallel static analysis lines (rule, taint, agent, codeql) into a unified `Vec<FusedFinding>`. Three lines (rule/taint/agent) undergo weighted-evidence fusion with configurable weights, corroboration boosts, and two-stage matching. CodeQL results are internally standardized and transparently passed through without cross-line dedup or corroboration.

## Configuration

Extend `FusionConfig` in `config.rs`:

```rust
pub struct FusionConfig {
    pub enabled: bool,
    pub require_confirmed_by: u32,           // existing
    pub boost_when_multiple_lines_agree: bool, // existing
    pub agent_only_as_advisory: bool,          // existing
    pub line_proximity: u32,                   // new (default 5)
    pub rule_weight: u32,                      // new (default 3)
    pub taint_weight: u32,                     // new (default 2)
    pub agent_weight: u32,                     // new (default 1)
    pub codeql_weight: u32,                    // new (default 4)
}
```

`strategy` field removed. Strategy is always `weighted_evidence`.

Default config (`rust/config/default.toml`):

```toml
[fusion]
enabled = true
require_confirmed_by = 1
boost_when_multiple_lines_agree = true
agent_only_as_advisory = true
line_proximity = 5
rule_weight = 3
taint_weight = 2
agent_weight = 1
codeql_weight = 4
```

## Data Model

### FusedFinding extension

Add `related_codeql_result_ids` field:

```rust
pub struct FusedFinding {
    // ... existing fields unchanged ...
    #[serde(default)]
    pub related_codeql_result_ids: Vec<String>,  // new
}
```

### StaticAnalysisSummary extension

Add `codeql_fused_count`:

```rust
pub struct StaticAnalysisSummary {
    // ... existing fields unchanged ...
    pub codeql_fused_count: usize,  // new — count of codeql-passthrough findings
}
```

## Module Structure

```
static_analysis/fusion/
├── mod.rs              # pub fn run(...) -> Result<Vec<FusedFinding>>
├── matcher.rs          # Two-stage matching
├── scorer.rs           # Weighted confidence scoring
├── merger.rs           # Merge matched groups into FusedFinding
└── codeql_passthrough.rs  # CodeQL standardization + conversion
```

## Data Flow

```
rule ──────────────────┐
taint ─────────────────┤ matcher ── scorer ── merger ──► Vec<FusedFinding>
agent ─────────────────┘                               (three-line fused)

codeql ── codeql_passthrough ───────────────────────► Vec<FusedFinding>
                                                      (codeql standalone)
```

Both vecs are concatenated in the final output. CodeQL findings are appended, not interleaved.

## Matching Algorithm (Two-Stage)

### Stage 1: File + Line Proximity

For each unmatched result pair across rule/taint/agent lines:
- Same file AND |line_a - line_b| ≤ `line_proximity`
- Results are greedily grouped: an incoming result joins the first existing group where it matches at least one member

### Stage 2: File + Category

Stage 1 remainders:
- Same file AND same category string (exact match)
- Same greedy grouping rule

### Conflict resolution

When multiple results of the same line type could join a group: prefer higher confidence; ties break on insertion order (first-come wins).

### Unmatched results

Results still unmatched after both stages each produce a single-line FusedFinding.

## Scoring Algorithm

### Confidence value mapping

| Confidence | Numeric |
|-----------|---------|
| Critical  | 1.0     |
| High      | 0.8     |
| Medium    | 0.6     |
| Low       | 0.4     |
| Info      | 0.2     |

### Weighted average

```
raw = Σ(line_weight × confidence_value) / Σ(line_weights_of_present_lines)
```

Only lines actually present in the match group contribute to the denominator.

### Corroboration boost

When `boost_when_multiple_lines_agree = true` AND ≥2 lines present in the group:
- `raw = min(raw + 0.1, 1.0)`

When `require_confirmed_by` is set, a finding must have ≥ that many lines to be emitted.

### Agent-only downgrade

When `agent_only_as_advisory = true` AND only the agent line is present:
- `raw = min(raw, 0.6)` — capping at Medium

### raw → Confidence

| raw   | Confidence |
|-------|-----------|
| ≥ 0.9 | Critical  |
| ≥ 0.7 | High      |
| ≥ 0.5 | Medium    |
| ≥ 0.3 | Low       |
| < 0.3 | Info      |

### Severity

`max()` of all severities in the match group (worst-case first).

## Merger: Generating FusedFinding

| Field | Source |
|---|---|
| `finding_id` | New UUID v4 |
| `title` | Highest-severity result's title: `rule.matched_text` > `agent.candidate_title` > `"taint: {source} → {sink}"` |
| `category` | Plurality vote within group; ties broken by highest-severity result's category |
| `severity` | max of group (from scorer) |
| `confidence` | From scorer |
| `status` | `"open"` |
| `supported_by` | Line names actually present, e.g. `["rule", "taint"]` |
| `related_rule_result_ids` | `result_id` of each rule result in the group |
| `related_taint_result_ids` | `result_id` of each taint result in the group |
| `related_agent_result_ids` | `result_id` of each agent result in the group |
| `related_codeql_result_ids` | Empty for three-line fusion |
| `evidence` | Union of all lines' `evidence` fields, deduplicated |
| `call_chain` | From taint result if present, else `[]` |
| `dataflow_path` | From taint result if present, else `[]` |
| `recommendation` | From rule result if present, else `agent.reasoning_summary` truncated |
| `conflict_notes` | When severity or category differ within group, e.g. `"severity mismatch: rule=High, agent=Low"` |

## CodeQL Passthrough

Each `CodeqlAnalysisResult` is independently converted to a `FusedFinding`:

| Field | Source |
|---|---|
| `finding_id` | New UUID v4 |
| `title` | `codeql.rule_name` or `codeql.message` |
| `category` | `codeql.rule_id` |
| `severity` | `codeql.severity` (already normalized) |
| `confidence` | Fixed `Medium` (CodeQL is static analysis, not runtime) |
| `status` | `"open"` |
| `supported_by` | `["codeql"]` |
| `related_codeql_result_ids` | `[codeql.result_id]` |
| `evidence` | `[codeql.message.clone()]` |
| `call_chain` | `[]` |
| `dataflow_path` | Flattened `dataflow_path.steps` if `codeql.dataflow_path` is `Some`, else `[]` |
| `recommendation` | `None` |
| `conflict_notes` | `[]` |

No cross-line dedup. No corroboration adjustment. CodeQL findings are appended after three-line fused findings in the final output.

## Integration Point

In `pipeline.rs`, after collecting all four line results, call:

```rust
let fused_findings = fusion::run(
    &config.fusion,
    &rule_results,
    &taint_results,
    &agent_results,
    &codeql_results,
)?;
```

The existing hardcoded `fused_findings: Vec::new()` is replaced.

## Reporting

- `reporting.rs` gains a `include_raw_codeql_results` option
- Fused findings section includes both three-line-fused and codeql-passthrough findings
- `codeql_fused_count` in summary tracks the count of CodeQL-originated fused findings

## Summary count mapping

| Summary field | Value |
|---|---|
| `fused_finding_count` | Three-line fused + CodeQL passthrough combined |
| `codeql_fused_count` | CodeQL passthrough count only |
| `codeql_result_count` | Raw CodeQL result count (unchanged) |

## Testing Strategy

- **matcher**: Unit tests for stage 1 proximity (boundary at `line_proximity`), stage 2 category matching, conflict resolution ordering, unmatched results
- **scorer**: Unit tests for weighted average, corroboration boost, agent-only downgrade, threshold boundaries, `require_confirmed_by` filtering
- **merger**: Unit tests for field composition, conflict_notes generation, evidence dedup
- **codeql_passthrough**: Unit tests for conversion fidelity, empty input
- **integration**: Round-trip test with synthetic four-line results feeding through full fusion pipeline
- Config round-trip: New fusion fields serialize/deserialize correctly
