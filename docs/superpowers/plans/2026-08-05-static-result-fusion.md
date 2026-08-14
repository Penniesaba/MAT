# Phase 13: Static Result Fusion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge four parallel static analysis lines (rule, taint, agent, codeql) into unified `Vec<FusedFinding>` via weighted-evidence fusion with configurable weights, two-stage matching, and CodeQL passthrough.

**Architecture:** Five new files under `static_analysis/fusion/`: `mod.rs` orchestrates, `matcher.rs` performs two-stage greedy grouping, `scorer.rs` computes weighted confidence, `merger.rs` builds FusedFinding from scored groups, `codeql_passthrough.rs` converts CodeQL results to standalone FusedFindings. Config and model types are extended in existing files before fusion module implementation.

**Tech Stack:** Rust 2024 edition, serde, uuid (v4 feature), existing model types

## Global Constraints

- Three-line fusion uses weighted-evidence only (strategy field removed from config)
- CodeQL results are passthrough: no cross-line dedup, no corroboration, appended after three-line findings
- Confidence enum has 3 levels: High=0.8, Medium=0.6, Low=0.4 (no Critical/Info in this model)
- Matching: stage 1 = file + line proximity (≤ `line_proximity`), stage 2 = file + category exact match
- Greedy grouping: each result joins the first existing group where it matches at least one member
- All public types must derive Serialize/Deserialize for JSON round-trip
- After each task: `cargo test -p mcp-sec-audit-core` must pass, `cargo build --workspace` clean

---

### Task 1: Config + Model Foundation

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/config.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/model/static_result.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/fixtures.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/reporting.rs`
- Modify: `rust/config/default.toml`
- Modify: `rust/Cargo.toml`
- Modify: `rust/crates/mcp-sec-audit-core/Cargo.toml`

**Interfaces:**
- Consumes: nothing (foundation task)
- Produces: `FusionConfig` with new fields and without `strategy`; `FusedFinding` with `related_codeql_result_ids`; `StaticAnalysisSummary` with `codeql_fused_count`; `ReportConfig`/render options with `include_raw_codeql_results`; `uuid` dependency available

#### FusionConfig changes

Remove `strategy` field and `default_fusion_strategy()` function. Add five new fields with defaults:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_require_confirmed_by")]
    pub require_confirmed_by: u32,
    #[serde(default = "default_true")]
    pub boost_when_multiple_lines_agree: bool,
    #[serde(default = "default_true")]
    pub agent_only_as_advisory: bool,
    #[serde(default = "default_line_proximity")]
    pub line_proximity: u32,
    #[serde(default = "default_rule_weight")]
    pub rule_weight: u32,
    #[serde(default = "default_taint_weight")]
    pub taint_weight: u32,
    #[serde(default = "default_agent_weight")]
    pub agent_weight: u32,
    #[serde(default = "default_codeql_weight")]
    pub codeql_weight: u32,
}
```

New default functions:

```rust
fn default_line_proximity() -> u32 { 5 }
fn default_rule_weight() -> u32 { 3 }
fn default_taint_weight() -> u32 { 2 }
fn default_agent_weight() -> u32 { 1 }
fn default_codeql_weight() -> u32 { 4 }
```

Update `Default for FusionConfig`:

```rust
impl Default for FusionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_confirmed_by: 1,
            boost_when_multiple_lines_agree: true,
            agent_only_as_advisory: true,
            line_proximity: 5,
            rule_weight: 3,
            taint_weight: 2,
            agent_weight: 1,
            codeql_weight: 4,
        }
    }
}
```

Update existing config test `runtime_config_defaults_are_stable`: remove the `assert_eq!(config.fusion.strategy, "weighted_evidence")` line, add assertions for the five new fields with their defaults.

Add a new test `fusion_config_defaults_are_correct`:

```rust
#[test]
fn fusion_config_defaults_are_correct() {
    let config = FusionConfig::default();
    assert!(config.enabled);
    assert_eq!(config.require_confirmed_by, 1);
    assert!(config.boost_when_multiple_lines_agree);
    assert!(config.agent_only_as_advisory);
    assert_eq!(config.line_proximity, 5);
    assert_eq!(config.rule_weight, 3);
    assert_eq!(config.taint_weight, 2);
    assert_eq!(config.agent_weight, 1);
    assert_eq!(config.codeql_weight, 4);
}
```

Add a test for partial TOML override:

```rust
#[test]
fn fusion_config_parses_new_fields_from_toml() {
    let config: RuntimeConfig = toml::from_str(
        r#"
        [fusion]
        line_proximity = 10
        rule_weight = 5
        "#,
    )
    .expect("parse");
    assert_eq!(config.fusion.line_proximity, 10);
    assert_eq!(config.fusion.rule_weight, 5);
    // defaults preserved
    assert_eq!(config.fusion.taint_weight, 2);
    assert!(config.fusion.enabled);
}
```

#### FusedFinding changes

Add field after `related_agent_result_ids`:

```rust
#[serde(default)]
pub related_codeql_result_ids: Vec<String>,
```

Update `synthetic_static_analysis_result()` in `fixtures.rs`: add `related_codeql_result_ids: Vec::new()` to the synthetic FusedFinding.

#### StaticAnalysisSummary changes

Add field after `codeql_result_count`:

```rust
pub codeql_fused_count: usize,
```

Update all construction sites:

1. `pipeline.rs` `run_static_scan()` summary (line ~81): add `codeql_fused_count: 0,`
2. `pipeline.rs` `empty_result()` summary (line ~180): add `codeql_fused_count: 0,`
3. `fixtures.rs` `synthetic_static_analysis_result()` summary: add `codeql_fused_count: 0,`

#### ReportConfig changes

Add field after `include_raw_agent_results`:

```rust
#[serde(default)]
pub include_raw_codeql_results: bool,
```

Update `Default for ReportConfig`: add `include_raw_codeql_results: false,`.

Update `MarkdownRenderOptions`:

```rust
pub struct MarkdownRenderOptions {
    pub include_fused_results: bool,
    pub include_raw_rule_results: bool,
    pub include_raw_taint_results: bool,
    pub include_raw_agent_results: bool,
    pub include_raw_codeql_results: bool,  // new
    pub include_facts: bool,
}
```

Update `JsonlRenderOptions` similarly:

```rust
pub struct JsonlRenderOptions {
    pub include_fused_results: bool,
    pub include_raw_rule_results: bool,
    pub include_raw_taint_results: bool,
    pub include_raw_agent_results: bool,
    pub include_raw_codeql_results: bool,  // new
    pub include_facts: bool,
}
```

Update both `From<&ReportConfig>` impls to propagate the new field.

Update both `Default` impls: `include_raw_codeql_results: false` for Markdown, `true` for Jsonl.

Add raw codeql results rendering in `render_jsonl`:

```rust
if options.include_raw_codeql_results {
    for codeql_result in &result.codeql_results {
        lines.push(serde_json::to_string(&JsonlRecord {
            event: "codeql_result",
            data: codeql_result,
        })?);
    }
}
```

Add raw codeql results section in `render_markdown` (after agent results section):

```rust
if options.include_raw_codeql_results {
    lines.push(String::new());
    lines.push("## Raw CodeQL Results".to_string());
    for item in &result.codeql_results {
        lines.push(format!(
            "- `{}` at {}:{} — {}",
            item.rule_id,
            item.locations.first().map(|l| l.file.as_str()).unwrap_or("?"),
            item.locations.first().map(|l| l.line).unwrap_or(0),
            item.message
        ));
    }
}
```

Add CodeQL result count to markdown summary (after the Agent Results line):

```rust
format!("- CodeQL Results: {}", result.summary.codeql_result_count),
```

#### Dependency: uuid

Add to workspace `Cargo.toml`:

```toml
uuid = { version = "1", features = ["v4"] }
```

Add to core crate `Cargo.toml`:

```toml
uuid.workspace = true
```

#### Config file update

In `rust/config/default.toml`, replace the `[fusion]` section:

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

(Remove the `strategy` line.)

#### Test expectations for Task 1

All existing tests must pass after updates. The `static_analysis_result_roundtrips_json` and `static_analysis_json_preserves_codeql_results` tests in `static_result.rs` verify the new field serializes correctly (it will appear as `"related_codeql_result_ids": []` in JSON).

The `jsonl_renderer_emits_expected_events` test exists but will need updating in a later task when codeql results are present in the synthetic fixture. For now, `codeql_results` in the synthetic result has 1 entry, so the JSONL line count test assertion will need updating: `assert_eq!(lines.len(), 7)` (was 6, +1 for codeql_result event).

- [ ] **Step 1: Add uuid to workspace and core Cargo.toml**

- [ ] **Step 2: Update FusionConfig** — remove `strategy` field and `default_fusion_strategy()`, add 5 new weight/proximity fields with defaults

- [ ] **Step 3: Update config tests** — fix `runtime_config_defaults_are_stable`, add `fusion_config_defaults_are_correct` and `fusion_config_parses_new_fields_from_toml`

- [ ] **Step 4: Add `related_codeql_result_ids` to FusedFinding**, update fixtures.rs

- [ ] **Step 5: Add `codeql_fused_count` to StaticAnalysisSummary**, update all construction sites (pipeline.rs ×2, fixtures.rs)

- [ ] **Step 6: Add `include_raw_codeql_results` to ReportConfig, MarkdownRenderOptions, JsonlRenderOptions**, update From impls, Default impls, and rendering functions

- [ ] **Step 7: Update default.toml** — new `[fusion]` section without `strategy`

- [ ] **Step 8: Run `cargo test -p mcp-sec-audit-core` and `cargo build --workspace`** — all must pass

- [ ] **Step 9: Commit**

```bash
git add rust/Cargo.toml rust/crates/mcp-sec-audit-core/Cargo.toml \
        rust/crates/mcp-sec-audit-core/src/config.rs \
        rust/crates/mcp-sec-audit-core/src/model/static_result.rs \
        rust/crates/mcp-sec-audit-core/src/fixtures.rs \
        rust/crates/mcp-sec-audit-core/src/reporting.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs \
        rust/config/default.toml
git commit -m "feat(fusion): extend config, model, and reporting for Phase 13"
```

---

### Task 2: Matcher — Two-Stage Greedy Grouping

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/matcher.rs`

**Interfaces:**
- Consumes: `FusionConfig` (for `line_proximity`), `RuleAnalysisResult`, `TaintAnalysisResult`, `AgentAnalysisResult` from model
- Produces: `pub(crate) fn match_results(...) -> Vec<MatchGroup>`

#### Types

```rust
use crate::model::{AgentAnalysisResult, Confidence, RuleAnalysisResult, TaintAnalysisResult};

/// A group of related results from different analysis lines.
#[derive(Debug, Clone)]
pub(crate) struct MatchGroup {
    pub rule_results: Vec<RuleAnalysisResult>,
    pub taint_results: Vec<TaintAnalysisResult>,
    pub agent_results: Vec<AgentAnalysisResult>,
}

impl MatchGroup {
    /// Number of distinct lines present (0–3).
    pub fn line_count(&self) -> u32 {
        let mut count = 0u32;
        if !self.rule_results.is_empty() { count += 1; }
        if !self.taint_results.is_empty() { count += 1; }
        if !self.agent_results.is_empty() { count += 1; }
        count
    }

    /// Line names present, ordered rule/taint/agent.
    pub fn supported_by(&self) -> Vec<&'static str> {
        let mut lines = Vec::new();
        if !self.rule_results.is_empty() { lines.push("rule"); }
        if !self.taint_results.is_empty() { lines.push("taint"); }
        if !self.agent_results.is_empty() { lines.push("agent"); }
        lines
    }
}
```

#### Public function

```rust
pub(crate) fn match_results(
    rule_results: &[RuleAnalysisResult],
    taint_results: &[TaintAnalysisResult],
    agent_results: &[AgentAnalysisResult],
    line_proximity: u32,
) -> Vec<MatchGroup> {
    // Collect all results as Matchable items
    let mut items: Vec<Matchable> = Vec::new();
    for r in rule_results {
        items.push(Matchable {
            file: r.file.clone(),
            line: r.line,
            category: Some(r.category.clone()),
            kind: MatchKind::Rule,
            rule_idx: Some(items.iter().filter(|m| m.kind == MatchKind::Rule).count()),
            taint_idx: None,
            agent_idx: None,
        });
    }
    for t in taint_results {
        items.push(Matchable {
            file: t.sink_id_to_file(),
            line: t.sink_id_to_line(),
            category: Some(t.sink_kind.clone()),
            kind: MatchKind::Taint,
            rule_idx: None,
            taint_idx: Some(items.iter().filter(|m| m.kind == MatchKind::Taint).count()),
            agent_idx: None,
        });
    }
    for a in agent_results {
        // Agent has no file/line directly; derive from affected_locations[0] if present
        let (file, line) = parse_first_location(&a.affected_locations);
        items.push(Matchable {
            file,
            line,
            category: None, // agent has no category field
            kind: MatchKind::Agent,
            rule_idx: None,
            taint_idx: None,
            agent_idx: Some(items.iter().filter(|m| m.kind == MatchKind::Agent).count()),
        });
    }

    let mut groups: Vec<Vec<usize>> = Vec::new(); // each group = Vec of indices into items

    // Stage 1: file + line proximity
    for (i, item) in items.iter().enumerate() {
        if item.file.is_empty() { continue; }
        let mut matched = false;
        for group in groups.iter_mut() {
            if can_join_group_proximity(i, group, &items, line_proximity) {
                group.push(i);
                matched = true;
                break;
            }
        }
        if !matched {
            groups.push(vec![i]);
        }
    }

    // Stage 2: file + category for unmatched items (single-item groups from stage 1)
    let mut stage2_groups: Vec<Vec<usize>> = Vec::new();
    let mut unmatched: Vec<usize> = Vec::new();
    for group in &groups {
        if group.len() == 1 {
            unmatched.push(group[0]);
        } else {
            stage2_groups.push(group.clone());
        }
    }

    for idx in unmatched {
        let item = &items[idx];
        if item.category.is_none() { 
            stage2_groups.push(vec![idx]); // agent without category stays solo
            continue;
        }
        let mut matched = false;
        for group in stage2_groups.iter_mut() {
            if can_join_group_category(idx, group, &items) {
                group.push(idx);
                matched = true;
                break;
            }
        }
        if !matched {
            stage2_groups.push(vec![idx]);
        }
    }

    // Build MatchGroup from grouped indices
    stage2_groups.into_iter().map(|indices| {
        let mut rule_results = Vec::new();
        let mut taint_results = Vec::new();
        let mut agent_results = Vec::new();
        for idx in indices {
            match items[idx].kind {
                MatchKind::Rule => {
                    if let Some(ri) = items[idx].rule_idx {
                        rule_results.push(rule_results[ri].clone()); // won't work, need original refs
                    }
                }
                // ... similar for Taint, Agent
            }
        }
        MatchGroup { rule_results, taint_results, agent_results }
    }).collect()
}
```

**Important design note on TaintAnalysisResult:** `TaintAnalysisResult` has `source_id`, `sink_id`, `call_chain` but no `file` or `line` field directly. For matching, extract file/line from the `dataflow_path` or from associated facts. Since facts aren't available in the matcher, use a heuristic: derive file from `source_id` or `sink_id` format (they contain file paths like `"source:server.py:..."`). Add a helper:

```rust
fn parse_file_from_id(id: &str) -> String {
    // Format: "source:file.py:name" or "sink:file.py:name"
    let parts: Vec<&str> = id.splitn(3, ':').collect();
    if parts.len() >= 2 { parts[1].to_string() } else { String::new() }
}

fn parse_line_from_id(id: &str) -> u32 {
    // Best effort: return 0 if not parseable
    0
}
```

For `AgentAnalysisResult`, parse file and line from `affected_locations[0]` which has format `"server.py:42"`:

```rust
fn parse_first_location(locations: &[String]) -> (String, u32) {
    if let Some(first) = locations.first() {
        if let Some((file, line_str)) = first.rsplit_once(':') {
            return (file.to_string(), line_str.parse::<u32>().unwrap_or(0));
        }
        return (first.clone(), 0);
    }
    (String::new(), 0)
}
```

**Correction:** The matcher needs access to the original result vectors. Rather than cloning indices that refer back to the originals, pass owned vectors and drain them into groups. Redesign:

```rust
pub(crate) fn match_results(
    rule_results: Vec<RuleAnalysisResult>,
    taint_results: Vec<TaintAnalysisResult>,
    agent_results: Vec<AgentAnalysisResult>,
    line_proximity: u32,
) -> Vec<MatchGroup> {
    // Build flat matchable items referencing original vecs by index
    let rule_items: Vec<Matchable> = rule_results.iter().enumerate().map(|(i, r)| {
        Matchable { file: r.file.clone(), line: r.line, category: Some(r.category.clone()), 
                    kind: MatchKind::Rule, index: i }
    }).collect();
    
    let taint_items: Vec<Matchable> = taint_results.iter().enumerate().map(|(i, t)| {
        Matchable { file: file_from_taint(t), line: 0, category: Some(t.sink_kind.clone()),
                    kind: MatchKind::Taint, index: i }
    }).collect();
    
    let agent_items: Vec<Matchable> = agent_results.iter().enumerate().map(|(i, a)| {
        let (file, line) = parse_first_location(&a.affected_locations);
        Matchable { file, line, category: None, kind: MatchKind::Agent, index: i }
    }).collect();
    
    // Run two-stage matching on the flat list, track which original index each item came from
    // Then build MatchGroup by collecting original results from the grouped indices
    // ...
}
```

#### Proximity check helper

```rust
fn can_join_group_proximity(
    candidate: &Matchable,
    group: &[Matchable],
    line_proximity: u32,
) -> bool {
    group.iter().any(|member| {
        member.file == candidate.file
            && (member.line as i64 - candidate.line as i64).unsigned_abs() <= line_proximity as u64
    })
}
```

#### Category check helper

```rust
fn can_join_group_category(
    candidate: &Matchable,
    group: &[Matchable],
) -> bool {
    candidate.category.is_some()
        && group.iter().any(|member| {
            member.file == candidate.file
                && member.category == candidate.category
        })
}
```

#### Confidence ordering for conflict resolution

When an item could join multiple groups, join the first one (greedy). The spec says "prefer higher confidence; ties break on insertion order." Since we iterate in insertion order and use first-match, the implementation naturally respects this when items are pre-sorted by confidence. Pre-sort within each type before matching:

```rust
// Sort by confidence descending before matching
rule_items.sort_by(|a, b| confidence_cmp(&b.confidence_val, &a.confidence_val));
// ... similarly for taint, agent items
```

Where `confidence_cmp` converts Confidence to a numeric value for ordering (same mapping as scorer).

#### Tests

Unit tests in `matcher.rs` `#[cfg(test)] mod tests`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Severity};

    fn make_rule(id: &str, file: &str, line: u32, category: &str, confidence: Confidence) -> RuleAnalysisResult {
        RuleAnalysisResult {
            result_id: id.to_string(),
            rule_id: "test_rule".to_string(),
            category: category.to_string(),
            owasp_mcp: None,
            file: file.to_string(),
            line,
            matched_text: None,
            evidence: vec![],
            severity: Severity::Medium,
            confidence,
            recommendation: None,
            related_facts_exist: false,
        }
    }

    fn make_taint(id: &str, sink_id: &str, sink_kind: &str, confidence: Confidence) -> TaintAnalysisResult {
        TaintAnalysisResult {
            result_id: id.to_string(),
            source_id: "source:test.py:param".to_string(),
            source_kind: "mcp_tool_param".to_string(),
            entrypoint_id: None,
            sink_id: sink_id.to_string(),
            sink_kind: sink_kind.to_string(),
            call_chain: vec![],
            dataflow_path: vec![],
            evidence: vec![],
            taint_confidence: confidence,
            entrypoint_is_mcp: false,
            backward_trace_found_root: false,
        }
    }

    fn make_agent(id: &str, file: &str, line: u32, confidence: Confidence) -> AgentAnalysisResult {
        AgentAnalysisResult {
            result_id: id.to_string(),
            agent_id: "test_agent".to_string(),
            prompt_profile: "test".to_string(),
            model_provider: None,
            input_scope: vec![],
            candidate_title: "Test finding".to_string(),
            affected_locations: vec![format!("{}:{}", file, line)],
            reasoning_summary: String::new(),
            evidence_snippets: vec![],
            related_rule_result_ids: vec![],
            related_taint_result_ids: vec![],
            confidence,
            verification_status: "uncorroborated".to_string(),
            limitations: vec![],
        }
    }

    #[test]
    fn stage1_proximity_matches_same_file_nearby_lines() {
        let rules = vec![make_rule("r1", "a.py", 42, "cmd_inj", Confidence::High)];
        let taints = vec![make_taint("t1", "sink:a.py:x", "command_exec", Confidence::Medium)];
        let agents = vec![];
        let groups = match_results(rules, taints, agents, 5);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].line_count(), 2);
    }

    #[test]
    fn stage1_proximity_excludes_far_lines() {
        let rules = vec![make_rule("r1", "a.py", 10, "cmd_inj", Confidence::High)];
        let taints = vec![make_taint("t1", "sink:a.py:x", "command_exec", Confidence::Medium)];
        let agents = vec![];
        let groups = match_results(rules, taints, agents, 5);
        // taint line is 0 by default (can't parse), proximity |10-0|=10 > 5
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn stage2_category_matches_same_file_same_category() {
        let rules = vec![make_rule("r1", "a.py", 10, "cmd_inj", Confidence::High)];
        let taints = vec![make_taint("t1", "sink:a.py:x", "cmd_inj", Confidence::Medium)];
        let agents = vec![];
        // line proximity fails but category should match in stage 2
        let groups = match_results(rules, taints, agents, 1);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].line_count(), 2);
    }

    #[test]
    fn unmatched_results_become_solo_groups() {
        let rules = vec![make_rule("r1", "a.py", 10, "cmd_inj", Confidence::High)];
        let taints = vec![make_taint("t1", "sink:b.py:x", "file_read", Confidence::Medium)];
        let agents = vec![];
        let groups = match_results(rules, taints, agents, 5);
        // Different files, different categories — both solo
        assert_eq!(groups.len(), 2);
        for g in &groups { assert_eq!(g.line_count(), 1); }
    }

    #[test]
    fn empty_inputs_produce_empty_groups() {
        let groups = match_results(vec![], vec![], vec![], 5);
        assert!(groups.is_empty());
    }

    #[test]
    fn confidence_ordering_prefers_higher_confidence_in_conflict() {
        // Two rules on same line — only one should join the group
        let rules = vec![
            make_rule("r1", "a.py", 42, "cmd_inj", Confidence::Low),
            make_rule("r2", "a.py", 42, "cmd_inj", Confidence::High),
        ];
        let taints = vec![make_taint("t1", "sink:a.py:x", "command_exec", Confidence::Medium)];
        let agents = vec![];
        let groups = match_results(rules, taints, agents, 5);
        // All should be in one group (same file, proximity match)
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rule_results.len(), 2);
        assert_eq!(groups[0].taint_results.len(), 1);
    }
}
```

- [ ] **Step 1: Create `fusion/matcher.rs`** with `MatchGroup`, `Matchable`, and `match_results()` implementation

- [ ] **Step 2: Write the 6 tests above** in the same file

- [ ] **Step 3: Run `cargo test -p mcp-sec-audit-core`** — verify matcher tests pass

- [ ] **Step 4: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/
git commit -m "feat(fusion): add matcher with two-stage greedy grouping"
```

---

### Task 3: Scorer — Weighted Confidence Scoring

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/scorer.rs`

**Interfaces:**
- Consumes: `FusionConfig`, `MatchGroup` (from matcher)
- Produces: `pub(crate) fn score_groups(...) -> Vec<ScoredGroup>`

#### Types

```rust
use crate::model::{Confidence, Severity};
use super::matcher::MatchGroup;

#[derive(Debug, Clone)]
pub(crate) struct ScoredGroup {
    pub group: MatchGroup,
    pub severity: Severity,
    pub confidence: Confidence,
    pub raw_score: f64,
}
```

#### Confidence helpers

```rust
/// Convert Confidence to numeric value for scoring.
fn confidence_value(c: &Confidence) -> f64 {
    match c {
        Confidence::High => 0.8,
        Confidence::Medium => 0.6,
        Confidence::Low => 0.4,
    }
}

/// Convert numeric raw score back to Confidence.
fn raw_to_confidence(raw: f64) -> Confidence {
    if raw >= 0.7 {
        Confidence::High
    } else if raw >= 0.5 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

/// Convert Confidence to numeric for ordering (same mapping, used in matcher).
pub(crate) fn confidence_ord(c: &Confidence) -> u8 {
    match c {
        Confidence::High => 3,
        Confidence::Medium => 2,
        Confidence::Low => 1,
    }
}
```

#### Severity helpers

```rust
/// Ordering value for severity comparison.
pub(crate) fn severity_ord(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}
```

#### Main scoring function

```rust
pub(crate) fn score_groups(
    groups: Vec<MatchGroup>,
    config: &crate::config::FusionConfig,
) -> Vec<ScoredGroup> {
    groups.into_iter().filter_map(|group| {
        if group.line_count() < config.require_confirmed_by {
            return None; // filtered out
        }

        // Collect all confidences in the group for weighted average
        let mut weighted_sum = 0.0f64;
        let mut weight_sum = 0u32;

        for r in &group.rule_results {
            weighted_sum += config.rule_weight as f64 * confidence_value(&r.confidence);
            weight_sum += config.rule_weight;
        }
        for t in &group.taint_results {
            weighted_sum += config.taint_weight as f64 * confidence_value(&t.taint_confidence);
            weight_sum += config.taint_weight;
        }
        for a in &group.agent_results {
            weighted_sum += config.agent_weight as f64 * confidence_value(&a.confidence);
            weight_sum += config.agent_weight;
        }

        let mut raw = if weight_sum > 0 {
            weighted_sum / weight_sum as f64
        } else {
            0.0
        };

        // Corroboration boost
        if config.boost_when_multiple_lines_agree && group.line_count() >= 2 {
            raw = (raw + 0.1).min(1.0);
        }

        // Agent-only downgrade
        if config.agent_only_as_advisory 
            && group.line_count() == 1 
            && !group.agent_results.is_empty() 
        {
            raw = raw.min(0.6);
        }

        // Compute max severity
        let severity = group_max_severity(&group);

        Some(ScoredGroup {
            group,
            severity,
            confidence: raw_to_confidence(raw),
            raw_score: raw,
        })
    }).collect()
}

fn group_max_severity(group: &MatchGroup) -> Severity {
    let mut max_sev = Severity::Low;
    for r in &group.rule_results {
        if severity_ord(&r.severity) > severity_ord(&max_sev) {
            max_sev = r.severity.clone();
        }
    }
    for t in &group.taint_results {
        // TaintAnalysisResult has taint_confidence but no severity field.
        // Map taint_confidence to severity as a heuristic.
        let taint_sev = taint_confidence_to_severity(&t.taint_confidence);
        if severity_ord(&taint_sev) > severity_ord(&max_sev) {
            max_sev = taint_sev;
        }
    }
    for a in &group.agent_results {
        // Agent has confidence but no severity. Map similarly.
        let agent_sev = confidence_to_severity(&a.confidence);
        if severity_ord(&agent_sev) > severity_ord(&max_sev) {
            max_sev = agent_sev;
        }
    }
    max_sev
}

fn taint_confidence_to_severity(c: &Confidence) -> Severity {
    match c {
        Confidence::High => Severity::High,
        Confidence::Medium => Severity::Medium,
        Confidence::Low => Severity::Low,
    }
}

fn confidence_to_severity(c: &Confidence) -> Severity {
    match c {
        Confidence::High => Severity::High,
        Confidence::Medium => Severity::Medium,
        Confidence::Low => Severity::Low,
    }
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::matcher::MatchGroup;
    use crate::config::FusionConfig;
    use crate::model::{Confidence, Severity, RuleAnalysisResult, TaintAnalysisResult, AgentAnalysisResult};

    fn make_rule(confidence: Confidence) -> RuleAnalysisResult {
        RuleAnalysisResult {
            result_id: "r1".into(), rule_id: "test".into(), category: "cmd".into(),
            owasp_mcp: None, file: "a.py".into(), line: 1, matched_text: None,
            evidence: vec![], severity: Severity::High, confidence,
            recommendation: None, related_facts_exist: false,
        }
    }

    fn make_taint(confidence: Confidence) -> TaintAnalysisResult {
        TaintAnalysisResult {
            result_id: "t1".into(), source_id: "s:x".into(), source_kind: "p".into(),
            entrypoint_id: None, sink_id: "sink:x".into(), sink_kind: "cmd".into(),
            call_chain: vec![], dataflow_path: vec![], evidence: vec![],
            taint_confidence: confidence, entrypoint_is_mcp: false, backward_trace_found_root: false,
        }
    }

    fn make_agent(confidence: Confidence) -> AgentAnalysisResult {
        AgentAnalysisResult {
            result_id: "a1".into(), agent_id: "ag".into(), prompt_profile: "t".into(),
            model_provider: None, input_scope: vec![], candidate_title: "t".into(),
            affected_locations: vec!["a.py:1".into()], reasoning_summary: "".into(),
            evidence_snippets: vec![], related_rule_result_ids: vec![],
            related_taint_result_ids: vec![], confidence,
            verification_status: "u".into(), limitations: vec![],
        }
    }

    #[test]
    fn weighted_average_rule_plus_taint() {
        let group = MatchGroup {
            rule_results: vec![make_rule(Confidence::High)],
            taint_results: vec![make_taint(Confidence::Medium)],
            agent_results: vec![],
        };
        let config = FusionConfig::default();
        let scored = score_groups(vec![group], &config);
        assert_eq!(scored.len(), 1);
        // (3*0.8 + 2*0.6) / (3+2) = (2.4 + 1.2) / 5 = 0.72
        // boost +0.1 → 0.82 → High (≥0.7)
        assert_eq!(scored[0].confidence, Confidence::High);
        assert!(scored[0].raw_score > 0.8);
    }

    #[test]
    fn agent_only_capped_to_medium() {
        let group = MatchGroup {
            rule_results: vec![],
            taint_results: vec![],
            agent_results: vec![make_agent(Confidence::High)],
        };
        let config = FusionConfig::default();
        let scored = score_groups(vec![group], &config);
        assert_eq!(scored.len(), 1);
        // 1*0.8/1 = 0.8, cap at 0.6 → Medium (≥0.5)
        assert_eq!(scored[0].confidence, Confidence::Medium);
    }

    #[test]
    fn require_confirmed_by_filters_solo() {
        let group = MatchGroup {
            rule_results: vec![make_rule(Confidence::High)],
            taint_results: vec![],
            agent_results: vec![],
        };
        let mut config = FusionConfig::default();
        config.require_confirmed_by = 2;
        let scored = score_groups(vec![group], &config);
        assert!(scored.is_empty());
    }

    #[test]
    fn empty_input() {
        let scored = score_groups(vec![], &FusionConfig::default());
        assert!(scored.is_empty());
    }

    #[test]
    fn severity_is_max_of_group() {
        let group = MatchGroup {
            rule_results: vec![{
                let mut r = make_rule(Confidence::High);
                r.severity = Severity::Critical;
                r
            }],
            taint_results: vec![make_taint(Confidence::Low)],
            agent_results: vec![],
        };
        let scored = score_groups(vec![group], &FusionConfig::default());
        assert_eq!(scored[0].severity, Severity::Critical);
    }
}
```

- [ ] **Step 1: Create `fusion/scorer.rs`** with `ScoredGroup`, confidence/severity helpers, and `score_groups()` 

- [ ] **Step 2: Write the 5 tests above**

- [ ] **Step 3: Run `cargo test -p mcp-sec-audit-core`** — verify scorer tests pass

- [ ] **Step 4: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/scorer.rs
git commit -m "feat(fusion): add scorer with weighted confidence scoring"
```

---

### Task 4: Merger + CodeQL Passthrough

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/merger.rs`
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/codeql_passthrough.rs`

**Interfaces:**
- Consumes: `ScoredGroup` (from scorer), `CodeqlAnalysisResult` (from model)
- Produces: `pub(crate) fn merge_groups(...) -> Vec<FusedFinding>`, `pub(crate) fn passthrough_codeql(...) -> Vec<FusedFinding>`

#### merger.rs

```rust
use uuid::Uuid;
use crate::model::{Confidence, FindingStatus, FusedFinding, Severity};
use super::scorer::ScoredGroup;

pub(crate) fn merge_groups(scored_groups: Vec<ScoredGroup>) -> Vec<FusedFinding> {
    scored_groups.into_iter().map(|sg| {
        let group = sg.group;

        // Title: highest-severity result's best description
        let title = build_title(&group);

        // Category: plurality vote, tie-broken by highest severity
        let category = build_category(&group);

        // Evidence: union of all evidence fields, deduplicated
        let evidence = build_evidence(&group);

        // Conflict notes
        let conflict_notes = build_conflict_notes(&group);

        // Call chain and dataflow path from taint
        let (call_chain, dataflow_path) = extract_taint_paths(&group);

        // Recommendation
        let recommendation = extract_recommendation(&group);

        FusedFinding {
            finding_id: Uuid::new_v4().to_string(),
            title,
            category,
            owasp_mcp: None,
            severity: sg.severity,
            confidence: sg.confidence,
            status: FindingStatus::Potential,
            supported_by: group.supported_by().iter().map(|s| s.to_string()).collect(),
            related_rule_result_ids: group.rule_results.iter().map(|r| r.result_id.clone()).collect(),
            related_taint_result_ids: group.taint_results.iter().map(|t| t.result_id.clone()).collect(),
            related_agent_result_ids: group.agent_results.iter().map(|a| a.result_id.clone()).collect(),
            related_codeql_result_ids: Vec::new(),
            evidence,
            call_chain,
            dataflow_path,
            recommendation,
            conflict_notes,
        }
    }).collect()
}

fn build_title(group: &super::matcher::MatchGroup) -> String {
    // Prefer rule's matched_text, then agent's candidate_title, then taint description
    if let Some(rule) = group.rule_results.first() {
        if let Some(ref text) = rule.matched_text {
            return text.clone();
        }
    }
    if let Some(agent) = group.agent_results.first() {
        return agent.candidate_title.clone();
    }
    if let Some(taint) = group.taint_results.first() {
        return format!("taint: {} → {}", taint.source_kind, taint.sink_kind);
    }
    "Unknown finding".to_string()
}

fn build_category(group: &super::matcher::MatchGroup) -> String {
    // Collect categories from rule and taint results (agent has no category).
    // Plurality vote; tie breaks by highest-severity result.
    use std::collections::HashMap;
    let mut counts: HashMap<&str, u32> = HashMap::new();
    for r in &group.rule_results {
        *counts.entry(&r.category).or_insert(0) += 1;
    }
    for t in &group.taint_results {
        *counts.entry(&t.sink_kind).or_insert(0) += 1;
    }
    counts.into_iter()
        .max_by_key(|(cat, count)| (*count, cat.len())) // tie-break arbitrarily stable
        .map(|(cat, _)| cat.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn build_evidence(group: &super::matcher::MatchGroup) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut evidence = Vec::new();
    for r in &group.rule_results {
        for e in &r.evidence {
            if seen.insert(e.clone()) {
                evidence.push(e.clone());
            }
        }
    }
    for t in &group.taint_results {
        for e in &t.evidence {
            if seen.insert(e.clone()) {
                evidence.push(e.clone());
            }
        }
    }
    for a in &group.agent_results {
        for e in &a.evidence_snippets {
            if seen.insert(e.clone()) {
                evidence.push(e.clone());
            }
        }
    }
    evidence
}

fn extract_taint_paths(group: &super::matcher::MatchGroup) -> (Vec<String>, Vec<String>) {
    if let Some(taint) = group.taint_results.first() {
        (taint.call_chain.clone(), taint.dataflow_path.clone())
    } else {
        (Vec::new(), Vec::new())
    }
}

fn extract_recommendation(group: &super::matcher::MatchGroup) -> Option<String> {
    if let Some(rule) = group.rule_results.first() {
        return rule.recommendation.clone();
    }
    if let Some(agent) = group.agent_results.first() {
        if agent.reasoning_summary.len() > 200 {
            return Some(format!("{}…", &agent.reasoning_summary[..200]));
        }
        return Some(agent.reasoning_summary.clone());
    }
    None
}

fn build_conflict_notes(group: &super::matcher::MatchGroup) -> Vec<String> {
    let mut notes = Vec::new();
    
    // Check severity conflicts
    let mut severities: Vec<(&str, &Severity)> = Vec::new();
    for r in &group.rule_results {
        severities.push(("rule", &r.severity));
    }
    // Taint has no severity field; skip for conflict detection
    // Agent has no severity field; skip
    
    if severities.len() > 1 {
        let first = severities[0];
        if severities.iter().any(|(_, s)| s != &first.1) {
            let parts: Vec<String> = severities.iter()
                .map(|(line, s)| format!("{line}={s:?}"))
                .collect();
            notes.push(format!("severity mismatch: {}", parts.join(", ")));
        }
    }

    // Check category conflicts
    let mut categories: Vec<&str> = Vec::new();
    for r in &group.rule_results {
        categories.push(&r.category);
    }
    for t in &group.taint_results {
        categories.push(&t.sink_kind);
    }
    if categories.len() > 1 {
        let first = categories[0];
        if categories.iter().any(|c| c != &first) {
            let parts: Vec<String> = categories.iter().map(|c| c.to_string()).collect();
            notes.push(format!("category mismatch: {}", parts.join(", ")));
        }
    }

    notes
}
```

#### codeql_passthrough.rs

```rust
use uuid::Uuid;
use crate::model::{CodeqlAnalysisResult, Confidence, FindingStatus, FusedFinding, Severity};

pub(crate) fn passthrough_codeql(results: Vec<CodeqlAnalysisResult>) -> Vec<FusedFinding> {
    results.into_iter().map(|c| {
        let dataflow_path: Vec<String> = c.dataflow_path
            .as_ref()
            .map(|dfp| dfp.steps.iter()
                .map(|step| format!("{}:{}", step.location.file, step.location.line))
                .collect())
            .unwrap_or_default();

        FusedFinding {
            finding_id: Uuid::new_v4().to_string(),
            title: if c.rule_name.is_empty() { c.message.clone() } else { c.rule_name.clone() },
            category: c.rule_id.clone(),
            severity: c.severity.clone(),
            confidence: Confidence::Medium,
            status: FindingStatus::Potential,
            supported_by: vec!["codeql".to_string()],
            related_rule_result_ids: Vec::new(),
            related_taint_result_ids: Vec::new(),
            related_agent_result_ids: Vec::new(),
            related_codeql_result_ids: vec![c.result_id.clone()],
            evidence: vec![c.message.clone()],
            call_chain: Vec::new(),
            dataflow_path,
            recommendation: None,
            conflict_notes: Vec::new(),
        }
    }).collect()
}
```

#### Tests for merger.rs

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::matcher::MatchGroup;
    use super::super::scorer::ScoredGroup;
    use crate::model::{Confidence, Severity, RuleAnalysisResult, AgentAnalysisResult};

    #[test]
    fn merge_single_rule_produces_fused_finding() {
        let group = MatchGroup {
            rule_results: vec![RuleAnalysisResult {
                result_id: "r1".into(), rule_id: "cmd_exec".into(),
                category: "command_execution".into(), owasp_mcp: None,
                file: "a.py".into(), line: 42, matched_text: Some("subprocess.run(x)".into()),
                evidence: vec!["line 42: subprocess.run(x)".into()],
                severity: Severity::High, confidence: Confidence::High,
                recommendation: Some("Use allowlist".into()), related_facts_exist: true,
            }],
            taint_results: vec![],
            agent_results: vec![],
        };
        let scored = ScoredGroup { group, severity: Severity::High, confidence: Confidence::High, raw_score: 0.8 };
        let findings = merge_groups(vec![scored]);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.title, "subprocess.run(x)");
        assert_eq!(f.category, "command_execution");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::High);
        assert_eq!(f.supported_by, vec!["rule"]);
        assert_eq!(f.related_rule_result_ids, vec!["r1"]);
        assert!(f.related_codeql_result_ids.is_empty());
        assert_eq!(f.recommendation, Some("Use allowlist".into()));
    }

    #[test]
    fn evidence_is_deduplicated() {
        let group = MatchGroup {
            rule_results: vec![RuleAnalysisResult {
                result_id: "r1".into(), rule_id: "x".into(), category: "x".into(),
                owasp_mcp: None, file: "a.py".into(), line: 1, matched_text: None,
                evidence: vec!["dup".into(), "unique".into()],
                severity: Severity::Medium, confidence: Confidence::Medium,
                recommendation: None, related_facts_exist: false,
            }],
            taint_results: vec![],
            agent_results: vec![AgentAnalysisResult {
                result_id: "a1".into(), agent_id: "ag".into(), prompt_profile: "t".into(),
                model_provider: None, input_scope: vec![], candidate_title: "t".into(),
                affected_locations: vec![], reasoning_summary: "".into(),
                evidence_snippets: vec!["dup".into()],
                related_rule_result_ids: vec![], related_taint_result_ids: vec![],
                confidence: Confidence::Medium, verification_status: "u".into(), limitations: vec![],
            }],
        };
        let scored = ScoredGroup { group, severity: Severity::Medium, confidence: Confidence::Medium, raw_score: 0.6 };
        let findings = merge_groups(vec![scored]);
        assert_eq!(findings[0].evidence.len(), 2); // "dup" appears once, "unique" once
    }

    #[test]
    fn empty_input() {
        let findings = merge_groups(vec![]);
        assert!(findings.is_empty());
    }
}
```

#### Tests for codeql_passthrough.rs

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Location;

    #[test]
    fn converts_codeql_result_to_fused_finding() {
        let cr = CodeqlAnalysisResult {
            result_id: "ql:1".into(),
            rule_id: "py/cmd-injection".into(),
            rule_name: "Command Injection".into(),
            message: "User input reaches shell".into(),
            severity: Severity::High,
            locations: vec![Location { file: "a.py".into(), line: 42, column: None, message: None }],
            dataflow_path: None,
            sarif_snippet: None,
            related_rule_ids: vec![],
            related_taint_ids: vec![],
            related_agent_ids: vec![],
            verification_status: "uncorroborated".into(),
            limitations: vec![],
        };
        let findings = passthrough_codeql(vec![cr]);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.title, "Command Injection");
        assert_eq!(f.category, "py/cmd-injection");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Medium);
        assert_eq!(f.supported_by, vec!["codeql"]);
        assert_eq!(f.related_codeql_result_ids, vec!["ql:1"]);
    }

    #[test]
    fn empty_codeql_results() {
        let findings = passthrough_codeql(vec![]);
        assert!(findings.is_empty());
    }
}
```

- [ ] **Step 1: Create `fusion/merger.rs`** with `merge_groups()` and all helpers

- [ ] **Step 2: Create `fusion/codeql_passthrough.rs`** with `passthrough_codeql()`

- [ ] **Step 3: Write all tests** (3 in merger, 2 in codeql_passthrough)

- [ ] **Step 4: Run `cargo test -p mcp-sec-audit-core`** — all 10 new tests pass

- [ ] **Step 5: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/merger.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/codeql_passthrough.rs
git commit -m "feat(fusion): add merger and codeql passthrough"
```

---

### Task 5: mod.rs + Pipeline Integration

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/mod.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`

**Interfaces:**
- Consumes: matcher, scorer, merger, codeql_passthrough submodules; pipeline.rs `StaticScanContext`
- Produces: `pub(crate) fn run(...) -> Vec<FusedFinding>`; pipeline integration

#### fusion/mod.rs

```rust
mod matcher;
mod scorer;
mod merger;
mod codeql_passthrough;

use crate::config::FusionConfig;
use crate::model::{AgentAnalysisResult, CodeqlAnalysisResult, FusedFinding, RuleAnalysisResult, TaintAnalysisResult};

pub(crate) fn run(
    config: &FusionConfig,
    rule_results: Vec<RuleAnalysisResult>,
    taint_results: Vec<TaintAnalysisResult>,
    agent_results: Vec<AgentAnalysisResult>,
    codeql_results: Vec<CodeqlAnalysisResult>,
) -> Vec<FusedFinding> {
    if !config.enabled {
        return Vec::new();
    }

    // Three-line fusion
    let match_groups = matcher::match_results(
        rule_results,
        taint_results,
        agent_results,
        config.line_proximity,
    );

    let scored_groups = scorer::score_groups(match_groups, config);

    let mut fused = merger::merge_groups(scored_groups);

    // CodeQL passthrough (always appended, not interleaved)
    let codeql_fused = codeql_passthrough::passthrough_codeql(codeql_results);
    fused.extend(codeql_fused);

    fused
}
```

#### static_analysis/mod.rs update

Add `pub(crate) mod fusion;` after `mod discovery;`:

```rust
pub mod facts;

mod agent;
mod codeql;
mod discovery;
mod fusion;       // <-- new
mod pipeline;
mod rule;
mod taint;
```

#### pipeline.rs integration

Update imports (add `fusion`):

```rust
use super::{agent, codeql, fusion, rule, taint, DiscoveredFile, discover_files};
```

After codeql line (after line 79), add fusion call:

```rust
let codeql_output = codeql::run(&ctx)?;

// Phase 13: Fusion
let fused_findings = fusion::run(
    &ctx.config.fusion,
    rule_results.clone(),
    taint_results.clone(),
    agent_results.clone(),
    codeql_output.results.clone(),
);
```

Update summary construction to use real fused counts:

```rust
let codeql_fused_count = fused_findings.iter()
    .filter(|f| f.supported_by.contains(&"codeql".to_string()))
    .count();

let summary = StaticAnalysisSummary {
    target: target_label(&targets),
    fact_count: all_facts.len(),
    rule_result_count: rule_results.len(),
    taint_result_count: taint_results.len(),
    agent_result_count: agent_results.len(),
    codeql_result_count: codeql_output.results.len(),
    fused_finding_count: fused_findings.len(),
    codeql_fused_count,
    highest_severity: fused_findings.iter()
        .map(|f| f.severity.clone())
        .max_by(|a, b| scorer_ord(a).cmp(&scorer_ord(b))),
    risk_level: compute_risk_level(&fused_findings),
};
```

Replace `fused_findings: Vec::new()` with `fused_findings`.

Add helper for `compute_risk_level`:

```rust
fn compute_risk_level(findings: &[FusedFinding]) -> String {
    use crate::model::Severity;
    let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
    let has_high = findings.iter().any(|f| f.severity == Severity::High);
    let has_medium = findings.iter().any(|f| f.severity == Severity::Medium);
    if has_critical { return "critical".into(); }
    if has_high { return "high".into(); }
    if has_medium { return "medium".into(); }
    if findings.is_empty() { "none".into() } else { "low".into() }
}

fn scorer_ord(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}
```

#### Pipeline test updates

Update `enabled_static_scan_includes_codeql_result_count` (line ~497): fusion is now enabled by default, so `fused_finding_count` will include the rule result (fused with taint/agent findings if they match by proximity). Since rule finds `subprocess.run` and taint also traces to it, they may fuse. Verify that `fused_finding_count > 0`.

Update the two other enabled scan tests similarly.

The `static_analysis_result_roundtrips_json` test in `static_result.rs` must still pass — the synthetic result now has `related_codeql_result_ids: []`.

#### Test added to pipeline

```rust
#[test]
fn fusion_produces_findings_when_enabled() {
    let root = temp_dir("fusion-test");
    let rules = write_rulebook(&root, "rules.toml", "command_exec");
    fs::write(
        root.join("server.py"),
        "import subprocess\nsubprocess.run('id')\n",
    ).expect("write file");

    let mut config = RuntimeConfig::default();
    config.static_.taint.enabled = true;
    config.fusion.enabled = true;
    let result = run_static_scan(&config, &[rules], Some(&[root.clone()]))
        .expect("run scan");
    
    assert!(result.summary.fused_finding_count > 0);
    assert!(!result.fused_findings.is_empty());
    // Rule line found subprocess.run → at least one fused finding
    let has_rule_support = result.fused_findings.iter()
        .any(|f| f.supported_by.contains(&"rule".to_string()));
    assert!(has_rule_support);

    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn fusion_disabled_returns_empty_findings() {
    let root = temp_dir("fusion-off");
    let rules = write_rulebook(&root, "rules.toml", "command_exec");
    fs::write(
        root.join("server.py"),
        "import subprocess\nsubprocess.run('id')\n",
    ).expect("write file");

    let mut config = RuntimeConfig::default();
    config.static_.taint.enabled = true;
    config.fusion.enabled = false;
    let result = run_static_scan(&config, &[rules], Some(&[root.clone()]))
        .expect("run scan");
    
    assert_eq!(result.summary.fused_finding_count, 0);
    assert!(result.fused_findings.is_empty());

    fs::remove_dir_all(root).expect("cleanup");
}
```

- [ ] **Step 1: Create `fusion/mod.rs`** with the `run()` orchestrator

- [ ] **Step 2: Update `static_analysis/mod.rs`** — add `mod fusion;`

- [ ] **Step 3: Update `pipeline.rs`** — integrate fusion call, compute risk level, update summary

- [ ] **Step 4: Write integration tests** — `fusion_produces_findings_when_enabled`, `fusion_disabled_returns_empty_findings`

- [ ] **Step 5: Run `cargo test -p mcp-sec-audit-core` and `cargo build --workspace`** — all must pass

- [ ] **Step 6: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/mod.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs
git commit -m "feat(fusion): integrate fusion into static analysis pipeline"
```

---

### Task 6: Final Polish — Reporting, Fixtures, REFACTOR_PLAN

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/reporting.rs` — ensure codeql sections render
- Modify: `rust/crates/mcp-sec-audit-core/src/reporting.rs` — update JSONL test line count
- Modify: `rust/crates/mcp-sec-audit-core/src/fixtures.rs` — update synthetic result `fused_finding_count` for accuracy
- Modify: `rust/docs/REFACTOR_PLAN.md` — mark Phase 13 complete

**Interfaces:**
- Consumes: everything from Tasks 1–5
- Produces: accurate synthetic fixtures, updated documentation

#### reporting.rs updates

Update `render_markdown` to include `codeql_result_count` in summary:

```rust
format!("- CodeQL Results: {}", result.summary.codeql_result_count),
```

Add after the Agent Results line in the summary section.

#### JSONL test update

In `jsonl_renderer_emits_expected_events`: now that `include_raw_codeql_results` defaults to `true` in `JsonlRenderOptions`, and the synthetic result has 1 codeql result, the line count changes from 6 to 7:

```rust
assert_eq!(lines.len(), 7);
assert!(lines[6].contains(r#""event":"codeql_result""#));
```

#### fixtures.rs update

Update `synthetic_static_analysis_result()` summary: `codeql_fused_count: 0` (no CodeQL in synthetic fusion).

#### REFACTOR_PLAN.md update

Change Phase 13 status from `未开始` to `完成`. Add completion note:

```
Phase 13 已完成静态结果融合与 finding 生成：加权置信度评分、两阶段匹配（文件+行号近邻、文件+category）、CodeQL 透传、可配置权重。融合模块位于 static_analysis/fusion/，管线已集成，报告输出支持融合 findings 和 CodeQL 原始结果。
```

- [ ] **Step 1: Add CodeQL count to markdown summary section**

- [ ] **Step 2: Fix JSONL test line count assertion** (6 → 7, add codeql_result event check)

- [ ] **Step 3: Verify synthetic fixture still round-trips correctly**

- [ ] **Step 4: Update REFACTOR_PLAN.md** — mark Phase 13 complete

- [ ] **Step 5: Run `cargo test -p mcp-sec-audit-core && cargo test -p mcp-sec-audit-cli && cargo build --workspace`** — all green

- [ ] **Step 6: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/reporting.rs \
        rust/crates/mcp-sec-audit-core/src/fixtures.rs \
        rust/docs/REFACTOR_PLAN.md
git commit -m "feat(fusion): finalize reporting, fixtures, and docs for Phase 13"
```
