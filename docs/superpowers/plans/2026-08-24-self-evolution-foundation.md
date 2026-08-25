# Self-Evolution Foundation (进化基座 + 自洽裁决核心) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为自主进化铺地基：给 learned 模型加跨运行生命周期字段、修正 `promoted` 语义、并搭建"自洽裁决"的 prompt 渲染 + claude CLI 多轮调用 + 后处理投票的核心骨架。

**Architecture:** 遵循 `SELF_EVOLUTION_SELF_CONSISTENT_DESIGN_20260824.md` 的扁平三段（预处理 → 自洽裁决 → 后处理）。本计划只做地基 + 裁决核心：① 模型生命周期字段（明确因子的跨运行记账载体）；② `promoted` 语义修正；③ 裁决 prompt 纯函数；④ claude CLI 多轮裁决 runner；⑤ 后处理（schema 校验 + 多数投票）。归因/接地/抑制/四线执行留待下一计划。

**Tech Stack:** Rust (workspace), serde (TOML/JSON), anyhow, claude code CLI（headless `claude -p` 子进程，复用 `CliAgentProvider`）。

**Spec:** `rust/docs/v4.0/SELF_EVOLUTION_SELF_CONSISTENT_DESIGN_20260824.md`

## Global Constraints

- Rust crate 名：`mcp-sec-audit-core`（路径 `rust/crates/mcp-sec-audit-core`）。测试命令：`cd rust && cargo test -p mcp-sec-audit-core <filter>`。
- 新字段一律 `#[serde(default)]` 且向后兼容：旧 learned TOML（无新字段）必须仍能 `load_models_dir` 加载。
- 自洽裁决**必须**通过 claude code CLI（`CliAgentProvider` 子进程），**不得**直连 LLM API。
- **P1-A 已完成**（`delete` 前缀已从 `infer.rs::NAME_PREFIX_CATEGORY` 删除，回归测试 `delete_prefix_is_not_inferred_as_file_delete` 已在 `infer.rs:403`）。不要重做。
- 本计划不触碰 fusion 相关代码（用户明确排除）。
- 每个 task 结束独立 commit；commit message 用 `feat:` / `fix:` 前缀 + 简短说明，末尾加 `Co-Authored-By: Claude <noreply@anthropic.com>`。

---

### Task 1: 模型生命周期字段（corroboration_count / pollution_count / last_seen_run）

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/models/mod.rs`（SinkModel 11-27、SourceModel 41-54、SanitizerModel 62-76）
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/learning.rs`（write_learned_sinks 152-173、write_learned_sources 176-194、write_learned_sanitizers 197-215，以及构造点 110/134/315）
- Modify: 测试构造点 `component.rs:221`、`facts/pipeline.rs:294`、`codeql/models.rs:160`、`learning.rs:638`、`models/mod.rs:453`（补新字段默认值）
- Test: `rust/crates/mcp-sec-audit-core/src/models/mod.rs`（新增 roundtrip 测试）

**Interfaces:**
- Consumes: `SinkModel`/`SourceModel`/`SanitizerModel`（`models/mod.rs`），`write_learned_*`（`learning.rs`）。
- Produces: 三个模型结构体各新增 `pub corroboration_count: u32`、`pub pollution_count: u32`、`pub last_seen_run: Option<String>`（均 `#[serde(default)]`）。后续 task 的记账直接读写这些字段。

- [ ] **Step 1: 写失败测试**（`models/mod.rs` 测试模块内追加）

```rust
#[test]
fn learned_model_lifecycle_fields_roundtrip_toml() {
    // 旧格式（无生命周期字段）仍能加载 → 向后兼容
    let old = r#"
[[sinks]]
language = "python"
category = "file_read"
severity = "medium"
confidence = "low"
reason = "legacy"
patterns = ["openpyxl.load_workbook"]
source = "learned"
"#;
    let dir = std::env::temp_dir().join(format!("lifecycle-old-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("old.toml"), old).unwrap();
    let cat = super::load_models_dir(&dir).expect("old TOML must still load");
    let s = &cat.sinks_for_language("python")[0];
    assert_eq!(s.corroboration_count, 0);
    assert_eq!(s.pollution_count, 0);
    assert_eq!(s.last_seen_run, None);
    std::fs::remove_dir_all(&dir).ok();

    // 新格式字段被反序列化
    let new = r#"
[[sinks]]
language = "python"
category = "file_read"
severity = "medium"
confidence = "high"
reason = "learned"
patterns = ["openpyxl.load_workbook"]
source = "learned"
corroboration_count = 2
pollution_count = 1
last_seen_run = "20260824"
"#;
    let dir2 = std::env::temp_dir().join(format!("lifecycle-new-{}", std::process::id()));
    std::fs::create_dir_all(&dir2).unwrap();
    std::fs::write(dir2.join("new.toml"), new).unwrap();
    let cat2 = super::load_models_dir(&dir2).expect("new TOML loads");
    let s2 = &cat2.sinks_for_language("python")[0];
    assert_eq!(s2.corroboration_count, 2);
    assert_eq!(s2.pollution_count, 1);
    assert_eq!(s2.last_seen_run.as_deref(), Some("20260824"));
    std::fs::remove_dir_all(&dir2).ok();
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cd rust && cargo test -p mcp-sec-audit-core learned_model_lifecycle_fields_roundtrip_toml`
Expected: 编译失败 — `SinkModel` 无 `corroboration_count` 等字段。

- [ ] **Step 3: 给三个结构体加字段**（`models/mod.rs`）

在 `SinkModel` 的 `learned_from` 字段后追加（`SourceModel`、`SanitizerModel` 同样追加）：

```rust
    /// Times this learned model was corroborated by the differential signal (b1/a1).
    #[serde(default)]
    pub corroboration_count: u32,
    /// Times this learned model was implicated in a b2 pollution event.
    #[serde(default)]
    pub pollution_count: u32,
    /// Run identifier (e.g. "20260824") of the last scan that observed this model.
    #[serde(default)]
    pub last_seen_run: Option<String>,
```

- [ ] **Step 4: 更新序列化与构造点**

`learning.rs` 三个 `write_learned_*` 的 `format!` 追加字段（以 sinks 为例，其余类推）：

```rust
let text = format!(
    "[[sinks]]\nlanguage = {:?}\ncategory = {:?}\nseverity = {:?}\nconfidence = {:?}\nreason = {:?}\npatterns = {:?}\nsource = \"learned\"\nlearned_from = {:?}\ncorroboration_count = {}\npollution_count = {}\nlast_seen_run = {:?}\n",
    m.language, m.category, severity_str(&m.severity), confidence_str(&m.confidence),
    m.reason, m.patterns, m.learned_from.as_deref().unwrap_or("unknown"),
    m.corroboration_count, m.pollution_count, m.last_seen_run.as_deref().unwrap_or("none"),
);
```

构造点 `learning.rs:110`、`134`、`315` 以及测试构造点 `component.rs:221`、`facts/pipeline.rs:294`、`codeql/models.rs:160`、`learning.rs:638`、`models/mod.rs:453` 的结构体字面量里补：

```rust
corroboration_count: 0,
pollution_count: 0,
last_seen_run: None,
```

（`SourceModel`/`SanitizerModel` 的构造点同理；用 `grep -rn "SourceModel {\|SanitizerModel {" rust/crates/mcp-sec-audit-core/src/` 找全。）

- [ ] **Step 5: 运行确认通过**

Run: `cd rust && cargo test -p mcp-sec-audit-core learned_model_lifecycle_fields_roundtrip_toml`
Expected: PASS

- [ ] **Step 6: 全量测试 + commit**

Run: `cd rust && cargo test -p mcp-sec-audit-core`
Expected: 全绿。

```bash
cd rust && git add crates/mcp-sec-audit-core/src/models/mod.rs crates/mcp-sec-audit-core/src/static_analysis/learning.rs crates/mcp-sec-audit-core/src/static_analysis/component.rs crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs crates/mcp-sec-audit-core/src/static_analysis/codeql/models.rs
git commit -m "feat(v4): add lifecycle fields (corroboration/pollution/last_seen) to learned models"
```

---

### Task 2: 修正 promoted 语义（P1-C）

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/model/static_result.rs:216-241`（EvolutionReport）
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs:504-535`（promote 分支）

**Interfaces:**
- Consumes: `EvolutionReport`（static_result.rs）、`delta.model_count()`（component.rs:43 已存在）。
- Produces: `EvolutionReport` 新增 `pub promoted_count: usize`、`pub retired_count: usize`（均 `#[serde(default)]`）。`promoted` 字段语义改为"本轮实际 promote 了模型"。

- [ ] **Step 1: 写失败测试**（`static_result.rs` 测试模块追加）

```rust
#[test]
fn evolution_report_counts_default_to_zero() {
    let e = EvolutionReport::default();
    assert_eq!(e.promoted_count, 0);
    assert_eq!(e.retired_count, 0);
    assert!(!e.promoted);
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cd rust && cargo test -p mcp-sec-audit-core evolution_report_counts_default_to_zero`
Expected: 编译失败 — 无 `promoted_count`/`retired_count`。

- [ ] **Step 3: 给 EvolutionReport 加字段**（`static_result.rs`）

在 `promoted` 字段后追加：

```rust
    /// Number of models actually persisted to learned/ this run (0 when empty delta).
    #[serde(default)]
    pub promoted_count: usize,
    /// Number of models retired/removed this run (0 until lifecycle phase lands).
    #[serde(default)]
    pub retired_count: usize,
```

- [ ] **Step 4: 修正 pipeline promote 分支**（`pipeline.rs:504-522`）

把：

```rust
    let rolled_back = migration.should_rollback();
    let (final_taint, final_agent, final_codeql, final_facts) = if rolled_back {
        ...
    } else {
        if let Some(dir) = &ctx.config.static_.learned_dir {
            base_component.promote(&delta, std::path::Path::new(dir))?;
        }
        tracing::info!(
            target: "mcp_sec_audit::evolution",
            learned = delta.model_count(),
            "promoted staged models to learned"
        );
        (taint_results_2, agent_output_2, codeql_output_2, facts_2)
    };
```

改为（记录 `promoted_n` 并在空 delta 时报 `nothing to promote`）：

```rust
    let rolled_back = migration.should_rollback();
    let promoted_n = delta.model_count();
    let (final_taint, final_agent, final_codeql, final_facts) = if rolled_back {
        base_component.rollback(&staging_dir)?;
        tracing::warn!(
            target: "mcp_sec_audit::evolution",
            "evolution polluted standard line — rolling back staged models"
        );
        (taint_results_1, agent_output_1, codeql_output_1, facts_1)
    } else {
        if promoted_n > 0 {
            if let Some(dir) = &ctx.config.static_.learned_dir {
                base_component.promote(&delta, std::path::Path::new(dir))?;
            }
            tracing::info!(
                target: "mcp_sec_audit::evolution",
                learned = promoted_n,
                "promoted staged models to learned"
            );
        } else {
            tracing::info!(
                target: "mcp_sec_audit::evolution",
                "nothing to promote — empty delta"
            );
        }
        (taint_results_2, agent_output_2, codeql_output_2, facts_2)
    };
```

- [ ] **Step 5: 更新 EvolutionReport 构造**（`pipeline.rs:524-535`）

把 `promoted: !rolled_back,` 改为：

```rust
        promoted: promoted_n > 0,
        promoted_count: if rolled_back { 0 } else { promoted_n },
        retired_count: 0,
```

- [ ] **Step 6: 运行确认通过**

Run: `cd rust && cargo test -p mcp-sec-audit-core evolution_report_counts_default_to_zero`
Expected: PASS

- [ ] **Step 7: 全量测试 + commit**

Run: `cd rust && cargo test -p mcp-sec-audit-core`
Expected: 全绿。

```bash
cd rust && git add crates/mcp-sec-audit-core/src/model/static_result.rs crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs
git commit -m "fix(v4): make promoted reflect actual persist count (P1-C)"
```

---

### Task 3: 自洽裁决 prompt 渲染（纯函数）

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/adjudicate.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/mod.rs`（`mod adjudicate;` + re-export）
- Test: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/adjudicate.rs`（内联 `#[cfg(test)]`）

**Interfaces:**
- Consumes: `crate::model::AdjudicationItem`（`static_result.rs:246`：`file`/`line`/`kind`/`agent_explanation`）。
- Produces: `pub fn render_adjudication_prompt(items: &[AdjudicationItem]) -> String`。后续 runner 直接消费该字符串。

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn prompt_contains_items_and_json_contract() {
    let items = vec![crate::AdjudicationItem {
        file: "server.ts".into(),
        line: 22,
        kind: "b_still_ambiguous".into(),
        agent_explanation: Some("read_config reads arbitrary files".into()),
    }];
    let p = render_adjudication_prompt(&items);
    assert!(p.contains("server.ts"));
    assert!(p.contains("22"));
    assert!(p.contains("read_config"));
    // 强制结构化输出契约：要求每行一个 JSON 对象
    assert!(p.contains("JSON"));
    assert!(p.contains("is_real"));
    assert!(p.contains("reachable"));
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cd rust && cargo test -p mcp-sec-audit-core prompt_contains_items_and_json_contract`
Expected: 编译失败 — `render_adjudication_prompt` 不存在。

- [ ] **Step 3: 实现**

```rust
//! Self-consistent adjudication: render the prompt that asks the claude CLI
//! to judge each ambiguous evolution candidate with three closed questions.

use crate::AdjudicationItem;

/// Render the adjudication prompt. The agent must answer each item as a single
/// line of strict JSON, one per line, nothing else — so the post-processing
/// pass can parse lines deterministically.
pub fn render_adjudication_prompt(items: &[AdjudicationItem]) -> String {
    let mut s = String::from(
        "You are an evolution adjudicator for an MCP security scanner.\n\
         For each item below, judge three things and answer as ONE line of strict \
         JSON per item (no markdown, no prose, one object per line):\n\
         {\"item_id\":\"<file:line>\",\"is_real\":true|false,\"reachable\":\"reachable|unreachable|unknown\",\
         \"abstractable\":{\"kind\":\"sink|rule|prompt\",\"category\":\"<snake_case>\",\"pattern\":\"<callee>\"}|null,\
         \"confidence\":\"high|medium|low\",\"reason\":\"<one sentence>\"}\n\n",
    );
    for it in items {
        s.push_str(&format!("- item_id: {}:{} kind: {}\n", it.file, it.line, it.kind));
        if let Some(exp) = &it.agent_explanation {
            s.push_str(&format!("  prior_agent_note: {exp}\n"));
        }
    }
    s.push_str("\nAnswer now:\n");
    s
}
```

- [ ] **Step 4: 接线 `mod adjudicate;`**（`agent/mod.rs`）

在 `mod parser;` 之后加 `mod adjudicate;`，并 `pub(crate) use adjudicate::render_adjudication_prompt;`。

- [ ] **Step 5: 运行确认通过**

Run: `cd rust && cargo test -p mcp-sec-audit-core prompt_contains_items_and_json_contract`
Expected: PASS

- [ ] **Step 6: commit**

```bash
cd rust && git add crates/mcp-sec-audit-core/src/static_analysis/agent/adjudicate.rs crates/mcp-sec-audit-core/src/static_analysis/agent/mod.rs
git commit -m "feat(v4): add self-consistent adjudication prompt renderer"
```

---

### Task 4: 自洽裁决 runner（claude CLI 多轮调用）

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/adjudicate.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/mod.rs`（re-export）
- Test: `adjudicate.rs` 内联

**Interfaces:**
- Consumes: `CliAgentProvider`（`provider.rs`）、`AgentRunConfig`、`AgentRunOutput`、`StaticScanContext`。
- Produces:
  ```rust
  pub struct AdjudicationVerdict {
      pub item_id: String,
      pub is_real: bool,
      pub reachable: String,
      pub abstractable: Option<Abstraction>,
      pub confidence: String,
  }
  pub struct Abstraction { pub kind: String, pub category: String, pub pattern: String }
  pub fn run_adjudication(ctx: &StaticScanContext, items: &[AdjudicationItem]) -> Result<Vec<Vec<AdjudicationVerdict>>>;
  ```
  返回 `Vec<Vec<Verdict>>`：外层是轮次（N=3），内层是该轮解析出的 verdicts，供 Task 5 投票。

- [ ] **Step 1: 写失败测试**（用假 provider 不实际起子进程，只测 `parse_verdicts` 与 `vote` 的纯逻辑，见 Task 5；本 task 的失败测试针对 `parse_verdicts`）

```rust
#[test]
fn parse_verdicts_parses_one_line_per_json() {
    let stdout = "{\"item_id\":\"server.ts:22\",\"is_real\":true,\"reachable\":\"reachable\",\"abstractable\":{\"kind\":\"sink\",\"category\":\"file_read\",\"pattern\":\"fs.readFileSync\"},\"confidence\":\"high\",\"reason\":\"arbitrary read\"}\n";
    let v = parse_verdicts(stdout).unwrap();
    assert_eq!(v.len(), 1);
    assert!(v[0].is_real);
    assert_eq!(v[0].abstractable.as_ref().unwrap().pattern, "fs.readFileSync");
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cd rust && cargo test -p mcp-sec-audit-core parse_verdicts_parses_one_line_per_json`
Expected: 编译失败 — `parse_verdicts` 不存在。

- [ ] **Step 3: 实现 verdict 结构 + 解析 + runner**

```rust
use anyhow::Result;
use serde::Deserialize;

use crate::AdjudicationItem;
use crate::static_analysis::pipeline::StaticScanContext;
use super::provider::{AgentRunConfig, CliAgentProvider, AgentProvider};

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Abstraction {
    pub kind: String,
    pub category: String,
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AdjudicationVerdict {
    pub item_id: String,
    pub is_real: bool,
    pub reachable: String,
    pub abstractable: Option<Abstraction>,
    pub confidence: String,
}

/// Parse one JSON object per line; ignore blank/non-JSON lines.
pub fn parse_verdicts(stdout: &str) -> Result<Vec<AdjudicationVerdict>> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let t = line.trim();
        if t.is_empty() || !t.starts_with('{') {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<AdjudicationVerdict>(t) {
            out.push(v);
        }
    }
    Ok(out)
}

const ROUNDS: u32 = 3;

/// Run the claude CLI adjudication ROUNDS times, returning one Vec per round.
pub fn run_adjudication(
    ctx: &StaticScanContext,
    items: &[AdjudicationItem],
) -> Result<Vec<Vec<AdjudicationVerdict>>> {
    let agent_config = &ctx.config.static_.agent;
    let prompt = render_adjudication_prompt(items);
    let target_root = ctx
        .discovered_files
        .first()
        .and_then(|df| df.path.parent())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| ".".to_string());

    let mut rounds = Vec::new();
    for _ in 0..ROUNDS {
        let cfg = AgentRunConfig {
            working_dir: target_root.clone(),
            prompt: prompt.clone(),
            provider_binary: agent_config.provider.clone(),
            max_turns: agent_config.max_turns,
            timeout_seconds: agent_config.timeout_seconds,
            extra_args: agent_config.extra_args.clone(),
        };
        let output = CliAgentProvider.run(&cfg)?;
        rounds.push(parse_verdicts(&output.stdout)?);
    }
    Ok(rounds)
}
```

- [ ] **Step 4: 接线 re-export**（`agent/mod.rs`）

`pub(crate) use adjudicate::{run_adjudication, parse_verdicts, AdjudicationVerdict};`

- [ ] **Step 5: 运行确认通过**

Run: `cd rust && cargo test -p mcp-sec-audit-core parse_verdicts_parses_one_line_per_json`
Expected: PASS

- [ ] **Step 6: commit**

```bash
cd rust && git add crates/mcp-sec-audit-core/src/static_analysis/agent/adjudicate.rs crates/mcp-sec-audit-core/src/static_analysis/agent/mod.rs
git commit -m "feat(v4): add claude-CLI self-consistent adjudication runner"
```

---

### Task 5: 输出后处理（schema 校验 + 多数投票）

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/adjudicate.rs`
- Test: `adjudicate.rs` 内联

**Interfaces:**
- Consumes: `AdjudicationVerdict`、`run_adjudication`（Task 4）。
- Produces:
  ```rust
  pub enum AdjudicationOutcome { Promote, Reject, Uncertain }
  pub struct ResolvedVerdict { pub verdict: AdjudicationVerdict, pub outcome: AdjudicationOutcome, pub votes: u32 }
  pub fn vote(rounds: &[Vec<AdjudicationVerdict>]) -> Vec<ResolvedVerdict>;
  ```

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn vote_requires_unanimous_or_downgrades_to_uncertain() {
    use AdjudicationVerdict as V;
    let mk = |is_real: bool| V {
        item_id: "a.py:1".into(), is_real,
        reachable: "reachable".into(),
        abstractable: Some(Abstraction { kind: "sink".into(), category: "file_read".into(), pattern: "foo.read".into() }),
        confidence: "high".into(),
    };
    // 3:0 一致 → Promote
    let unanimous = vec![vec![mk(true)], vec![mk(true)], vec![mk(true)]];
    let r = vote(&unanimous);
    assert_eq!(r[0].outcome, AdjudicationOutcome::Promote);
    assert_eq!(r[0].votes, 3);
    // 2:1 分裂 → Uncertain
    let split = vec![vec![mk(true)], vec![mk(true)], vec![mk(false)]];
    let r2 = vote(&split);
    assert_eq!(r2[0].outcome, AdjudicationOutcome::Uncertain);
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cd rust && cargo test -p mcp-sec-audit-core vote_requires_unanimous_or_downgrades_to_uncertain`
Expected: 编译失败 — `vote`/`AdjudicationOutcome` 不存在。

- [ ] **Step 3: 实现投票 + schema 校验**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjudicationOutcome { Promote, Reject, Uncertain }

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedVerdict {
    pub verdict: AdjudicationVerdict,
    pub outcome: AdjudicationOutcome,
    pub votes: u32,
}

/// Schema gate: `reachable` must be one of three enum values; else treat as unknown.
fn valid_reachable(s: &str) -> bool {
    matches!(s, "reachable" | "unreachable" | "unknown")
}

/// Majority-vote each item across rounds. 3:0 => Promote/Reject by is_real;
/// any split (2:1 / 1:2) => Uncertain; invalid reachable => Uncertain.
pub fn vote(rounds: &[Vec<AdjudicationVerdict>]) -> Vec<ResolvedVerdict> {
    use std::collections::BTreeMap;
    let mut by_item: BTreeMap<String, Vec<&AdjudicationVerdict>> = BTreeMap::new();
    for round in rounds {
        for v in round {
            by_item.entry(v.item_id.clone()).or_default().push(v);
        }
    }
    let mut out = Vec::new();
    for (item_id, vs) in by_item {
        if vs.is_empty() { continue; }
        let total = vs.len() as u32;
        let yes = vs.iter().filter(|v| v.is_real).count() as u32;
        let all_valid = vs.iter().all(|v| valid_reachable(&v.reachable));
        let outcome = if !all_valid {
            AdjudicationOutcome::Uncertain
        } else if yes == total {
            AdjudicationOutcome::Promote
        } else if yes == 0 {
            AdjudicationOutcome::Reject
        } else {
            AdjudicationOutcome::Uncertain
        };
        out.push(ResolvedVerdict { verdict: vs[0].clone(), outcome, votes: total });
    }
    out.sort_by(|a, b| a.verdict.item_id.cmp(&b.verdict.item_id));
    out
}
```

- [ ] **Step 4: 运行确认通过**

Run: `cd rust && cargo test -p mcp-sec-audit-core vote_requires_unanimous_or_downgrades_to_uncertain`
Expected: PASS

- [ ] **Step 5: 全量测试 + commit**

Run: `cd rust && cargo test -p mcp-sec-audit-core`
Expected: 全绿。

```bash
cd rust && git add crates/mcp-sec-audit-core/src/static_analysis/agent/adjudicate.rs
git commit -m "feat(v4): add adjudication post-processing (schema gate + majority vote)"
```

---

## Self-Review Notes

- **Spec coverage**：本计划覆盖 spec §3（输入预处理）里的"结构化契约"与 §4/§5（自洽裁决 + 输出后处理）的核心骨架（prompt/runner/vote）。**未覆盖**：§3.2 归因（evidence.rs）、§5.2 接地核验、§6 进化执行（promote/retire/suppress 写 learned）、四线执行、退化护栏——这些留待 Plan 2。
- **Type consistency**：`AdjudicationVerdict`/`Abstraction`/`AdjudicationOutcome`/`ResolvedVerdict` 在 Task 4/5 内定义且命名一致；`corroboration_count` 等字段名在 Task 1 定义后由后续计划复用。
- **P1-A 已跳过**：`delete` 前缀修复已在工作区，不重复。

## Execution Handoff

计划保存后由用户选择执行方式（subagent-driven / inline）。
