# Self-Evolution Execution (进化执行闭环) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 Plan 1 建好的自洽裁决核心接到管线里，实现"模糊因子 → 裁决 → promote/retire → 写 learned"的零人工闭环，并让 learned 模型跨运行累积 corroboration/pollution 证据。

**Architecture:** 复用 Plan 1 的 `agent/adjudicate.rs`（`run_adjudication`/`vote`/`ResolvedVerdict`）。新增纯函数把裁决结果转成模型动作（sink/source/sanitizer/rule/prompt），在 `pipeline.rs` 的迁移校验之后接线：对 `still_ambiguous` + `b0` 跑裁决、按结果 promote/retire、写入 `learned_dir`、回填 `EvolutionReport`。

**Tech Stack:** Rust (workspace), serde, anyhow, claude code CLI（headless 子进程，经 `CliAgentProvider`）。

**Spec:** `rust/docs/v4.0/SELF_EVOLUTION_SELF_CONSISTENT_DESIGN_20260824.md`（§3.2 归因、§5.2 接地、§6 进化执行）

## Global Constraints

- Rust crate：`mcp-sec-audit-core`。测试：`cd rust && cargo test -p mcp-sec-audit-core <filter>`。
- **本计划不逐 task commit**（用户要求统一提交）。实现者只写代码 + 测试，**不得执行 `git commit`**；controller 在全部 task 完成后统一 commit。
- 自洽裁决必须经 claude CLI（`CliAgentProvider` 子进程），不得直连 LLM API。
- 新字段/新类型一律 `#[serde(default)]` 向后兼容；旧 learned TOML 仍能加载。
- 不触碰 fusion 相关代码。
- Plan 1 已交付（供本计划消费）：`agent/adjudicate.rs` 的 `AdjudicationVerdict`/`Abstraction`/`parse_verdicts`/`run_adjudication`/`vote`/`AdjudicationOutcome`/`ResolvedVerdict`/`render_adjudication_prompt`；`models` 的 `corroboration_count`/`pollution_count`/`last_seen_run`；`pipeline.rs` 的 `promoted`/`promoted_count` 语义。

---

### Task 1: 裁决结果 → 模型动作（纯函数）

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/adjudicate.rs`
- Test: `adjudicate.rs` 内联

**Interfaces:**
- Consumes: `ResolvedVerdict`（Plan 1 已定义：`verdict`/`outcome`/`votes`）、`Abstraction`（`kind`/`category`/`pattern`）、`AdjudicationVerdict`（`item_id`/`is_real`/`reachable`/`abstractable`/`confidence`）。
- Produces:
  ```rust
  pub enum PromoteAction {
      Sink(crate::models::SinkModel),
      Source(crate::models::SourceModel),
      Sanitizer(crate::models::SanitizerModel),
      Rule(String),   // rule capability line, e.g. "path_traversal"
      Prompt(String), // prompt-extra text
  }
  pub fn resolved_to_promote_action(r: &ResolvedVerdict) -> Option<PromoteAction>;
  ```

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn resolved_to_promote_action_maps_sink_verdict() {
    let r = ResolvedVerdict {
        verdict: AdjudicationVerdict {
            item_id: "server.ts:22".into(),
            is_real: true,
            reachable: "reachable".into(),
            abstractable: Some(Abstraction { kind: "sink".into(), category: "file_read".into(), pattern: "fs.readFileSync".into() }),
            confidence: "high".into(),
        },
        outcome: AdjudicationOutcome::Promote,
        votes: 3,
    };
    let a = resolved_to_promote_action(&r).expect("maps");
    match a {
        PromoteAction::Sink(m) => {
            assert_eq!(m.language, "javascript");
            assert_eq!(m.category, "file_read");
            assert_eq!(m.patterns, vec!["fs.readFileSync"]);
            assert_eq!(m.confidence, crate::Confidence::Low);
            assert_eq!(m.corroboration_count, 1);
        }
        _ => panic!("expected Sink"),
    }
}

#[test]
fn resolved_to_promote_action_rejects_on_uncertain_or_reject() {
    let mk = |outcome| ResolvedVerdict {
        verdict: AdjudicationVerdict {
            item_id: "a.py:1".into(), is_real: true, reachable: "reachable".into(),
            abstractable: Some(Abstraction { kind: "sink".into(), category: "file_read".into(), pattern: "foo.read".into() }),
            confidence: "high".into(),
        },
        outcome, votes: 1,
    };
    assert!(resolved_to_promote_action(&mk(AdjudicationOutcome::Reject)).is_none());
    assert!(resolved_to_promote_action(&mk(AdjudicationOutcome::Uncertain)).is_none());
}
```

- [ ] **Step 2: 运行确认失败**（`cd rust && cargo test -p mcp-sec-audit-core resolved_to_promote_action`）

- [ ] **Step 3: 实现**

```rust
use crate::models::{SanitizerModel, SinkModel, SourceModel};
use crate::Confidence;

/// A concrete learned-model write the evolution executor should apply.
pub enum PromoteAction {
    Sink(SinkModel),
    Source(SourceModel),
    Sanitizer(SanitizerModel),
    Rule(String),
    Prompt(String),
}

/// Convert a resolved adjudication verdict into a promote action. Returns
/// `None` unless the outcome is Promote, the verdict is real and reachable,
/// and an abstraction was produced. New models enter at confidence Low with
/// corroboration_count = 1 (first evidence is this adjudication).
pub fn resolved_to_promote_action(r: &ResolvedVerdict) -> Option<PromoteAction> {
    if r.outcome != AdjudicationOutcome::Promote {
        return None;
    }
    let v = &r.verdict;
    if !v.is_real || v.reachable != "reachable" {
        return None;
    }
    let abs = v.abstractable.as_ref()?;
    let language = language_for_file(&v.item_id);
    match abs.kind.as_str() {
        "sink" => Some(PromoteAction::Sink(SinkModel {
            language,
            category: abs.category.clone(),
            severity: crate::Severity::Medium,
            confidence: Confidence::Low,
            reason: format!("learned sink via adjudication: {}", abs.category),
            patterns: vec![abs.pattern.clone()],
            source: Some("learned".into()),
            learned_from: Some("adjudication".into()),
            corroboration_count: 1,
            pollution_count: 0,
            last_seen_run: None,
        })),
        "source" => Some(PromoteAction::Source(SourceModel {
            language,
            category: abs.category.clone(),
            patterns: vec![abs.pattern.clone()],
            source: Some("learned".into()),
            learned_from: Some("adjudication".into()),
            corroboration_count: 1,
            pollution_count: 0,
            last_seen_run: None,
        })),
        "sanitizer" => Some(PromoteAction::Sanitizer(SanitizerModel {
            language,
            patterns: vec![abs.pattern.clone()],
            neutralizes: vec![abs.category.clone()],
            source: Some("learned".into()),
            learned_from: Some("adjudication".into()),
            corroboration_count: 1,
            pollution_count: 0,
            last_seen_run: None,
        })),
        "rule" => Some(PromoteAction::Rule(abs.category.clone())),
        "prompt" => Some(PromoteAction::Prompt(format!(
            "{} — {}",
            abs.category,
            abs.pattern
        ))),
        _ => None,
    }
}

/// Infer a language key from an item_id of the form `file.ext:line`.
fn language_for_file(item_id: &str) -> String {
    let file = item_id.split(':').next().unwrap_or(item_id).to_lowercase();
    if file.ends_with(".py") {
        "python".into()
    } else if file.ends_with(".rs") {
        "rust".into()
    } else if file.ends_with(".ts") || file.ends_with(".js") {
        "javascript".into()
    } else {
        "javascript".into()
    }
}
```

- [ ] **Step 4: 运行确认通过**（`cd rust && cargo test -p mcp-sec-audit-core resolved_to_promote_action`）

- [ ] **Step 5: re-export**（`agent/mod.rs` 的 `pub(crate) use adjudicate::{...}` 加 `PromoteAction, resolved_to_promote_action`）

---

### Task 2: 跨运行证据累积（纯函数）

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/evolution.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`（`mod evolution;`）
- Test: `evolution.rs` 内联

**Interfaces:**
- Consumes: `crate::models::{SinkModel, SourceModel, SanitizerModel}`（含生命周期字段）。
- Produces:
  ```rust
  pub enum EvidenceKind { Corroborated, Polluted, Inactive }
  /// Apply one piece of evidence to a model, mutating its lifecycle fields in
  /// place; returns true if the model should be retired.
  pub fn apply_evidence(model: &mut SinkModel, kind: EvidenceKind) -> bool;
  ```
  （对 `SourceModel`/`SanitizerModel` 提供同构函数；或用一个泛型 trait。实现者选 DRY 方案，但三个类型的字段名相同。）

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn corroboration_upgrades_confidence_and_pollution_retires() {
    let mut m = SinkModel {
        language: "python".into(), category: "file_read".into(),
        severity: crate::Severity::Medium, confidence: crate::Confidence::Low,
        reason: "t".into(), patterns: vec!["x.read".into()],
        source: None, learned_from: None,
        corroboration_count: 0, pollution_count: 0, last_seen_run: None,
    };
    // 第一次 corroboration → medium, count=1
    assert!(!apply_evidence(&mut m, EvidenceKind::Corroborated));
    assert_eq!(m.corroboration_count, 1);
    assert_eq!(m.confidence, crate::Confidence::Medium);
    // 第二次 corroboration → high, count=2
    assert!(!apply_evidence(&mut m, EvidenceKind::Corroborated));
    assert_eq!(m.corroboration_count, 2);
    assert_eq!(m.confidence, crate::Confidence::High);
    // 一次污染 → 降级
    assert!(!apply_evidence(&mut m, EvidenceKind::Polluted));
    assert_eq!(m.pollution_count, 1);
    assert_eq!(m.confidence, crate::Confidence::Medium);
    // 二次污染 → retire
    assert!(apply_evidence(&mut m, EvidenceKind::Polluted));
}
```

- [ ] **Step 2: 运行确认失败**（`cd rust && cargo test -p mcp-sec-audit-core corroboration_upgrades_confidence_and_pollution_retires`）

- [ ] **Step 3: 实现**

```rust
//! Cross-run evidence accumulation for learned models: corroboration raises
//! confidence (Low→Medium→High), pollution lowers it, and two pollutions (or
//! long inactivity) retire the model.

use crate::models::{SanitizerModel, SinkModel, SourceModel};
use crate::Confidence;

pub enum EvidenceKind { Corroborated, Polluted, Inactive }

fn bump_confidence(c: &Confidence, up: bool) -> Confidence {
    match (c, up) {
        (Confidence::Low, true) => Confidence::Medium,
        (Confidence::Medium, true) => Confidence::High,
        (Confidence::High, true) => Confidence::High,
        (Confidence::High, false) => Confidence::Medium,
        (Confidence::Medium, false) => Confidence::Low,
        (Confidence::Low, false) => Confidence::Low,
    }
}

pub fn apply_evidence(model: &mut SinkModel, kind: EvidenceKind) -> bool {
    match kind {
        EvidenceKind::Corroborated => {
            model.corroboration_count += 1;
            model.confidence = bump_confidence(&model.confidence, true);
            false
        }
        EvidenceKind::Polluted => {
            model.pollution_count += 1;
            model.confidence = bump_confidence(&model.confidence, false);
            model.pollution_count >= 2
        }
        EvidenceKind::Inactive => true, // long-unseen → retire (caller decides threshold)
    }
}

pub fn apply_evidence_source(model: &mut SourceModel, kind: EvidenceKind) -> bool {
    match kind {
        EvidenceKind::Corroborated => { model.corroboration_count += 1; false }
        EvidenceKind::Polluted => { model.pollution_count += 1; model.pollution_count >= 2 }
        EvidenceKind::Inactive => true,
    }
}

pub fn apply_evidence_sanitizer(model: &mut SanitizerModel, kind: EvidenceKind) -> bool {
    match kind {
        EvidenceKind::Corroborated => { model.corroboration_count += 1; false }
        EvidenceKind::Polluted => { model.pollution_count += 1; model.pollution_count >= 2 }
        EvidenceKind::Inactive => true,
    }
}
```

- [ ] **Step 4: 运行确认通过**

- [ ] **Step 5: 接线**（`static_analysis/mod.rs` 加 `mod evolution;`）

---

### Task 3: 进化执行接线（pipeline）

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/model/static_result.rs`（EvolutionReport 加裁决摘要字段）
- Test: `pipeline.rs` 若可行加集成测试，否则依赖 Task 1/2 的纯函数测试 + 一次真实扫描验证

**Interfaces:**
- Consumes: `agent::run_adjudication`、`agent::vote`、`agent::resolved_to_promote_action`、`PromoteAction`、`learning::write_learned_sinks/sources/sanitizers`、`validate::ambiguous_items`、`EvolutionReport`。
- Produces: `EvolutionReport` 新增 `adjudicated: usize`、`promoted_from_adjudication: usize`、`retired: usize`（均 `#[serde(default)]`）。pipeline 在 migrate 之后对 `ambiguous` + `b0` 执行裁决闭环。

- [ ] **Step 1: 给 EvolutionReport 加字段**（`static_result.rs`，`promoted_count` 后追加）

```rust
    /// Number of ambiguous/b0 items this run submitted to adjudication.
    #[serde(default)]
    pub adjudicated: usize,
    /// Number of models promoted from adjudication this run.
    #[serde(default)]
    pub promoted_from_adjudication: usize,
    /// Number of models retired this run.
    #[serde(default)]
    pub retired: usize,
```

- [ ] **Step 2: 在 pipeline 中接线**（`pipeline.rs` 中 `let mut ambiguous = validate::ambiguous_items(&diff_1, &diff_2);` **之后**、L2 解释 pass 之后、`let rolled_back = ...` **之前**插入；实现者须读当前文件确认 `ambiguous` 与 `b0` 都在作用域内）

```rust
    // ---------- 自洽裁决（模糊因子闭环） ----------
    let mut adjudicated = 0usize;
    let mut promoted_from_adjudication = 0usize;
    let mut retired = 0usize;
    let mut actions: Vec<agent::PromoteAction> = Vec::new();
    if (!ambiguous.is_empty() || !b0.is_empty())
        && effective_config.static_.agent.enabled
    {
        // b0 candidates carry no file:line; build AdjudicationItem-shaped input.
        let mut items: Vec<crate::AdjudicationItem> = ambiguous.clone();
        for c in &b0 {
            items.push(crate::AdjudicationItem {
                file: c.name.clone(),
                line: 0,
                kind: "b0_semantic_only".to_string(),
                agent_explanation: c.evidence_snippets.first().cloned(),
            });
        }
        if !items.is_empty() {
            if let Ok(rounds) = agent::run_adjudication(&ctx, &items) {
                let resolved = agent::vote(&rounds);
                for r in &resolved {
                    adjudicated += 1;
                    match r.outcome {
                        agent::AdjudicationOutcome::Promote => {
                            if let Some(a) = agent::resolved_to_promote_action(r) {
                                promoted_from_adjudication += 1;
                                actions.push(a);
                            }
                        }
                        agent::AdjudicationOutcome::Reject => { /* discard */ }
                        agent::AdjudicationOutcome::Uncertain => { /* leave for next run */ }
                    }
                }
            }
        }
    }
```

- [ ] **Step 3: 在 promote 分支写入裁决产物**（`pipeline.rs` 的 `if promoted_n > 0 { ... }` 之前或之后，把 `actions` 写入 learned_dir）

在 `base_component.promote(&delta, ...)` 之后追加：

```rust
        // Persist adjudication-derived models (sink/source/sanitizer).
        if let Some(dir) = &ctx.config.static_.learned_dir {
            let (sinks, sources, sanitizers): (Vec<_>, Vec<_>, Vec<_>) =
                actions.iter().fold(
                    (Vec::new(), Vec::new(), Vec::new()),
                    |(mut s, mut so, mut sa), a| {
                        match a {
                            agent::PromoteAction::Sink(m) => s.push(m.clone()),
                            agent::PromoteAction::Source(m) => so.push(m.clone()),
                            agent::PromoteAction::Sanitizer(m) => sa.push(m.clone()),
                            _ => {}
                        }
                        (s, so, sa)
                    },
                );
            if !sinks.is_empty() { super::learning::write_learned_sinks(Path::new(dir), &sinks)?; }
            if !sources.is_empty() { super::learning::write_learned_sources(Path::new(dir), &sources)?; }
            if !sanitizers.is_empty() { super::learning::write_learned_sanitizers(Path::new(dir), &sanitizers)?; }
        }
```

- [ ] **Step 4: 回填 EvolutionReport 构造**（`pipeline.rs` 的 `EvolutionReport { ... }` 里补 `adjudicated, promoted_from_adjudication, retired` 三字段，值来自上面的局部变量；注意变量所有权/移动，需在构造前确定值）

- [ ] **Step 5: 运行确认通过**

Run: `cd rust && cargo test -p mcp-sec-audit-core`（全量）
Expected: 全绿（Task 1/2 的纯函数测试 + 现有 285 测试）。

- [ ] **Step 6: 一次真实扫描冒烟**（可选，若环境有 claude CLI）

Run: `cd rust && cargo run -- ../test-targets/configs/v4-evolution-config.toml`（需 agent enabled）
Expected: 日志出现 `adjudicated=`/`promoted_from_adjudication=`，learned 目录产生新 sink TOML。

---

## Self-Review Notes

- **Spec coverage**：本计划实现 spec §6 进化执行（裁决 → promote/retire → 写 learned）与 §5.2 接地核验的**子集**（`resolved_to_promote_action` 里 `reachable != "reachable"` 即拒，等价于轻量接地）。**未覆盖**：§3.2 完整归因（finding→model 反查）、§5.2 完整接地（dataflow 路径核验）、rule/prompt 四线写入、退化护栏——留待 Plan 3。
- **Type consistency**：`PromoteAction`/`resolved_to_promote_action`（Task 1）→ `evolution.rs::EvidenceKind`/`apply_evidence`（Task 2，独立）→ pipeline 接线（Task 3）。字段名 `corroboration_count`/`pollution_count`/`last_seen_run` 与 Plan 1 一致。
- **Commit policy**：本计划所有 task 不单独 commit；实现者写代码+测试后停，controller 最后统一 commit。

## Execution Handoff

计划保存后由 controller 按 subagent-driven 流程执行（实现者不 commit，最后统一 commit）。
