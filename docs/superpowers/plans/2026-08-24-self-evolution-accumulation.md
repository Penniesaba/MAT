# Self-Evolution Accumulation (跨运行累积 + 四线 + 一致性) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 补齐 spec 剩余核心：修 `vote` 的 `reachable` 一致性、落盘 rule/prompt 四线、修复 learned 模型被覆盖丢失累积证据的 bug。

**Architecture:** 三个独立、可测的任务，均落在已有模块上。Task 1 修 `vote`（spec §5.3）；Task 2 让 `PromoteAction::Rule/Prompt` 落盘（spec §6 四线）；Task 3 把 promote 写入从"覆盖"改为"合并"以保留 `corroboration_count` 累积（Plan 2 终审标记的真实缺陷）。

**Tech Stack:** Rust, serde, anyhow.

**Spec:** `rust/docs/v4.0/SELF_EVOLUTION_SELF_CONSISTENT_DESIGN_20260824.md`

## Global Constraints

- Rust crate：`mcp-sec-audit-core`。测试：`cd rust && cargo test -p mcp-sec-audit-core <filter>`。
- **本计划不逐 task commit**（用户要求统一提交）。实现者只写代码+测试，不 `git commit`；controller 最后统一 commit。
- 新字段/类型 `#[serde(default)]` 向后兼容；旧 learned TOML 仍能加载。
- 不触碰 fusion。
- Plan 1/2 已交付：`agent/adjudicate.rs`（`vote`/`AdjudicationVerdict`/`PromoteAction`/`resolved_to_promote_action`…）、`evolution.rs`（`EvidenceKind`/`apply_evidence`）、`pipeline.rs`（裁决接线）、models 生命周期字段。

---

### Task 1: `vote` 的 `reachable` 一致性（spec §5.3）

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/agent/adjudicate.rs`
- Test: `adjudicate.rs` 内联

**Interfaces:**
- Consumes: `AdjudicationVerdict`（`is_real`/`reachable`）、`AdjudicationOutcome`。
- Produces: `vote` 现在要求 Promote 必须同时满足 `is_real` 全票 true 且 `reachable` 全票 `"reachable"`。

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn vote_downgrades_on_reachable_split() {
    let mk = |reachable: &str| AdjudicationVerdict {
        item_id: "a.py:1".into(), is_real: true, reachable: reachable.into(),
        abstractable: Some(Abstraction { kind: "sink".into(), category: "file_read".into(), pattern: "x.read".into() }),
        confidence: "high".into(),
    };
    // 3 轮 is_real 全 true，但 reachable 2:1 分裂（2 reachable + 1 unreachable）
    let rounds = vec![
        vec![mk("reachable")],
        vec![mk("reachable")],
        vec![mk("unreachable")],
    ];
    let r = vote(&rounds);
    assert_eq!(r[0].outcome, AdjudicationOutcome::Uncertain);
}
```

- [ ] **Step 2: 运行确认失败**（`cd rust && cargo test -p mcp-sec-audit-core vote_downgrades_on_reachable_split`）

- [ ] **Step 3: 实现**（在现有 `vote` 里，把 Promote/Reject 判定从只看 `is_real` 改为同时看 `reachable` 全票一致）

在 `vote` 里，把 `let all_valid = ...` 的判定扩展：除 `valid_reachable` 外，增加"全票 `reachable == "reachable"`"才允许 Promote；否则 Uncertain。即：

```rust
let all_reachable = vs.iter().all(|v| v.reachable == "reachable");
let outcome = if !all_valid || total != expected {
    AdjudicationOutcome::Uncertain
} else if yes == total && all_reachable {
    AdjudicationOutcome::Promote
} else if yes == 0 {
    AdjudicationOutcome::Reject
} else {
    AdjudicationOutcome::Uncertain
};
```

（若 `total != expected` 已在 Plan 2 落为 Uncertain，保留该判断。）

- [ ] **Step 4: 运行确认通过**

- [ ] **Step 5: 检查既有测试仍绿**（`vote_requires_unanimous_or_downgrades_to_uncertain` 与 `postprocess_stages_connect_...` 的 3 轮全 `reachable` 输入应仍 Promote；2:1 的 `is_real` 分裂测试应仍 Uncertain）

---

### Task 2: rule/prompt 四线落盘

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/learning.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`（接线）
- Test: `learning.rs` 内联

**Interfaces:**
- Consumes: `agent::PromoteAction::Rule(String)` / `Prompt(String)`。
- Produces:
  ```rust
  /// Append rule capabilities to a learned-rulebook file (one "- capability" per line).
  pub fn write_learned_rules(dir: &Path, capabilities: &[String]) -> anyhow::Result<()>;
  /// Append prompt-extra text to a learned-prompt file.
  pub fn write_learned_prompt(dir: &Path, text: &str) -> anyhow::Result<()>;
  ```

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn write_learned_rules_appends_capabilities() {
    let dir = std::env::temp_dir().join(format!("learn-rules-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    write_learned_rules(&dir, &["path_traversal".into()]).expect("write");
    let content = std::fs::read_to_string(dir.join("learned-capabilities.txt")).expect("read");
    assert!(content.contains("- path_traversal"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn write_learned_prompt_writes_text() {
    let dir = std::env::temp_dir().join(format!("learn-prompt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    write_learned_prompt(&dir, "## recheck capability over-exposure\n").expect("write");
    let content = std::fs::read_to_string(dir.join("learned-prompt.md")).expect("read");
    assert!(content.contains("capability over-exposure"));
    std::fs::remove_dir_all(&dir).ok();
}
```

- [ ] **Step 2: 运行确认失败**

- [ ] **Step 3: 实现**（`learning.rs`）

```rust
pub fn write_learned_rules(dir: &Path, capabilities: &[String]) -> anyhow::Result<()> {
    if capabilities.is_empty() { return Ok(()); }
    std::fs::create_dir_all(dir)?;
    let text = capabilities.iter().map(|c| format!("- {c}")).collect::<Vec<_>>().join("\n");
    std::fs::write(dir.join("learned-capabilities.txt"), text)?;
    Ok(())
}

pub fn write_learned_prompt(dir: &Path, text: &str) -> anyhow::Result<()> {
    if text.trim().is_empty() { return Ok(()); }
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("learned-prompt.md"), text)?;
    Ok(())
}
```

- [ ] **Step 4: 接线**（`pipeline.rs` 的持久化 fold 里，把 `Rule`/`Prompt` 分支从 `_ => {}` 改为收集，并在 learned_dir 存在时写盘）

在裁决 loop 里维护 `let mut rules: Vec<String>` 与 `let mut prompt_extra: String`，把 `PromoteAction::Rule(c)` push 进 `rules`、`Prompt(t)` 追加进 `prompt_extra`；在持久化段调用 `write_learned_rules`/`write_learned_prompt`。

- [ ] **Step 5: 运行确认通过**（`cd rust && cargo test -p mcp-sec-audit-core`）

---

### Task 3: promote 合并而非覆盖（保留累积证据）

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/learning.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`（接线）
- Test: `learning.rs` 内联

**Interfaces:**
- Consumes: `SinkModel`（含 `corroboration_count`/`pollution_count`/`last_seen_run`）。
- Produces:
  ```rust
  /// Merge new models into existing by (language, category, pattern): sum
  /// corroboration/pollution counts and take the newer last_seen_run; existing
  /// models not in `new` are preserved. Sorted by pattern for determinism.
  pub fn merge_sink_models(existing: &[SinkModel], new: &[SinkModel]) -> Vec<SinkModel>;
  ```

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn merge_sink_models_preserves_existing_evidence() {
    let mut existing = SinkModel {
        language: "python".into(), category: "file_read".into(),
        severity: crate::Severity::Medium, confidence: crate::Confidence::Medium,
        reason: "t".into(), patterns: vec!["openpyxl.load_workbook".into()],
        source: Some("learned".into()), learned_from: None,
        corroboration_count: 2, pollution_count: 0, last_seen_run: Some("20260821".into()),
    };
    let new = SinkModel {
        language: "python".into(), category: "file_read".into(),
        severity: crate::Severity::Medium, confidence: crate::Confidence::Low,
        reason: "t".into(), patterns: vec!["openpyxl.load_workbook".into()],
        source: Some("learned".into()), learned_from: Some("adjudication".into()),
        corroboration_count: 1, pollution_count: 0, last_seen_run: None,
    };
    let merged = merge_sink_models(&[existing.clone()], &[new]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].corroboration_count, 3); // 2 + 1
    assert_eq!(merged[0].confidence, crate::Confidence::Medium); // existing preserved
}
```

- [ ] **Step 2: 运行确认失败**

- [ ] **Step 3: 实现**

```rust
use std::collections::BTreeMap;

/// Confidence ordering: High(2) > Medium(1) > Low(0). `Confidence` derives
/// only `PartialEq`, not `PartialOrd`, so we rank explicitly.
fn confidence_rank(c: &crate::Confidence) -> u8 {
    match c {
        crate::Confidence::High => 2,
        crate::Confidence::Medium => 1,
        crate::Confidence::Low => 0,
    }
}

fn sink_key(m: &SinkModel) -> String {
    let pat = m.patterns.first().cloned().unwrap_or_default();
    format!("{}:{}:{}", m.language, m.category, pat)
}

pub fn merge_sink_models(existing: &[SinkModel], new: &[SinkModel]) -> Vec<SinkModel> {
    let mut map: BTreeMap<String, SinkModel> = BTreeMap::new();
    for m in existing {
        map.insert(sink_key(m), m.clone());
    }
    for m in new {
        let key = sink_key(m);
        map.entry(key)
            .and_modify(|e| {
                e.corroboration_count += m.corroboration_count;
                e.pollution_count += m.pollution_count;
                if m.last_seen_run.is_some() {
                    e.last_seen_run = m.last_seen_run.clone();
                }
                // 已有模型置信度取较高者（不因新来 low 而降级）
                if confidence_rank(&m.confidence) > confidence_rank(&e.confidence) {
                    e.confidence = m.confidence.clone();
                }
            })
            .or_insert_with(|| m.clone());
    }
    map.into_values().collect()
}
```

- [ ] **Step 4: 接线**（`pipeline.rs` 持久化段，写盘前先加载已有 learned 模型并 merge）

把当前直接 `write_learned_sinks(dir, &sinks)` 改为：先 `load_models_dir(dir)` 取已有 sinks，`merge_sink_models(existing, &sinks)` 得合并结果，再 `write_learned_sinks(dir, &merged)`。（sources/sanitizers 同理，若无对应 merge 函数可先只对 sinks 做，其余保持原覆盖行为并加注释。）

- [ ] **Step 5: 运行确认通过**（`cd rust && cargo test -p mcp-sec-audit-core` 全量）

---

## Self-Review Notes

- **Spec coverage**：覆盖 spec §5.3（vote reachable 一致性）、§6 四线（rule/prompt 落盘）、跨运行累积的"合并不覆盖"。**未覆盖（留待 Plan 4）**：完整 b1/b2 逐模型归因（`evidence.rs` 反查）、staleness retire 接线、benchmark 退化护栏。
- **Type consistency**：`merge_sink_models`/`write_learned_rules`/`write_learned_prompt` 命名一致；`corroboration_count`/`pollution_count`/`last_seen_run` 与 Plan 1 一致。`Confidence` 比较用 match（不依赖 as u8 转换）。
- **Commit policy**：不逐 task commit，最后统一 commit。

## Execution Handoff

计划保存后由 controller 按 subagent-driven 流程执行（不 commit，最后统一 commit）。
