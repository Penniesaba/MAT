# Self-Evolution Completion (合并补全 + 四线累积) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 补全 Plan 3 遗留的 TODO(plan4)：sources/sanitizers 也做 load-merge-write（不再覆盖），rule/prompt 跨运行累积（append 而非覆盖）。

**Architecture:** 两个独立任务，均落在 `learning.rs` + `pipeline.rs`。Task 1 为 source/sanitizer 增加 `merge_source_models`/`merge_sanitizer_models` 并在 pipeline 接线；Task 2 把 `write_learned_rules`/`write_learned_prompt` 从覆盖改为追加。

**Tech Stack:** Rust, serde, anyhow.

**Spec:** `rust/docs/v4.0/SELF_EVOLUTION_SELF_CONSISTENT_DESIGN_20260824.md`

## Global Constraints

- Rust crate：`mcp-sec-audit-core`。测试：`cd rust && cargo test -p mcp-sec-audit-core <filter>`。
- **不逐 task commit**（用户要求统一提交）。实现者不 `git commit`；controller 最后统一 commit。
- 新字段/类型 `#[serde(default)]` 向后兼容；旧 learned TOML 仍能加载。
- 不触碰 fusion。
- `SourceModel`/`SanitizerModel` **无 `confidence` 字段**（只有 `SinkModel` 有）——merge 时不要比较 confidence。

---

### Task 1: sources/sanitizers 合并（load-merge-write）

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/learning.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`
- Test: `learning.rs` 内联

**Interfaces:**
- Consumes: `SourceModel`/`SanitizerModel`（含 `corroboration_count`/`pollution_count`/`last_seen_run`）。
- Produces:
  ```rust
  pub fn merge_source_models(existing: &[SourceModel], new: &[SourceModel]) -> Vec<SourceModel>;
  pub fn merge_sanitizer_models(existing: &[SanitizerModel], new: &[SanitizerModel]) -> Vec<SanitizerModel>;
  ```

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn merge_source_models_preserves_evidence() {
    let existing = SourceModel {
        language: "python".into(), category: "env_var".into(), patterns: vec!["os.environ".into()],
        source: Some("learned".into()), learned_from: None,
        corroboration_count: 2, pollution_count: 1, last_seen_run: Some("20260821".into()),
    };
    let new = SourceModel {
        language: "python".into(), category: "env_var".into(), patterns: vec!["os.environ".into()],
        source: Some("learned".into()), learned_from: Some("adjudication".into()),
        corroboration_count: 1, pollution_count: 0, last_seen_run: None,
    };
    let merged = merge_source_models(&[existing], &[new]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].corroboration_count, 3);
    assert_eq!(merged[0].pollution_count, 1);
}
```

- [ ] **Step 2: 运行确认失败**

- [ ] **Step 3: 实现**（`learning.rs`，与 `merge_sink_models` 同构，但无 confidence 比较；key 用 language:category:patterns.first()）

```rust
fn source_key(m: &SourceModel) -> String {
    let pat = m.patterns.first().cloned().unwrap_or_default();
    format!("{}:{}:{}", m.language, m.category, pat)
}

pub fn merge_source_models(existing: &[SourceModel], new: &[SourceModel]) -> Vec<SourceModel> {
    let mut map: BTreeMap<String, SourceModel> = BTreeMap::new();
    for m in existing { map.insert(source_key(m), m.clone()); }
    for m in new {
        map.entry(source_key(m))
            .and_modify(|e| {
                e.corroboration_count += m.corroboration_count;
                e.pollution_count += m.pollution_count;
                if m.last_seen_run.is_some() { e.last_seen_run = m.last_seen_run.clone(); }
            })
            .or_insert_with(|| m.clone());
    }
    map.into_values().collect()
}

fn sanitizer_key(m: &SanitizerModel) -> String {
    let pat = m.patterns.first().cloned().unwrap_or_default();
    format!("{}:{}:{}", m.language, pat, m.neutralizes.join(","))
}

pub fn merge_sanitizer_models(existing: &[SanitizerModel], new: &[SanitizerModel]) -> Vec<SanitizerModel> {
    let mut map: BTreeMap<String, SanitizerModel> = BTreeMap::new();
    for m in existing { map.insert(sanitizer_key(m), m.clone()); }
    for m in new {
        map.entry(sanitizer_key(m))
            .and_modify(|e| {
                e.corroboration_count += m.corroboration_count;
                e.pollution_count += m.pollution_count;
                if m.last_seen_run.is_some() { e.last_seen_run = m.last_seen_run.clone(); }
            })
            .or_insert_with(|| m.clone());
    }
    map.into_values().collect()
}
```

- [ ] **Step 4: 接线**（`pipeline.rs` 持久化段，把 sources/sanitizers 的 `TODO(plan4)` 覆盖改为 load-merge-write，与 sinks 相同模式：`load_models_dir` → 提取 sources/sanitizers → merge → write）

- [ ] **Step 5: 运行确认通过**（`cd rust && cargo test -p mcp-sec-audit-core`）

---

### Task 2: rule/prompt 跨运行累积（append）

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/learning.rs`
- Test: `learning.rs` 内联

**Interfaces:**
- Consumes: 无。
- Produces: `write_learned_rules`/`write_learned_prompt` 现改为追加（读旧内容，去重/拼接，写回）。

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn write_learned_rules_accumulates_across_calls() {
    let dir = std::env::temp_dir().join(format!("learn-rules-acc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    write_learned_rules(&dir, &["path_traversal".into()]).expect("w1");
    write_learned_rules(&dir, &["command_execution".into(), "path_traversal".into()]).expect("w2");
    let content = std::fs::read_to_string(dir.join("learned-capabilities.txt")).expect("read");
    assert!(content.contains("- path_traversal"));
    assert!(content.contains("- command_execution"));
    // dedup: path_traversal 不重复
    assert_eq!(content.matches("- path_traversal").count(), 1);
    std::fs::remove_dir_all(&dir).ok();
}
```

- [ ] **Step 2: 运行确认失败**（第一次写后第二次调用当前会覆盖，`command_execution` 缺失）

- [ ] **Step 3: 实现**（`learning.rs`，改为读-改-写）

```rust
pub fn write_learned_rules(dir: &Path, capabilities: &[String]) -> anyhow::Result<()> {
    if capabilities.is_empty() { return Ok(()); }
    std::fs::create_dir_all(dir)?;
    let path = dir.join("learned-capabilities.txt");
    let mut existing: Vec<String> = if path.exists() {
        std::fs::read_to_string(&path)?
            .lines()
            .filter_map(|l| l.strip_prefix("- ").map(str::to_string))
            .collect()
    } else {
        Vec::new()
    };
    let mut seen: std::collections::BTreeSet<String> = existing.iter().cloned().collect();
    for c in capabilities {
        if seen.insert(c.clone()) { existing.push(c.clone()); }
    }
    let text = existing.iter().map(|c| format!("- {c}")).collect::<Vec<_>>().join("\n");
    std::fs::write(&path, text)?;
    Ok(())
}

pub fn write_learned_prompt(dir: &Path, text: &str) -> anyhow::Result<()> {
    if text.trim().is_empty() { return Ok(()); }
    std::fs::create_dir_all(dir)?;
    let path = dir.join("learned-prompt.md");
    let mut content = if path.exists() { std::fs::read_to_string(&path)? } else { String::new() };
    if !content.is_empty() && !content.ends_with('\n') { content.push('\n'); }
    content.push_str(text);
    std::fs::write(&path, content)?;
    Ok(())
}
```

- [ ] **Step 4: 运行确认通过**（`cd rust && cargo test -p mcp-sec-audit-core` 全量）

---

## Self-Review Notes

- **Spec coverage**：覆盖 §6 四线（rule/prompt 累积）与跨运行累积的 source/sanitizer merge。**未覆盖（未来工作）**：完整 b1/b2 逐模型归因、staleness retire、benchmark 退化护栏。
- **Type consistency**：`merge_source_models`/`merge_sanitizer_models` 与 `merge_sink_models` 同构；`corroboration_count`/`pollution_count`/`last_seen_run` 与 Plan 1 一致。source/sanitizer 无 confidence（不比较）。
- **Commit policy**：不逐 task commit，最后统一 commit。

## Execution Handoff

计划保存后由 controller 按 subagent-driven 流程执行（不 commit，最后统一 commit）。
