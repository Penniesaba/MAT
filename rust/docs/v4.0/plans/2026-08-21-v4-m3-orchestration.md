# v4.0 M3 两阶段编排 + 真进化固化 实现计划

> **给执行者：** 必用子技能：superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务实现。步骤用复选框跟踪。

**目标：** 把 M2 的三大原语（staging/rollback、prompt'、migrate）接到 pipeline 里，跑通「阶段1 → 门控+staging → 阶段2 → migrate → promote/rollback」的真进化闭环，并让进化后的 catalog **优先喂回 CodeQL（MaD）**、其次 taint。

**架构：** 先把 catalog 装载、CodeQL、agent 三处「内部装配」的隐藏输入抽成显式参数（`load_catalog`、`codeql::run` 接 catalog、`agent::run` 接 prompt 覆盖），再在 `pipeline.rs` 里把单轮扫描改成两阶段。阶段 2 用进化后的 catalog（内存中 base+staged）与 prompt' 重跑 taint/codeql/agent（rule 不变、复用阶段 1 结果），`migrate` 决定固化或回退。

**技术栈：** Rust（edition 2024，rust-version 1.88），workspace crate `mcp-sec-audit-core`，`anyhow`，`tracing`。

**规格：** `rust/docs/v4.0/IDEA_EVALUATION_AND_DESIGN.md`（§5 两阶段路程、§6.3 CodeQL MaD 必须打开、§7.2 门控+试探、§7.3 回滚、§九 映射表）。

## 全局约束

- Rust edition **2024**，`rust-version = "1.88"`；`serde` 固定 `=1.0.224`，不加外部依赖。
- 代码在 `rust/crates/mcp-sec-audit-core/src/static_analysis/`。
- 现有 `tracing` target：`mcp_sec_audit::*`；新增 `mcp_sec_audit::evolution`、`mcp_sec_audit::validate`。
- **CodeQL MaD 在 CLI < 2.26.3 下是 dormant**（M1 已做运行时门控）：阶段 2 的 CodeQL 进化在 2.26.2 下不会生效，会打 warning；taint 的进化**立即可用**。这是预期行为，不是 bug。
- 门控顺序：`gate_sink_candidate`（G1 Hot/Warm/Cold）→ `diff::classify_candidate`（G2 可表达性）→ `stage_catalog_evolution`（G3 试探）。

---

### 任务 1：抽离 catalog 装载 + taint 接受 catalog 覆盖

把 catalog 装配从 `extract_static_facts` 里抽出来，并让 taint 能接收一个外部 catalog（阶段 2 喂进化后的 catalog）。

**文件：**
- 修改：`rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`
- 修改：`rust/crates/mcp-sec-audit-core/src/static_analysis/taint/mod.rs`

**接口：**
- 产出：
  - `facts::load_catalog(&StaticScanContext) -> anyhow::Result<ModelCatalog>`（default + `models_dir` + `learned_dir`）
  - `facts::extract_static_facts_with_catalog(&StaticScanContext, &ModelCatalog) -> anyhow::Result<Vec<Fact>>`
  - `taint::run_with_catalog(&StaticScanContext, &ModelCatalog) -> anyhow::Result<(Vec<TaintAnalysisResult>, Vec<Fact>)>`

- [ ] **步骤 1：写失败的测试（learned_dir 会被装载）**

在 `facts/pipeline.rs` 现有 `mod tests` 追加：

```rust
    #[test]
    fn learned_dir_is_merged_into_catalog() {
        let root = temp_dir("learned-dir-load");
        let learned_dir = root.join("learned");
        fs::create_dir_all(&learned_dir).expect("create learned dir");
        fs::write(
            learned_dir.join("l.toml"),
            "[[sinks]]\nlanguage = \"python\"\ncategory = \"file_read\"\nseverity = \"medium\"\nconfidence = \"low\"\nreason = \"learned\"\npatterns = [\"openpyxl.load_workbook\"]\nsource = \"learned\"\n",
        )
        .expect("write learned model");

        let mut config = RuntimeConfig::default();
        config.static_.learned_dir = Some(learned_dir.display().to_string());
        let ctx = StaticScanContext {
            config,
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        let catalog = load_catalog(&ctx).expect("load catalog");
        assert!(catalog
            .sinks_for_language("python")
            .iter()
            .any(|m| m.patterns.contains(&"openpyxl.load_workbook".to_string())));

        fs::remove_dir_all(root).expect("cleanup");
    }
```

- [ ] **步骤 2：跑一下确认失败**

运行：`cargo test -p mcp-sec-audit-core facts::pipeline::tests::learned_dir_is_merged_into_catalog`
预期：FAIL（`load_catalog` 未定义）。

- [ ] **步骤 3：抽离 load_catalog 并重构 extract_static_facts**

在 `facts/pipeline.rs` 里，把当前 `extract_static_facts` 开头的 catalog 装配抽成 `load_catalog`，并把函数体拆成「带 catalog 参数」的版本：

```rust
/// 装配完整 sink 模型目录：内置 + `models_dir` + `learned_dir`（学到的模型下次运行载回）。
pub(crate) fn load_catalog(ctx: &StaticScanContext) -> Result<ModelCatalog> {
    let mut catalog = default_catalog();
    if let Some(dir) = &ctx.config.static_.models_dir {
        catalog.merge(load_models_dir(std::path::Path::new(dir))?);
    }
    if let Some(dir) = &ctx.config.static_.learned_dir {
        catalog.merge(load_models_dir(std::path::Path::new(dir))?);
    }
    tracing::info!(
        target: "mcp_sec_audit::taint",
        sinks = catalog.sink_count(),
        "sink model catalog ready"
    );
    Ok(catalog)
}

pub fn extract_static_facts(ctx: &StaticScanContext) -> Result<Vec<Fact>> {
    let catalog = load_catalog(ctx)?;
    extract_static_facts_with_catalog(ctx, &catalog)
}

/// 用给定的 catalog（而非重新装载）抽取 facts —— 阶段 2 用它喂进化后的 catalog。
pub(crate) fn extract_static_facts_with_catalog(
    ctx: &StaticScanContext,
    catalog: &ModelCatalog,
) -> Result<Vec<Fact>> {
    let mut facts = Vec::new();
    let mut diagnostics = Vec::new();
    // ... 原 for file in &ctx.discovered_files 循环体不变，继续用 catalog.sinks_for_language(...)
    // ... 原 infer::assemble 调用不变
    Ok(facts)
}
```

（说明：`extract_static_facts_with_catalog` 的函数体就是把原 `extract_static_facts` 里 `let mut catalog = ...` 那段删掉后的剩余部分；`infer::assemble` 那段 `facts.extend(inferred)` 保留在尾部。为避免占位符，执行时按原文件逐行搬运即可。）

- [ ] **步骤 4：taint 加 run_with_catalog**

在 `taint/mod.rs` 里，把 `run` 拆成带 catalog 参数的版本：

```rust
pub fn run(ctx: &StaticScanContext) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)> {
    if !ctx.config.static_.taint.enabled {
        return Ok((Vec::new(), Vec::new()));
    }
    let facts = extract_static_facts(ctx)?;
    let catalog = crate::static_analysis::facts::load_catalog(ctx)?;
    run_with_catalog_inner(ctx, &facts, &catalog)
}

/// 用给定 catalog（阶段 2 喂进化后的）跑 taint：抽取 facts + 跑分析。
pub(crate) fn run_with_catalog(
    ctx: &StaticScanContext,
    catalog: &crate::models::ModelCatalog,
) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)> {
    if !ctx.config.static_.taint.enabled {
        return Ok((Vec::new(), Vec::new()));
    }
    let facts = crate::static_analysis::facts::extract_static_facts_with_catalog(ctx, catalog)?;
    run_with_catalog_inner(ctx, &facts, catalog)
}

fn run_with_catalog_inner(
    ctx: &StaticScanContext,
    facts: &[Fact],
    _catalog: &crate::models::ModelCatalog,
) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)> {
    let (results, dataflow_facts) = run_taint_analysis(facts, &ctx.config.static_.taint)?;
    let mut all_facts = facts.to_vec();
    all_facts.extend(dataflow_facts);
    Ok((results, all_facts))
}
```

- [ ] **步骤 5：跑 facts + taint 测试**

运行：`cargo test -p mcp-sec-audit-core facts:: taint::`
预期：PASS。

- [ ] **步骤 6：提交**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/taint/mod.rs
git commit -m "feat(v4): extract load_catalog and add taint run_with_catalog"
```

---

### 任务 2：`codeql::run` 接受 catalog 参数

让 CodeQL 的 MaD 编译使用传入的 catalog（阶段 2 喂进化后的），而不是硬编码 `default_catalog()`。

**文件：**
- 修改：`rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs`

**接口：**
- 产出：`codeql::run(ctx: &StaticScanContext, catalog: &ModelCatalog, progress) -> Result<CodeqlOutput>`（签名从 `run(ctx, progress)` 改为三参）。

- [ ] **步骤 1：改签名与 MaD 编译**

在 `codeql/mod.rs` 的 `run` 函数：

1. 把签名 `pub fn run(ctx: &StaticScanContext, mut progress: impl FnMut(&str))` 改为：
   `pub fn run(ctx: &StaticScanContext, catalog: &crate::models::ModelCatalog, mut progress: impl FnMut(&str))`
2. 把 `models::write_model_pack_dir(&crate::models::default_catalog(), ctx)` 改为 `models::write_model_pack_dir(catalog, ctx)`。
3. 更新 `run` 函数体里唯一的调用点（pipeline 里目前是 `codeql::run(&ctx, &mut progress)`）——这一步会在任务 4 一起改，先让本文件可编译：把 `codeql::run` 内的递归/调用点不用改，只需确认 `write_model_pack_dir` 现在接收传入的 `catalog`。

- [ ] **步骤 2：跑 codeql 测试（会因 pipeline 调用点编译失败）**

运行：`cargo test -p mcp-sec-audit-core codeql::`
预期：codeql 模块自身测试 PASS，但整体 crate 编译会因 `pipeline.rs` 仍用两参调用 `codeql::run` 而失败。**此时先不修 pipeline，任务 4 统一改。** 为让本任务可独立提交，把 pipeline 里 `codeql::run(&ctx, &mut progress)` 暂时改成 `codeql::run(&ctx, &crate::models::default_catalog(), &mut progress)`（等价行为），随本任务提交。

- [ ] **步骤 3：确认编译 + 测试**

运行：`cargo build -p mcp-sec-audit-core && cargo test -p mcp-sec-audit-core codeql::`
预期：PASS。

- [ ] **步骤 4：提交**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs
git commit -m "feat(v4): codeql::run accepts a catalog parameter"
```

---

### 任务 3：`agent::run` 接受 prompt 覆盖

让 agent 能用注入 a1/a2 的 prompt'（阶段 2），而不是固定渲染基础模板。

**文件：**
- 修改：`rust/crates/mcp-sec-audit-core/src/static_analysis/agent/mod.rs`

**接口：**
- 产出：`agent::run_with_prompt(ctx: &StaticScanContext, prompt_extra: Option<&str>) -> Result<AgentOutput>`；`run(ctx)` 变成 `run_with_prompt(ctx, None)` 的包装。

- [ ] **步骤 1：拆出带 prompt 参数的版本**

在 `agent/mod.rs`，把 `run` 拆成：

```rust
pub fn run(ctx: &StaticScanContext) -> Result<AgentOutput> {
    run_with_prompt(ctx, None)
}

/// 跑 agent，可选地在渲染好的基础 prompt 之后追加一段验证提示词（阶段 2 的 prompt'）。
pub(crate) fn run_with_prompt(
    ctx: &StaticScanContext,
    prompt_extra: Option<&str>,
) -> Result<AgentOutput> {
    let agent_config = &ctx.config.static_.agent;
    if !agent_config.enabled {
        return Ok(AgentOutput { findings: Vec::new(), model_candidates: Vec::new() });
    }
    // ... 原 run() 的文件摘要、target_root、prompt 渲染逻辑不变 ...
    let mut prompt = prompt::render(
        agent_config.prompt_template_path.as_deref(),
        &file_summaries,
        &target_root,
    )?;
    if let Some(extra) = prompt_extra {
        prompt.push_str(extra);
    }
    // ... 原 provider 调用、解析逻辑不变，用 `prompt` ...
}
```

（说明：就是把原 `run()` 函数体里 `let prompt = prompt::render(...)` 改成 `let mut prompt`，并在其后加 `if let Some(extra)` 追加；`run` 变成包装函数。）

- [ ] **步骤 2：确认编译 + 测试**

运行：`cargo build -p mcp-sec-audit-core && cargo test -p mcp-sec-audit-core agent::`
预期：PASS。

- [ ] **步骤 3：提交**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/agent/mod.rs
git commit -m "feat(v4): agent::run accepts a verification prompt override"
```

---

### 任务 4：两阶段编排 + promote/rollback（`pipeline.rs`）

把单轮扫描改成两阶段进化闭环。这是 M3 的核心。

**文件：**
- 修改：`rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`

**接口：**
- 消费：`learning::{stage_catalog_evolution, write_staging, rollback_staging, write_learned_sinks, gate_sink_candidate, GateDecision}`、`diff::{diff_lines, classify_candidate, Representability}`、`validate::migrate`、`prompt::render_verification_prompt`、`facts::load_catalog`、`taint::run_with_catalog`、`codeql::run(.., catalog, ..)`、`agent::run_with_prompt`。
- 产出：无新公开 API（内部编排）。

- [ ] **步骤 1：在 pipeline 顶部加 imports**

```rust
use crate::models::{default_catalog, ModelCatalog};
use crate::static_analysis::facts::load_catalog;
```

并把 `use super::{...}` 扩展为包含 `validate`、`component`：

```rust
use super::{agent, codeql, diff, fusion, learning, rule, taint, validate, DiscoveredFile, discover_files};
```

- [ ] **步骤 2：重构 run_static_scan_with_progress 为两阶段**

把 `run_static_scan_with_progress` 里「四线并行跑」之后的流程替换成下面结构（保留 discovery / rulebook / ctx 构建不变）：

```rust
    let base_catalog = load_catalog(&ctx)?;

    // ---------- 阶段 1：基线运行 ----------
    let rule_results = /* 原 rule::run(&ctx, loaded_rulebook.as_ref()) 不变 */;
    let (taint_results_1, facts_1) = taint::run_with_catalog(&ctx, &base_catalog)?;
    let agent_output_1 = agent::run(&ctx)?;
    let codeql_output_1 = codeql::run(&ctx, &base_catalog, &mut progress)?;

    // ---------- 门控 + 试探性进化 ----------
    let rules = crate::models::default_package_rules();
    let gated: Vec<ModelCandidate> = agent_output_1.model_candidates.iter()
        .filter(|c| c.kind == "sink"
            && matches!(learning::gate_sink_candidate(c, &rules),
                        learning::GateDecision::Hot | learning::GateDecision::Warm)
            && matches!(diff::classify_candidate(c),
                        diff::Representability::MadSink | diff::Representability::TaintModel))
        .cloned()
        .collect();

    let diff_1 = diff::diff_lines(
        rule_results.clone(), taint_results_1.clone(),
        agent_output_1.findings.clone(), codeql_output_1.results.clone(),
        ctx.config.fusion.line_proximity,
    );

    // 无进化可做时，直接用阶段 1 结果走旧流程（融合 + 冷持久化），返回。
    let Some(staged) = learning::stage_catalog_evolution(&base_catalog, &gated) else {
        progress("Differential: no evolution candidates — skipping phase 2");
        return finish(ctx, rule_results, taint_results_1, agent_output_1, codeql_output_1, facts_1, progress);
    };

    // 进化后的 catalog（内存中 base + staged）
    let mut evolved_catalog = base_catalog.clone();
    evolved_catalog.merge(crate::models::ModelCatalog::from_sinks(staged.models.clone()));
    // 写 staging（可观测 / 回退锚点）
    let staging_dir = std::env::temp_dir().join(format!("mcp-sec-audit-staging-{}", std::process::id()));
    learning::write_staging(&staging_dir, &staged)?;

    // 验证提示词：把阶段 1 的 a-only 全量作为「请复核」项（a1/a2 此时混沌，无法区分）
    let recheck: Vec<prompt::PromptFinding> = diff_1.a_only.iter().filter_map(|g| {
        let key = /* 从 g 取首个 rule/taint/codeql 的 file:line + category */;
        Some(prompt::PromptFinding { location: key.0, category: key.1, note: String::new() })
    }).collect();
    let prompt_extra = if recheck.is_empty() { None }
        else { Some(prompt::render_verification_prompt("", &recheck, &[])) };

    // ---------- 阶段 2：进化后重跑（rule 复用） ----------
    let (taint_results_2, facts_2) = taint::run_with_catalog(&ctx, &evolved_catalog)?;
    let agent_output_2 = agent::run_with_prompt(&ctx, prompt_extra.as_deref())?;
    let codeql_output_2 = codeql::run(&ctx, &evolved_catalog, &mut progress)?;

    let diff_2 = diff::diff_lines(
        rule_results.clone(), taint_results_2.clone(),
        agent_output_2.findings.clone(), codeql_output_2.results.clone(),
        ctx.config.fusion.line_proximity,
    );

    // ---------- 迁移校验 + 固化/回退 ----------
    let migration = validate::migrate(&diff_1, &diff_2);
    tracing::info!(target: "mcp_sec_audit::validate", ?migration, "cross-stage migration");

    let (final_taint, final_agent, final_codeql, final_facts) =
        if migration.should_rollback() {
            learning::rollback_staging(&staging_dir)?;
            tracing::warn!(target: "mcp_sec_audit::evolution",
                "evolution polluted standard line — rolling back staged models");
            (taint_results_1, agent_output_1, codeql_output_1, facts_1)
        } else {
            if let Some(dir) = &ctx.config.static_.learned_dir {
                learning::write_learned_sinks(std::path::Path::new(dir), &staged.models)?;
            }
            tracing::info!(target: "mcp_sec_audit::evolution",
                learned = staged.models.len(), "promoted staged models to learned");
            (taint_results_2, agent_output_2, codeql_output_2, facts_2)
        };

    finish(ctx, rule_results, final_taint, final_agent, final_codeql, final_facts, progress)
```

其中 `finish` 是把现有「融合 + 汇总 + 冷持久化 + 构造 StaticAnalysisResult」的后半段抽成的一个私有函数（签名：`fn finish(ctx, rule, taint, agent_out, codeql_out, facts, progress) -> Result<StaticAnalysisResult>`）。它内部沿用现有 fusion、summary、`write_learned_sinks` 之外的冷持久化逻辑——**注意**：原「冷持久化」步骤（Phase 5 的 `write_learned_sinks`）在 M3 已由上面的 promote 承担，`finish` 里不要再重复写 learned（否则会双写）。

- [ ] **步骤 3：抽 finish 辅助函数**

把 `run_static_scan_with_progress` 后半段（fusion → diff 分区日志 → summary → 构造 `StaticAnalysisResult`）抽成 `fn finish(...)`，去掉其中的冷持久化写盘（promote 已接管），保留 `diff_lines` 分区日志（作为最终报告的分区）。`empty_result` 与 `disabled` 分支保持原样。

- [ ] **步骤 4：编译 + 全量测试**

运行：`cargo build -p mcp-sec-audit-core && cargo test -p mcp-sec-audit-core`
预期：PASS，0 警告（残留的 `#[allow(dead_code)]` 若仍未接线则按需要补注释）。

- [ ] **步骤 5：提交**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs
git commit -m "feat(v4): two-phase evolution orchestration with promote/rollback"
```

---

## 自审记录

- **规格覆盖**：任务 1-3 ↔ §九映射表（taint 三类模型、codeql MaD、prompt 覆盖的管道打通）；任务 4 ↔ §5 两阶段路程 + §7.2/§7.3 + §6.3。§7.1 的 L0 round-trip 实验 = 阶段 2 重跑；L1 = `migrate`。
- **占位符**：任务 1/2/3/4 中「原函数体不变/搬运」处是**忠实复用现有代码**而非占位符——执行者按文件原文搬运，计划已给出新签名与关键差异。
- **类型一致性**：`load_catalog`/`run_with_catalog`/`codeql::run(.., catalog, ..)`/`run_with_prompt`/`stage_catalog_evolution`/`migrate`/`render_verification_prompt` 的签名与 M2 定义一致。
- **已知环境缺口**：CodeQL MaD 在 CLI 2.26.2 下 dormant，阶段 2 的 CodeQL 进化不生效（有 warning），taint 进化立即生效；升级到 2.26.3+ 后 CodeQL 进化自动激活。
- **刻意简化**：a1/a2 在阶段 1 混沌，故 prompt' 只把 a-only 全量放入「请复核」段（`do_not_report` 留空）；a1/a2 的区分交给阶段 2 的 migrate 结果。

---

## 执行交接

计划完成，保存于 `rust/docs/v4.0/plans/2026-08-21-v4-m3-orchestration.md`。**等你审阅/批准后再实现。**
