# v5.0 并行多仓库分析 —— 实现进度自检报告

**日期：** 2026-08-31
**规格：** `PARALLEL_MULTI_REPO_DESIGN_20260825.md`（设计文档）、`plans/2026-08-25-v5-parallel-orchestration.md`（实现计划，任务 0–14）
**自检方式：** 对照设计文档 §2 阻塞点与实现计划任务清单逐项核对，并在 `v5-parallel-orchestration` worktree 中实测 build / test / clippy。

---

## 0. 一句话结论

**v5.0 的最初设想（单进程内 tokio 全链路 async 并行分析 N 个仓库 + 跨仓库共享学习总线）已完整实现并通过全部测试。** 另在其上叠加了一个设计于 08-26 的「20 项已知漏洞 MCP 基准」扩展（`bench` 子命令），代码与数据也均已落地。

⚠️ 但实现**尚未合并到 `master`**——它位于分支 `worktree-v5-parallel-orchestration` 的一个 **locked worktree**（`.claude/worktrees/v5-parallel-orchestration/`）中，`master` 上只有 08-25 提交的设计文档与扫描结果。详见 §4 遗留事项。

---

## 1. 实现进度自检

### 1.1 里程碑对照表（实现计划任务 0–14 → 提交 → 状态）

| 任务 | 内容 | 对应提交（`worktree-v5-parallel-orchestration`） | 状态 |
|---|---|---|---|
| 0 | CodeQL 缺失改为 `Err` 而非 `panic!` | `5231220` | ✅ |
| 1 | 黄金回归基线（golden fixture + 归一化） | `9d90eaa` `e9b17f4` `10d6923` | ✅ |
| 2 | `runctx.rs`：RunId / Progress / RunContext | `c642ed1` `dcaef8c` | ✅ |
| 3 | `run_id` 进 `StaticScanContext` | `49de856` | ✅ |
| 4 | 临时路径按 RunId 键控 + 删除不安全 DB 复用缓存 | `0d121fa` `2df5a0d` | ✅ |
| 5 | `Progress` 取代 `impl FnMut(&str)` | `212a413` | ✅ |
| 6 | 两个 provider 异步化（超时真杀子进程） | `aad4690` | ✅ |
| 7 | 管线异步化 + 同步兼容外壳 | `dcfb71b` `71dc867` | ✅ |
| 8 | 批次配置 + 每仓库覆盖深合并 | `6bb06eb` | ✅ |
| 9 | 资源限流器（分级信号量） | `43fc1ab` `3901e68` | ✅ |
| 10 | 学习总线（单写者 actor + 入场快照） | `a2a63ad` `dbbe50b` | ✅ |
| 11 | 批次汇总 + `<repo>` 占位符 | `2eaa729` | ✅ |
| 12 | 编排器（JoinSet + governor + bus） | `d14db94` `10a36c1` | ✅ |
| 13 | CLI `batch` 子命令 + 取消 + 退出码 | `9f0fe38` `7a1361d` `31a0400` | ✅ |
| 14 | 文档索引（README 补 v4.0 / v5.0 行） | 已并入 `master` `4a5cd89` | ✅ |

**14/14 任务全部完成**，无未实现的 TBD。

### 1.2 阻塞点解决对照表（设计文档 §2 的 6 个阻塞点）

| # | 阻塞点 | 解决方案 | 核实位置 | 状态 |
|---|---|---|---|---|
| 2.1 | 临时路径按 PID 键控，同进程并行相撞 | `RunId::temp_dir(kind)` 统一出口 | `runctx.rs:47` | ✅ |
| 2.2 | `learned_dir` 读-改-写丢失更新 | 单写者 actor 串行化 merge + 原子持久化 | `batch/learning_bus.rs` | ✅ |
| 2.3 | 超时孤儿进程（并行放大 OOM） | `tokio::process` + `.kill_on_drop(true)` + `timeout` | `agent/provider.rs:93`、`codeql/provider.rs:97/220` | ✅ |
| 2.4 | CodeQL CLI 缺失 panic | 改为 `anyhow::bail!` | `codeql/mod.rs`（第 79 行 panic 已移除） | ✅ |
| 2.5 | `scan_identifier` 并发撞车 | 并入 `run_id` | `pipeline.rs` | ✅ |
| 2.6 | 全局日志订阅器无法区分来源 | span 带 `repo` 字段，`ModuleFormat` 输出 `[repo]` 前缀 | `cli/src/logging.rs` | ✅ |

其中危害最高的 2.1「后到仓库静默复用前一个仓库的 CodeQL DB」——该缓存已整段删除，`create_database` 每次按 run-id 独立建库。

### 1.3 实测结果（在 worktree 内执行）

| 检查 | 命令 | 结果 |
|---|---|---|
| 编译 | `cargo build --workspace` | ✅ 通过 |
| 单元 + 集成 + 黄金回归 | `cargo test --workspace` | ✅ **387 passed / 0 failed / 1 ignored**（详见 §2） |
| lint | `cargo clippy --workspace -- -D warnings` | ⚠️ 34 个 lint 报错（见 §4） |

测试分解：
- `mcp-sec-audit-core`（lib 单测）：371 passed，1 ignored
- `tests/golden_regression.rs`：2 passed（`golden_python_mcp_server_result_is_stable`、`golden_agent_evolution_result_is_stable`）
- `mcp-sec-audit-cli`（main 单测）：13 passed
- `tests/bench_smoke.rs`：1 passed

### 1.4 最初设想达成度

设计文档 §0 的两个驱动力均已落地并被测试覆盖：

1. **异构阶段重叠**：`orchestrator` 用 `max_parallel` 信号量（每仓库整任务一张许可）+ `ResourceGovernor` 分级信号量（codeql / agent / cpu）实现并行受控；CPU 密集阶段经 `spawn_blocking` 卸载，codeql/agent 子进程异步等待——`governor_caps_peak_concurrency_per_class` 测试断言 codeql 峰值并发被压到 1。
2. **学习协同**：`LearningBus` actor 独占 `learned_dir` 写权，仓库入场取快照、固化时回投证据；`bus_merges_evidence_across_repos` 测试断言两个仓库各自发现同一 sink 时 corroboration 累加到 2。

**结论：达到最初设想。** 规格 §5–§10 的 RunId / 限流 / 学习总线 / 批次配置 / 报告 / 失败与取消语义，均已按设计落地。

---

## 2. 运行测试的命令

```bash
cd rust

# 全量测试（workspace 两个 crate + 集成 + 黄金回归 + bench 冒烟）
cargo test --workspace

# 只跑黄金回归基线（async 迁移的行为一致性安全网）
cargo test -p mcp-sec-audit-core --test golden_regression

# 只跑批次/学习总线/限流器相关单测
cargo test -p mcp-sec-audit-core batch::

# lint（注意：rustc 1.97.1 下当前有 34 个告警，见 §4.3）
cargo clippy --workspace -- -D warnings
```

---

## 3. v5.0 代码架构简述

仍是 `rust/` 下的双 crate workspace（`mcp-sec-audit-core` 库 + `mcp-sec-audit-cli` 入口），v5.0 在其上新增并发与协同层，**未改动 v4 仓库内部的两阶段自进化语义**。

### 3.1 新增模块

```
mcp-sec-audit-core/src/
├── runctx.rs                 # RunId / Progress / RunContext（身份与运行期管道，无业务逻辑）
├── batch/
│   ├── config.rs             # BatchConfig / RepoConfig / LimitsConfig + 深合并（纯函数，重点单测）
│   ├── governor.rs           # ResourceClass + ResourceGovernor（codeql/agent/cpu 三级信号量）
│   ├── learning_bus.rs       # 单写者 actor：Promote / Snapshot，原子持久化（temp+rename）
│   ├── orchestrator.rs       # run_batch：JoinSet + 懒分发 + 每仓库 current-thread runtime
│   └── summary.rs            # BatchSummary / BatchRepoSummary + json/markdown 渲染
├── bench/                    # 【v5 之上的扩展】20 项 MCP 漏洞基准
│   ├── manifest.rs           #   语料清单 schema（20 项，SSH URL + 锁定 commit + 语言 + 作用域）
│   ├── ground_truth.rs       #   ground-truth schema（sink 行 + CWE + 类别 + evidence_tier）
│   ├── scorer.rs             #   sink 行对齐 + TP/FP/unconfirmed 三分类 + P/R/F1
│   ├── report.rs             #   metrics.json / metrics.md
│   └── mod.rs                #   run_bench（把 manifest 翻译成 batch 配置 → 复用 run_batch → 打分）
└── static_analysis/          # 既有分析管线，async 化
    ├── pipeline.rs           #   run_static_scan_async + 同步外壳（run_static_scan / _with_progress）
    ├── agent/provider.rs     #   tokio::process + kill_on_drop + timeout
    └── codeql/provider.rs    #   同上

mcp-sec-audit-cli/src/
├── main.rs                   # 子命令：status/config/rules/report/batch/bench + 单仓库位置参数
├── batch.rs                  # 薄层：加载 BatchConfig → 装 Ctrl-C → 调 core
├── bench.rs                  # 薄层：加载 manifest → 调 core::run_bench
└── logging.rs                # ModuleFormat 读取 span 的 repo 字段，输出 <时间> [repo] 模块: 消息
```

### 3.2 关键类型

- **`RunId`**：`uuid v4`，`for_repo(batch_id, repo)` 生成确定性子 id（sanitize + 短哈希防碰撞）。`temp_dir(kind)` 是所有 run 键控临时目录（`codeql`/`sarif`/`mad`/`staging`）的唯一出口。
- **`Progress`**：可克隆的进度上报器，四种后端——`tracing`（单仓库实时）、`channel`（批次聚合后带 `[repo]` 前缀统一输出）、`closure`（同步桥接）、`noop`。
- **`RunContext`**：携带 `run_id` + `progress` + `cancel` + `governor?` + `learning_bus?`。单仓库模式二者为 `None`，保持与 v4 字节一致；`cleanup()` 统一回收 run 键控临时目录。
- **`ResourceGovernor`**：三个 `Arc<Semaphore>`，防死锁不变量「任一时刻最多持有一类许可，绝不跨类申请」以独立作用域 + `OwnedSemaphorePermit` RAII 保证。
- **`LearningBusHandle`**：actor 独占 `learned_dir` 写权，`promote` 恒 merge 既有证据（修复设计 §7.3 隐患 1），`snapshot` 供仓库入场取一次快照。

### 3.3 批次数据流

```
mcp-sec-audit batch batch.toml
  └─ cli/main.rs  为 batch 单独构建 multi-thread runtime + CancellationToken + ctrl_c
      └─ core/batch/orchestrator::run_batch(cfg, cancel)
           ├── LearningBus actor（若 learning_bus=true，加载 learned_dir 一次）
           ├── ResourceGovernor::new(limits)
           ├── Progress::channel() + drain task（统一输出带 [repo] 前缀）
           ├── max_parallel 信号量（每仓库任务持一张许可，控制同时运行的仓库数）
           └── 懒分发：每个仓库一个 current-thread runtime + spawn_blocking
                 └─ run_repo：merge_repo_config → run_static_scan_async
                      ├─ 入场快照 ← bus.snapshot()
                      ├─ 阶段1（rule→taint→agent→codeql，G1/G2 门控）→ diff_1
                      ├─ 阶段2 → diff_2 → validate::migrate → L2/L3 裁决
                      ├─ promote → bus.promote()  或  rollback（只删自己 staging）
                      └─ 写每仓库报告 + run_ctx.cleanup()
           └─ 写 batch-summary.md / batch-summary.json（含 learning_bus_enabled 字段）
```

> 设计要点：`async` 管线 future 持 `tracing::EnteredSpan` 是 `!Send`，无法直接进多线程 runtime 的 `JoinSet::spawn`，故编排器为每个仓库构建独立 `current_thread` runtime 并放在 `spawn_blocking` 里，用 `max_parallel` 许可把阻塞线程数封顶到 `max_parallel`（`orchestrator.rs:172-226` 注释详述）。

---

## 4. 遗留事项与偏差（诚实声明）

1. **未合并 master**。v5.0 实现 + bench 全部在分支 `worktree-v5-parallel-orchestration`（HEAD `b0ef8e1`），位于 `.claude/worktrees/v5-parallel-orchestration/` 的 **locked worktree**（遗留了一个 Claude 会话锁：`claude session v5-parallel-orchestration (pid 3133315)`）。`master` 停留在 `4a5cd89`，仅有设计文档与 08-25 扫描结果。合入前需解锁 worktree、跑黄金回归、再决定是否 squash/merge。

2. **`CURRENT_PHASE` 未 bump**。仍是 `phase13-static-result-fusion`（`lib.rs:51`），设计 §13 问题 6「是否 bump 为 `phase14-batch-parallel`」未落实——纯命名遗留，无功能影响。

3. **clippy 不绿（当前工具链）**。`rustc 1.97.1` 下 `cargo clippy --workspace -- -D warnings` 有 **34 个 lint 报错**，全部为风格类（`if` 可折叠 16、`map_or`→`is_none_or` 2、`impl` 可 derive 3、闭包冗余 3、复杂类型 2，及若干 1 次项）。workspace 声明 `rust-version = "1.88"`，这些 lint 是 1.88 之后的 clippy 新增/收紧的，**不影响编译与测试**；若以 1.88 工具链复核或按 lint 逐个修掉即可回到「clippy 全绿」的计划门槛。多数报错在既有 v4 代码（如 `taint/propagation.rs`），非 v5 新增逻辑引入。

4. **`main()` 未改 `#[tokio::main]`**。实现计划任务 13 步骤 1 原写「`fn main` 改 `#[tokio::main]`」，实际改为仅对 `batch`/`bench` 子命令就地构建 `multi_thread` runtime（`main.rs:158-161`）。这是一处有意的工程取舍：单仓库路径依赖 `block_on` 桥接 async 管线，而在已激活的 runtime 线程内 `block_on` 会 panic，故保留同步 `main`。属对计划的合理偏离，且行为等价。

5. **bench 扩展的定位**。`bench`（20 项已知漏洞 MCP 基准，设计文档 `docs/superpowers/specs/2026-08-26-mcp-vuln-benchmark-design.md`）不属于 v5.0 并行多仓库的最初设想，而是其上的次日（08-26）后续设计。当前**代码与数据均已落地**：`benchmark/manifest.toml`（20 项 commit 全部锁定真实 SHA）、`ground-truth.toml`（22 条 sink 行全部核定）、`corpus/`（20 个仓库已 clone）、`bench_smoke` 测试通过。可直接跑 `cargo run -- bench --manifest ../benchmark/manifest.toml` 打分。

---

## 5. 运行命令

```bash
cd rust

# —— v5.0 核心交付：批量并行分析多个仓库 ——
cargo run -- batch ../test-targets/configs/batch-example.toml

# —— 单仓库（位置参数，v4 行为不变）——
cargo run -- ../test-targets/configs/all-languages-config.toml

# —— 基准打分（v5 之上的扩展）——
cargo run -- bench --manifest ../benchmark/manifest.toml            # 默认 ±5 行容差、并发 4
cargo run -- bench --manifest ../benchmark/manifest.toml --tolerance 5 --max-parallel 4

# —— 其他子命令 ——
cargo run -- status
cargo run -- config validate --config <config.toml>
cargo run -- rules validate --rules <rulebook.toml>
cargo run -- report demo --format markdown
```

批次配置示例 `test-targets/configs/batch-example.toml` 的关键语义：

- `[batch].max_parallel`：同时运行的仓库数上限（整任务许可）。
- `[batch].learning_bus`：`true` 共享学习总线（后启动仓库吃到先完成仓库成果）；`false` 各仓库隔离（可重现评测基线）。
- `[batch].fail_fast`：首个仓库失败即中止批次。
- `[batch.limits]`：codeql/agent/cpu 三级并发上限。
- 其余顶层表（`[scan]`/`[static]`/`[report]`/`[fusion]`…）为共享基座，语法与单仓库 config 一致；每个 `[[batch.repo]]` 用 `name`/`path` + 任意嵌套覆盖描述一个仓库。

退出码：`0` 全部成功；`1` ≥1 仓库失败/取消；`2` 配置错误；`130` Ctrl-C 取消。
