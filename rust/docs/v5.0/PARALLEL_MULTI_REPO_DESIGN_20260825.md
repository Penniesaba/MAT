# v5.0 并行多仓库静态分析 设计文档

**日期：** 2026-08-25
**范围：** 单进程内并行分析 N 个 MCP 源码仓库（tokio 异步重构 + 跨仓库学习总线）
**前身：** `rust/docs/v4.0/IDEA_EVALUATION_AND_DESIGN.md`（两阶段差分自进化）、`SELF_EVOLUTION_SELF_CONSISTENT_DESIGN_20260824.md`（自洽裁决）
**本版要点：** 并发承载从「无」到 tokio 全链路 async；`learned_dir` 从「每进程独占」升级为「单写者 actor + 入场快照」，使同批次仓库互相增强检测能力。

---

## 0. 摘要

v4.0 把系统做成了会自进化的单仓库分析器。v5.0 解决的是**吞吐与协同**：让一次运行同时分析多个 MCP 仓库，并让它们共享学习成果。

驱动力有二：

1. **资源利用率。** 管线里最耗时的两个阶段资源性质正交 —— CodeQL 是 CPU 密集（`database create` 自身多线程 + 数 GB 内存），Agent 是网络延迟密集（等 `claude` CLI 返回）。串行执行时，等 Agent 的几分钟内 CPU 完全闲置。并行的收益主要来自**异构阶段重叠**，而非线程数本身。
2. **学习协同。** v4 的 `learned_dir` 是跨运行累积的冷持久化。若多个仓库在同一批次内并行且共享该目录，仓库 A 学到的 sink 可被后启动的仓库 B 立即使用 —— 并行从「N 倍速度」升级为「N 个仓库互相增强检测能力」。

---

## 1. 现状盘点

| 维度 | 现状 |
|---|---|
| 并发基建 | **零**。全仓无 `tokio` / `rayon` / `futures` / `crossbeam`。`fn main()` 是同步的（`cli/src/main.rs:86`） |
| 仅有的线程 | 2 处 `thread::spawn`，用途是读子进程 stdout/stderr 配合 `recv_timeout`（`codeql/provider.rs:207`、`agent/provider.rs:107`） |
| 单仓库入口 | `run_static_scan_with_progress(config, rulebook_paths, target_overrides, progress)` @ `pipeline.rs:38`（全文件 1575 行） |
| 仓库输入 | CLI 只有一个位置参数 `config: PathBuf`；仓库路径写在 `[scan].targets: Vec<String>` |
| clone 阶段 | **无**。目标仓库必须已在本地 |
| 现有依赖 | `anyhow` `clap` `libc` `regex` `serde(=1.0.224)` `serde_json` `toml` `tracing` `tracing-subscriber` `uuid(v4)` + 三个语言的 parser |
| 测试规模 | 320 个 `#[test]`，其中 13 个在 `pipeline.rs` 调 `run_static_scan` |

**已经存在的有利条件：** `uuid` 带 `v4` feature、`libc` 均已是依赖，`RunId` 与「杀超时子进程」都无需新增依赖。

---

## 2. 并行化的阻塞点（已逐一定位到行并核实）

### 2.1 临时路径按 PID 键控 —— 同进程并行必然相撞

生产代码里只有 **4 处**（其余 `temp_dir()` 出现均在 `#[cfg(test)]` 内，不影响）：

| # | 位置 | 路径模板 | 并行后果 |
|---|---|---|---|
| 1 | `codeql/provider.rs:94-97` | `$TMP/mcp-sec-audit-codeql/db-{pid}/{lang}` | 同语言的两个仓库算出同一路径 |
| 2 | `codeql/provider.rs:160-164` | `$TMP/mcp-sec-audit-sarif-{pid}-{lang}.sarif` | 覆写 + 读后删除（`:240`），互删对方文件 |
| 3 | `codeql/models.rs:116` | `$TMP/mcp-sec-audit-mad-{pid}` | MaD pack 互相覆盖 |
| 4 | `pipeline.rs:390` | `$TMP/mcp-sec-audit-staging-{pid}` | staging 互相污染，回滚锚点失效 |

**最危险的不是撞路径，而是 `codeql/provider.rs:99-106` 的复用缓存**：

```rust
if db_dir.join("codeql-database.yml").exists() {
    return Ok(DatabaseInfo { path: db_dir, language });   // 直接复用
}
```

并行时后到的仓库会**静默地拿到前一个仓库的 CodeQL 数据库**并对其出报告 —— 无报错、无日志，结果彻底错误。这是本次改造中危害最高的一处。

### 2.2 `learned_dir` 的丢失更新

> **勘误：** 早期分析曾把 `learning.rs:283/311/339` 的 `write_learned_sinks/sources/sanitizers` 记为 read-modify-write。核实后**并非如此** —— 它们是「每个模型一个 `learned-{safe}.toml` 文件、整文件覆写」。

真正的 RMW 有两类：

**(a) 函数级：** `write_learned_rules`（`learning.rs:358-385`）与 `write_learned_prompt`（`learning.rs:390-407`）确实是 `read_to_string` → 合并 → `write`。

**(b) 管线级（危害更大）：** `pipeline.rs:654-693` 是一个跨函数的读-改-写序列：

```
load_models_dir(learned_dir)        ← 读取既有累积证据
  → merge_sink_models(existing, new)   ← 合并 corroboration_count / pollution_count
    → write_learned_sinks(...)          ← 写回
```

两个仓库并发走到这里：A 读、B 读、A 写、B 写 → **A 的证据被 B 的写覆盖**，corroboration 计数回退。这才是必须串行化的真正对象。

### 2.3 超时不杀子进程（既有缺陷，并行放大）

`codeql/provider.rs:206-224` 与 `agent/provider.rs:107-153` 均为 `mpsc::channel` + `thread::spawn` + `rx.recv_timeout()`。超时后函数返回 `timed_out: true`，**但子进程仍在运行**。

单仓库时最多漏一个孤儿进程；并行时每个漏掉的 `codeql database create` 占数 GB 内存，累积几个即 OOM，会拖垮整台机器而非仅本次运行。

### 2.4 CodeQL CLI 缺失会 panic 而非返回错误

`codeql/mod.rs:79` 是 `panic!(...)` 而非 `bail!(...)`。单仓库时这只是难看的崩溃；**并行时一个仓库的环境问题会炸掉整个批次**，其余仓库的已完成工作全部丢失。必须在并行化之前改为可恢复错误。

### 2.5 `scan_identifier` 并发撞车

`pipeline.rs:1009` 的 `scan_identifier` 由 `{第一个 target}-{unix 秒}` 构成，被写入学习模型的 `learned_from` 字段作溯源。并行时同秒完成的仓库可能生成相同标识，污染证据溯源。需并入 `run_id`。

### 2.6 全局日志订阅器

`cli/src/logging.rs` 的 `init_with_writer` 用 `try_init()`，二次调用即失败；`ModuleFormat::format_event` 只输出 `<时间> <模块>: <消息>`，不携带 span 上下文。并行时多个仓库的日志交错且**无法区分来源**。

---

## 3. 设计决策与取舍

以下选项在设计讨论中逐一对比后锁定：

| 决策点 | 选择 | 放弃的方案与理由 |
|---|---|---|
| 并发模型 | **tokio 异步** | 线程池（改动更小但原语不完整）；多进程 supervisor（本质是进程管理，且跨仓库学习共享做不了） |
| async 深度 | **全链路 async**（CPU 内部 `spawn_blocking`） | 仅编排层 async（签名统一性差）；分层混合 |
| 学习成果 | **共享学习总线** | 完全隔离（可重现但放弃协同）；批次末合并（同批次内不互相受益） |
| 仓库输入 | **`batch` 子命令 + `[[batch.repo]]`** | 复用 `[scan].targets`（破坏 `all-languages-config.toml` 的现有语义，且无法表达每仓库差异） |
| git clone | **不做** | 避免引入网络重试、认证、磁盘配额、浅克隆等一大堆副作用；职责单一 |
| 报告 | **每仓库报告 + 批次汇总** | 单份合并大报告（丢失单仓库报告，大批量时文件巨大） |

### 关于 async 深度的实测数据

五条分析线的性质是割裂的，只有**两个叶子**真正需要 async：

| 阶段 | 性质 | 是否必须 async |
|---|---|---|
| `discovery` 文件遍历 | 同步 fs，量小 | 否 |
| `facts` AST 解析（rustpython / swc / syn） | **纯 CPU**，重 | 否 |
| `rule` 正则扫描 | **纯 CPU** | 否 |
| `taint` 图构建 + 传播 | **纯 CPU**，最重 | 否 |
| `agent` 调 `claude` CLI | **子进程 + 长等待** | **是** |
| `codeql` 调 `codeql` CLI | **子进程 + 长等待** | **是** |
| `fusion` / `diff` / `validate` | 纯 CPU | 否 |

因此「全链路 async」的实际成本远低于教科书式估算：**必须改签名的只有 6 个函数**（`pipeline::run_static_scan` / `run_static_scan_with_progress`、`agent::run` / `run_with_prompt` / `run_adjudication`、`codeql::run`）。`rule` / `taint` / `fusion` 改 async 是为签名统一，属风格选择而非必需。

---

## 4. 架构

```
mcp-sec-audit batch batch.toml
   │
   └─ [cli] main.rs   #[tokio::main(flavor = "multi_thread")]
        │
        └─ batch::orchestrator::run_batch(BatchConfig, CancellationToken)
             │
             ├── ResourceGovernor      分级信号量（codeql / agent / cpu）
             ├── LearningBus           actor 任务，独占 learned_dir 写权
             ├── Progress              mpsc，统一收敛后带 [repo] 前缀输出
             ├── CancellationToken     Ctrl-C → 杀光子进程
             │
             └── JoinSet<RepoOutcome>
                   ├─ repo A ── RunId ── run_static_scan_async(..)
                   ├─ repo B ── RunId ── run_static_scan_async(..)
                   └─ repo C ── （排队等并发额度）

每个 repo 内部（保持 v4 两阶段语义不变）：
   入场快照 ← LearningBus.snapshot()
      ↓
   阶段 1（rule → taint → agent → codeql）
      ↓  G1/G2 门控 → stage_catalog_evolution → diff_1
   阶段 2（taint' → agent' → codeql'）
      ↓  diff_2 → validate::migrate → L2/L3 裁决
   promote → LearningBus.promote()    或    rollback → 只删自己的 staging
```

### 4.1 新增模块

**core** (`rust/crates/mcp-sec-audit-core/src/`)

| 文件 | 职责 |
|---|---|
| `runctx.rs` | `RunId` / `Progress` / `RunContext` —— 身份与运行期管道，无业务逻辑 |
| `batch/mod.rs` | 对外 re-export |
| `batch/config.rs` | `BatchConfig` / `BatchSettings` / `LimitsConfig` / `RepoConfig` + 合并逻辑（纯函数，重点单测） |
| `batch/governor.rs` | `ResourceClass` + `ResourceGovernor`，不感知仓库概念 |
| `batch/learning_bus.rs` | 单写者 actor：`Promote` / `Snapshot` / `Shutdown` |
| `batch/summary.rs` | `BatchSummary` / `BatchRepoSummary` + json / markdown 渲染 |
| `batch/orchestrator.rs` | 唯一 spawn 仓库任务、持有 governor 与 bus 的地方 |

**cli** (`rust/crates/mcp-sec-audit-cli/src/`)

- `main.rs` — 新增 `Command::Batch`；`fn main` 改 `#[tokio::main]`；退出码映射
- `batch.rs` — 薄层：解析参数 → 加载 `BatchConfig` → 装 Ctrl-C → 调 core
- `logging.rs` — `ModuleFormat` 读取 span 里的 `repo` 字段，输出 `<时间> [repo] 模块: 消息`

### 4.2 新增依赖

```toml
tokio      = { version = "1", features = ["rt-multi-thread", "macros", "process", "sync", "time", "signal"] }
tokio-util = { version = "0.7", features = ["rt"] }     # 仅为 CancellationToken
```

不引入 `indicatif` 等 TUI 依赖。`serde` 保持 `=1.0.224` 锁定不动（`swc_common 0.37.5` 的 `__private` 约束，见 workspace `Cargo.toml` 注释）。

---

## 5. RunId —— 临时路径的唯一来源

```rust
// core/src/runctx.rs
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(String);

impl RunId {
    pub fn new() -> Self;                               // uuid v4
    pub fn for_repo(batch_id: &str, repo: &str) -> Self;   // "{batch_id}-{sanitized_repo}"
    pub fn as_str(&self) -> &str;
    /// 所有 run-id 键控临时目录的唯一出口。
    pub fn temp_dir(&self, kind: &str) -> PathBuf;      // $TMP/mcp-sec-audit-{kind}-{id}
}
```

两级身份：每次 `batch` 调用产生一个 `batch_id`，每个仓库得到 `RunId::for_repo(batch_id, name)`。单仓库路径用 `RunId::new()`。

**放置位置：** `run_id` 作为**纯数据字段**挂到 `StaticScanContext`（`pipeline.rs:23-28`）。

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticScanContext {
    pub config: RuntimeConfig,
    pub rulebook_paths: Vec<String>,
    pub discovered_files: Vec<DiscoveredFile>,
    pub run_id: RunId,                                  // 新增
}
```

理由：`StaticScanContext` 已经 `&ctx` 贯穿所有阶段与 `codeql::models::write_model_pack_dir`，加一个字段即让 4 处临时路径与 `scan_identifier` 拿到 run_id，零额外管道。

**这不会让它变成 god-object** —— 判据是「是否携带行为句柄」。信号量、channel、actor handle 一律**不**放这里，而是放在独立的 `RunContext`：

```rust
pub struct RunContext {
    pub run_id: RunId,
    pub progress: Progress,
    pub cancel: CancellationToken,
    pub governor: Option<ResourceGovernor>,      // 单仓库模式为 None
    pub learning_bus: Option<LearningBusHandle>, // 单仓库模式为 None
}
```

`RunContext` 只传给顶层 `run_static_scan_async` 与两个子进程 provider；`rule` / `taint` / `fusion` / `validate` / `diff` 保持对 `&StaticScanContext` 的纯函数形态。

### Progress 取代 `impl FnMut(&str)`

`progress: impl FnMut(&str)`（`pipeline.rs:42`、`codeql/mod.rs:250`）是 `&mut` 闭包，**无法跨 await 点**。替换为可克隆的 sender：

```rust
#[derive(Clone)]
pub struct Progress { tx: tokio::sync::mpsc::UnboundedSender<String> }
impl Progress {
    pub fn report(&self, msg: impl Into<String>);
    pub fn scoped(&self, repo: &str) -> Progress;   // 消息加 [repo] 前缀
}
```

`UnboundedSender` 是 `Clone + Send + Sync + 'static`，跨 await 无障碍。

---

## 6. ResourceGovernor —— 分级限流

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceClass { Codeql, Agent, Cpu }

#[derive(Clone)]
pub struct ResourceGovernor {
    codeql: Arc<Semaphore>,
    agent:  Arc<Semaphore>,
    cpu:    Arc<Semaphore>,
}

impl ResourceGovernor {
    pub async fn acquire(&self, class: ResourceClass) -> OwnedSemaphorePermit;
}
```

| 类别 | 默认 | 理由 |
|---|---|---|
| `codeql` | `1` | `database create` 自身多线程 + 数 GB 内存，并发只会互相抢 CPU |
| `agent` | `1` | 延迟密集但受 LLM CLI 速率限制；提高成本低 |
| `cpu` | `min(available_parallelism(), 4)` | 正则扫描 / fact 提取 / 污点传播 |

### 防死锁不变量（必须写进代码注释）

> **任一时刻最多持有一个类别的许可，且绝不在持有 A 类许可时去申请 B 类许可。**

实现方式是给每个阶段独立作用域，靠 `OwnedSemaphorePermit` 的 RAII 在离开作用域时释放：

```rust
{ let _p = governor.acquire(ResourceClass::Codeql).await; codeql::run(...).await?; }
{ let _p = governor.acquire(ResourceClass::Agent).await;  agent::run(...).await?; }
```

因为许可从不跨类别持有，「CodeQL 持有许可等 Agent 许可」这类环形等待在结构上不可能出现。

---

## 7. LearningBus —— 共享学习总线

```rust
pub enum BusMsg {
    Promote  { repo: String, sinks: Vec<SinkModel>, sources: Vec<SourceModel>,
               sanitizers: Vec<SanitizerModel>, rules: Vec<String>, prompt_extra: String,
               ack: oneshot::Sender<Result<()>> },
    Snapshot { reply: oneshot::Sender<ModelCatalog> },
    Shutdown,
}

#[derive(Clone)]
pub struct LearningBusHandle { tx: mpsc::UnboundedSender<BusMsg> }
pub fn spawn(learned_dir: Option<PathBuf>) -> LearningBusHandle;
```

actor 持有 `learned_dir` 与内存中的权威 `ModelCatalog`（启动时从盘加载一次），外加规则集合与 prompt 累积文本。

**§2.2 的丢失更新由此消失** —— 因为「读既有 → merge → 写回」这一整段序列现在只在 actor 单线程内发生，天然串行。`learning.rs` 的函数本体无需改动，actor 直接复用 `merge_sink_models` / `merge_source_models` / `merge_sanitizer_models`。持久化改为**临时文件 + rename** 以获得原子性。

### 7.1 语义：入场快照（snapshot-at-entry）

每个仓库在**开始时取一次**快照，运行期间不再接收总线更新：

```rust
let learned = match &run_ctx.learning_bus {
    Some(bus) => Some(bus.snapshot().await?),
    None => None,
};
let base_catalog = load_catalog_with_learned(&ctx, learned.as_ref())?;
```

（新增 `load_catalog_with_learned`；原 `load_catalog` 退化为传 `None` 的薄包装。）

**为什么不能中途更新：** v4 的核心不变量是阶段 1 用 `base_catalog`、阶段 2 用 `evolved_catalog`，`validate::migrate` 靠两者结果之差判定「污染信号」并决定 `should_rollback`。若运行中途混入其他仓库的模型，阶段 2 多出的发现无法归因，污染信号被污染，回滚决策失真。

入场快照同时满足两个目标：**仓库内**保持 v4 的确定性两阶段语义，**仓库间**实现学习协同（后启动的仓库自然吃到先完成仓库的成果）。

**已接受的代价：** 结果依赖仓库完成顺序，不可重现。为需要可重现基线的评测场景保留 `[batch].learning_bus = false` 开关（各仓库隔离读取 `learned_dir`，不写回）。

### 7.2 回滚安全性（核查结论：风险小于预期）

链路是 `pipeline.rs:607-624` → `component.rs:111-113` → `learning::rollback_staging(staging_dir)`。

- `rollback` **只删自己 run-id 键控的 staging 目录**，从不触碰 `learned_dir`，也不向总线发任何消息
- `promote` **只在未回滚时**执行

因此「仓库 A 回滚清掉仓库 B 已固化成果」不成立。`learned_dir` 的唯一写入者是 actor。

### 7.3 遗留的正确性隐患（需在实现中处理）

| # | 隐患 | 说明 | 建议 |
|---|---|---|---|
| 1 | **delta 固化不合并既有证据** | `TaintComponent::promote`（`component.rs:137-142`）→ `write_learned_sinks` 直接写入 `corroboration_count = 0` 的 delta 模型，**覆盖**同名模型的既有累积；而裁决路径（`pipeline.rs:670-693`）**会**先 merge。同一份 learned 文件被两条语义不同的路径写 | 两条路径统一走 actor（actor 恒 merge）。这是**既有缺陷的修复**，会改变单仓库模式的 corroboration 记账，需在 PR 中显式声明 |
| 2 | **`scan_identifier` 撞车** | `pipeline.rs:1009` 用 `{target}-{unix 秒}`，并行同秒可能相同 | 并入 `run_id` |
| 3 | **同一新 sink 被两个仓库同时提交** | 各自只对自己的快照去重，actor merge 时按 key 去重并累加 corroboration | **接受为 corroboration 语义**（两个独立仓库都发现 ⇒ 证据确实更强），不做二次去重 |
| 4 | **`component.rs:174/206` 的 promote 是死代码** | `RuleComponent::promote` / `PromptComponent::promote` 用整文件覆写，但活跃路径是 `pipeline.rs:694-695` 直接调 `learning::write_learned_rules` / `write_learned_prompt`（累积式） | 接线到 actor 时一并清理，避免留下两套语义 |

---

## 8. 批次配置

```toml
# test-targets/configs/batch-example.toml
[batch]
max_parallel = 2
learning_bus = true          # false = 各仓库隔离，用于可重现的评测基线
fail_fast    = false

[batch.limits]
codeql = 1
agent  = 1
cpu    = 4

# ↓ 以下是共享基座，语法与现有单仓库 config 完全一致
[scan]
languages = ["python", "typescript", "rust"]
exclude   = ["__pycache__", ".venv", "node_modules", "target", ".git"]

[static]
enabled     = true
learned_dir = "models/learned"

[static.codeql]
enabled = true
binary  = "/home/xiao/App/codeql/codeql/codeql"

[report]
output  = "docs/result/batch-<timestamp>/<repo>"
formats = ["json", "markdown"]

# ↓ 仓库清单，每项可覆盖上面任意字段
[[batch.repo]]
name = "excel-mcp-server"
path = "../test-targets/excel-mcp-server"

[[batch.repo]]
name = "mcts-examples"
path = "../test-targets/MCTS/examples"
```

### serde 结构

```rust
pub struct BatchConfig {
    #[serde(default)] pub batch: BatchSettings,
    #[serde(flatten)] pub runtime: RuntimeConfig,       // 共享基座
}

pub struct BatchSettings {
    #[serde(default = "default_max_parallel")] pub max_parallel: usize,
    #[serde(default = "default_true")]         pub learning_bus: bool,
    #[serde(default)]                          pub fail_fast: bool,
    #[serde(default)]                          pub limits: LimitsConfig,
    #[serde(default, rename = "repo")]         pub repos: Vec<RepoConfig>,
}

pub struct RepoConfig {
    pub name: String,
    pub path: String,
    #[serde(flatten)] pub overrides: BTreeMap<String, toml::Value>,
}
```

**合并规则**（纯函数，重点单测）：

```
RuntimeConfig → toml::Value
  → 对 repo.overrides 逐个顶层 key 深合并（表递归合并；标量与数组直接替换）
    → scan.targets = 覆盖值（若有）否则 [repo.path]
      → toml::Value → RuntimeConfig
```

`#[serde(flatten)]` 到 `BTreeMap<String, toml::Value>` 使 `[[batch.repo]]` 能接受任意嵌套的 `[static...]` / `[report...]` / `[fusion...]` 覆盖，无需写一个庞大的 Option 化镜像结构。

**向后兼容：** 这是一种全新的顶层格式，`load_runtime_config` 与现有 7 个 `test-targets/configs/*.toml` 完全不受影响。

---

## 9. 报告

### `<repo>` 占位符

```rust
pub fn resolve_output_path(output: &str, repo: Option<&str>) -> String;
```

`<timestamp>` 行为不变；`<repo>` 在给出时替换为经过文件名净化的仓库名。单仓库路径传 `Some(&result.summary.target)`，批次路径传 `Some(&repo.name)`。需同步更新 `reporting.rs` 中 3 个相关测试。

**每仓库报告的格式与现在完全一致**，不破坏下游消费。

### 批次汇总

```rust
pub struct BatchSummary {
    pub batch_id: String,
    pub started_at: String,
    pub repos: Vec<BatchRepoSummary>,
    pub total_fused_findings: usize,
    pub succeeded: usize, pub failed: usize, pub cancelled: usize,
    pub learning_bus_enabled: bool,          // 提示结果是否顺序相关
    pub cross_repo_learned: Vec<String>,     // 跨仓库新学到的模型
}

pub struct BatchRepoSummary {
    pub name: String, pub path: String,
    pub status: RepoStatus,                  // Ok | Failed | Cancelled
    pub error: Option<String>,
    pub duration_ms: u64,
    pub risk_level: Option<String>,
    pub fused_finding_count: Option<usize>,
    pub report_paths: Vec<String>,
}
```

渲染为 `batch-summary.md` + `batch-summary.json`。`learning_bus_enabled` 显式落在汇总里，使 CI 对比时不会把「顺序导致的差异」误判为回归。

---

## 10. 失败与取消语义

### 失败

- 每个仓库是 `JoinSet` 成员，产出 `RepoOutcome::{ Ok(StaticAnalysisResult), Failed { error } }`
- **仓库返回 `Err`**：记为 `Failed`，其余仓库继续
- **仓库 panic**：由 `JoinError::is_panic()` 观测，记为 `Failed`。不需要 `catch_unwind` —— 分析是全有全无的（末尾才返回完整结果），panic 本就拿不到部分结果
- **前置修复**：`codeql/mod.rs:79` 的 `panic!` 必须改为 `bail!`，否则缺 CodeQL CLI 会炸掉整个批次（见 §2.4）
- **部分结果**：成功的仓库照常写报告并进入汇总；失败项在汇总中列出错误

### 退出码

| 码 | 含义 |
|---|---|
| `0` | 全部成功 |
| `1` | ≥1 个仓库失败或 panic（汇总仍然写出） |
| `2` | 配置解析失败 / 仓库清单为空 / 批次文件不可读 |
| `130` | Ctrl-C 取消（128 + SIGINT） |

### 取消

`tokio_util::sync::CancellationToken` 在 CLI 层创建，`tokio::signal::ctrl_c()` 任务调 `token.cancel()`。token 作为 `RunContext` 字段下发到：

- 两个 provider —— `tokio::select! { res = wait => ..., _ = token.cancelled() => bail!("cancelled") }`；因 `Child` 构造时带 `.kill_on_drop(true)`，取消分支上 drop 即杀掉子进程
- orchestrator 主循环 —— 停止启动新仓库

这同时**顺带修复了 §2.3 的超时孤儿进程问题**：`tokio::time::timeout` + `kill_on_drop` 使超时必然回收子进程。

---

## 11. 分阶段实施

> **风险控制核心：** v4 的两阶段自进化（门控 → staging → 阶段 2 → 裁决 → promote/rollback）是本项目最有价值也最脆弱的部分。整个 async 迁移期间**保留同步公开 API 作为 `block_on` 外壳**，使 320 个既有测试**一个都不用改**，始终作为回归网。

| 里程碑 | 内容 | 验证 |
|---|---|---|
| **M0 前置修复** | `codeql/mod.rs:79` `panic!` → `bail!`；建立黄金回归基线（对 `test-targets/python-mcp-server` 跑全管线，屏蔽易变字段后快照 JSON） | 新测试通过 |
| **M1 身份基建** | 加 `tokio` / `tokio-util`；`runctx.rs`（`RunId` / `Progress` / `RunContext`）；`run_id` 进 `StaticScanContext` | 320 测试全绿 |
| **M2 路径隔离** | 4 处 pid 路径改 run-id；**删除 `provider.rs:99-106` 的不安全 DB 复用缓存**；`scan_identifier` 并入 run_id | 全绿 + 黄金一致 |
| **M3 Progress 替换** | `impl FnMut(&str)` → `&Progress`，`run_static_scan_with_progress` 改为桥接（channel + drain 调原闭包） | 全绿（尚无 await） |
| **M4 provider 异步化** | 两个 provider 改 `tokio::process` + `kill_on_drop` + `tokio::time::timeout`；保留私有 `block_on` 同步外壳 | 新增「超时确实杀死子进程」测试 |
| **M5 管线异步化** | 抽出 `run_static_scan_async`（函数体逐字搬移，仅在两处子进程调用点注入 `.await`）；`rule`/`taint` 的 CPU 内部包 `spawn_blocking`；保留同步外壳 | **黄金基线必须一致** |
| **M6 移除外壳** | 删掉 provider 与管线的同步外壳，单仓库 CLI 路径改 async | 全绿 |
| **M7 批次基建** | `batch/config.rs` + `governor.rs` + 各自单测 | 合并规则与限流峰值测试 |
| **M8 学习总线** | `learning_bus.rs` + `load_catalog_with_learned` + `persist_promotion` 抽取与路由 | actor 单测 + 跨仓库学习端到端 |
| **M9 编排与报告** | `orchestrator.rs`；`<repo>` 占位符；`BatchSummary` | 双仓库批次跑通 |
| **M10 CLI 与取消** | `batch` 子命令；`#[tokio::main]`；Ctrl-C；退出码 | 取消后无残留子进程 |
| **M11 文档** | 更新 `rust/docs/README.md` 版本表（**顺带补上缺失的 v4.0 行**） | 文档提交 |

M0–M3 完全不涉及 async，却解决了 §2 里 5 个阻塞点中的 4 个（2.1 / 2.4 / 2.5 / 2.6 的一半）。即使后续 async 改造受阻，这部分价值独立成立。

---

## 12. 测试策略

| 层次 | 对象 | 方式 |
|---|---|---|
| 单元 | `RunId` 唯一性 / `temp_dir` / `for_repo`；`Progress::scoped` | `#[test]` |
| 单元 | `merge_repo_config`（标量覆盖、嵌套覆盖、`path`→`targets`） | 表驱动 `#[test]` |
| 单元 | `BatchConfig` 解析（默认值、`[[batch.repo]]`、`[batch.limits]`） | `toml::from_str` |
| 单元 | `resolve_output_path` 的 `<repo>` + `<timestamp>` | `#[test]` |
| 单元 | 批次汇总的 json / markdown 渲染 | fixture `#[test]` |
| 单元 | **学习总线** —— 同一模型 `Promote` 两次，断言 corroboration 累加、`Snapshot` 反映合并；断言规则与 prompt 累积 | `#[tokio::test(flavor = "current_thread")]` |
| 单元 | **限流器** —— `cpu = 1` 时两个任务并发获取，用 `AtomicUsize` 断言峰值并发为 1 | `#[tokio::test]` |
| 集成 | **批次编排** —— 两个临时小仓库，禁用 agent/codeql，`max_parallel = 2`，断言 2 份报告 + 汇总 | `#[tokio::test(flavor = "multi_thread")]` |
| 集成 | **部分失败** —— 一个仓库路径不存在 → `Failed`，另一个 `Ok`，断言退出码与汇总内容 | `#[tokio::test]` |
| 回归 | **黄金基线** —— 全管线输出快照 | 每个里程碑必跑 |
| 迁移 | 320 个既有测试 | **保持原样**，通过同步外壳运行；仅新增的异步代码用 `#[tokio::test]` |

关于「并行的确定性测试」：不去竞态地断言并发行为，而是**用限流器的峰值并发测试**证明并行受控，**用受控消息顺序**驱动总线断言合并语义。

---

## 13. 待确认决策点

1. **结果不可重现已被接受**（共享总线的必然代价）。汇总里已加 `learning_bus_enabled` 字段以便 CI 区分。是否还需要在每仓库报告里也标注该批次的仓库完成顺序？
2. **§7.3 隐患 1 的处理范围**：把 delta 固化与裁决固化统一走 actor 会改变**单仓库模式**的 corroboration 记账。选择「统一（视为缺陷修复）」还是「仅在批次模式合并、单仓库保持 v4 原样」？
3. **`codeql` 限流为 1 偏保守**。`database create` 是内存大户，但 `analyze` 较轻。是否要拆成 `codeql-create` 与 `codeql-analyze` 两类许可以提升吞吐？
4. **每仓库覆盖用 `toml::Value` 弱类型**：键名打错会静默失效。替代方案是写一个 Option 化的镜像结构（啰嗦但有校验）。选哪个？
5. **`learned_dir` 的每仓库覆盖**：批次模式下所有仓库共享顶层 `[static].learned_dir`（这正是总线的意义）。是否存在必须让某些仓库用独立 learned 目录的场景？若有，这些仓库将自动退出总线。
6. **`CURRENT_PHASE` 命名**：当前是 `phase13-static-result-fusion`。v5.0 是否 bump 为 `phase14-batch-parallel`？
7. **`spawn_blocking` 的克隆成本**：`StaticScanContext` / `ModelCatalog` 需按值移入闭包（`Send + 'static`）。对大仓库是浅克隆（`Vec<PathBuf>` + catalog）。是否接受，还是改用 `Arc<StaticScanContext>`？

---

## 附：术语速查

| 术语 | 含义 |
|---|---|
| **入场快照** | 仓库开始时从学习总线取一次 catalog，运行期不再更新，以保住 v4 阶段 1/2 的确定性 |
| **分级限流** | 按资源性质（CodeQL / Agent / CPU）分别设信号量，而非只限总并发数 |
| **run-id 键控** | 临时路径以 `RunId` 而非 `process::id()` 为键，使同进程内多仓库互不干扰 |
| **同步外壳** | 迁移期间保留的 `block_on` 包装，使既有同步测试无需改动即可继续作为回归网 |
| **异构阶段重叠** | 并行的真正收益来源：A 仓库等 Agent（网络）时，B 仓库跑 CodeQL（CPU） |
