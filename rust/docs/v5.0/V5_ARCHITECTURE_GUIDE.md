# v5.0 架构详解指南（架构 / 目录 / 配置 / 命令）

**目标读者：** 需要跟上 v5.0 技术细节、但被「tokio 异步化 + 并行编排 + 学习总线」这套改动绕晕的读者。
**配套文档：** `PARALLEL_MULTI_REPO_DESIGN_20260825.md`（设计规格）、`IMPLEMENTATION_PROGRESS_SELF_CHECK_20260831.md`（实现自检）。
**代码位置：** 分支 `worktree-v5-parallel-orchestration`，`rust/` 目录（双 crate workspace）。

> 全文约定：`[x.y]` 表示 TOML 配置里的表 `[x]` 下的字段 `y`。`§N` 指向本文档章节。

---

## 0. 一分钟总览

v5.0 做的事一句话：**把「一次只能分析一个仓库」改成「一次并行分析 N 个仓库，且仓库之间互相共享学习成果」。**

为此它做了三件大事：

1. **全链路异步化**——把整个分析管线从同步函数改成 `async` 函数，让「等 CodeQL 子进程跑完」这种耗时操作不再阻塞 CPU，转而让别的仓库去跑 CPU 密集的解析工作。
2. **并行编排层**——新增 `batch` 子命令 + 编排器，用信号量控制「同时跑几个仓库」「同时跑几个 CodeQL 进程」。
3. **共享学习总线**——把原来「每个进程独占的 `learned_dir`」升级成「单写者 actor」，同批次的仓库能即时吃到别的仓库刚学到的漏洞模型。

仓库**内部**的两阶段自进化逻辑（v4 的核心）**一行语义没改**，只是被包了一层异步外壳。

---

## 1. 核心概念速览（先读这节，术语后面不再重复解释）

### 1.1 进程 / 线程 / 协程（process / thread / coroutine）

| 概念 | 类比 | 特点 | 在本项目里 |
|---|---|---|---|
| **进程** | 一个独立程序 | 内存隔离，开销大 | 每个 `codeql` / `claude` 子进程就是一个进程 |
| **线程** | 进程里的一个工人 | 共享内存，切换有开销 | `spawn_blocking` 里的 CPU 任务 |
| **协程** | 线程里的一个「轻量任务」 | 极轻量，可成千上万个 | tokio 里的 `async` 任务 |

关键：**协程的切换是「协作式」的**——只有遇到 `.await` 才让出控制权。所以 `async` 函数里写 `子进程.wait().await` 时，当前线程不会傻等，而是去执行别的协程。

### 1.2 tokio 异步运行时（async runtime）

tokio 是 Rust 生态标准的异步框架。它维护一个线程池（`multi_thread`）或单线程（`current_thread`），负责调度协程。

- **`#[tokio::main]`**：宏，把 `main` 函数包进一个运行时。
- **`tokio::runtime::Builder`**：手动建运行时（本项目用这种方式，因为单仓库路径必须保持同步，见 §2.3）。
- **`flavor = "multi_thread"`**：多线程运行时，能真正并行跑 CPU 任务。
- **`flavor = "current_thread"`**：单线程运行时，所有协程挤在一个线程上（本项目的每仓库任务用它，因为异步管线的 future 是 `!Send`，见 §2.4）。

### 1.3 `spawn` / `spawn_blocking` / `block_on`

- **`tokio::spawn(future)`**：把一个异步任务丢给运行时调度，不等待，返回 `JoinHandle`。任务必须是 `Send`（可跨线程移动）。
- **`tokio::task::spawn_blocking(closure)`**：把一个**同步**（纯 CPU）闭包丢给专门的阻塞线程池，避免阻塞异步线程。返回的 future `.await` 后拿到闭包结果。本项目用它跑 `rule` / `taint` 这类纯 CPU 阶段。
- **`runtime.block_on(future)`**：在**同步代码里**执行一个异步 future，直到它完成——这是「异步世界」和「同步世界」之间的桥。项目里所有 `run_static_scan` 同步入口都是 `block_on(run_static_scan_async(...))` 的外壳。

> 为什么既有「异步」又留「同步外壳」？因为项目里有 320+ 个既有同步测试。保留 `run_static_scan` 等同步 API，让这些测试**一个都不用改**，继续当回归网。

### 1.4 Actor 模型 + 消息传递（message passing）

**Actor 模型**：一个独立任务（协程）独占某份数据，外界不直接碰这份数据，只能「发消息」给它，由它自己在单线程里串行处理。因为只有一个写入者，天然没有数据竞争。

本项目用 actor 实现**学习总线**（§2.6）：actor 独占 `learned_dir`（学到的漏洞模型目录），各仓库通过 `promote`（提交证据）/ `snapshot`（读取快照）消息与它通信。

配套的通道（channel）原语：

- **`mpsc::channel`**（multi-producer single-consumer，多生产者单消费者）：多个发送端 → 一个接收端。`UnboundedSender` 可克隆、无界（不阻塞发送）。
- **`oneshot::channel`**：一对一的「一次性」通道，用于「请求-应答」——发一个 `Snapshot` 请求，等一个 `reply`。

### 1.5 信号量（Semaphore）与限流

**信号量**维护一个计数器，`acquire()` 时减一（减到 0 就等），释放时加一。用来限制「同一时刻最多 N 个东西在跑」。

本项目有两层信号量，**别混淆**（`orchestrator.rs` 顶部注释反复强调）：

| 信号量 | 控制什么 | 默认 |
|---|---|---|
| `max_parallel` | 同时运行几个**仓库**（每个仓库任务持一张许可，从头到尾） | 4 |
| `ResourceGovernor` 的**分级信号量** | 每个资源类别同时跑几个：`codeql` / `agent` / `cpu` | 1 / 1 / 4 |

- **`OwnedSemaphorePermit`**：拿到手就是一张「所有权许可」，作用域结束时自动释放（RAII，见下）。它的存在保证「不会忘记释放」。
- **防死锁不变量**（代码里强制写注释）：**任一时刻最多持有一类许可，且绝不在持有 A 类许可时去申请 B 类许可。** 因为每个 provider 调用点用独立作用域包裹，许可从不跨类持有，环形等待（A 等 B、B 等 A）在结构上不可能发生。

### 1.6 RAII（Resource Acquisition Is Initialization，资源获取即初始化）

Rust 里「资源在变量离开作用域时自动清理」的机制。`OwnedSemaphorePermit` 就是典型：`{ let _p = governor.acquire(...).await; 跑一段 }`——离开 `{}` 时 `_p` 被 drop，许可自动归还。`.kill_on_drop(true)` 同理：`Child` 被 drop 时自动杀死子进程。

### 1.7 `JoinSet` / `JoinHandle`

- **`JoinHandle`**：一个异步任务的句柄，`handle.await` 等待它完成并取结果。
- **`JoinSet`**：一组任务句柄的集合，`join_next().await` 返回「**最先完成**的那个」。编排器用它承载 N 个仓库任务，按完成顺序收集结果，再按配置顺序重排。
- **`JoinError::is_panic()`**：判断任务是否 panic。仓库 panic 了，编排器记为 `Failed`，不影响其他仓库。

### 1.8 `CancellationToken`（取消令牌）

`tokio_util::sync::CancellationToken`：一个可克隆的「取消开关」。任一处调 `cancel()`，所有持该 token 的任务都能通过 `token.cancelled()` 观察到。CLI 里 Ctrl-C → `cancel()`，编排器和 provider 立即停手并回收子进程。

### 1.9 污点分析三要素：source / sink / sanitizer

污点分析（taint analysis）追踪「外部不可信输入」流经程序、最终到达「危险函数」的路径。

- **source（源）**：不可信输入的入口——如 `os.environ`（环境变量）、`sys.argv`（命令行参数）、HTTP 请求、MCP 工具参数。
- **sink（汇）**：危险汇聚点——如 `subprocess.run`（命令执行）、`open`（文件读写）、`eval`（代码执行）。
- **sanitizer（净化器）**：把污点「洗干净」的函数——如 `shlex.quote`（转义后不再构成命令注入）。

发现「source 流到 sink」= 一条污点漏洞。补 sanitizer = 降低误报。

### 1.10 其他术语

- **MaD pack（Model as Data）**：CodeQL 的一种机制，把「危险函数模型」写进一个数据文件（`modeling` 扩展），CodeQL 建库时读入。本项目把自学的 sink 模型翻译成 MaD 塞给 CodeQL，让它也认这些 sink。
- **SARIF**：CodeQL 输出的标准 JSON 格式（`codeql database analyze` 的结果）。
- **Fused finding（融合发现）**：把 rule / taint / agent / codeql 四条线的结果按「位置相近 + 类别一致」合并成一条「融合发现」，多线支持可提高置信度（§2.7）。
- **入场快照（snapshot-at-entry）**：仓库开始分析时从学习总线取一次模型目录的快照，运行期间不再更新（§2.6）。
- **corroboration_count（佐证计数）**：一个学到的模型被「多个独立仓库/多轮」确认的次数，越高越可信。

---

## 2. 代码架构（详细）

### 2.1 双 crate workspace

```
rust/
├── Cargo.toml                        # workspace 根：定义成员 + 共享依赖
├── crates/
│   ├── mcp-sec-audit-core/           # 库 crate：所有分析逻辑 + 编排 + bench
│   │   └── src/                      #   （无 main，纯库）
│   └── mcp-sec-audit-cli/            # 二进制 crate：命令行入口
│       └── src/main.rs               #   （clap 子命令派发）
```

- **`mcp-sec-audit-core`**（简称 core）：真正的引擎。约 2.7 万行。对外通过 `lib.rs` 的 `pub use` 暴露稳定的类型和函数。
- **`mcp-sec-audit-cli`**（简称 cli）：薄壳，解析命令行参数 → 调 core。约几百行。

依赖关系：**cli 依赖 core，core 不依赖 cli。** 分层清晰：CLI → 编排层 → 管线 → 分析线 → 数据模型。

### 2.2 五层架构

```
┌─────────────────────────────────────────────────────────────┐
│ L1 CLI 层（cli/src/*.rs）                                    │
│   main.rs 派发子命令；batch.rs / bench.rs 加载配置、装 Ctrl-C │
├─────────────────────────────────────────────────────────────┤
│ L2 编排层（core/src/batch/*.rs）                             │
│   orchestrator.rs 并行调度仓库；governor.rs 分级限流；        │
│   learning_bus.rs 共享学习；config.rs 配置合并；summary.rs   │
├─────────────────────────────────────────────────────────────┤
│ L3 管线层（core/src/static_analysis/pipeline.rs）            │
│   run_static_scan_async：两阶段自进化管线的编排               │
├─────────────────────────────────────────────────────────────┤
│ L4 分析线（static_analysis/{rule,taint,agent,codeql,facts}/） │
│   四条独立检测线 + 事实提取 + 融合 + 迁移校验                  │
├─────────────────────────────────────────────────────────────┤
│ L5 数据模型 + 基础（core/src/model/ + models/ + config.rs    │
│    + reporting.rs + runctx.rs + rules.rs）                   │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 关键类型详解

#### `RunId`（`runctx.rs:20`）

一次分析的唯一标识。核心价值：**所有 run 键控的临时目录都以它命名，而不是以进程 PID 命名**——所以同一进程里的多个仓库各用各的临时目录，不会互相覆盖（这是设计 §2.1 最危险的并行 bug 的解法）。

```rust
pub struct RunId(String);                       // 里面是个 uuid v4 的字符串
impl RunId {
    pub fn new() -> Self;                       // 全新随机 id
    pub fn for_repo(batch_id, repo) -> Self;    // 确定性子 id：batch_id + 净化仓库名 + 短哈希
    pub fn temp_dir(kind) -> PathBuf;           // $TMP/mcp-sec-audit-{kind}-{id}，唯一出口
}
```

`temp_dir` 的 `kind` 有四种：`codeql` / `sarif` / `mad` / `staging`。`RunContext::cleanup()` 枚举这四种目录统一删除。

#### `Progress`（`runctx.rs:86`）

可克隆的进度上报器，取代了原来无法跨 `.await` 的 `&mut impl FnMut(&str)` 闭包。四种后端：

| 后端 | `report(msg)` 行为 | 用于 |
|---|---|---|
| `Tracing` | 立即 `tracing::info!` | 单仓库 CLI 路径（实时） |
| `Channel` | 发到 `mpsc` 通道 | 批次编排（聚合后带 `[repo]` 前缀统一输出） |
| `Closure` | 立即转发给闭包 | 同步桥接 `run_static_scan_with_progress` |
| `Noop` | 什么都不做 | 测试 |

`scoped(repo)` 返回一个带 `[repo]` 前缀的副本。

#### `RunContext`（`runctx.rs:202`）

一次运行的「运行期状态」包，只传给顶层 async 函数和两个子进程 provider：

```rust
pub struct RunContext {
    pub run_id: RunId,
    pub progress: Progress,
    pub cancel: CancellationToken,          // 取消令牌
    pub governor: Option<ResourceGovernor>, // 单仓库模式为 None
    pub learning_bus: Option<LearningBusHandle>, // 单仓库模式为 None
}
```

**设计要点**：`governor` / `learning_bus` 为 `None` 时（单仓库模式），管线不申请许可、不走总线，行为与 v4 **逐字节一致**。

#### `StaticScanContext`（`pipeline.rs:24`）

贯穿所有分析阶段的**纯数据**上下文：

```rust
pub struct StaticScanContext {
    pub config: RuntimeConfig,           // 生效配置（合并后）
    pub rulebook_paths: Vec<String>,
    pub discovered_files: Vec<DiscoveredFile>,
    pub run_id: RunId,                   // 新增字段：让 4 处临时路径 + scan_identifier 拿到 run id
}
```

它**只带数据、不带行为句柄**（信号量、channel、actor handle 都放 `RunContext`），所以 rule/taint/fusion 这些阶段仍是对 `&StaticScanContext` 的纯函数。

#### `ModelCatalog`（`models/mod.rs:131`）

「sink/source/sanitizer 三类模型」按语言分组的目录。内建 34 个 sink（python 13 / rust 11 / javascript 10）+ 若干 source + sanitizer，编译期从 `models/*.toml` 内嵌。`learned_dir` / `models_dir` 里的模型在运行时合并进来。

### 2.4 异步管线的入口（`pipeline.rs`）

有四个对外入口，本质上是同一份 `run_static_scan_async` 的包装：

```
run_static_scan_async(config, rulebook, overrides, run_ctx)   ← 真身，async
    ↑
    ├── run_static_scan(config, ...)                    = block_on(async)  （noop progress）
    ├── run_static_scan_with_progress(config, ..., f)   = block_on(async)  （closure progress）
    └── run_static_scan_inner(config, ..., &Progress)   = block_on(async)  （显式 Progress）
```

三个同步外壳都用 `Builder::new_current_thread().block_on(...)`。为什么是 `current_thread` 而非 `multi_thread`？——因为异步管线里的 future 持有 `tracing::EnteredSpan`，而它是 `!Send`（不能跨线程），多线程 runtime 的 `spawn` 拒绝它。单线程 runtime 没这个问题。

### 2.5 两阶段差分自进化管线（v4 核心，v5 原样保留）

这是本项目最有价值的逻辑，v5 的 async 化**没有动它**，只是把两个子进程调用点改成 `.await`、把 CPU 阶段包进 `spawn_blocking`。

```
run_static_scan_async 内部流程：

  1. discover_files（扫文件）
  2. load_merged_rulebook（加载规则书）
  3. 入场快照 ← learning_bus.snapshot()   【批次模式才发生】
  4. load_catalog_with_learned(base_catalog)  【基线模型目录】
  5. 记录 4 个 Component 的基线指纹（可观测锚点）
  ─────── 阶段 1：基线运行 ───────
  6. rule 分析      （spawn_blocking，CPU 许可）
  7. taint 分析     （spawn_blocking，CPU 许可）→ taint_results_1, facts_1
  8. agent 分析     （async，Agent 许可；失败降级为空）
  9. codeql 分析    （async，Codeql 许可）→ codeql_output_1
  ─────── 门控 + 试探性进化 ───────
 10. 对 agent 提出的候选模型做 G1（信号门控）+ G2（可表达性门控）
     筛出 b0（语义漏洞 / Cold sink，交报告/人工）
 11. stage_catalog_evolution → staged（待进化的模型集合）
 12. diff_1 = diff_lines(阶段1 四线结果)  ← 找出 a-only / b-only
 13. Component::evolve → evolved_catalog；写 staging（回退锚点）
 14. 构造验证提示词 prompt'（把 a1 请复核 / a2 请勿报告二分）
  ─────── 阶段 2：进化后重跑（rule 复用阶段1结果）───────
 15. taint' 分析   （用 evolved_catalog）
 16. agent' 分析   （带 prompt'）
 17. codeql' 分析  （用 evolved_catalog）
 18. diff_2 = diff_lines(阶段2 结果)
  ─────── 迁移校验 + 固化/回退 ───────
 19. validate::migrate(diff_1, diff_2)  ← L1：判定 b1/a1/a2/b2
 20. L2：仍混沌的 b-only 交 agent 语义解释（只解释，不下结论）
 21. 决定 promote（固化到学习总线）还是 rollback（删自己 staging）
 22. finish：融合四线 → StaticAnalysisResult
```

**两个阶段为什么存在？** 阶段 1 用「基线模型」跑一遍，agent 提出新模型；把这些新模型「试探性」加进去跑阶段 2；对比两阶段结果差异，用 `validate::migrate` 判断新模型是「真阳性增强」（b1/a1，固化）还是「幻觉污染」（b2，回滚）。这就是「自进化」：系统靠差分信号自己决定要不要采纳新知识。

### 2.6 批次编排（`batch/orchestrator.rs`）

`run_batch(cfg, cancel)` 是整个 v5 的集成点：

```
run_batch:
  1. 拒绝空仓库清单（→ 退出码 2）
  2. batch_id = RunId::new()
  3. 若 learning_bus=true：spawn(learned_dir) → LearningBusHandle
  4. governor = ResourceGovernor::new(limits)
  5. max_parallel = Semaphore::new(max_parallel)
  6. (progress, rx) = Progress::channel()；spawn drain 任务（带 [repo] 前缀输出）
  7. 懒分发循环：
        while 有空位 && 还有仓库没发:
            slot = max_parallel.acquire_owned()   ← 占一个仓库位
            repo_id = RunId::for_repo(batch_id, name)
            spawn_blocking( 每个仓库一个 current_thread runtime:
                run_repo(idx, repo, base, repo_id, shared) )
        join_next() 等一个仓库完成 → 收 outcome
        fail_fast 时首个失败 → cancel()
  8. 收尾：drop 发送端 → drain 排空；bus 最后快照 → cross_repo_learned
  9. 汇总 BatchSummary；写 batch-summary.md / .json
```

**一个仓库任务（`run_repo`）做**：合并配置 → 进入 `repo` span → `run_static_scan_async` → 写每仓库报告 → `run_ctx.cleanup()` 删临时目录。

**两层并发的关键**（模块顶部注释强调）：`max_parallel` 是「仓库级」许可（一个仓库任务从头到尾持一张），governor 的分级许可是「阶段级」许可（每个 provider 调用点短暂持有一张）。它们安全共存，因为仓库持有 `max_parallel` 许可期间，只是短暂地、一次一个地申请 governor 许可，且信号量按类独立，无跨仓库环。

### 2.7 学习总线（`batch/learning_bus.rs`）

actor 独占 `learned_dir` 的写权：

```rust
pub enum BusMsg {
    Promote { req, ack },        // 提交证据，等 ack
    Snapshot { reply },          // 取当前权威目录快照
}
```

- **启动**：从 `learned_dir` 读一次既有的 sink/source/sanitizer 模型 + 规则 + prompt 文本。
- **Promote**：`merge_models`（复用 `merge_sink_models` 等）+ 累积规则/prompt + `persist`（临时文件 + `rename` 原子写回）。**因为读-改-写整段只在 actor 单线程里发生，设计 §2.2 的「丢失更新」竞态消失。**
- **Snapshot**：返回当前 catalog 的克隆。

**入场快照语义**（关键）：每个仓库**开始时取一次**快照，运行期间不再接收更新。为什么不能中途更新？因为 v4 的核心不变量是「阶段 1 用 base_catalog、阶段 2 用 evolved_catalog」，靠两者结果之差判定污染信号。若中途混入别的仓库的模型，阶段 2 多出的发现无法归因，回滚决策会失真。

**corroboration 语义**：actor 把每个入站模型计数归一为 1 再 merge。两个独立仓库各自固化同一个 sink → corroboration_count = 2（证据确实更强）。

### 2.8 融合与报告（`fusion/` + `reporting.rs` + `batch/summary.rs`）

- **融合**（`fusion/`）：把 rule / taint / agent / codeql 四条线结果按 `line_proximity`（行距）和类别合并，`require_confirmed_by`（最少几线支持）、`boost_when_multiple_lines_agree`（多线一致加权）、各线权重 `*_weight`。`agent_only_as_advisory` 决定 agent 单独报的是否只当「参考」。
- **报告**：`reporting.rs` 的 `render_json` / `render_jsonl` / `render_markdown`；`resolve_output_path` 支持 `<timestamp>` / `<repo>` 占位符。
- **批次汇总**：`batch/summary.rs` 的 `BatchSummary`，含 `learning_bus_enabled`（供 CI 区分「顺序导致的差异」vs 真回归）和 `cross_repo_learned`（跨仓库新学到的模型）。

### 2.9 benchmark（v5 之上的扩展，`bench/`）

`run_bench`：加载 manifest（20 项语料清单）+ ground-truth（22 条已知漏洞的 sink 行）→ 翻译成 batch 配置 → 复用 `run_batch` 跑检测 → 逐仓读报告 JSON 打分（sink 行对齐 ±N 容差，TP/FP/unconfirmed 三分类）→ 写 `metrics.json` + `metrics.md`（P/R/F1，按语言/tier/类别分层）。数据含 `<PENDING>` 时直接 bail（不静默给 recall≈0）。

---

## 3. 工作目录拆解

### 3.1 根目录

| 路径 | 作用 |
|---|---|
| `rust/` | **Rust 主工程**（v5.0 主体全在这） |
| `detection/` | 早期 Python 原型检测器（历史，非 v5 主体） |
| `test-targets/` | 被扫描的测试目标仓库（`excel-mcp-server`、`MCTS/examples`、`rust-mcp-server` 等）+ `configs/` 配置样例 |
| `benchmark/` | benchmark 数据：`manifest.toml` / `ground-truth.toml` / `fetch.sh` / `corpus/`（20 个 clone 仓库）/ `bench_results/` |
| `targets/` | 早期静态分析目标（历史） |
| `docs/` | 顶层文档（`IDEA.md`、`RUN_GUIDE.md` 等，Obsidian vault） |
| `web-detection-portal/` | 一个 Web 门户（历史/并行项目） |
| `.claude/worktrees/` | Claude 的 git worktree（v5 实现在这） |

### 3.2 `rust/` 顶层

| 文件/目录 | 作用 |
|---|---|
| `Cargo.toml` | workspace 根：成员列表 + `[workspace.dependencies]` 共享依赖（含 `tokio` / `tokio-util`） |
| `Cargo.lock` | 锁定的依赖版本 |
| `crates/` | 两个 crate（见下） |
| `models/` | **内建模型 TOML**：`sinks/{python,javascript,rust}.toml`、`sources/`、`sanitizers/`、`package_inference.toml`——编译期内嵌 |
| `rules/` | 规则书 TOML（`mcp/`、`languages/` 子目录），`[static.rule].rule_paths` 指向这 |
| `docs/` | 版本化文档：`v2.0/`、`v3.0/`、`v4.0/`、`v5.0/`、`result/`（扫描结果）、`reference/` |
| `target/` | cargo 构建产物（gitignore） |

### 3.3 `core/src/` 逐文件

**顶层**

| 文件 | 作用 |
|---|---|
| `lib.rs` | 库根：`pub mod` 声明 + `pub use` 集中 re-export（对外 API 面）+ `CURRENT_PHASE` / `product_name` |
| `config.rs` | `RuntimeConfig` 及全部子配置结构体 + 默认值 + TOML 解析（§4 详解） |
| `runctx.rs` | `RunId` / `Progress` / `RunContext`（§2.3） |
| `reporting.rs` | 报告渲染：`render_json/jsonl/markdown`、`ReportFormat`、`resolve_output_path`（`<timestamp>`/`<repo>` 占位符） |
| `rules.rs` | 规则书 schema：`RuleBook` / `CapabilityRule` / `IndicatorRule`（keyword/regex 指示器）+ 解析 |
| `fixtures.rs` | 合成测试数据（`synthetic_static_analysis_result` 等，测试/演示用） |

**`model/`（数据模型，纯 serde 结构体）**

| 文件 | 作用 |
|---|---|
| `mod.rs` | re-export |
| `enums.rs` | 枚举：`Severity`（critical/high/medium/low）、`Confidence`、`FindingStatus`、`EvidenceSource`、`EntryPointKind`、`ImportKind`、`PathStepKind`、`RuntimeEventKind` |
| `facts.rs` | `Fact` 枚举：Function/Import/Entrypoint/Call/Sink/Sanitizer/Source/Assign/Dataflow/RuntimeEvent/Finding |
| `static_result.rs` | **核心输出**：`StaticAnalysisResult` + `RuleAnalysisResult` / `TaintAnalysisResult` / `AgentAnalysisResult` / `CodeqlAnalysisResult` / `FusedFinding` / `ModelCandidate` / `StaticAnalysisSummary` / `ConfigSnapshot` / `EvolutionReport` / `AdjudicationItem` |
| `report.rs` | 报告相关模型 |

**`models/`（sink/source/sanitizer 模型目录）**

| 文件 | 作用 |
|---|---|
| `mod.rs` | `SinkModel` / `SourceModel` / `SanitizerModel` / `PackageRule` / `ModelCatalog`；`default_catalog()`（内嵌 `models/*.toml`）、`load_models_dir()`、`parse_*` |

**`static_analysis/`（分析管线）**

| 文件/目录 | 作用 |
|---|---|
| `mod.rs` | 模块声明 + 对外 re-export（`run_static_scan*`、`discover_files` 等） |
| `pipeline.rs` | **管线核心**：`run_static_scan_async` + 三个同步外壳 + `StaticScanContext` + `acquire_permit`（约 1000+ 行） |
| `discovery.rs` | 文件发现：`discover_files`、`DiscoveredFile`、`ScanLanguage`、`detect_language` |
| `category.rs` | 漏洞类别词汇表（`command_execution`、`file_read` 等） |
| `component.rs` | `Component` trait 抽象：`TaintComponent` / `CodeqlComponent` / `RuleComponent` / `PromptComponent`（统一指纹 + `evolve`） |
| `evolution.rs` | 进化相关辅助 |
| `diff.rs` | `diff_lines`（四线结果差分，出 a-only/b-only）、`classify_candidate`（可表达性） |
| `validate.rs` | `migrate`（L1 迁移判定 b1/a1/a2/b2）、`ambiguous_items`（L2/L3 残留） |
| `learning.rs` | 学习逻辑：`gate_sink_candidate`（G1 信号门控）、`stage_catalog_evolution`、`write_staging`、`merge_*_models`、`rollback_staging`、`stable_hash` |
| `infer.rs` | 包语义推断（package → category） |
| `recon.rs` | 侦查（reconnaissance）辅助 |
| `facts/` | 事实提取（AST 解析） |
| `facts/pipeline.rs` | 提取入口：`extract_static_facts`、`load_catalog_with_learned` |
| `facts/python/` | Python 事实：`calls.rs` / `functions.rs` / `mcp.rs` / `sinks.rs` / `mod.rs`（rustpython-parser） |
| `facts/js_ts/` | JS/TS 事实：同上（swc_core） |
| `facts/rust/` | Rust 事实：`calls.rs` / `sinks.rs` / `mcp.rs` / `display.rs`（syn） |
| `facts/ids.rs` | 事实 id 工具 |
| `rule/` | 规则扫描线（regex/keyword），`mod.rs` |
| `taint/` | 污点分析线：`graph.rs`（图）、`builder.rs`（建图）、`propagation.rs`（传播）、`result.rs`（结果）、`mod.rs` |
| `agent/` | Agent 分析线（调 `claude` CLI） |
| `agent/provider.rs` | 子进程 provider：`tokio::process` + `kill_on_drop` + `timeout` |
| `agent/prompt.rs` | 提示词渲染（验证提示词 / 解释提示词） |
| `agent/parser.rs` | 解析 agent 输出 |
| `agent/adjudicate.rs` | 裁决 |
| `agent/mod.rs` | `run_async` / `run_with_prompt_async` |
| `codeql/` | CodeQL 分析线 |
| `codeql/provider.rs` | 子进程 provider：`create_database` / `run_analysis`（异步 + kill_on_drop） |
| `codeql/models.rs` | `sink_models_to_mad`（sink 模型 → MaD pack）+ `write_model_pack_dir` |
| `codeql/parser.rs` | 解析 SARIF 结果 |
| `codeql/queries.rs` | 内置查询 |
| `codeql/mod.rs` | `run_async` + `CodeqlSession`（CLI 缺失返回 Err 而非 panic） |
| `fusion/` | 融合：`matcher.rs` / `merger.rs` / `scorer.rs` / `mod.rs` |

**`batch/`（v5 编排层，§2.6）**

| 文件 | 作用 |
|---|---|
| `mod.rs` | re-export |
| `config.rs` | `BatchConfig` / `BatchSettings` / `LimitsConfig` / `RepoConfig` + `merge_repo_config` 深合并 |
| `governor.rs` | `ResourceClass` / `ResourceGovernor`（三级信号量） |
| `learning_bus.rs` | `BusMsg` / `LearningBusHandle` / `spawn`（actor） |
| `orchestrator.rs` | `run_batch`（懒分发 + JoinSet + 两级并发） |
| `summary.rs` | `BatchSummary` / `BatchRepoSummary` + 渲染 |

**`bench/`（benchmark 扩展，§2.9）**

| 文件 | 作用 |
|---|---|
| `mod.rs` | `run_bench` / `BenchOptions`（把 manifest 翻译成 batch 配置） |
| `manifest.rs` | `BenchManifest` / `RepoEntry` / `load_manifest` / `to_batch_config` |
| `ground_truth.rs` | ground-truth schema + `load_ground_truth` |
| `scorer.rs` | sink 行对齐 + TP/FP/unconfirmed + `AggregateMetrics` / `RepoMetrics` |
| `report.rs` | `BenchMetrics` + metrics.json/md 渲染 |

### 3.4 `cli/src/` 逐文件

| 文件 | 作用 |
|---|---|
| `main.rs` | clap 定义 6 个子命令 + 单仓库位置参数；`Batch`/`Bench` 就地构建 multi_thread runtime；退出码映射 |
| `batch.rs` | `batch::run`：加载 `BatchConfig` → 装 Ctrl-C → 调 `core::run_batch` |
| `bench.rs` | `bench::run`：加载 manifest → 调 `core::run_bench` |
| `logging.rs` | `init`（初始化 tracing 订阅器）+ `ModuleFormat`（自定义日志格式 + `[repo]` 前缀）+ `scope_directives`（`[logging.scopes]` → target 映射） |

---

## 4. 配置文件详解

v5 配置文件是**单仓库配置的超集**：顶层 `[batch]` 表控制并行，其余表是共享基座（语法与单仓库 config 完全一致），每个 `[[batch.repo]]` 用 `name`/`path` + 嵌套覆盖描述一个仓库。

### 4.1 顶层结构

```toml
[batch]        # 仅批次模式有：并行控制
[scan]         # 扫哪些文件
[static]       # 静态分析开关（含 rule/taint/agent/codeql 四个子表）
[dynamic]      # 动态分析（历史，默认关）
[fusion]       # 四线融合参数
[report]       # 报告输出
[logging]      # 日志

[[batch.repo]] # 仓库清单（可多个）
```

### 4.2 `[scan]`

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `targets` | `Vec<String>` | `["."]` | 扫描目标路径列表（单仓库时是仓库根；批次时默认取 repo 的 `path`） |
| `exclude` | `Vec<String>` | `["node_modules","target",".venv","dist"]` | 排除的目录名 |
| `languages` | `Vec<String>` | `["python","javascript","typescript","rust"]` | 分析的语言 |

### 4.3 `[static]`

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | `bool` | `true` | 静态分析总开关；false 时直接返回空结果 |
| `save_facts` | `bool` | `true` | 是否保存事实（facts） |
| `models_dir` | `Option<String>` | 无 | 额外 sink/source/sanitizer 模型 TOML 目录，运行时合并到内建目录 |
| `learned_dir` | `Option<String>` | 无 | **自学习成果冷持久化目录**：门控通过的模型写这；下次运行加载；批次模式下是学习总线的持久化目标 |

#### `[static.rule]` 规则线

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | `bool` | `true` | 是否跑正则/keyword 规则扫描 |
| `rule_paths` | `Vec<String>` | `["rules/mcp","rules/languages"]` | 规则书 TOML 目录 |

#### `[static.taint]` 污点线

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | `bool` | **`false`** | 是否跑污点分析（注意默认关） |
| `forward` | `bool` | `true` | 前向传播（source → sink） |
| `backward` | `bool` | `true` | 后向追踪（sink → 找根） |
| `max_depth` | `u32` | `8` | 传播最大深度（调用链长度） |
| `entrypoint_required` | `bool` | `true` | 是否要求从 MCP 入口点起算 |

#### `[static.agent]` Agent 线（调 `claude` CLI）

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | `bool` | `false` | 是否跑 agent（默认关，需真实 `claude` CLI） |
| `provider` | `String` | `"claude"` | agent CLI 名 |
| `prompt_template_path` | `Option<String>` | 无 | 提示词模板路径（无则内置） |
| `max_turns` | `u32` | `30` | 最大轮数 |
| `timeout_seconds` | `u64` | `600` | 超时秒数（超时真杀子进程） |
| `extra_args` | `Vec<String>` | `[]` | 传给 CLI 的额外参数 |

#### `[static.codeql]` CodeQL 线

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | `bool` | `false` | 是否跑 CodeQL（默认关） |
| `query_pack_path` | `Option<String>` | 无 | 自定义查询包路径（无则内置） |
| `binary` | `String` | `"codeql"` | codeql 可执行文件路径（如 `/home/xiao/App/codeql/codeql/codeql`） |
| `timeout_seconds` | `u64` | `1200` | 超时秒数 |
| `extra_args` | `Vec<String>` | `[]` | 额外参数 |

### 4.4 `[dynamic]` 动态分析（历史遗留，默认关）

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | `bool` | `false` | 动态分析开关 |
| `sandbox` | `String` | `"existing_python_runtime"` | 沙箱类型 |
| `timeout_seconds` | `u64` | `120` | 超时 |

### 4.5 `[fusion]` 融合

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | `bool` | `true` | 融合开关 |
| `require_confirmed_by` | `u32` | `1` | 一条融合发现至少需几条线支持 |
| `boost_when_multiple_lines_agree` | `bool` | `true` | 多线一致时加权提升置信度 |
| `agent_only_as_advisory` | `bool` | `true` | agent 单独报的只当「参考」，不单独定级 |
| `line_proximity` | `u32` | `5` | 判「同一处」的行距容差 |
| `rule_weight` | `u32` | `3` | rule 线权重 |
| `taint_weight` | `u32` | `2` | taint 线权重 |
| `agent_weight` | `u32` | `1` | agent 线权重 |
| `codeql_weight` | `u32` | `4` | codeql 线权重 |

### 4.6 `[report]` 报告

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `formats` | `Vec<String>` | `["json","markdown"]` | 输出格式：`json` / `jsonl` / `markdown` |
| `output` | `String` | `"report"` | 输出路径模板，支持 `<timestamp>`（`YYYYMMDD-HHMMSS`）和 `<repo>`（批次模式仓库名，文件名净化）占位符 |
| `include_fused_results` | `bool` | `true` | 含融合发现 |
| `include_raw_rule_results` | `bool` | `true` | 含原始 rule 结果 |
| `include_raw_taint_results` | `bool` | `true` | 含原始 taint 结果 |
| `include_raw_agent_results` | `bool` | `true` | 含原始 agent 结果 |
| `include_raw_codeql_results` | `bool` | `true` | 含原始 codeql 结果 |
| `include_facts` | `bool` | `false` | 含事实（facts） |

### 4.7 `[logging]` 日志

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `level` | `enum` | `"info"` | 全局日志级：`trace`/`debug`/`info`/`warn`/`error` |
| `format` | `enum` | `"compact"` | 格式：`full`/`compact`/`pretty`/`json`（人读格式统一为 `<时间> <模块>: <消息>`；json 结构化） |
| `ansi` | `bool` | `true` | 是否输出 ANSI 颜色（绿色模块名） |
| `show_timestamps` | `bool` | `true` | 是否带时间戳 |
| `show_progress` | `bool` | `true` | 是否显示进度（false 时进度走 noop） |
| `log_file` | `Option<String>` | 无 | 日志文件（设置后写入文件，且强制 `ansi=false`） |
| `scopes` | `BTreeMap<String,LogLevel>` | `{}` | 按模块覆盖日志级，见下 |

`[logging.scopes]` 的 key（映射到内部 `mcp_sec_audit::*` target）：

```
pipeline / rule / taint / agent / codeql / fusion / learning / facts / infer / diff / validate / evolution / component
```

示例：`[logging.scopes]` 里 `codeql = "trace"` 让 CodeQL 模块打 trace 级日志。

### 4.8 批次配置 `[batch]`（v5 核心新增）

```toml
[batch]
max_parallel = 4          # 同时运行几个仓库（默认 4）
learning_bus = true       # 是否启用共享学习总线（默认 true；false = 各仓库隔离，可重现评测基线）
fail_fast    = false      # 首个仓库失败是否中止整个批次（默认 false）

[batch.limits]
codeql = 1                # 同时几个 CodeQL 进程（内存大户，保守）
agent  = 1                # 同时几个 agent 进程（受 LLM 速率限制）
cpu    = 4                # 同时几个 CPU 密集阶段

[[batch.repo]]
name = "excel-mcp-server"       # 仓库名（报告文件名、[repo] 前缀、日志归属）
path = "../test-targets/excel-mcp-server"   # 仓库路径（默认映射为 scan.targets）

# 每个仓库可覆盖任意基座字段（表递归合并，标量/数组整体替换）：
[batch.repo.static.codeql]
enabled = false                 # 只对这个仓库关掉 CodeQL
```

`[[batch.repo]]` 的覆盖规则（`merge_repo_config`，纯函数重点单测）：
- `name`、`path` 必填；`path` 默认作为 `scan.targets`（除非显式覆盖 `[batch.repo.scan].targets`）。
- 其余任意嵌套表（`static`/`report`/`fusion`/`scan`…）深合并到基座上：**表递归合并，标量与数组整体替换**。

### 4.9 benchmark 的 manifest（`benchmark/manifest.toml`）

`bench` 子命令读的是 manifest 而非 runtime config：

```toml
[[repo]]
slug         = "servers-git-py"          # 唯一标识
url          = "git@github.com:..."      # SSH clone URL
commit       = "<vulnerable-commit-sha>" # 锁定漏洞态 commit
language     = "python"                  # python|typescript|javascript|rust
scan_targets = ["src/git"]               # 仓库内作用域（可选，默认整仓）
evidence_tier = "cve"                    # cve|issue|synthetic
vulns        = ["CVE-2025-68144"]        # 引 ground-truth 的 key
```

---

## 5. 运行命令拆解

统一约定：**在 `rust/` 目录下**用 `cargo run -- <子命令>`，或先 `cargo build --release` 后用 `target/release/mcp-sec-audit <...>`。

### 5.1 单仓库静态分析（无子命令 + 位置参数）

```bash
cargo run -- ../test-targets/configs/all-languages-config.toml
# 等价于：cargo run -- <运行时配置 TOML 路径>
```

**行为**：加载 config → `logging::init` → 走同步路径 `run_static_scan_inner`（`block_on` 桥接 async 管线，`Progress` 用 tracing 后端实时输出）→ 写报告。这是 **v4 的原始入口，v5 完全兼容**。

### 5.2 批量并行分析（v5 核心交付）

```bash
cargo run -- batch ../test-targets/configs/batch-example.toml
# 等价于：cargo run -- batch <批次配置 TOML 路径>
```

**行为**：CLI 为 batch 单独构建 `multi_thread` runtime → 装 Ctrl-C → `batch::run` → `core::run_batch`。每仓库独立 `current_thread` runtime + `spawn_blocking` 并行跑；日志带 `[repo]` 前缀；结束时写每仓库报告 + `batch-summary.md`/`.json`；清理各仓库临时目录。

**退出码**：`0` 全部成功；`1` ≥1 仓库失败/取消（汇总仍写出）；`2` 配置解析失败/仓库清单为空/批次文件不可读；`130` Ctrl-C 取消（128 + SIGINT）。

### 5.3 benchmark 打分（v5 之上的扩展）

```bash
cargo run -- bench --manifest ../benchmark/manifest.toml
# 可选参数：
#   --tolerance 5         sink 行匹配容差（±N 行，默认 5）
#   --max-parallel 4      扫描并发仓库数（默认 4）
```

**行为**：加载 manifest + ground-truth（`<PENDING>` 则 bail）→ 翻译成 batch 配置 → `run_batch` 跑语料 → 逐仓读报告 JSON → sink 行对齐打分（TP/FP/unconfirmed，P/R/F1）→ 写 `benchmark/bench_results/<timestamp>/metrics.{json,md}`。

### 5.4 其他子命令

```bash
cargo run -- status                                    # 打印产品名 + CURRENT_PHASE
cargo run -- config validate --config <config.toml>    # 校验运行时配置能否解析
cargo run -- rules validate --rules <rulebook.toml>    # 校验规则书能否解析
cargo run -- report demo --format markdown             # 渲染一份合成报告（json/jsonl/markdown）
```

### 5.5 测试命令

```bash
cd rust

# 全量（两个 crate 单测 + 集成 + 黄金回归 + bench 冒烟）
cargo test --workspace

# 只跑黄金回归基线（async 迁移行为一致性安全网）
cargo test -p mcp-sec-audit-core --test golden_regression

# 只跑 batch / 学习总线 / 限流器相关
cargo test -p mcp-sec-audit-core batch::

# lint（注意：rustc 1.97.1 下当前有 34 个风格 lint，见自检报告 §4.3）
cargo clippy --workspace -- -D warnings
```

### 5.6 一条端到端验证（手工）

```bash
cd rust
cargo run -- batch ../test-targets/configs/batch-example.toml
# 逐项确认：
# 1. 每仓库报告落到 docs/result/batch-<ts>/<repo>.{json,md}
# 2. batch-summary.md 生成，耗时与发现数正确
# 3. $TMP/mcp-sec-audit-*-<run_id>/ 每仓库独立，结束后清理
# 4. 日志行带 [repo] 前缀，可区分来源
# 5. 并行期间 pgrep -c codeql 不超过 limits.codeql
# 6. 运行中 Ctrl-C → pgrep -f 'codeql|claude' 应为空
```

---

## 附：一句记忆法

> **v5 = 异步外壳 + 两级并发 + 一个 actor。**
> 异步外壳：`run_static_scan_async` 是唯一真身，三个同步入口都是 `block_on` 包装。
> 两级并发：`max_parallel` 管「几个仓库」，`ResourceGovernor` 管「每类资源几个」。
> 一个 actor：学习总线独占 `learned_dir`，仓库入场取快照、固化时回投。
> 而仓库内部的「两阶段差分自进化」——v4 最值钱的部分——**原封不动**。
