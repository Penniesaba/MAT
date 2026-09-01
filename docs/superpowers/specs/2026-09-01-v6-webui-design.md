# v6.0 Web UI 设计规格

> **状态**：待审阅
> **日期**：2026-09-01
> **版本**：v6.0
> **分支**：`feat/v6-webui`（自 `master` 切出，v5 代码已全量在 master）
> **代码位置**：`rust/crates/mcp-sec-audit-webui/`（`rust/` workspace 新增成员）
> **配套文档**：`rust/docs/v6.0/`（实现阶段建立）

---

## 0. 一句话定位

把 mcp-sec-audit 从「纯 CLI + 冗余日志」升级为「**配置 → 运行 → 监控**」三位一体的 Web UI 前端；Web 运行方式与 CLI 运行方式**并行共存**，不取代后者。

三大功能块：

1. **配置**：在 Web 页面填写配置（或一键导入现成 TOML），不依赖提前手写配置文件。
2. **运行**：按页面配置启动批量 / 单仓库分析。
3. **监控**：实时监控并行分析的各仓库进度，点击某仓库查看其运行细节日志。

---

## 1. 现状与痛点

### 1.1 现状（v5）

- 双 crate workspace：`mcp-sec-audit-cli`（二进制）+ `mcp-sec-audit-core`（库）。
- v5 已实现**并行多仓库编排**：`run_batch` 编排器 + `max_parallel` 信号量 + 每仓库 current-thread runtime + 分级 `ResourceGovernor` + 跨仓库 `LearningBus`。
- 进度是**自由文本**：`Progress::report(msg)`（tracing / channel / closure / noop 四后端）。
- 日志走 `tracing`，按仓库 `info_span!("repo", repo=%name)` 归属，CLI 自定义 `ModuleFormat` 渲染成 `[repo] module: message`。

### 1.2 痛点

- **日志冗余**：tracing 文本行混杂了进度、阶段、结果、诊断，无法结构化监控。
- **无监控面**：终端一次只能看一条流，20 个仓库并行时无法同时掌握每个仓库的进度与细节。
- **配置门槛**：必须提前写好 TOML 再调 CLI，缺少「先起服务、再填配置、再运行」的交互路径。

### 1.3 目标（v6）

- 并行分析 N 个仓库时，Web 页面纵向列出每个仓库的进度条（黑白灰），点击弹出该仓库详细日志。
- 新增 `webui` 子命令（与 `batch` 平级），起服务后在页面填配置/导配置，再运行。
- 不改 cli/core 既有行为；单仓库 CLI 路径**字节级不变**。

---

## 2. 总体架构

### 2.1 目录与依赖

```
rust/
├── Cargo.toml                        ← members 增加 "crates/mcp-sec-audit-webui"
└── crates/
    ├── mcp-sec-audit-core/           ← 不变（+ 新增 events 模块 + RunContext 加 EventSink）
    ├── mcp-sec-audit-webui/          ← 新增 lib crate（axum 服务，依赖 core）
    └── mcp-sec-audit-cli/            ← 新增 webui 子命令，依赖 webui
```

依赖方向（无环）：`cli → webui → core`；`cli → core`（既有）。

- **webui 是独立 crate**：不并入 cli/core 代码，不依赖 cli（只被 cli 以一个子命令调起）。
- 复用 `rust/` workspace 的 `[workspace.dependencies]`（新增 `axum`、`tower` 等共享依赖项）。

### 2.2 进程模型

**进程内调用 core**：webui 通过 path 依赖 `mcp-sec-audit-core`，在服务进程内直接调 `run_batch` / `run_static_scan_async`，通过注入的 `EventSink` 拿到结构化进度事件。不 spawn CLI 子进程，不解析 stdout。

### 2.3 技术选型

| 维度 | 选型 |
|---|---|
| Web 框架 | `axum`（Rust） |
| 实时推送 | WebSocket（`/ws/events` 单连接，推送所有 `AnalysisEvent`，前端按 repo 过滤） |
| 前端 | 服务端渲染 HTML + 极简原生 JS + 内嵌静态资产（无 npm 工具链） |
| 模板/资产 | `rust-embed` 或 `include_str!` 内嵌 `static/`（index.html / app.css / app.js） |
| 日志捕获 | webui 侧安装 `tracing` Layer，把按仓库归属的日志行路由进事件总线 + 每仓库环形缓冲 |

---

## 3. 命令与入口

### 3.1 CLI 子命令

`webui` 作为 `mcp-sec-audit` 的**子命令**，与 `batch` / `bench` 完全平级：

```rust
enum Command {
    Status,
    Config { .. },
    Rules { .. },
    Report { .. },
    Batch(BatchArgs),
    Bench(BenchArgs),
    Webui(WebuiArgs),   // 新增
}

struct WebuiArgs {
    /// 监听地址，默认 127.0.0.1:8770
    #[arg(long, default_value = "127.0.0.1:8770")]
    addr: String,
    /// 启动后自动打开浏览器
    #[arg(long)]
    open: bool,
    /// 可选：启动即导入的配置文件路径（等价于页面点「导入」）
    #[arg(long)]
    config: Option<PathBuf>,
}
```

运行方式：`cargo run -- webui`（从 `rust/` 目录，默认二进制即 CLI）。

### 3.2 生命周期

- `webui` 子命令**阻塞运行**直到 Ctrl-C（与 batch/bench 相同的 runtime + 信号处理模式）。
- 与 `batch` 的区别：`batch` 读一个 TOML 就跑；`webui` 起常驻服务，配置由页面/导入决定，运行由页面触发。

---

## 4. 结构化事件流（core 改动）

### 4.1 事件类型

新增 `core::events` 模块：

```rust
#[derive(Clone, Serialize, Deserialize)]
pub enum AnalysisEvent {
    BatchStarted  { batch_id: String, repos: Vec<RepoRef>, max_parallel: usize },
    BatchFinished { summary: BatchSummary },
    RepoStarted   { repo: String },
    RepoFinished  { repo: String, status: RepoStatus, duration_ms: u64,
                    risk_level: Option<String>, fused_finding_count: Option<usize> },
    StageProgress { repo: String, stage: Stage, percent: u8 },
    Log           { repo: String, level: LogLevel, line: String },
}
```

- `Stage` 是**层级 stage 树**（见 §5），不是平铺枚举。
- 事件全部 `Send + Sync + Clone + 'static`，经 `tokio::sync::broadcast` 扇出。

### 4.2 传输机制 `EventSink`

与 `Progress` 并列，新增一个 `EventSink`：

```rust
#[derive(Clone)]
pub struct EventSink {
    tx: Option<broadcast::Sender<AnalysisEvent>>,  // None = noop（无订阅者）
}

impl EventSink {
    pub fn noop() -> Self;                      // 单仓库 CLI 路径默认
    pub fn broadcast() -> (Self, broadcast::Receiver<AnalysisEvent>);
    pub fn emit(&self, event: AnalysisEvent);   // None 时直接丢弃
}
```

- **无订阅者 = noop**：单仓库 CLI 路径不订阅，`emit` 空转，行为字节级不变。
- `EventSink` 挂到 `RunContext`（与 `progress` / `cancel` / `governor` / `learning_bus` 并列）。
- `run_batch` 签名扩展为 `run_batch(cfg, cancel, events: EventSink)`；编排器 emit `BatchStarted/Finished` 与每仓库 `RepoStarted/Finished`，并把 `EventSink` 经 `Shared` 克隆进每个仓库任务、塞入 `RunContext::for_repo`。

### 4.3 埋点位置

- **阶段事件**：`pipeline.rs` 各阶段边界（§5 的每个节点）显式 `emit(StageProgress { stage, percent })`。
- **日志事件**：webui 侧 tracing Layer 捕获按仓库归属的日志行 → 每仓库环形缓冲 + `Log` 事件广播。复用 CLI `ModuleFormat::repo_from_context` 的 span 归属逻辑。

### 4.4 subscriber 所有权

- webui 模式下，**webui crate 初始化** `tracing_subscriber`（带捕获 Layer），不走 CLI 的 `logging::init`。
- CLI 其它子命令仍走 `logging::init`，互不影响（进程级单例，各自进程各自初始化）。

---

## 5. 阶段模型（两阶段 × 两线）

> 这是 v6 监控的**核心粒度**，直接决定进度条与弹窗日志的分层。逐行还原自 `pipeline.rs::run_static_scan_async` 与 v4.0 `IDEA_EVALUATION_AND_DESIGN.md`。

### 5.1 两条线

| 线 | 组成 | 能力决定性部件 | 产物 |
|---|---|---|---|
| **A 线 · 标准线** | rule + taint + codeql | `Component`（RuleBook / TaintModelCatalog / QueryPack+MaD） | `Result_A`（确定性） |
| **B 线 · agent 线** | agent | `Prompt` | `Result_B`（LLM 语义） |

### 5.2 完整 stage 树

```
每仓库 scan
├─ Setup（预处理）
│   ├─ discover_files       发现文件
│   ├─ load_rulebook        装载 rulebook
│   ├─ load_catalog         装载 sink 模型目录（builtin + models_dir + learned）
│   └─ baseline_components  基线组件指纹（rule/taint/codeql/prompt 四组件）
│
├─ Phase1（阶段 1 · 基线运行）
│   ├─ A线.rule      rulebook 匹配 → 结果
│   ├─ A线.taint     build_graph(facts) → 前向/后向传播 → 结果 + facts
│   ├─ A线.codeql    建库 → 编译 MaD → 分析 → 解析 SARIF
│   └─ B线.agent     文件摘要 → 渲染 prompt → 调 LLM → 解析 findings + model_candidates
│
├─ Evolution（进化中间层）
│   ├─ gate_g1_g2    门控 G1（信号：sink Hot/Warm）+ G2（可表达性：MadSink/TaintModel）
│   ├─ stage_g3      试探性进化 stage_catalog_evolution → staged（无候选 → 跳过 Phase2）
│   └─ diff_1        差分（四线并集三分 c / a / b）
│
├─ Phase2（阶段 2 · 进化后重跑；rule 复用不重跑）
│   ├─ A线.taint₂    用 evolved_catalog 重跑
│   ├─ A线.codeql₂   用 evolved_catalog 重跑
│   └─ B线.agent₂    带验证提示词 prompt'（a1 请复核 / a2 请勿重复）重跑
│
├─ Validation（校验 + 裁决 + 固化）
│   ├─ diff_2        差分
│   ├─ migrate       L1 迁移校验（b0/a1/a2/b1/b2）
│   ├─ explain       L2 混沌解释（ambiguous → agent 语义解释）
│   ├─ adjudicate    L3 自洽裁决（b0 + ambiguous → promote/reject/uncertain）
│   └─ promote       回滚判定 + 固化（→ learning bus / learned_dir）
│
└─ Finish（收尾）
    ├─ fusion        四线融合打分
    ├─ partition     最终分区 + 汇总（risk_level）
    └─ report        报告写盘（CLI/orchestrator 层）
```

### 5.3 Stage 枚举（层级）

```rust
pub enum Stage {
    Setup(SetupStep),
    Phase1(LineStep),
    Evolution(EvolutionStep),
    Phase2(LineStep),
    Validation(ValidationStep),
    Finish(FinishStep),
}

pub enum LineStep {
    Standard(StandardStep),   // A 线
    Agent,                    // B 线
}

pub enum StandardStep {
    Rule,                       // 仅 Phase1（Phase2 rule 复用，不重跑）
    Taint,
    Codeql { sub: CodeqlStep }, // CreateDb / CompileMad / Analyze / ParseSarif
}
// 注：Phase1 的 Standard = {Rule, Taint, Codeql}；Phase2 的 Standard = {Taint, Codeql}。
// 实现时用不同枚举（Phase1StandardStep / Phase2StandardStep）或运行时校验禁止 Phase2::Rule。
// EvolutionStep / ValidationStep / FinishStep / SetupStep / CodeqlStep 同理展开
```

### 5.4 进度条语义

- **确定百分比**：在 §5.2 的每个 stage 边界，按「启用阶段 + 权重表」给 `percent`。
- **权重表**（默认值，实现时按实测校准，可配置）：

| 区间 | 权重（占 0–100） |
|---|---|
| Setup | 5 |
| Phase1（A线 rule/taint/codeql + B线 agent） | 40 |
| Evolution | 5 |
| Phase2（A线 taint₂/codeql₂ + B线 agent₂） | 40 |
| Validation | 5 |
| Finish | 5 |

- **长耗时外部阶段内部**：codeql 按语言建库/分析/解析给子步进度；agent 单次 LLM 调用给**不定态**（前端动画），不假装精确。
- 阶段被禁用（如 `agent.enabled=false`）或跳过（无进化候选跳过 Phase2）时，权重让渡给后续阶段，避免进度条停住或回跳。

---

## 6. webui crate 组件与路由

### 6.1 模块

```
rust/crates/mcp-sec-audit-webui/src/
├── lib.rs            暴露 build_router() / AppState / serve()
├── server.rs         axum Router + 路由
├── state.rs          RunManager（当前运行生命周期 + 每仓库进度/日志缓冲 + 运行历史）
├── run.rs            拉起 batch / 单仓库，喂 EventSink
├── events.rs         消费 core::events::AnalysisEvent，转 WS 帧
├── log_capture.rs    tracing Layer → 每仓库环形缓冲 + Log 事件
└── toml_import.rs    TOML 导入 / 校验 / 导出
```

### 6.2 路由

| 路由 | 方法 | 作用 |
|---|---|---|
| `/` | GET | SSR 首页（配置表单 + 导入 + 运行 + 监控区） |
| `/api/config` | GET / PUT | 读取 / 写入当前配置（表单双向绑定） |
| `/api/import` | POST | 导入 TOML → 服务端解析校验 → 回填 + 字段级错误 |
| `/api/config/export` | GET | 当前配置导出为 TOML（下载/复制） |
| `/api/run` | POST | 按当前配置启动 run（batch 或 single），返回 run_id |
| `/api/run/:id/cancel` | POST | 取消运行（映射 `CancellationToken::cancel`） |
| `/ws/events` | WS | 单连接推送所有 `AnalysisEvent`；连接即回放当前状态快照 |

### 6.3 RunManager（state.rs）

- **单活动运行 + 历史**：同一时刻一个活动 run；历史 runs 保留在内存（+ 复用既有 `batch-summary.json` 落盘）。
- **每仓库缓冲**：进度（当前 stage + percent + status）+ 日志环形缓冲（每仓库上限 N 条，防内存爆）。
- **断线恢复**：`/ws/events` 重连时，服务端先发「快照」（当前 run 状态 + 每仓库进度 + 近期日志），再续增量。

---

## 7. 数据流（配置 → 运行 → 监控）

```
浏览器 ──POST /api/import(TOML)──▶ toml_import 解析校验 ──▶ 回填表单
   │
   ├──POST /api/run──▶ run.rs 判定 batch/single
   │                      ├─ batch: core::run_batch(cfg, cancel, events)
   │                      └─ single: core::run_static_scan_async(..., run_ctx{events})
   │                                   │（pipeline 边界 emit StageProgress / 日志 Layer 捕 Log）
   │◀──WS /ws/events 推送 AnalysisEvent ◀──────────────┘
   │
   └──前端：按 repo 聚合 StageProgress → 进度条；按 repo 缓存 Log → 弹窗详情
```

---

## 8. UI 规格（tailscale 黑白灰）

### 8.1 视觉

- 配色**纯黑白灰**：`#fff` 底 / `#000` 文字 / 灰阶边框与进度条，无彩色；克制衬线/无衬线混排，大留白。
- 参照 tailscale docs 的极简信息密度与排版。

### 8.2 监控区

- N 个仓库**纵向排列**的进度条；每行「仓库名 + 状态徽标 + 百分比 + 进度条」。
- 进度条灰阶状态：
  - 未开始 = 浅灰
  - 进行中 = 中灰动效（阶段内部不定态）
  - 完成 = 深灰实心
  - 失败 = 黑 + × 徽标
  - 取消 = 中灰斜纹

### 8.3 详情弹窗

- 点击进度条 → 居中弹窗：**宽 = 网页 1/3，高 = 网页 4/5**。
- 内容：该仓库的实时详细日志（按 stage 分层 + 自动滚动跟随），右上角关闭。

### 8.4 配置区

- 表单覆盖 `RuntimeConfig` + `BatchConfig` 全字段：
  `scan` / `static.rule` / `static.taint` / `static.agent` / `static.codeql` / `dynamic` / `fusion` / `report` / `logging` / `batch`（max_parallel / learning_bus / fail_fast / limits / repos 列表）。
- 另提供「原始 TOML 编辑器」视图 + 「导入 TOML」一键导入 + 「导出 TOML」。

---

## 9. 错误处理

| 场景 | 处理 |
|---|---|
| 配置非法（导入/运行） | 返回字段级错误，表单内联标红 |
| 单仓库失败 | 进度条转失败态，弹窗显示该仓库 `error` + 相关日志 |
| `fail_fast` | 沿用 core 语义：首个失败取消整个 batch |
| 运行中服务异常 | RunManager 记录 `Failed`，前端保持可读不崩溃 |
| 浏览器刷新/断线 | WS 重连回放快照，监控画面不丢 |

---

## 10. 测试

- **core**：`EventSink` emit/订阅单测、noop 回归（单仓库路径字节不变）、stage→percent 权重映射单测。
- **webui**：TOML 导入/校验、run 生命周期、WS 事件推送、SSR HTML golden、路由集成测试（`tower::ServiceExt`）。
- **cli**：`webui` 子命令参数解析（`clap` `debug_assert` 覆盖）。

---

## 11. 范围与非目标（YAGNI）

**做**：配置（表单 + 导入）→ 运行（batch/single）→ 监控（进度条 + 详情弹窗 + 日志回放）。

**不做（本轮）**：
- 用户认证 / 多用户 / 权限。
- 运行结果的可视化报表（只做监控，复用既有 `batch-summary.md/json` 与报告文件，不新增图表）。
- 历史 run 的持久化数据库（内存 + 既有 summary 文件足够）。
- 动态分析（dynamic）的运行控制（沿用 core 既有开关，不新增动态监控面）。
- 前端构建工具链（npm/Vite）。

---

## 12. 待决 / 风险

| # | 项 | 状态 |
|---|---|---|
| R1 | 阶段权重表需要实测校准（codeql/agent 占时最长） | 实现时按真实 run 校准 |
| R2 | 单仓库 CLI 路径「字节级不变」需靠 noop EventSink + 回归测试保障 | 设计内已含回归 |
| R3 | tracing subscriber 在 webui 模式由 webui 接管（CLI `logging::init` 不参与） | 需单测覆盖 |
