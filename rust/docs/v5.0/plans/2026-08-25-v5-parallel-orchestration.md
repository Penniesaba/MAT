# v5.0 并行多仓库编排 实现计划

> **给执行者：** 必用子技能：`superpowers:subagent-driven-development`（推荐）或 `superpowers:executing-plans` 逐任务实现。步骤用复选框（`- [ ]`）跟踪。**任务 0 与任务 1 必须最先完成** —— 它们是后续 async 改造的安全网。

**目标：** 让 `mcp-sec-audit` 具备单进程内并行分析 N 个 MCP 源码仓库的能力：tokio 全链路 async 承载并发，分级信号量按资源性质限流，单写者 actor 独占 `learned_dir` 实现跨仓库学习协同。

**架构：** 新增 `batch` 子命令读取 `[[batch.repo]]` 清单 → `orchestrator` 用 `JoinSet` 并发跑 N 个仓库任务 → 每任务持 `RunId` 隔离全部临时路径、经 `ResourceGovernor` 申请 CodeQL/Agent/CPU 许可、从 `LearningBus` 取入场快照并在固化时回投证据 → 输出每仓库报告 + 批次汇总。**仓库内部的 v4 两阶段自进化语义逐字不变。**

**技术栈：** Rust（edition 2024，rust-version 1.88），workspace crate `mcp-sec-audit-core` / `mcp-sec-audit-cli`，新增 `tokio` + `tokio-util`，沿用 `anyhow` / `tracing` / `uuid` / `libc`。

**规格：** `rust/docs/v5.0/PARALLEL_MULTI_REPO_DESIGN_20260825.md`（§2 阻塞点、§5 RunId、§6 限流、§7 学习总线、§8 批次配置、§9 报告、§10 失败与取消、§11 分阶段）。

## 全局约束

- Rust edition **2024**，`rust-version = "1.88"`，`resolver = "3"`。
- `serde` 固定 `=1.0.224` —— **不要 bump**（`swc_common 0.37.5` 把 `serde::__private` 当公开 API 用，1.0.225 起会 E0432）。
- **v5.0 解除 v4「不加新外部依赖」的约束，但只加两个：`tokio` 与 `tokio-util`。** 不引入 `rayon` / `futures` / `indicatif` / `async-trait`。
- 沿用现有约定：内部用 `pub(crate)`，分类用 snake_case，`tracing` target 用 `mcp_sec_audit::*`（本计划新增 `mcp_sec_audit::batch`）。
- **迁移期间保留同步公开 API 作为 `block_on` 外壳**，使 320 个既有测试一个都不用改。只有新增的异步代码写 `#[tokio::test]`。
- 每个任务结束时 `cargo test --workspace` + `cargo clippy --workspace -- -D warnings` 必须全绿，并跑黄金回归基线。
- 提交信息用 `feat(v5): ...` / `fix(v5): ...`；文档单独 `docs: ...`。

---

### 任务 0：前置缺陷修复 —— CodeQL 缺失不得 panic

并行时一个仓库的环境问题必须只失败它自己，不能炸掉整个批次。`codeql/mod.rs:79` 当前是 `panic!`。

**文件：**
- 修改：`rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs`

**接口：**
- 消费：`anyhow::bail`
- 产出：`CodeqlSession::create` 在 CLI 缺失时返回 `Err` 而非 panic

- [ ] **步骤 1：写失败的测试**

在 `codeql/mod.rs` 的 `#[cfg(test)] mod tests` 追加：

```rust
    #[test]
    fn missing_codeql_binary_returns_err_not_panic() {
        let mut config = RuntimeConfig::default();
        config.static_.codeql.enabled = true;
        config.static_.codeql.binary = "/nonexistent/definitely-not-codeql".to_string();
        let ctx = context_with_config(config);   // 复用现有测试辅助
        let result = CodeqlSession::create(&ctx);
        assert!(result.is_err(), "missing CLI must be a recoverable Err");
        assert!(result.unwrap_err().to_string().contains("codeql"));
    }
```

- [ ] **步骤 2：运行确认失败**

```bash
cd rust && cargo test -p mcp-sec-audit-core missing_codeql_binary_returns_err_not_panic
```

- [ ] **步骤 3：把 `panic!` 改成 `bail!`**

`codeql/mod.rs:79` 附近的 `panic!(...)` 改为 `bail!(...)`，保留原有的错误文案（含安装指引 URL）。确认函数返回类型已是 `Result`。

- [ ] **步骤 4：运行确认通过**

```bash
cd rust && cargo test --workspace && cargo clippy --workspace -- -D warnings
```

- [ ] **步骤 5：提交**

```bash
git commit -am "fix(v5): return Err instead of panicking when codeql CLI is missing"
```

---

### 任务 1：黄金回归基线

整个 async 迁移的安全网。v4 的两阶段自进化逻辑测试覆盖不足，必须有一份端到端输出快照来证明改造未改变行为。

**文件：**
- 新建：`rust/crates/mcp-sec-audit-core/tests/golden_regression.rs`
- 新建：`rust/crates/mcp-sec-audit-core/tests/fixtures/golden-python-mcp.json`

**接口：**
- 消费：`mcp_sec_audit_core::{run_static_scan, RuntimeConfig, render_json}`
- 产出：`normalize_for_golden(&StaticAnalysisResult) -> serde_json::Value`（测试内私有）

- [ ] **步骤 1：写归一化函数与测试骨架**

易变字段必须屏蔽：`summary.scan_id` / 任何时间戳 / 绝对路径前缀 / `learned_from` 里的 run 标识。

```rust
fn normalize_for_golden(json: &str, root: &Path) -> serde_json::Value {
    let mut v: serde_json::Value = serde_json::from_str(json).expect("parse");
    // 1. 抹掉时间戳与 scan_id
    // 2. 把 root 的绝对路径替换为 "<ROOT>"
    // 3. 递归排序数组，消除顺序不确定性
    v
}

#[test]
fn golden_python_mcp_server_result_is_stable() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../test-targets/python-mcp-server");
    let mut config = RuntimeConfig::default();
    config.static_.rule.enabled = true;
    config.static_.taint.enabled = true;
    config.static_.agent.enabled = false;      // 不依赖外部 CLI
    config.static_.codeql.enabled = false;     // 同上
    let result = run_static_scan(&config, &[], Some(&[root.clone()])).expect("scan");
    let actual = normalize_for_golden(&render_json(&result).expect("json"), &root);

    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/golden-python-mcp.json")).expect("fixture");
    assert_eq!(actual, expected, "golden regression: pipeline output changed");
}
```

- [ ] **步骤 2：生成 fixture**

先让测试失败并打印 `actual`，人工核对内容合理后写入 `fixtures/golden-python-mcp.json`。

> **注意：** fixture 一旦落地就是契约。后续任务中它变化即视为回归，除非该任务明确声明要改变行为（只有任务 9 的 corroboration 记账统一属于此类）。

- [ ] **步骤 3：确认通过并连跑三次验证稳定性**

```bash
cd rust && for i in 1 2 3; do cargo test -p mcp-sec-audit-core --test golden_regression || break; done
```

- [ ] **步骤 4：提交**

```bash
git commit -am "test(v5): add golden regression baseline for the static pipeline"
```

---

### 任务 2：`runctx.rs` —— RunId / Progress / RunContext

**文件：**
- 新建：`rust/crates/mcp-sec-audit-core/src/runctx.rs`
- 修改：`rust/crates/mcp-sec-audit-core/src/lib.rs`（挂模块 + re-export）
- 修改：`rust/Cargo.toml`、两个 crate 的 `Cargo.toml`（加依赖）

**接口：**
- 消费：`uuid::Uuid`、`tokio::sync::mpsc`、`tokio_util::sync::CancellationToken`
- 产出：`RunId`、`Progress`、`RunContext`

- [ ] **步骤 1：加依赖**

workspace `Cargo.toml` 的 `[workspace.dependencies]` 追加：

```toml
tokio = { version = "1", features = ["rt-multi-thread", "macros", "process", "sync", "time", "signal"] }
tokio-util = { version = "0.7", features = ["rt"] }
```

两个 crate 的 `Cargo.toml` 加 `tokio.workspace = true` / `tokio-util.workspace = true`。

- [ ] **步骤 2：写失败的测试**

新建 `runctx.rs`，先只写 `#[cfg(test)] mod tests`：

```rust
    #[test]
    fn run_ids_are_unique() {
        let a = RunId::new();
        let b = RunId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn temp_dir_is_keyed_by_run_id_not_pid() {
        let a = RunId::new();
        let b = RunId::new();
        assert_ne!(a.temp_dir("codeql"), b.temp_dir("codeql"));
        assert!(a.temp_dir("codeql").to_string_lossy().contains(a.as_str()));
    }

    #[test]
    fn for_repo_sanitizes_and_embeds_batch_id() {
        let id = RunId::for_repo("batch-1", "MCTS/examples");
        assert!(id.as_str().starts_with("batch-1-"));
        assert!(!id.as_str().contains('/'), "path separators must be sanitized");
    }
```

- [ ] **步骤 3：运行确认失败**

```bash
cd rust && cargo test -p mcp-sec-audit-core runctx
```

- [ ] **步骤 4：实现 `RunId`**

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(String);

impl RunId {
    pub fn new() -> Self { Self(uuid::Uuid::new_v4().simple().to_string()) }
    pub fn for_repo(batch_id: &str, repo: &str) -> Self {
        Self(format!("{batch_id}-{}", sanitize(repo)))
    }
    pub fn as_str(&self) -> &str { &self.0 }
    /// 所有 run-id 键控临时目录的唯一出口。
    pub fn temp_dir(&self, kind: &str) -> PathBuf {
        std::env::temp_dir().join(format!("mcp-sec-audit-{kind}-{}", self.0))
    }
}
```

`sanitize` 把 `/` `\` `:` `空格` 替换为 `-`。`Default` 实现委托给 `new()`。

- [ ] **步骤 5：实现 `Progress` 并加测试**

```rust
#[derive(Clone)]
pub struct Progress { tx: Option<mpsc::UnboundedSender<String>>, prefix: Option<String> }

impl Progress {
    pub fn noop() -> Self;
    pub fn channel() -> (Self, mpsc::UnboundedReceiver<String>);
    pub fn report(&self, msg: impl Into<String>);
    pub fn scoped(&self, repo: &str) -> Self;    // 设置 prefix，report 时加 "[repo] "
}
```

测试：`scoped("excel").report("hi")` 后接收端收到 `"[excel] hi"`；`noop().report(..)` 不 panic。

- [ ] **步骤 6：实现 `RunContext`**

```rust
pub struct RunContext {
    pub run_id: RunId,
    pub progress: Progress,
    pub cancel: CancellationToken,
    pub governor: Option<crate::batch::ResourceGovernor>,     // 任务 7 前先留 Option<()> 占位
    pub learning_bus: Option<crate::batch::LearningBusHandle>,// 任务 9 前同上
}
impl RunContext { pub fn single(run_id: RunId) -> Self; }
```

> 先用占位类型编译通过，任务 7 / 9 完成后再替换为真实类型。

- [ ] **步骤 7：确认通过并提交**

```bash
cd rust && cargo test --workspace && cargo clippy --workspace -- -D warnings
git commit -am "feat(v5): add RunId/Progress/RunContext plumbing types"
```

---

### 任务 3：`run_id` 进 `StaticScanContext`

**文件：**
- 修改：`rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`（结构体 + 构造）
- 修改：约 6 处测试内的字面量构造（`facts/pipeline.rs`、`codeql/mod.rs`、`rule/mod.rs`、`agent/mod.rs`、`codeql/models.rs`、`learning.rs`）

**接口：**
- 产出：`StaticScanContext.run_id: RunId`、`StaticScanContext::new(...)`

- [ ] **步骤 1：写失败的测试**

```rust
    #[test]
    fn scan_context_carries_a_run_id() {
        let ctx = StaticScanContext::new(RuntimeConfig::default(), Vec::new(), Vec::new());
        assert!(!ctx.run_id.as_str().is_empty());
    }
```

- [ ] **步骤 2：加字段与构造函数**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticScanContext {
    pub config: RuntimeConfig,
    pub rulebook_paths: Vec<String>,
    pub discovered_files: Vec<DiscoveredFile>,
    pub run_id: RunId,
}

impl StaticScanContext {
    pub fn new(config: RuntimeConfig, rulebook_paths: Vec<String>,
               discovered_files: Vec<DiscoveredFile>) -> Self {
        Self { config, rulebook_paths, discovered_files, run_id: RunId::new() }
    }
}
```

`RunId` 已 derive `PartialEq, Eq`，`StaticScanContext` 的 derive 不受影响。

- [ ] **步骤 3：修复所有字面量构造点**

优先改用 `StaticScanContext::new(..)`；无法改的补 `run_id: RunId::new()`。

```bash
cd rust && cargo build --workspace 2>&1 | grep -A3 'missing field `run_id`'
```

- [ ] **步骤 4：确认通过并提交**

```bash
cd rust && cargo test --workspace && cargo test -p mcp-sec-audit-core --test golden_regression
git commit -am "feat(v5): thread RunId through StaticScanContext"
```

---

### 任务 4：临时路径 run-id 键控 + 删除不安全的 DB 复用缓存

本任务解决设计文档 §2.1 —— 危害最高的阻塞点。

**文件：**
- 修改：`static_analysis/codeql/provider.rs`（DB 目录、SARIF 路径、去缓存）
- 修改：`static_analysis/codeql/models.rs`（MaD pack 目录）
- 修改：`static_analysis/pipeline.rs`（staging 目录 @ `:390`、`scan_identifier` @ `:1009`）

**接口：**
- 消费：`RunId::temp_dir`
- 产出：`CliCodeqlProvider::new(binary, run_id)`

- [ ] **步骤 1：写失败的测试**

```rust
    #[test]
    fn codeql_db_dirs_differ_across_runs_in_one_process() {
        let a = CliCodeqlProvider::new("codeql".into(), RunId::new());
        let b = CliCodeqlProvider::new("codeql".into(), RunId::new());
        assert_ne!(a.db_dir("python"), b.db_dir("python"),
                   "same-process runs must not share a CodeQL database");
        assert_ne!(a.sarif_path("python"), b.sarif_path("python"));
    }

    #[test]
    fn scan_identifier_embeds_run_id() {
        let ctx = StaticScanContext::new(RuntimeConfig::default(), Vec::new(), Vec::new());
        assert!(scan_identifier(&ctx).contains(ctx.run_id.as_str()));
    }
```

（需把 `db_dir` / `sarif_path` 抽成 `CliCodeqlProvider` 的可测方法。）

- [ ] **步骤 2：给 `CliCodeqlProvider` 加 `run_id` 字段**

```rust
pub(crate) struct CliCodeqlProvider { binary: String, run_id: RunId }

impl CliCodeqlProvider {
    pub(crate) fn new(binary: String, run_id: RunId) -> Self { Self { binary, run_id } }
    fn db_dir(&self, language: &str) -> PathBuf {
        self.run_id.temp_dir("codeql").join("db").join(language)
    }
    fn sarif_path(&self, language: &str) -> PathBuf {
        self.run_id.temp_dir("sarif").join(format!("{language}.sarif"))
    }
}
```

在 `codeql/mod.rs` 里构造 provider 处传入 `ctx.run_id.clone()`。

- [ ] **步骤 3：删除不安全的复用缓存**

`provider.rs:99-106` 整段删除：

```rust
// 删掉这段 —— run_id 每次唯一，此缓存既无效又会在并行时返回别的仓库的 DB
if db_dir.join("codeql-database.yml").exists() { return Ok(DatabaseInfo { .. }); }
```

- [ ] **步骤 4：改 MaD pack 与 staging 目录**

- `codeql/models.rs:116`：`write_model_pack_dir` 已接收 `ctx`，改为 `ctx.run_id.temp_dir("mad")`
- `pipeline.rs:390`：改为 `ctx.run_id.temp_dir("staging")`

- [ ] **步骤 5：`scan_identifier` 并入 run_id**

`pipeline.rs:1009` 的 `scan-{target}-{secs}` 改为 `scan-{target}-{run_id}`，消除并发同秒撞车。

> 这会改变 `learned_from` 字段的形态 —— **黄金 fixture 的归一化函数必须已屏蔽该字段**（任务 1 步骤 1 已要求）。若未屏蔽，先补屏蔽再继续。

- [ ] **步骤 6：确认通过并提交**

```bash
cd rust && cargo test --workspace && cargo test -p mcp-sec-audit-core --test golden_regression
git commit -am "feat(v5): key all temp paths by RunId; drop unsafe CodeQL DB reuse cache"
```

---

### 任务 5：`Progress` 取代 `impl FnMut(&str)`

`&mut` 闭包无法跨 await 点，必须在异步化之前替换掉。本任务**不引入任何 await**。

**文件：**
- 修改：`static_analysis/pipeline.rs`、`static_analysis/codeql/mod.rs`
- 修改：`crates/mcp-sec-audit-cli/src/main.rs`

**接口：**
- 产出：`codeql::run(ctx, catalog, progress: &Progress)`；`run_static_scan_with_progress` 变为桥接层

- [ ] **步骤 1：写失败的测试**

```rust
    #[test]
    fn progress_bridge_forwards_messages_to_the_legacy_closure() {
        let mut seen = Vec::new();
        let config = disabled_static_config();          // static_.enabled = false，最短路径
        let _ = run_static_scan_with_progress(&config, &[], None, |m| seen.push(m.to_string()));
        assert!(seen.iter().any(|m| m.contains("Scanning")));
    }
```

- [ ] **步骤 2：改内部签名**

`codeql::run` 与 pipeline 内部的 `progress` 参数由 `impl FnMut(&str)` 改为 `&Progress`，调用点 `progress(&format!(..))` → `progress.report(format!(..))`。

- [ ] **步骤 3：把公开 API 改成桥接层**

```rust
pub fn run_static_scan_with_progress(
    config: &RuntimeConfig, rulebook_paths: &[PathBuf],
    target_overrides: Option<&[PathBuf]>, mut progress: impl FnMut(&str),
) -> Result<StaticAnalysisResult> {
    let (sink, mut rx) = Progress::channel();
    let result = run_static_scan_inner(config, rulebook_paths, target_overrides, &sink);
    drop(sink);                                  // 关闭发送端，排空接收端
    while let Ok(msg) = rx.try_recv() { progress(&msg); }
    result
}
```

> 注意语义变化：进度消息现在是**运行结束后一次性回放**，而非实时。这在同步阶段可接受（任务 8 异步化后 orchestrator 会实时排空）。若 CLI 的实时进度是硬需求，改用 `std::sync::mpsc` 并在同一线程内交替排空。

- [ ] **步骤 4：确认通过并提交**

```bash
cd rust && cargo test --workspace && cargo test -p mcp-sec-audit-core --test golden_regression
git commit -am "feat(v5): replace FnMut progress closure with a cloneable Progress sink"
```

---

### 任务 6：两个 provider 异步化（含超时真杀子进程）

本任务解决设计文档 §2.3。**保留私有同步外壳**，使上层暂不需要改。

**文件：**
- 修改：`static_analysis/agent/provider.rs`
- 修改：`static_analysis/codeql/provider.rs`

**接口：**
- 产出：`CliAgentProvider::run(&self, config) -> impl Future<Output = Result<AgentRunOutput>>`；`CliCodeqlProvider::{create_database, run_analysis}` 同理

- [ ] **步骤 1：写失败的测试 —— 超时必须回收子进程**

```rust
    #[tokio::test]
    async fn agent_timeout_kills_the_child_process() {
        let provider = CliAgentProvider::default();
        let config = AgentRunConfig {
            provider_binary: "sleep".into(),
            extra_args: vec!["30".into()],
            timeout_seconds: 1,
            ..minimal_agent_run_config()
        };
        let started = std::time::Instant::now();
        let out = provider.run(&config).await.expect("run");
        assert!(out.timed_out);
        assert!(started.elapsed().as_secs() < 5, "must not wait for the child");
        // 子进程已被 kill_on_drop 回收：同名进程不应残留
        let ps = std::process::Command::new("pgrep").arg("-f").arg("sleep 30")
            .output().expect("pgrep");
        assert!(ps.stdout.is_empty(), "child leaked after timeout");
    }
```

- [ ] **步骤 2：重写 agent provider**

```rust
pub(crate) async fn run(&self, config: &AgentRunConfig) -> Result<AgentRunOutput> {
    let mut cmd = tokio::process::Command::new(&config.provider_binary);
    // ... 沿用现有参数拼装与 current_dir 逻辑 ...
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
       .kill_on_drop(true);                                  // ← 关键
    let child = cmd.spawn().map_err(/* 保留现有 NotFound 友好文案 */)?;

    match tokio::time::timeout(Duration::from_secs(config.timeout_seconds),
                               child.wait_with_output()).await {
        Ok(Ok(out))  => Ok(AgentRunOutput { timed_out: false, /* ... */ }),
        Ok(Err(e))   => Err(anyhow!("agent process failed: {e}")),
        Err(_elapsed) => Ok(AgentRunOutput { timed_out: true, /* ... */ }),
        // timeout 分支返回时 child 已被 drop → kill_on_drop 回收
    }
}
```

删除 `mpsc::channel` + `thread::spawn` + `recv_timeout` 那一整段。

- [ ] **步骤 3：加同步外壳供上层暂用**

```rust
pub(crate) fn run_blocking(&self, config: &AgentRunConfig) -> Result<AgentRunOutput> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?
        .block_on(self.run(config))
}
```

`agent::run` 暂时调 `run_blocking`。

- [ ] **步骤 4：同样重写 codeql provider**

`create_database` 用 `tokio::process::Command::output().await`；`run_analysis` 用 `spawn` + `tokio::time::timeout`，同样 `.kill_on_drop(true)`。保留 `run_analysis_blocking` 外壳。

- [ ] **步骤 5：确认通过并提交**

```bash
cd rust && cargo test --workspace && cargo test -p mcp-sec-audit-core --test golden_regression
git commit -am "feat(v5): async subprocess providers with kill-on-timeout"
```

---

### 任务 7：管线异步化

**最需要小心的一步。** 手法是「函数体逐字搬移 + 只在两处注入 `.await`」，不做任何重排。

**文件：**
- 修改：`static_analysis/pipeline.rs`

**接口：**
- 产出：`pub async fn run_static_scan_async(config, rulebook_paths, target_overrides, run_ctx: &RunContext) -> Result<StaticAnalysisResult>`
- 保留：`run_static_scan` / `run_static_scan_with_progress` 作为 `block_on` 外壳

- [ ] **步骤 1：抽出 async 版本**

把 `run_static_scan_inner` 的函数体**原样**搬进 `run_static_scan_async`，然后只做三件事：
1. `agent::run*` 调用点加 `.await`
2. `codeql::run` 调用点加 `.await`
3. 其余一行不动 —— 门控、`stage_catalog_evolution`、`diff_1`、`evolve`、`write_staging`、验证提示词、阶段 2、`diff_2`、`validate::migrate`、L2/L3 裁决、promote/rollback、`EvolutionReport`、`finish` 全部保持原样

- [ ] **步骤 2：CPU 重活包 `spawn_blocking`**

```rust
let ctx_owned = ctx.clone();
let catalog_owned = base_catalog.clone();
let (taint_results, taint_facts) = tokio::task::spawn_blocking(move || {
    taint::run_with_catalog(&ctx_owned, &catalog_owned)
}).await??;
```

对 `rule::run` 同样处理。`fusion::run` 轻量，直接同步调用即可。

- [ ] **步骤 3：同步外壳**

```rust
pub fn run_static_scan_with_progress(
    config: &RuntimeConfig, rulebook_paths: &[PathBuf],
    target_overrides: Option<&[PathBuf]>, mut progress: impl FnMut(&str),
) -> Result<StaticAnalysisResult> {
    let (sink, mut rx) = Progress::channel();
    let run_ctx = RunContext::single_with_progress(RunId::new(), sink);
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = rt.block_on(run_static_scan_async(config, rulebook_paths, target_overrides, &run_ctx));
    while let Ok(msg) = rx.try_recv() { progress(&msg); }
    result
}
```

- [ ] **步骤 4：黄金基线必须字节一致**

```bash
cd rust && cargo test --workspace && cargo test -p mcp-sec-audit-core --test golden_regression
```

> **如果黄金基线在此步变化，不要修改 fixture —— 那是回归信号。** 回退并逐段比对搬移前后的函数体。

- [ ] **步骤 5：提交**

```bash
git commit -am "feat(v5): async static analysis pipeline with sync compatibility shim"
```

---

### 任务 8：批次配置与合并

**文件：**
- 新建：`rust/crates/mcp-sec-audit-core/src/batch/{mod.rs,config.rs}`

**接口：**
- 产出：`BatchConfig` / `BatchSettings` / `LimitsConfig` / `RepoConfig`、`load_batch_config(&Path)`、`merge_repo_config(&RuntimeConfig, &RepoConfig)`

- [ ] **步骤 1：写失败的测试**

```rust
    #[test]
    fn repo_path_becomes_scan_target() {
        let base = RuntimeConfig::default();
        let repo = RepoConfig { name: "excel".into(), path: "../t/excel".into(),
                                overrides: Default::default() };
        let merged = merge_repo_config(&base, &repo).expect("merge");
        assert_eq!(merged.scan.targets, vec!["../t/excel".to_string()]);
    }

    #[test]
    fn nested_override_replaces_only_that_key() {
        let toml = r#"
[static.codeql]
enabled = true
timeout_seconds = 1200
[[batch.repo]]
name = "a"
path = "/a"
[batch.repo.static.codeql]
enabled = false
"#;
        let cfg: BatchConfig = toml::from_str(toml).expect("parse");
        let merged = merge_repo_config(&cfg.runtime, &cfg.batch.repos[0]).expect("merge");
        assert!(!merged.static_.codeql.enabled, "override applied");
        assert_eq!(merged.static_.codeql.timeout_seconds, 1200, "sibling key preserved");
    }

    #[test]
    fn limits_have_conservative_defaults() {
        let cfg: BatchConfig = toml::from_str("[batch]\n").expect("parse");
        assert_eq!(cfg.batch.limits.codeql, 1);
        assert_eq!(cfg.batch.limits.agent, 1);
        assert!(cfg.batch.learning_bus, "learning bus on by default");
    }
```

- [ ] **步骤 2：实现结构体与深合并**

见设计文档 §8。深合并规则：**表递归合并，标量与数组直接替换。**

- [ ] **步骤 3：确认通过并提交**

```bash
cd rust && cargo test -p mcp-sec-audit-core batch::config
git commit -am "feat(v5): batch config schema with per-repo override merging"
```

---

### 任务 9：资源限流器

**文件：**
- 新建：`rust/crates/mcp-sec-audit-core/src/batch/governor.rs`

- [ ] **步骤 1：写失败的测试 —— 峰值并发受控**

```rust
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn governor_caps_peak_concurrency_per_class() {
        let gov = ResourceGovernor::new(&LimitsConfig { codeql: 1, agent: 1, cpu: 2 });
        let peak = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let mut set = JoinSet::new();
        for _ in 0..8 {
            let (gov, peak, live) = (gov.clone(), peak.clone(), live.clone());
            set.spawn(async move {
                let _p = gov.acquire(ResourceClass::Codeql).await;
                let n = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
        while set.join_next().await.is_some() {}
        assert_eq!(peak.load(Ordering::SeqCst), 1, "codeql must be serialized");
    }
```

- [ ] **步骤 2：实现**

见设计文档 §6。**必须在 `acquire` 上方写下防死锁不变量的注释：**

```rust
/// # 防死锁不变量
/// 调用方任一时刻最多持有一个类别的许可，且绝不在持有 A 类许可时申请 B 类许可。
/// 因许可从不跨类别持有，环形等待在结构上不可能出现。
/// 实现方式：每个阶段独立作用域，靠 OwnedSemaphorePermit 的 RAII 释放。
pub async fn acquire(&self, class: ResourceClass) -> OwnedSemaphorePermit { .. }
```

- [ ] **步骤 3：确认通过并提交**

```bash
git commit -am "feat(v5): resource governor with per-class semaphores"
```

---

### 任务 10：学习总线

**文件：**
- 新建：`rust/crates/mcp-sec-audit-core/src/batch/learning_bus.rs`
- 修改：`static_analysis/facts/pipeline.rs`（新增 `load_catalog_with_learned`）
- 修改：`static_analysis/pipeline.rs`（抽出 `persist_promotion` 并路由）

**接口：**
- 产出：`BusMsg`、`LearningBusHandle::{snapshot, promote}`、`spawn(learned_dir)`

- [ ] **步骤 1：写失败的测试**

```rust
    #[tokio::test(flavor = "current_thread")]
    async fn bus_merges_evidence_across_repos() {
        let dir = tempdir_for("bus-merge");
        let bus = learning_bus::spawn(Some(dir.clone()));
        let sink = sink_model("os.system", "command_injection");

        bus.promote(PromoteRequest { repo: "a".into(), sinks: vec![sink.clone()], ..Default::default() })
           .await.expect("promote a");
        bus.promote(PromoteRequest { repo: "b".into(), sinks: vec![sink.clone()], ..Default::default() })
           .await.expect("promote b");

        let snap = bus.snapshot().await.expect("snapshot");
        let found = snap.sinks_for_language("python").iter()
            .find(|m| m.patterns.contains(&"os.system".to_string())).expect("model");
        assert!(found.corroboration_count >= 2,
                "two independent repos finding the same sink must corroborate");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn snapshot_reflects_only_prior_promotions() {
        let bus = learning_bus::spawn(None);
        let before = bus.snapshot().await.expect("snapshot");
        bus.promote(/* 新 sink */).await.expect("promote");
        let after = bus.snapshot().await.expect("snapshot");
        assert!(after.sinks_for_language("python").len() > before.sinks_for_language("python").len());
    }
```

- [ ] **步骤 2：实现 actor**

actor 持有 `learned_dir` 与内存权威 `ModelCatalog`，复用 `learning::merge_{sink,source,sanitizer}_models`。**持久化改为临时文件 + `fs::rename`** 以获得原子性。

- [ ] **步骤 3：`load_catalog_with_learned`**

```rust
pub(crate) fn load_catalog_with_learned(
    ctx: &StaticScanContext, learned: Option<&ModelCatalog>,
) -> Result<ModelCatalog>;
```

`load_catalog` 退化为传 `None` 的薄包装（既有行为不变）。

- [ ] **步骤 4：抽出 `persist_promotion` 并路由**

把 `pipeline.rs:637-696` 的固化逻辑抽成函数：`learning_bus` 为 `Some` 时发一条 `Promote` 并等 ack；为 `None` 时逐字执行现有代码。

> **行为变更声明（设计文档 §7.3 隐患 1）：** 统一走 actor 后，delta 固化路径也会 merge 既有证据（原先 `TaintComponent::promote` 直接覆写 `corroboration_count = 0`）。这是**既有缺陷的修复**。若此步导致黄金基线变化，**这是唯一允许更新 fixture 的时刻** —— 更新前须人工确认差异仅限 corroboration/pollution 计数。

- [ ] **步骤 5：入场快照接线**

`run_static_scan_async` 在阶段 1 之前：

```rust
let learned = match &run_ctx.learning_bus {
    Some(bus) => Some(bus.snapshot().await?),
    None => None,
};
let base_catalog = load_catalog_with_learned(&ctx, learned.as_ref())?;
```

**运行期间不再取快照** —— 保住 v4 阶段 1/2 的确定性（理由见设计文档 §7.1）。

- [ ] **步骤 6：确认通过并提交**

```bash
cd rust && cargo test --workspace && cargo test -p mcp-sec-audit-core --test golden_regression
git commit -am "feat(v5): single-writer learning bus with snapshot-at-entry semantics"
```

---

### 任务 11：批次汇总与 `<repo>` 占位符

**文件：**
- 新建：`rust/crates/mcp-sec-audit-core/src/batch/summary.rs`
- 修改：`rust/crates/mcp-sec-audit-core/src/reporting.rs`
- 修改：`rust/crates/mcp-sec-audit-cli/src/main.rs`

- [ ] **步骤 1：写失败的测试**

```rust
    #[test]
    fn resolve_output_path_substitutes_repo() {
        let out = resolve_output_path("docs/result/batch-<timestamp>/<repo>", Some("excel"));
        assert!(out.ends_with("/excel"));
        assert!(!out.contains("<timestamp>"));
    }

    #[test]
    fn repo_name_is_sanitized_for_filenames() {
        let out = resolve_output_path("r/<repo>", Some("MCTS/examples"));
        assert!(!out.trim_start_matches("r/").contains('/'), "must not create nested dirs");
    }
```

- [ ] **步骤 2：改签名并更新 3 个既有测试与调用点**

- [ ] **步骤 3：实现 `BatchSummary` 与渲染**

见设计文档 §9。**务必包含 `learning_bus_enabled` 字段** —— 使 CI 对比时能区分「顺序导致的差异」与真回归。

- [ ] **步骤 4：确认通过并提交**

```bash
git commit -am "feat(v5): batch summary report and <repo> output placeholder"
```

---

### 任务 12：编排器

**文件：**
- 新建：`rust/crates/mcp-sec-audit-core/src/batch/orchestrator.rs`

**接口：**
- 产出：`pub async fn run_batch(cfg: BatchConfig, cancel: CancellationToken) -> Result<BatchSummary>`

- [ ] **步骤 1：写失败的集成测试**

```rust
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batch_analyzes_two_repos_and_writes_both_reports() {
        let (dir_a, dir_b) = (tiny_python_repo("a"), tiny_python_repo("b"));
        let cfg = batch_config_for(&[("a", &dir_a), ("b", &dir_b)]);   // agent/codeql 关闭
        let summary = run_batch(cfg, CancellationToken::new()).await.expect("batch");
        assert_eq!(summary.succeeded, 2);
        assert_eq!(summary.failed, 0);
        for repo in &summary.repos { assert!(!repo.report_paths.is_empty()); }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_failing_repo_does_not_abort_the_batch() {
        let cfg = batch_config_for(&[("ok", &tiny_python_repo("ok")),
                                     ("missing", Path::new("/nonexistent/repo"))]);
        let summary = run_batch(cfg, CancellationToken::new()).await.expect("batch");
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed, 1);
        assert!(summary.repos.iter().any(|r| r.error.is_some()));
    }
```

- [ ] **步骤 2：实现**

- `batch_id = RunId::new()`；每仓库 `RunId::for_repo(batch_id, name)`
- `learning_bus = true` 时 `spawn(learned_dir)`，否则 `None`
- `JoinSet` 承载仓库任务，`max_parallel` 通过一个额外信号量控制
- 单独 task 排空 `Progress` 接收端，实时输出带 `[repo]` 前缀的日志
- `JoinError::is_panic()` → `RepoOutcome::Failed { error: "panicked" }`，批次继续
- `fail_fast = true` 时首个失败调 `cancel.cancel()`
- 全部结束后 `bus.shutdown()`，写每仓库报告 + 汇总

- [ ] **步骤 3：确认通过并提交**

```bash
git commit -am "feat(v5): batch orchestrator with JoinSet, governor and learning bus"
```

---

### 任务 13：CLI 接线、取消与退出码

**文件：**
- 修改：`rust/crates/mcp-sec-audit-cli/src/main.rs`
- 新建：`rust/crates/mcp-sec-audit-cli/src/batch.rs`
- 修改：`rust/crates/mcp-sec-audit-cli/src/logging.rs`
- 新建：`test-targets/configs/batch-example.toml`

- [ ] **步骤 1：加 `Batch` 子命令**

```rust
#[derive(Subcommand)]
enum Command {
    Status,
    Config { .. }, Rules { .. }, Report { .. },
    /// Analyze multiple MCP repositories in parallel.
    Batch(BatchArgs),
}

#[derive(Args)]
struct BatchArgs { config: PathBuf }
```

`fn main` 改 `#[tokio::main(flavor = "multi_thread")]`。**无子命令 + 位置参数 config 的旧行为必须原样保留。**

- [ ] **步骤 2：日志加 repo 归属**

`ModuleFormat::format_event` 里查 span 的 `repo` 字段，有则输出 `<时间> [repo] 模块: 消息`。仓库任务用 `tracing::info_span!("repo", repo = %name)` 包裹。

加测试断言格式。

- [ ] **步骤 3：Ctrl-C 与退出码**

```rust
let cancel = CancellationToken::new();
tokio::spawn({ let c = cancel.clone(); async move {
    let _ = tokio::signal::ctrl_c().await; c.cancel();
}});
let summary = batch::run(args, cancel.clone()).await;
std::process::exit(match summary {
    Ok(s) if cancel.is_cancelled() => 130,
    Ok(s) if s.failed > 0          => 1,
    Ok(_)                          => 0,
    Err(_)                         => 2,
});
```

- [ ] **步骤 4：写 `batch-example.toml`**

见设计文档 §8。

- [ ] **步骤 5：端到端手工验证**

```bash
cd rust && cargo run --release -- batch ../test-targets/configs/batch-example.toml
```

逐项确认：
1. 每仓库报告落到 `docs/result/batch-<ts>/<repo>.{json,md}`
2. `batch-summary.md` 生成，耗时与发现数正确
3. `$TMP/mcp-sec-audit-*-<run_id>/` 每仓库独立，结束后清理
4. 日志行带 `[repo]` 前缀，可区分来源
5. 并行期间 `pgrep -c codeql` 不超过 `limits.codeql`
6. 运行中 Ctrl-C → `pgrep -f 'codeql|claude'` 应为空

- [ ] **步骤 6：提交**

```bash
git commit -am "feat(v5): batch CLI subcommand with cancellation and exit codes"
```

---

### 任务 14：文档收尾

**文件：**
- 修改：`rust/docs/README.md`

- [ ] **步骤 1：版本表补两行**

```markdown
| **v4.0** | 两阶段差分自进化（M1–M4） | 2026-08-21 ~ 08-25 | `rust/docs/v4.0/` |
| **v5.0** | 并行多仓库分析（tokio + 学习总线） | 2026-08-25 ~ | `rust/docs/v5.0/` |
```

> v4.0 行在当前 README 中**缺失**，本任务一并补上。

- [ ] **步骤 2：目录结构与 v5.0 章节**

在目录树加 `v5.0/`，新增 v5.0 小节链接设计文档与本计划。

- [ ] **步骤 3：提交**

```bash
git commit -am "docs: index v4.0 and v5.0 in the docs README"
```

---

## 自查记录

**规格覆盖：** 设计文档 §2 的 6 个阻塞点 → 任务 0（2.4）、任务 4（2.1 + 2.5）、任务 6（2.3）、任务 10（2.2）、任务 13 步骤 2（2.6）。§5–§10 分别对应任务 2/3、9、10、8、11、12/13。

**占位符：** 无 TBD。任务 2 步骤 6 的 `Option<()>` 占位在任务 9 / 10 完成后替换，已显式标注。

**类型一致性：** `RunId` derive `PartialEq, Eq, Hash`，与 `StaticScanContext` 现有 derive 兼容。`Progress` 与 `LearningBusHandle` 均 `Clone + Send + Sync`，可跨 await。

**已知环境依赖：** 任务 6 的超时测试用 `sleep` 与 `pgrep`（Linux 可用）。任务 13 步骤 5 需真实 CodeQL CLI 才能验证第 5、6 项。

**唯一允许更新黄金 fixture 的时刻：** 任务 10 步骤 4（corroboration 记账统一）。其余任何任务导致 fixture 变化均为回归。

## 执行交接

按任务序号顺序执行；任务 8 与任务 9 相互独立，可并行。任务 12 依赖 8/9/10/11 全部完成。
