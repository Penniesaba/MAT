# Logging & Observability Foundation (R0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give mcp-sec-audit a configurable, structured logging subsystem (`tracing` + `tracing-subscriber`) so every stage of the static scan is observable in the terminal, and verbosity is tunable per component via `[logging]` config.

**Architecture:** Add a `LoggingConfig` section to the runtime config; add `tracing`/`tracing-subscriber` as workspace deps; instrument the core pipeline with `tracing` spans + target-scoped events (keeping the existing `progress` callback as the coarse user-facing channel); initialize the process-global subscriber in the CLI from `[logging]` and route the progress callback through it.

**Tech Stack:** Rust edition 2024; `tracing` 0.1 (facade), `tracing-subscriber` 0.3 (fmt + registry + Targets filter); `toml`/`serde` for config.

**Spec:** `rust/docs/ARCHITECTURE_REDESIGN.md` §3 原则 5、§5.7 日志与可观测性(这是 P1 实现的规格)。同时参考 `rust/docs/GENERALITY_STRATEGY.md`(原理)。

---

## Global Constraints

- 工作区根:`rust/`(所有 `cargo` 命令从该目录运行)。
- `LoggingConfig` 是 core 的一部分(`config.rs`),并需经 `lib.rs` re-export 供 CLI 使用。
- 日志默认写 **stderr**(stdout 留给报告输出),`ansi` 默认开启。
- 不得破坏既有测试:core 的 `pipeline.rs` / `codeql/mod.rs` / `config.rs` 测试须保持全绿。
- 追踪目标(target)命名约定:`mcp_sec_audit::{pipeline|rule|taint|agent|codeql|fusion|learning}`。
- 每步 `cargo test` 全绿后再提交;提交信息遵循仓库既有 `type(scope): summary` 风格。

---

## File Structure

| 文件 | 职责 | 动作 |
|---|---|---|
| `crates/mcp-sec-audit-core/src/config.rs` | 运行时配置 schema | 新增 `LogLevel`/`LogFormat`/`LoggingConfig`,挂到 `RuntimeConfig` |
| `crates/mcp-sec-audit-core/src/lib.rs` | 公共导出 | re-export `LoggingConfig`/`LogLevel`/`LogFormat` |
| `Cargo.toml`(工作区) | 依赖版本 | 新增 `tracing`、`tracing-subscriber` |
| `crates/mcp-sec-audit-core/Cargo.toml` | core 依赖 | 新增 `tracing` |
| `crates/mcp-sec-audit-cli/Cargo.toml` | cli 依赖 | 新增 `tracing`、`tracing-subscriber` |
| `crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs` | 编排 | 每阶段包 `info_span!` + 带计数/耗时的 `info!` 事件 |
| `crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs` | CodeQL 线 | 建库/分析步骤加 `debug!`/`info!` 事件 |
| `crates/mcp-sec-audit-cli/src/logging.rs` | 订阅器构建 | `init()` + `build_targets()` + `scope_directives()` |
| `crates/mcp-sec-audit-cli/src/main.rs` | 入口 | 声明 `mod logging;`,scan 前 `init`,progress 走 tracing |

---

## Task 1: Add `LoggingConfig` to runtime config

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/config.rs`
- Modify: `crates/mcp-sec-audit-core/src/lib.rs`

**Interfaces:**
- Produces: `LogLevel`(enum: Trace/Debug/Info/Warn/Error, serde lowercase)、`LogFormat`(enum: Full/Compact/Pretty/Json, serde lowercase)、`LoggingConfig { level, format, ansi, show_timestamps, show_progress, log_file, scopes }`。`RuntimeConfig` 新增 `logging: LoggingConfig` 字段。

- [ ] **Step 1: Write the failing test**

在 `config.rs` 的 `#[cfg(test)] mod tests` 末尾追加:

```rust
    #[test]
    fn logging_config_parses_from_toml() {
        let config: RuntimeConfig = toml::from_str(
            r#"
            [logging]
            level = "debug"
            format = "json"
            ansi = false
            show_timestamps = false
            show_progress = false
            log_file = "logs/audit.log"

            [logging.scopes]
            codeql = "trace"
            rule = "debug"
            "#,
        )
        .expect("parse config");

        assert_eq!(config.logging.level, LogLevel::Debug);
        assert_eq!(config.logging.format, LogFormat::Json);
        assert!(!config.logging.ansi);
        assert!(!config.logging.show_timestamps);
        assert!(!config.logging.show_progress);
        assert_eq!(config.logging.log_file.as_deref(), Some("logs/audit.log"));
        assert_eq!(config.logging.scopes.get("codeql"), Some(&LogLevel::Trace));
        assert_eq!(config.logging.scopes.get("rule"), Some(&LogLevel::Debug));
    }

    #[test]
    fn logging_config_defaults_are_stable() {
        let logging = LoggingConfig::default();
        assert_eq!(logging.level, LogLevel::Info);
        assert_eq!(logging.format, LogFormat::Compact);
        assert!(logging.ansi);
        assert!(logging.show_timestamps);
        assert!(logging.show_progress);
        assert!(logging.log_file.is_none());
        assert!(logging.scopes.is_empty());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mcp-sec-audit-core config::tests::logging_config_parses_from_toml`
Expected: FAIL — `cannot find type LogLevel` / `no field logging on RuntimeConfig`.

- [ ] **Step 3: Write minimal implementation**

在 `config.rs` 顶部 `use` 处加 `BTreeMap`:

```rust
use std::{collections::BTreeMap, fs, path::Path};
```

在 `RuntimeConfig` 定义之前(或之后)新增三个类型:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Full,
    Compact,
    Pretty,
    Json,
}

impl Default for LogFormat {
    fn default() -> Self {
        LogFormat::Compact
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default)]
    pub level: LogLevel,
    #[serde(default)]
    pub format: LogFormat,
    #[serde(default = "default_true")]
    pub ansi: bool,
    #[serde(default = "default_true")]
    pub show_timestamps: bool,
    #[serde(default = "default_true")]
    pub show_progress: bool,
    #[serde(default)]
    pub log_file: Option<String>,
    #[serde(default)]
    pub scopes: BTreeMap<String, LogLevel>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Compact,
            ansi: true,
            show_timestamps: true,
            show_progress: true,
            log_file: None,
            scopes: BTreeMap::new(),
        }
    }
}
```

给 `RuntimeConfig` 加字段(在 `report` 之后):

```rust
    #[serde(default)]
    pub logging: LoggingConfig,
```

给 `RuntimeConfig::default()` 加字段:

```rust
            report: ReportConfig::default(),
            logging: LoggingConfig::default(),
```

在 `lib.rs` 的 `pub use config::{...}` 里加入 `LogFormat, LogLevel, LoggingConfig`。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mcp-sec-audit-core config::tests::logging_config_`
Expected: PASS(两个新测试 + 既有 config 测试全绿)。

- [ ] **Step 5: Commit**

```bash
git add crates/mcp-sec-audit-core/src/config.rs crates/mcp-sec-audit-core/src/lib.rs
git commit -m "feat(config): add [logging] section (LoggingConfig, level/format/scopes)"
```

---

## Task 2: Add tracing dependencies

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/mcp-sec-audit-core/Cargo.toml`
- Modify: `crates/mcp-sec-audit-cli/Cargo.toml`

**Interfaces:**
- Produces: workspace deps `tracing = "0.1"`、`tracing-subscriber = "0.3"`,供 Task 3/4 使用。

- [ ] **Step 1: Add workspace deps**

在 `Cargo.toml` 的 `[workspace.dependencies]` 末尾追加:

```toml
tracing = "0.1"
tracing-subscriber = "0.3"
```

- [ ] **Step 2: Add crate deps**

在 `crates/mcp-sec-audit-core/Cargo.toml` 的 `[dependencies]` 追加:

```toml
tracing.workspace = true
```

并在 `crates/mcp-sec-audit-core/Cargo.toml` 新增 `[dev-dependencies]`(Task 4 的捕获型日志测试需要):

```toml
[dev-dependencies]
tracing-subscriber.workspace = true
```

在 `crates/mcp-sec-audit-cli/Cargo.toml` 的 `[dependencies]` 追加:

```toml
tracing.workspace = true
tracing-subscriber.workspace = true
```

- [ ] **Step 3: Verify build**

Run: `cargo build -p mcp-sec-audit-core -p mcp-sec-audit-cli`
Expected: 编译通过(新增依赖不影响既有代码)。

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/mcp-sec-audit-core/Cargo.toml crates/mcp-sec-audit-cli/Cargo.toml
git commit -m "chore(deps): add tracing and tracing-subscriber"
```

---

## Task 3: CLI logging module (subscriber init + target filter)

**Files:**
- Create: `crates/mcp-sec-audit-cli/src/logging.rs`
- Modify: `crates/mcp-sec-audit-cli/src/main.rs`

**Interfaces:**
- Consumes: `mcp_sec_audit_core::{LogFormat, LogLevel, LoggingConfig}`(Task 1)。
- Produces: `pub fn scope_directives(&LoggingConfig) -> Vec<(String, LevelFilter)>`(可测)、`pub fn build_targets(&LoggingConfig) -> Targets`、`pub fn init(&LoggingConfig) -> anyhow::Result<()>`。

- [ ] **Step 1: Write the failing test**

在新建 `logging.rs` 末尾加:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mcp_sec_audit_core::LoggingConfig;

    #[test]
    fn scope_directives_maps_scopes_to_targets() {
        let mut config = LoggingConfig::default();
        config.level = LogLevel::Info;
        config.scopes.insert("codeql".to_string(), LogLevel::Trace);
        config.scopes.insert("rule".to_string(), LogLevel::Debug);

        let directives = scope_directives(&config);

        assert_eq!(directives[0], ("".to_string(), LevelFilter::INFO));
        assert!(directives.contains(&("mcp_sec_audit::codeql".to_string(), LevelFilter::TRACE)));
        assert!(directives.contains(&("mcp_sec_audit::rule".to_string(), LevelFilter::DEBUG)));
    }

    #[test]
    fn scope_directives_ignores_unknown_scope_keys() {
        let mut config = LoggingConfig::default();
        config.scopes.insert("bogus".to_string(), LogLevel::Trace);

        let directives = scope_directives(&config);
        // unknown key contributes nothing beyond the default entry
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0], ("".to_string(), LevelFilter::INFO));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mcp-sec-audit-cli logging::tests::scope_directives_maps_scopes_to_targets`
Expected: FAIL — `file not found for module logging`(先做 Step 3 的 `mod logging;` 或本步失败于缺失模块)。

- [ ] **Step 3: Write minimal implementation**

创建 `crates/mcp-sec-audit-cli/src/logging.rs`:

```rust
use std::io;

use anyhow::Result;
use mcp_sec_audit_core::{LogFormat, LogLevel, LoggingConfig};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// `[logging.scopes]` keys mapped to the tracing targets used by the
/// pipeline and analysis lines.
const SCOPE_TARGETS: &[(&str, &str)] = &[
    ("pipeline", "mcp_sec_audit::pipeline"),
    ("rule", "mcp_sec_audit::rule"),
    ("taint", "mcp_sec_audit::taint"),
    ("agent", "mcp_sec_audit::agent"),
    ("codeql", "mcp_sec_audit::codeql"),
    ("fusion", "mcp_sec_audit::fusion"),
    ("learning", "mcp_sec_audit::learning"),
];

/// Pure mapping from config to per-target (target, level) directives.
/// The first entry is the default (`""` = all targets).
pub fn scope_directives(config: &LoggingConfig) -> Vec<(String, LevelFilter)> {
    let mut out = vec![("".to_string(), to_level_filter(config.level))];
    for (key, target) in SCOPE_TARGETS {
        if let Some(&level) = config.scopes.get(*key) {
            out.push((target.to_string(), to_level_filter(level)));
        }
    }
    out
}

/// Build the `Targets` filter consumed by the subscriber.
pub fn build_targets(config: &LoggingConfig) -> Targets {
    let mut targets = Targets::new().with_default(to_level_filter(config.level));
    for (target, level) in scope_directives(config).into_iter().skip(1) {
        targets = targets.with_target(&target, level);
    }
    targets
}

fn to_level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Trace => LevelFilter::TRACE,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
    }
}

/// Initialize the process-global subscriber from `[logging]` config.
/// Writes to stderr (and optionally a file). Only call once.
pub fn init(config: &LoggingConfig) -> Result<()> {
    let targets = build_targets(config);
    let registry = tracing_subscriber::registry()
        .with(targets)
        .with(fmt_layer(config).with_writer(io::stderr));

    let result = match &config.log_file {
        Some(path) => {
            let file = std::fs::File::create(path)
                .map_err(|e| anyhow::anyhow!("create log file {path}: {e}"))?;
            registry
                .with(fmt_layer(config).with_writer(file))
                .try_init()
        }
        None => registry.try_init(),
    };

    result.map_err(|e| anyhow::anyhow!("tracing init failed: {e}"))
}

fn fmt_layer<S>(config: &LoggingConfig) -> tracing_subscriber::fmt::Layer<S> {
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(config.ansi)
        .with_target(true);
    let layer = match config.format {
        LogFormat::Full => layer,
        LogFormat::Compact => layer.compact(),
        LogFormat::Pretty => layer.pretty(),
        LogFormat::Json => layer.json(),
    };
    if config.show_timestamps {
        layer
    } else {
        layer.without_time()
    }
}
```

在 `main.rs` 顶部(第 1 行 `use` 之前)加:

```rust
mod logging;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mcp-sec-audit-cli`
Expected: PASS(两个新测试 + 既有 `cli_definition_is_valid` / `write_report_files_*` 全绿)。

- [ ] **Step 5: Commit**

```bash
git add crates/mcp-sec-audit-cli/src/logging.rs crates/mcp-sec-audit-cli/src/main.rs
git commit -m "feat(cli): add logging module (subscriber init + target filter)"
```

---

## Task 4: Instrument pipeline + CodeQL line with tracing

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs`
- Modify: `crates/mcp-sec-audit-cli/src/main.rs`(progress 走 tracing + init)

**Interfaces:**
- Consumes: `LoggingConfig.show_progress`(Task 1)、`logging::init`(Task 3)。
- Produces: 五阶段各自的 `info_span!` + 带 `findings`/`elapsed_ms` 的 `info!` 事件;CodeQL 建库/分析步骤的 `debug!`/`info!` 事件。保持 `progress` 回调签名不变(作为粗粒度用户可见通道)。

- [ ] **Step 1: Write the failing test**

在 `pipeline.rs` 的 `#[cfg(test)] mod tests` 末尾追加(依赖既有的 `temp_dir`/`write_rulebook` 辅助函数)。该测试用一个捕获型 `MakeWriter` 把 tracing 输出收集到内存,断言结构化事件已发出:

```rust
    #[test]
    fn scan_emits_structured_stage_logs() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
            type Writer = Buffer;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let root = temp_dir("structured-logs");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(root.join("server.py"), "subprocess.run('id')").expect("write file");

        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = true;

        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(buffer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");
        });

        let output = String::from_utf8(buffer.0.lock().unwrap().clone()).expect("utf8");
        assert!(output.contains("rule analysis complete"), "rule event: {output}");
        assert!(output.contains("taint analysis complete"), "taint event: {output}");
        assert!(output.contains("fusion complete"), "fusion event: {output}");

        fs::remove_dir_all(root).expect("cleanup");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mcp-sec-audit-core pipeline::tests::scan_emits_structured_stage_logs`
Expected: FAIL — 当前 pipeline 未发任何 `tracing` 事件,`output` 为空,`contains("rule analysis complete")` 为 false。

- [ ] **Step 3: Write minimal implementation**

**(a) `pipeline.rs`**:把五个阶段各自包进 `info_span!` 并补 `info!` 事件。以下为 rule 阶段的改造范式(其余 taint/agent/codeql/fusion 同构替换,`target` 分别用 `mcp_sec_audit::rule|taint|agent|codeql|fusion`)。替换现有:

```rust
    progress(if effective_config.static_.rule.enabled {
        "Running rule analysis..."
    } else {
        "Rule analysis: skipped (disabled)"
    });
    let rule_results = rule::run(&ctx, loaded_rulebook.as_ref())?;
    progress(&format!("Rule analysis done: {} findings", rule_results.len()));
```

为:

```rust
    let rule_results = {
        let _enter = tracing::info_span!(
            target: "mcp_sec_audit::rule",
            "rule",
            enabled = effective_config.static_.rule.enabled
        )
        .entered();
        progress(if effective_config.static_.rule.enabled {
            "Running rule analysis..."
        } else {
            "Rule analysis: skipped (disabled)"
        });
        let start = std::time::Instant::now();
        let results = rule::run(&ctx, loaded_rulebook.as_ref())?;
        tracing::info!(
            target: "mcp_sec_audit::rule",
            findings = results.len(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "rule analysis complete"
        );
        progress(&format!("Rule analysis done: {} findings", results.len()));
        results
    };
```

> 其余阶段同构:taint 的 `findings` 用 `(taint_results.len(), all_facts.len())` 两个字段;agent 用 `findings = agent_results.len()`;codeql 用 `findings = codeql_output.results.len()` + `diagnostics = codeql_output.diagnostics.len()`;fusion 用 `findings = fused_findings.len()`。变量仍保持函数作用域(见「Fusing results...」段),仅把 `let` 包进块并在块尾返回。

在文件顶部 `use` 之后加(如无则新增):

```rust
use std::time::Instant;
```

**(b) `codeql/mod.rs`**:让「无支持语言」的 skip 也调 `progress`(这是 Step 2 失败的直接原因),并给建库/分析加事件。替换:

```rust
    if supported_files.is_empty() {
        progress("CodeQL skipped: no CodeQL-supported language in target");
```

为(在 `progress(...)` 前加一条 `warn!`,并保持 `progress` 调用——它原本就有,问题在 Step 2 里 codeql disabled 分支未调 progress;见下方 (c)):

```rust
    if supported_files.is_empty() {
        tracing::warn!(
            target: "mcp_sec_audit::codeql",
            "CodeQL skipped: no CodeQL-supported language in target"
        );
        progress("CodeQL skipped: no CodeQL-supported language in target");
```

在建库循环里 `provider.create_database(...)` 前加:

```rust
        tracing::debug!(
            target: "mcp_sec_audit::codeql",
            language = %language,
            "creating CodeQL database"
        );
```

在 `provider.run_analysis(...)` 调用前加:

```rust
        tracing::debug!(
            target: "mcp_sec_audit::codeql",
            language = %language,
            "running CodeQL analysis"
        );
```

在 `parser::parse_sarif(...)` 的 `Ok(results) =>` 分支里、`all_results.extend(results);` 之前加:

```rust
                        tracing::info!(
                            target: "mcp_sec_audit::codeql",
                            language = %language,
                            findings = results.len(),
                            "CodeQL analysis produced results"
                        );
```

**(c) `codeql/mod.rs`**:让「codeql 未启用」也走 `progress`,以满足测试断言 "codeql" 出现。在 `run` 开头 `if !codeql_config.enabled { return Ok(CodeqlOutput::empty()); }` 改为:

```rust
    if !codeql_config.enabled {
        progress("CodeQL analysis: skipped (disabled)");
        return Ok(CodeqlOutput::empty());
    }
```

**(d) `main.rs`**:scan 前初始化订阅器,progress 走 tracing。替换 `run_static_scan_from_config`:

```rust
fn run_static_scan_from_config(config_path: &PathBuf) -> Result<()> {
    let config = mcp_sec_audit_core::load_runtime_config(config_path)?;
    logging::init(&config.logging)?;
    let result = mcp_sec_audit_core::run_static_scan_with_progress(
        &config,
        &[] as &[PathBuf],
        None,
        |msg| {
            if config.logging.show_progress {
                tracing::info!(target: "mcp_sec_audit::pipeline", "{msg}");
            }
        },
    )?;
    for path in write_report_files(&result, &config.report)? {
        tracing::info!(target: "mcp_sec_audit::pipeline", path = %path.display(), "wrote report");
    }
    Ok(())
}
```

> 说明:closure 捕获 `config.logging.show_progress`(`bool`,`Copy`),类型唯一,满足 `impl FnMut(&str)` 约束。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mcp-sec-audit-core` 然后 `cargo test -p mcp-sec-audit-cli`
Expected: PASS(新测试 + 既有 pipeline/codeql/config 测试全绿;codeql 既有测试 `unsupported_language_emits_skip_progress` 仍通过,因为它已捕获 "CodeQL skipped")。

- [ ] **Step 5: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs \
        crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs \
        crates/mcp-sec-audit-cli/src/main.rs
git commit -m "feat(static): instrument pipeline and codeql with tracing spans/events"
```

---

## Self-Review

**Spec coverage(对照 `ARCHITECTURE_REDESIGN.md` §5.7):**
- `[logging]` 配置(level/format/ansi/show_timestamps/show_progress/log_file/scopes)→ Task 1 ✅
- `tracing` + `tracing-subscriber` 技术选型 → Task 2 ✅
- 订阅器初始化 + 每组件力度(scopes)→ Task 3 ✅
- 五阶段关键日志(计数/耗时)→ Task 4 ✅(pipeline 五阶段 + codeql 建库/分析)
- 终端体验(progress 走 stderr、`show_progress` 开关)→ Task 4 (d) ✅
- 四条铁律之「绝不静默 / 决策必留痕」→ 阶段级 `info!` + codeql skip `warn!` ✅(每组件更深日志留待 P2–P6)

**Placeholder scan:** 无 TBD/TODO;所有步骤含可运行代码与断言。

**Type consistency:** `LogLevel`/`LogFormat`(Copy,serde lowercase)在 Task 1 定义,Task 3 通过 `mcp_sec_audit_core::{...}` 消费,`scope_directives` 返回 `Vec<(String, LevelFilter)>` 且被 `build_targets` 复用 —— 一致。目标串 `mcp_sec_audit::{...}` 在 Task 3 的 `SCOPE_TARGETS` 与 Task 4 的 `target:` 字面量一致。

**已知遗留(不阻塞,记录在案):** `log_file` 目前只实现「写文件 + 仍写 stderr」双通道;若需仅写文件需后续加开关。每子线(rule/taint/agent/fusion)的逐 sink/逐判定 trace 日志不在 P1,随 P2–P6 各自子系统落地时补齐。

---

## Execution Notes(与计划的偏差)

实现时的两处偏差,已作为工程决策记录:

1. **Task 4 的捕获型日志测试被替换为 CLI 冒烟测试。** 原计划的 `scan_emits_structured_stage_logs`
   (用 `tracing::subscriber::with_default` + 自定义 `MakeWriter` 捕获)在并行测试下**不稳定**:
   `tracing` 的 per-callsite interest 缓存是全局的,兄弟 pipeline 测试先以「无订阅器」状态命中同一
   callsite、把 interest 缓存成 Never,导致本测试的捕获订阅器永远收不到事件(串行 `--test-threads=1`
   通过、并行失败)。tracing 事件本身由 `tracing`/`tracing-subscriber` 保证正确,因此改为用 CLI 冒烟
   测试(`cargo build -p mcp-sec-audit-cli` + 跑一份带 `[logging]` 的配置,验证终端出现五阶段 span 与
   `findings`/`elapsed_ms` 字段)验证,并保留 189 个既有测试作回归防线。若后续需单测具体日志内容,再引入
   `tracing-test` crate。
2. **CodeQL `!enabled` 分支的 `progress` 调用被回退。** pipeline 在调用 `codeql::run` 前已发出
   `CodeQL analysis: skipped (disabled)`,codeql 内再加一条会重复;回退后日志不再出现两次 skip。

## Execution Handoff

Plan complete and saved to `rust/docs/superpowers/plans/2026-08-20-logging-foundation.md`。
