# v6.0 — Web UI（配置 → 运行 → 监控）

- 设计规格：`docs/superpowers/specs/2026-09-01-v6-webui-design.md`
- 实现计划：`docs/superpowers/plans/2026-09-01-v6-webui.md`

核心变更：新增 `webui` 子命令（与 `batch` 平级），提供 tailscale 黑白灰风格的
Web 前端，用于在页面填写/导入配置、启动批量或单仓库分析、实时监控各仓库进度与日志。
core 新增结构化事件流（`AnalysisEvent` + `EventSink`），管线按「两阶段 × 两线」层级上报阶段进度。

## 运行

从 `rust/` 目录执行 `cargo run -- webui`（默认二进制即 CLI，`webui` 与 `batch` 平级）。默认监听
`127.0.0.1:8770`，可用 `--addr` 指定地址、`--open` 自动打开浏览器（详见 CLI `--help`）。

> 注：`webui --config` 是**保留参数**（可接受但尚未接线）。启动时的 TOML 配置导入留作后续跟进，
> v6 请在页面中填写/导入配置。
