# mcp-sec-audit 文档索引

## 版本命名规范

| 版本 | 含义 | 时间 | 文档位置 |
|---|---|---|---|
| **v1.0** | Python 原版实现 | 2026-07-31 ~ 08-03 | 仓库根 `docs/` |
| **v2.0** | Rust 重构（Phase 2–13，多语言 fact 提取 + 四线静态分析） | 2026-08-04 ~ 08-18 | `rust/docs/v2.0/` |
| **v3.0** | 8.21 架构重构（模型驱动 · 双引擎 · 自进化，R0–R5） | 2026-08-19 ~ 08-21 | `rust/docs/v3.0/` |
| **v4.0** | 两阶段差分自进化（M1–M4，门控 · 回滚 · 自洽裁决） | 2026-08-21 ~ 08-25 | `rust/docs/v4.0/` |
| **v5.0** | 并行多仓库分析（tokio 全链路 async · 跨仓库学习总线） | 2026-08-25 ~ | `rust/docs/v5.0/` |

> v1.0 文档仍保留在仓库根目录 `docs/`（Python 原版），未迁入 `rust/docs/`。

## 目录结构

```
rust/docs/
├── v2.0/         Rust 重构文档（设计与计划）
├── v3.0/         8.21 架构重构文档
│   └── plans/    R0–R5 里程碑 SDD 计划
├── v4.0/         两阶段差分自进化文档
│   └── plans/    M1–M4 里程碑 SDD 计划
├── v5.0/         并行多仓库分析文档（当前）
│   └── plans/    实现计划
├── reference/    版本无关参考
├── result/       各版本扫描结果输出（按日期排序）
└── .obsidian/    Obsidian 配置（勿动）
```

## v5.0 — 并行多仓库分析（当前）

- [`PARALLEL_MULTI_REPO_DESIGN_20260825.md`](v5.0/PARALLEL_MULTI_REPO_DESIGN_20260825.md) — **设计规格书**（阻塞点盘点 · RunId 隔离 · 分级限流 · 学习总线 · 失败与取消语义）
- [`plans/2026-08-25-v5-parallel-orchestration.md`](v5.0/plans/2026-08-25-v5-parallel-orchestration.md) — 实现计划（任务 0–14，TDD 步骤）

核心变更：单进程内并行分析 N 个仓库；`learned_dir` 由单写者 actor 独占，仓库间以「入场快照」共享学习成果。仓库内部的 v4 两阶段自进化语义保持不变。

## v4.0 — 两阶段差分自进化

- [`IDEA_EVALUATION_AND_DESIGN.md`](v4.0/IDEA_EVALUATION_AND_DESIGN.md) — **v4.0 规格书**
- [`SELF_EVOLUTION_DESIGN_20260824.md`](v4.0/SELF_EVOLUTION_DESIGN_20260824.md) — 自进化方案对比（A/B/C/D）
- [`SELF_EVOLUTION_SELF_CONSISTENT_DESIGN_20260824.md`](v4.0/SELF_EVOLUTION_SELF_CONSISTENT_DESIGN_20260824.md) — 自洽裁决设计
- [`SELF_CHECK_AND_TEST_PLAN.md`](v4.0/SELF_CHECK_AND_TEST_PLAN.md) — 自检与测试方案（含配置字段全表）
- [`plans/`](v4.0/plans/) — M1–M4 里程碑计划

## v3.0 — 8.21 架构重构

- [`ARCHITECTURE_REDESIGN.md`](v3.0/ARCHITECTURE_REDESIGN.md) — **新架构规格书**（模型驱动 · 双引擎 · 自进化 五阶段管线）
- [`GENERALITY_STRATEGY.md`](v3.0/GENERALITY_STRATEGY.md) — 战略层：为什么「无限补 QL 文件」不是答案
- [`CODEQL_MASTER_PLAN.md`](v3.0/CODEQL_MASTER_PLAN.md) — CodeQL 方案完善计划 + 从零精通指南（R4）
- [`rust-ql-api-notes.md`](v3.0/rust-ql-api-notes.md) — Rust CodeQL API spike 参考（R4 支撑）
- [`EXCEL_SCAN_DIAGNOSIS.md`](v3.0/EXCEL_SCAN_DIAGNOSIS.md) — Excel MCP Server 扫描诊断（架构重构的直接触发点）
- [`plans/`](v3.0/plans/) — R0–R5 里程碑 SDD 计划

### R0–R5 里程碑计划

| 里程碑 | 计划文件 |
|---|---|
| R2 模型目录 | `plans/2026-08-20-model-catalog-yaml.md` |
| R3 语义推理 | `plans/2026-08-20-model-assembly-semantic-inference.md` |
| R3 融合对齐 | `plans/2026-08-20-fusion-category-alignment.md` |
| 日志基座 | `plans/2026-08-20-logging-foundation.md` |
| R4 CodeQL 全量 | `plans/2026-08-20-codeql-full-leverage.md` |
| R5 Agent 三角色 + 门控 + 温/冷注入 | `plans/2026-08-20-agent-gate-warm-cold.md` |

## v2.0 — Rust 重构

- `REFACTOR_PLAN.md` — 分阶段 Rust 重构总计划
- `STATIC_ANALYSIS_REFACTOR_DESIGN.md` — 静态分析 Rust 重构设计
- `STATIC_ANALYSIS_ARCHITECTURE.md` — 静态分析架构与技术原理
- `PHASE2_DATA_MODEL_DESIGN.md` — Phase 2 兼容数据模型设计
- `PHASES_789_COMPREHENSIVE_REVIEW.md` — Phase 7/8/9 多语言 fact 提取总结
- `TEST_PLAN.md` — 静态分析测试方案
- `OUTPUT_AND_CONFIG_GUIDE.md` — 输出文件与配置字段详解
- `IMPROVEMENT_PLAN.md` — Rust 结果改进计划（准确性 + 融合）
- `STATIC_ANALYSIS_LIMITATIONS.md` — 静态分析问题与不足分析
- `RUN_ANALYSIS_20260815-100928.md` — 运行结果分析报告

## reference — 版本无关参考

- `VULNERABLE_PYTHON_MCP_SERVERS.md` — 带公开漏洞的真实 Python MCP Server 测试目标清单
