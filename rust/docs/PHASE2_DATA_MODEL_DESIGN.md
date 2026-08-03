# Phase 2：兼容数据模型设计

## 目标

Phase 2 的目标是在 Rust 实现中建立一组可共享、可序列化、可测试的数据模型，用于承接现有 Python 实现中的报告输出和静态分析 fact schema。

本阶段只定义模型和 JSON 兼容行为，不实现静态分析逻辑。

## 范围

本阶段包含两层模型：

1. 报告层模型：面向最终检测结果、报告输出、Web portal 和 benchmark 对齐。
2. Fact 层模型：面向后续 extractor、call graph、taint-lite、dynamic correlation 和 finding builder。

本阶段不包含：

- 文件扫描
- AST parser
- TOML 规则加载
- call graph
- taint analysis
- finding builder
- dynamic correlation
- 报告格式渲染

## 模块结构

Phase 2 的模型放在 `mcp-sec-audit-core` crate 中：

```text
rust/crates/mcp-sec-audit-core/src/
├── lib.rs
├── fixtures.rs
└── model/
    ├── mod.rs
    ├── enums.rs
    ├── report.rs
    └── facts.rs
```

职责划分：

- `model/enums.rs`：跨层共享枚举，例如 severity、confidence、finding status、runtime event kind。
- `model/report.rs`：最终报告兼容模型，对齐 Python 的 `CapabilityFinding` 和 `DetectionResult`。
- `model/facts.rs`：AST、runtime、finding fact 模型，对齐 Python 的 `analysis/facts/schema.py`。
- `fixtures.rs`：提供 synthetic model 构造函数，只用于测试和后续阶段验收样例。

## JSON 兼容策略

Rust 模型使用 `serde` 序列化和反序列化。

兼容规则：

- 字段名默认使用 `snake_case`，与 Python dataclass 当前 JSON 字段保持一致。
- 枚举序列化为小写字符串，例如 `high`、`medium`、`static`、`runtime_event`。
- `PathStep.from_` 序列化为 JSON 字段 `from`，保持与 Python 序列化逻辑一致。
- 可选字段默认保留为 `null`，不在模型层全局跳过；后续报告格式是否省略空字段由 Phase 4 控制。
- `SCHEMA_VERSION` 初始保持为 `1.0.0`，用于后续兼容性测试。

## 报告层模型

报告层模型包括：

- `EvidenceSource`
- `CapabilityFinding`
- `DetectionResult`

其中 `CapabilityFinding` 保留现有 Python 字段：

- `name`
- `description`
- `score_weight`
- `confidence`
- `sources`
- `evidence`
- `metadata`

`DetectionResult` 保留现有 Python 字段：

- `server_name`
- `findings`
- `total_score`
- `risk_level`
- `mitigations`
- `notes`

## Fact 层模型

Fact 层模型对齐现有 Python AST security fact schema，包含：

- `FunctionFact`
- `ImportFact`
- `EntryPointFact`
- `CallFact`
- `SinkFact`
- `SourceFact`
- `AssignFact`
- `DataFlowFact`
- `RuntimeEventFact`
- `FindingFact`

同时定义必要辅助结构：

- `ParamInfo`
- `CallArg`
- `CallKwarg`
- `CallResolution`
- `EntryPointEvidence`
- `PathStep`

Rust 中使用 enum `Fact` 表达不同 fact 类型，并通过 `type` 字段进行 tagged JSON 兼容。

## 测试策略

Phase 2 的测试集中验证模型稳定性：

- `DetectionResult` 可以 JSON roundtrip。
- `FindingFact` 可以 JSON roundtrip。
- `PathStep.from_` 输出字段名为 `from`。
- 枚举 JSON 值与 Python 版本一致。
- synthetic fixture 可以作为后续报告输出和兼容性测试输入。

## 后续阶段关系

Phase 2 完成后：

- Phase 3 规则加载可以直接使用 severity、confidence 和 sink/finding 相关模型。
- Phase 4 报告输出可以消费 `DetectionResult`。
- Phase 7 和 Phase 8 extractor 可以逐步填充 function、import、call、entrypoint、sink 等 facts。
- Phase 9 和 Phase 10 可以消费 call/source/sink/dataflow facts。
- Phase 11 可以生成 `FindingFact`，并转换为报告层 `CapabilityFinding`。
