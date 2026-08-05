# Rust 重构计划

## 目标

本文档用于维护 MCP Security Auditor 在 `rust/` 目录下的分阶段 Rust 重构进程。

本次重构有三个主要目标：

- 将静态分析系统重构为 Rust 原生实现。
- 通过兼容的 Rust 入口保留完整的动态分析能力。
- 通过小阶段、明确验收标准和进度跟踪，让重构过程可度量、可回退、可维护。

## 非目标

早期阶段不会直接替换现有 Python 实现。

第一批 Rust 里程碑不要求实现 Rust 原生 eBPF 监控器。动态分析必须保持完整可用，但可以先复用现有 Docker、eBPF、Python monitor 和 fuzzer 组件。

本文档不是详细实现设计。某个阶段需要技术细节时，应单独编写阶段文档。

## 兼容性要求

Rust 实现必须保留现有工作流依赖的用户可见行为：

- 支持 Python、JavaScript、TypeScript、Rust 和 metadata 输入的静态扫描，其中 Rust MCP server 源码应作为一等分析目标，而不是附加实验能力。
- 支持通过现有沙箱分析流程进行动态扫描。
- 保持现有 TOML 规则语义。
- 保持现有风险、严重性、置信度和 finding 概念。
- 支持 JSON、JSONL 和 Markdown 报告输出。
- 输出兼容现有 Web portal 和 benchmark 工作流。
- 能够与当前 Python 实现进行可度量对比。

可以增加新字段和改进项，但不能破坏已有消费者。

## 目录策略

Rust 重构工作放在 `rust/` 目录下。

第一份计划文档就是本文档：

```text
rust/docs/REFACTOR_PLAN.md
```

后续可按需增加详细文档：

```text
rust/docs/MCP_VULNERABILITY_TAXONOMY.md
rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md
rust/docs/DYNAMIC_ANALYSIS_PLAN.md
rust/docs/PROGRESS.md
rust/docs/DECISIONS.md
```

MCP 漏洞分类、漏洞原理和静态挖掘方法见 [`MCP_VULNERABILITY_TAXONOMY.md`](MCP_VULNERABILITY_TAXONOMY.md)。

静态分析 Rust 重构采用“三线并行、独立产出、统一融合、配置驱动”的总体设计，见 [`STATIC_ANALYSIS_REFACTOR_DESIGN.md`](STATIC_ANALYSIS_REFACTOR_DESIGN.md)。

总控重构计划应保持简洁。阶段级实现细节应放入阶段文档，而不是写入本路线图。

## 阶段路线图

| 阶段                          | 状态  | 目标                                                         | 验收标准                                                                                                |
| --------------------------- | --- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Phase 0：重构计划                | 完成  | 建立路线图和进度维护方式。                                              | `rust/docs/REFACTOR_PLAN.md` 存在，并且阶段边界已确认。                                                          |
| Phase 1：Rust 工程骨架           | 完成  | 创建 Rust workspace 和最小 CLI。                                 | `cargo test` 通过，并且可以从 `rust/` 运行 CLI help。                                                          |
| Phase 2：兼容数据模型              | 完成  | 定义 findings、results、facts、severity、confidence 等 Rust 共享模型。 | 模型可以序列化为稳定 JSON，用于兼容性测试。                                                                            |
| Phase 3：配置与规则加载             | 完成  | 加载静态/动态运行配置和当前项目已有 TOML 规则。                                | Rust 可以读取运行配置和规则文件，并为三线静态分析和动态分析保留配置开关。                                                             |
| Phase 4：统一结果与报告输出           | 完成  | 实现 JSON、JSONL 和 Markdown 报告输出。                             | synthetic 三线结果和融合结果可以渲染为所有支持格式，JSON 保留完整原始结果。                                                       |
| Phase 5：静态扫描入口              | 完成  | 建立 Rust static pipeline 外壳、文件发现流程和分析线调度。                   | CLI 可以扫描目标目录、识别支持的输入文件，并按配置启用规则线、污点线和 Agent 线。                                                      |
| Phase 6：传统规则分析线             | 完成  | 重构规则驱动的 legacy 静态检测路径。                                     | Rust 可以在聚焦 fixture 上检测关键词、regex、metadata 和危险 API finding。                                           |
| Phase 7：Python fact 提取      | 完成  | 从 Python 源码中提取核心静态 facts。                                  | Python fixtures 可以产出预期的函数、导入、调用、入口、source、assign、sink 等基础 facts；facts 已接入静态扫描结果，taint 默认禁用且显式启用时报错。 |
| Phase 8：JS/TS fact 提取       | 完成  | 从 JavaScript 和 TypeScript 源码中提取核心静态 facts。                 | JS/TS fixtures 可以产出预期的入口、调用、导入、sink 和相关基础 facts。                                                    |
| Phase 9：Rust fact 提取        | 完成  | 从 Rust MCP server 源码中提取核心静态 facts。                         | Rust fixtures 可以产出预期的函数、导入、调用、MCP 入口、sink 和相关基础 facts。                                              |
| Phase 10：调用关系分析             | 完成 | 重构 call graph、可达性分析和反向 sink 追踪基础能力。                        | Rust 可以在聚焦 fixture 上从 entrypoint 或 root function 追踪到 sink。                                          |
| Phase 11：轻量数据流分析            | 完成 | 重构 taint-lite 分析能力，并让 Python、JS/TS、Rust facts 进入统一数据流。     | Rust 可以在聚焦 fixture 上识别基础的参数到 sink 传播路径。                                                             |
| Phase 12：Agent 分析线          | 完成 | 接入可配置的 Agent 辅助源码分析，生成独立的候选风险结果。                           | Agent 线可以按配置读取源码、facts 和已有分析结果，并输出结构化 `AgentAnalysisResult`。                                        |
| Phase 12.5：CodeQL 分析线 | 完成 | 作为第四条并行静态分析线，调用 CodeQL CLI 进行专业级污点分析。 | CodeQL 线独立产出 CodeqlAnalysisResult + SARIF 审计原始数据。 |

Phase 12 已完成 Agent 辅助分析线实现。Agent 线通过 CLI 子进程调用外部 Agent 工具（claude），传入 MCP 安全审计 prompt 模板，Agent 自主使用工具探索源码并产出结构化 AgentAnalysisResult。同时完成了三线工程化解耦重构：规则线（rule/）、污点线（taint/）、Agent 线（agent/）各自独立目录，每条线有单一 pub fn run() 入口，pipeline.rs 纯编排。Fact 提取下沉至 taint 线内部，不再作为全局前置步骤。

Phase 12.5 已完成 CodeQL 分析线集成。codeql::run() 作为第四条并行静态分析线接入 run_static_scan()，通过 codeql CLI 子进程调用进行专业级多语言污点分析。CodeQL 线在默认配置禁用，启用后自动过滤 Python/JS/TS 文件、创建 CodeQL 数据库、运行查询包（内置或自定义）、解析 SARIF 输出为 CodeqlAnalysisResult，产出结构化结果和原始 SARIF 审计数据。含 queries.rs（查询包管理）、provider.rs（CLI 子进程调用）、parser.rs（SARIF 解析）三个子模块。
| Phase 13：静态结果融合与 finding 生成 | 未开始 | 将规则线、污点线和 Agent 线结果融合为最终静态 findings。                       | Rust 静态分析可以输出包含 evidence、severity、confidence、risk 和来源线索的融合 findings。                                |
| Phase 14：静态分析对齐             | 未开始 | 将 Rust 静态输出与 Python 实现进行对比。                                | 主要 fixtures 和 benchmark 路径完成对比，差异被记录为 bug、改进或可接受差异。                                                 |
| Phase 15：动态分析兼容             | 未开始 | 通过 Rust CLI 支持完整动态分析，并按需复用现有运行时组件。                         | Rust CLI 可以完成一次动态扫描，并生成兼容报告输出。                                                                      |
| Phase 16：Rust 原生动态分析评估      | 未开始 | 决定是否以及如何将动态运行时组件迁移到 Rust。                                  | 单独的动态设计文档记录决策、风险和迁移路径。                                                                              |
| Phase 17：产品化收尾              | 未开始 | 完成 Rust 用户工作流、文档、测试、诊断和发布路径。                               | 用户可以从 `rust/` 构建、运行和测试 Rust 实现，并有清晰文档。                                                              |

## 进度跟踪

阶段路线图表格是高层进度的事实来源。

状态固定使用：

- `未开始`
- `进行中`
- `阻塞`
- `完成`
- `暂缓`

阶段验收不接受空实现或占位实现。某条分析线或某种语言能力如果在配置中标记为已启用，则该阶段必须实现该阶段承诺的完整功能；如果功能尚未实现，应保持禁用、返回明确错误，或在路线图中继续标记为未开始，不能用空结果伪装为完成。

阶段开始时，将状态更新为 `进行中`。阶段结束时，如有必要更新验收标准，并将状态标记为 `完成`。

Phase 7 已完成 Python fact extraction 基础能力：RustPython AST extractor 已产出 import、function、entrypoint、source、call、assign、sink facts，并已接入 `run_static_scan()` 的 `facts` 和 `summary.fact_count`。Phase 7 不包含完整 taint propagation、完整 call graph、finding fusion、Agent 分析或动态分析；taint line 在默认配置中保持禁用，显式启用时返回明确未实现错误。

Phase 8 已完成 JS/TS fact extraction 基础能力：SWC AST extractor 已产出 import (ESM/CJS, 6 ImportKind)、function (4 种形态)、entrypoint (MCP 回调模式)、source (含递归解构展开)、call (含双轨别名解析)、assign、sink (8 类 JS 特定类别) facts，并已接入 `run_static_scan()` 的 `facts` 和 `summary.fact_count`。Phase 8 不包含完整 taint propagation、完整 call graph、finding fusion、Agent 分析或动态分析；taint line 在默认配置中保持禁用，显式启用时返回明确未实现错误。

Phase 9 已完成 Rust fact extraction 基础能力：syn-based AST extractor 已产出 import (Use/UseAs/UseGlob/UseGroup, 4 种 Rust ImportKind)、function (fn decl + impl method, 含 doc comment、return type)、entrypoint (attribute macro `#[tool]`/`#[resource]`/`#[prompt]` + SDK 调用模式)、source (MCP tool 参数)、call (含 use alias 解析)、assign (let 绑定 + 赋值表达式)、sink (7 类 Rust 特定类别: command_execution, file_read, file_write, network_request, credential_leak, deserialization, unsafe_block) facts，并已接入 `run_static_scan()` 的 `facts` 和 `summary.fact_count`。Phase 9 不包含完整 taint propagation、完整 call graph、finding fusion、Agent 分析或动态分析；taint line 在默认配置中保持禁用，显式启用时返回明确未实现错误。行号当前使用占位值（同 Phase 8），因 proc_macro2::Span 在稳定 Rust 上不暴露 line/column。

Phase 10 和 Phase 11 已作为统一污点分析模块（`static_analysis/taint/`）一起交付。模块包含：统一跨文件程序图构造（graph + builder）、前向/后向 BFS 污点传播（propagation），以及 TaintAnalysisResult 和 DataFlowFact 结果生成（result）。支持 Python、JavaScript/TypeScript、Rust 三种语言的跨文件调用链追踪和参数到 sink 的数据流分析。taint line 已集成到 static scan pipeline，默认配置保持 disabled；启用 config `[static.taint].enabled = true` 时正常产出污点分析结果。

如果某个阶段需要超过本路线图粒度的技术细节，应创建单独文档，并在阶段行或表格下方的简短备注中链接该文档。

## 风险摘要

静态分析的主要风险是 parser 行为对齐、规则线覆盖不足、污点分析精度、Agent 结果可复现性、三线结果融合、输出兼容、benchmark 差异解释，以及避免检测能力退化。

动态分析的主要风险是沙箱环境差异、Docker 和内核权限、eBPF 行为、事件兼容，以及在引入 Rust CLI 时保持现有动态工作流稳定。

这些风险应通过小阶段、兼容性测试、fixture 对比和明确的差异记录来处理。

## 决策记录

- Rust 重构工作从 `rust/` 目录开始。
- 静态分析目标是 Rust 原生实现，并采用三线并行结构：传统规则线、污点分析线和 Agent 分析线。
- 三条静态分析线必须独立产出结果，再由融合层生成最终 findings。
- JSON 输出应保留完整三线原始结果和融合结果；Markdown 和 Web 展示由用户配置控制。
- 动态分析在重构期间必须保持完整可用。
- 在 Rust 原生动态分析迁移前，可以复用现有动态运行时组件。
- Rust MCP server 已经有开源 SDK 和 server 项目生态，因此 Rust 源码静态分析应作为一等目标进入重构范围。
- Python、JavaScript、TypeScript、Rust 四类源码都应进入同一套三线并行静态分析结构，最终输出统一 facts、独立三线结果和融合 findings。
- 后续实现阶段不接受空实现作为完成状态；阶段验收必须对应可运行、可测试、可审查的真实能力。
- 路线图保持简洁；实现细节写入单独阶段文档。
- 每个阶段都需要可运行或可审查的验收标准，满足后才视为完成。
