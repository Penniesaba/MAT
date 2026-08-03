# 静态分析 Rust 重构设计

## 1. 文档目的

本文档用于指导 MCP Security Auditor 在 Rust 重构过程中的静态分析部分设计。

静态分析重构的目标不是简单复刻现有 Python 实现，而是在保持原有检测能力的基础上，建立一个更清晰、可扩展、可度量、可配置的 MCP 专用静态分析架构。

本文档重点说明：

- 静态分析系统的总体架构。
- 三线并行分析结构。
- 每条分析线的职责边界。
- 三线结果如何独立产出并融合。
- 用户如何通过 TOML 配置每次静态和动态分析。
- 后续 Rust 重构阶段如何围绕该设计推进。

本文档不直接定义每个漏洞规则的完整内容，也不展开具体 parser、call graph、taint 算法的实现细节。阶段级实现细节应在后续阶段文档中补充。

## 2. 总体设计结论

Rust 静态分析系统采用：

```text
三线并行、独立产出、统一融合、配置驱动
```

三条静态分析线分别是：

1. **传统规则线**：通过规则、关键词、模式、metadata、危险 API 和配置检查发现已知风险。
2. **污点分析线**：通过 fact extraction、call graph、正向/反向追踪和 taint-lite 分析验证从 MCP entrypoint 到危险 sink 的可达性和数据流。
3. **Agent 分析线**：通过 LLM/Agent 读取源码、facts 和其他分析线结果，发现复杂语义问题、规则外风险和审计假设。

三条线都必须独立产出结构化结果。系统随后通过融合算法把三条线的结果汇总为最终静态分析结论。

JSON 输出应始终保留完整三线原始结果和融合结果。Markdown、Web portal 等用户可读报告是否展示每条线的原始结果，应由用户 TOML 配置控制。

## 3. 设计目标

静态分析 Rust 重构应满足以下目标：

- 覆盖 MCP 协议和 MCP server 实现相关安全缺陷。
- 保留现有 Python 静态分析能力，并支持可度量对齐。
- 支持 Python、JavaScript、TypeScript，后续扩展 Rust MCP server 源码分析。
- 支持规则驱动检测、源码 fact 分析、调用关系分析、轻量数据流分析。
- 支持 Agent 辅助源码审计，但不让 Agent 成为唯一安全结论来源。
- 每条分析线都有独立结果，便于调试、benchmark 和误报/漏报分析。
- 最终 finding 有明确 evidence、provenance、severity、confidence 和来源线索。
- 用户可以通过 TOML 配置每次静态和动态分析。

## 4. 非目标

早期静态分析重构不追求一次性实现完整 CodeQL 级查询语言。

早期 Rust 版本不要求 Agent 完全自主完成审计闭环。Agent 线应先作为候选风险发现、解释、复核和补充机制。

静态分析不能替代动态分析。动态分析仍用于验证运行时行为、系统调用、网络连接、文件访问、进程执行等静态分析难以确认的问题。

## 5. 总体架构

建议的静态分析架构如下：

```text
Source Repository
       |
       v
File Discovery / Language Detection
       |
       v
Parser / Extractors
       |
       v
FactStore
       |
       +-----------------------------+
       |                             |
       v                             v
Rule Analyzer                  Taint Analyzer
       |                             |
       v                             v
RuleAnalysisResult             TaintAnalysisResult
       |                             |
       +-------------+---------------+
                     |
                     v
              Agent Analyzer
    Source + Facts + Rule/Taint Results
                     |
                     v
              AgentAnalysisResult
                     |
                     v
              Finding Fusion
                     |
                     v
          StaticAnalysisResult
                     |
                     v
      JSON / JSONL / Markdown / Web Portal
```

该结构采用方案 A 的“三线独立结果 + 融合层”作为主架构，同时保留统一 FactStore 作为规则线和污点线的共享事实基础。

Agent 线默认不直接写入确定性 facts，而是消费源码、facts、规则线结果和污点线结果，生成独立的 Agent 分析结果。

## 6. 三条分析线

### 6.1 传统规则线

传统规则线负责快速、可解释、可扩展的已知模式检测。

它适合发现：

- 关键词和危险 API 命中。
- metadata 和 tool description 中的风险模式。
- MCP tool poisoning 线索。
- hardcoded secret、token、API key。
- 不安全配置。
- 可疑依赖和供应链风险。
- 明显危险 sink，例如命令执行、文件读写、网络访问、动态代码执行。

传统规则线应以 TOML 规则为主要输入。

早期规则系统不需要复刻完整 Semgrep 或 CodeQL 语言，但可以借鉴它们的思想：

- rule id
- category
- severity
- confidence
- language
- pattern
- regex
- metadata condition
- source kind
- sink kind
- recommendation
- OWASP MCP category mapping

传统规则线的输出应是独立的 `RuleAnalysisResult`。

规则线的优点是速度快、解释性强、适合覆盖已知漏洞模式。缺点是对跨函数语义、复杂数据流和上下文理解能力有限。

### 6.2 污点分析线

污点分析线是确定性静态分析的核心能力。

它负责回答：

```text
MCP 暴露入口的外部输入，是否能够到达危险 sink？
```

污点分析线应基于 Rust fact model 构建：

- `FunctionFact`
- `ImportFact`
- `EntryPointFact`
- `CallFact`
- `SourceFact`
- `SinkFact`
- `AssignFact`
- `DataFlowFact`
- `FindingFact`

污点分析线包括以下阶段：

1. parser / extractor 生成 facts。
2. call graph pass 构建函数调用关系。
3. source / sink pass 标记 MCP 输入和危险操作。
4. forward taint 从 entrypoint 参数向 sink 追踪。
5. backward trace 从 sink 反向寻找 root function 或 MCP entrypoint。
6. finding builder 将路径证据转换为结构化 finding。

污点分析线适合发现：

- command injection
- arbitrary file read/write
- SSRF / arbitrary network request
- unsafe deserialization
- dynamic code execution
- prompt/context 参数进入危险模板或外部调用
- MCP tool 参数未经验证进入敏感能力

污点分析线的输出应是独立的 `TaintAnalysisResult`。

污点线的优点是证据链强、可解释性好、能降低规则线误报。缺点是实现复杂，对 parser、symbol resolution、call graph 和语言语义有依赖。

### 6.3 Agent 分析线

Agent 分析线负责发现规则和污点分析不容易覆盖的问题。

它可以读取：

- 源码片段。
- 项目结构。
- MCP tool/resource/prompt 定义。
- FactStore 中的 facts。
- 规则线初步结果。
- 污点线初步结果。
- 漏洞 taxonomy 和规则说明。

Agent 线适合发现：

- 复杂业务语义风险。
- tool description 与实际行为不一致。
- prompt injection 和 intent flow subversion 线索。
- context over-sharing。
- 权限边界不清晰。
- MCP tool 能力组合导致的复合风险。
- 规则库尚未覆盖的新型风险。

Agent 线不应直接成为唯一裁判。它的结果必须带有 provenance 和置信度说明，并且应尽量被规则线、污点线或动态分析验证。

Agent 线建议支持三种模式：

1. `source_only`：只读取源码并提出候选风险。
2. `evidence_aware`：读取源码、facts、规则线结果和污点线结果，对已有证据进行解释、补充和复核。
3. `hypothesis_then_verify`：先生成候选漏洞假设，再由规则、污点或动态分析尝试验证。

默认推荐模式是 `evidence_aware`。后续产品化目标可以演进到 `hypothesis_then_verify`。

Agent 分析线的输出应是独立的 `AgentAnalysisResult`。

## 7. 结果模型原则

三条线必须独立产出结果，不能互相覆盖。

建议最终静态分析结果包含：

```text
StaticAnalysisResult
├── rule_results
├── taint_results
├── agent_results
├── fused_findings
├── summary
└── config_snapshot
```

### 7.1 RuleAnalysisResult

规则线结果应记录：

- rule id
- rule category
- OWASP MCP category
- file
- line
- matched text or snippet
- evidence
- severity
- confidence
- recommendation
- whether related facts exist

### 7.2 TaintAnalysisResult

污点线结果应记录：

- source id
- source kind
- entrypoint id
- sink id
- sink kind
- call chain
- dataflow path
- file and line evidence
- taint confidence
- whether entrypoint is MCP tool/resource/prompt
- whether backward trace found root function

### 7.3 AgentAnalysisResult

Agent 线结果应记录：

- agent id
- prompt profile or skill profile
- model/provider if applicable
- input scope
- candidate finding title
- affected files and locations
- reasoning summary
- evidence snippets
- related rule findings
- related taint findings
- confidence
- verification status
- limitations

Agent 结果中的 `reasoning_summary` 应是面向审计解释的摘要，不要求保存完整推理过程。

### 7.4 FusedFinding

融合结果应记录：

- final finding id
- title
- category
- OWASP MCP category
- severity
- confidence
- status
- supported_by lines
- related rule result ids
- related taint result ids
- related agent result ids
- evidence
- call chain / dataflow path if available
- recommendation
- conflict notes

`FusedFinding` 可以在后续 Phase 11 中映射为已有 `FindingFact` 和报告层 `CapabilityFinding`。

## 8. 融合算法

融合层负责把三条线的结果合并为最终 finding。

早期融合算法应保持简单、透明、可解释。

初始策略可以是 `weighted_evidence`：

```text
rule only                 -> medium confidence
agent only                -> low confidence or advisory
rule + agent              -> medium-high confidence
taint only                -> high confidence
rule + taint              -> high confidence
taint + agent             -> high confidence
rule + taint + agent      -> very high confidence
dynamic confirmed         -> confirmed
```

融合层还需要处理：

- 重复 finding 去重。
- 同一 sink 的多条路径聚合。
- 同一漏洞被多条线发现时的 evidence 合并。
- Agent 发现但未被验证的 advisory 输出。
- 规则线命中但污点线不可达时的置信度降级。
- 动态分析确认后状态升级为 confirmed。

融合算法后续可以扩展为：

- policy-driven fusion
- evidence graph
- benchmark-calibrated scoring
- per-category weighting

## 9. 输出策略

输出策略采用：

```text
JSON 完整，报告可配置
```

具体原则：

- JSON 输出始终保留完整三线原始结果和融合结果。
- JSONL 输出适合 benchmark、调试和批量处理，可以按 finding、fact 或 result event 分行。
- Markdown 报告默认展示融合结果和摘要。
- Markdown 是否展示规则线、污点线、Agent 线原始结果，由配置控制。
- Web portal 可以读取完整 JSON，并通过 UI toggle 展示不同分析线。

这种设计可以同时支持：

- 用户阅读。
- 调试和研发。
- benchmark 评估。
- 三线贡献度分析。
- Web portal 可视化。

## 10. TOML 配置设计

系统应支持用户通过 TOML 配置每次静态和动态分析。

建议配置分为两类：

```text
rust/config/default.toml       # 每次扫描如何运行
rust/rules/**/*.toml           # 系统检测什么漏洞
```

### 10.1 分析运行配置示例

```toml
[scan]
targets = ["."]
exclude = ["node_modules", "target", ".venv", "dist"]
languages = ["python", "javascript", "typescript", "rust"]

[static]
enabled = true
save_facts = true

[static.rule]
enabled = true
rule_paths = ["rules/mcp", "rules/languages"]
mode = "strict"

[static.taint]
enabled = true
forward = true
backward = true
max_depth = 8
entrypoint_required = true

[static.agent]
enabled = false
mode = "evidence_aware"
provider = "claude"
prompt_profile = "mcp_security_audit"
max_files = 80
include_low_confidence = false

[dynamic]
enabled = false
sandbox = "existing_python_runtime"
timeout_seconds = 120

[fusion]
enabled = true
strategy = "weighted_evidence"
require_confirmed_by = 1
boost_when_multiple_lines_agree = true
agent_only_as_advisory = true

[report]
formats = ["json", "markdown"]
include_fused_results = true
include_raw_rule_results = false
include_raw_taint_results = false
include_raw_agent_results = false
include_facts = false
```

### 10.2 规则配置示例

```toml
[[rules]]
id = "mcp.command_execution.subprocess"
category = "command_execution"
owasp_mcp = "MCP05"
severity = "high"
confidence = "medium"
languages = ["python"]

patterns = [
  "subprocess.run",
  "os.system",
  "shell=True"
]

sources = ["mcp_tool_param"]
sinks = ["command_exec"]
recommendation = "Avoid passing MCP tool parameters into shell commands without validation."
```

运行配置控制“这次如何分析”。规则配置控制“系统检测什么”。两者应分离，避免用户为了调整一次扫描而修改漏洞知识库。

## 11. MCP 漏洞覆盖策略

三线结构的目标是完整覆盖 MCP 相关安全缺陷。

建议以 OWASP MCP Top 10 和项目自定义 taxonomy 作为漏洞分类基础。

不同漏洞类型适合不同分析线：

| 漏洞类型 | 规则线 | 污点线 | Agent 线 | 动态分析 |
| --- | --- | --- | --- | --- |
| Token / Secret Exposure | 强 | 弱 | 中 | 弱 |
| Scope Creep / Over-permission | 中 | 中 | 强 | 中 |
| Tool Poisoning | 强 | 弱 | 强 | 中 |
| Supply Chain Attack | 强 | 弱 | 中 | 中 |
| Command Injection | 强 | 强 | 中 | 强 |
| Intent Flow Subversion | 中 | 中 | 强 | 中 |
| Auth/Authz 缺失 | 中 | 中 | 强 | 中 |
| Lack of Audit / Telemetry | 中 | 弱 | 中 | 中 |
| Shadow MCP Servers | 中 | 弱 | 中 | 强 |
| Context Injection / Over-sharing | 中 | 中 | 强 | 中 |

其中：

- 规则线负责快速覆盖已知静态模式。
- 污点线负责验证输入到敏感能力的真实路径。
- Agent 线负责语义、上下文和复合风险。
- 动态分析负责运行时行为确认。

## 12. 与现有 Phase 路线图的关系

本文档指导 Phase 3 到 Phase 12 的静态分析重构。

对应关系如下：

- Phase 3：规则加载
  - 建立运行配置和规则配置的基础 TOML loader。
- Phase 4：报告输出
  - 支持完整 JSON 和可配置 Markdown 输出。
- Phase 5：静态扫描入口
  - 建立 file discovery、language detection 和 static runner 外壳。
- Phase 6：关键词和元数据检测
  - 实现规则线的第一批能力。
- Phase 7：Python fact 提取
  - 为污点线提供 Python facts。
- Phase 8：JS/TS fact 提取
  - 为污点线提供 JS/TS facts。
- Phase 9：调用关系分析
  - 支持 entrypoint 到 sink 的可达性分析。
- Phase 10：轻量数据流分析
  - 支持 source 到 sink 的 taint-lite。
- Phase 11：静态 finding 生成
  - 实现三线结果到 fused findings 的转换。
- Phase 12：静态分析对齐
  - 与现有 Python 实现和 benchmark 对齐。

Agent 分析线可以在规则线和污点线稳定后加入。早期文档和模型应先预留 Agent 结果结构，但不要求在 Phase 3 立即实现完整 Agent 调度。

## 13. 测试和验收策略

静态分析重构应建立分层测试：

1. 配置测试
   - TOML 配置可以解析。
   - 默认值稳定。
   - 禁用某条线时不会运行该线。

2. 规则线测试
   - 聚焦 fixture 命中预期规则。
   - 不相关代码不应误报。
   - 规则 severity、confidence、category 正确。

3. fact extraction 测试
   - Python、JS、TS fixture 产出预期 facts。
   - 后续 Rust fixture 产出预期 facts。

4. call graph 测试
   - entrypoint 到 sink 的调用链可达。
   - 不可达 sink 不应被误判为 MCP 暴露风险。

5. taint 测试
   - 参数到 sink 的数据流路径正确。
   - 简单赋值、函数调用、参数传递路径可识别。

6. Agent 线测试
   - Agent 输出必须符合结构化 schema。
   - Agent-only finding 默认不能直接升级为 confirmed。
   - Agent 结果必须保留 input scope 和 evidence。

7. 融合测试
   - rule-only、taint-only、agent-only、rule+taint、rule+taint+agent 等组合有稳定输出。
   - 重复 finding 被合并。
   - JSON 完整保留原始结果。
   - Markdown 按配置展示。

8. 对齐测试
   - Rust 静态输出与现有 Python 静态输出进行 fixture 对比。
   - 差异被记录为 bug、改进或可接受差异。

## 14. 风险和约束

主要风险包括：

- 规则系统过早设计得过复杂，拖慢 Phase 3。
- Agent 输出不可复现，影响 benchmark 和安全结论可信度。
- 三线结果模型不统一，导致融合层复杂度失控。
- call graph 和 taint 过度追求完整精度，导致实现难以落地。
- Markdown 报告展示过多原始结果，影响用户阅读。

对应约束：

- Phase 3 只做 TOML 加载和结构校验，不实现复杂检测语言。
- Agent 线默认作为辅助和复核，不作为唯一高置信度来源。
- JSON 保留完整原始数据，用户报告按配置裁剪。
- 融合算法初期保持透明简单。
- 每个阶段只实现该阶段验收需要的最小能力。

## 15. 后续实施建议

建议后续按以下顺序推进：

1. Phase 3 先实现运行配置和规则配置的 Rust 数据模型与 TOML loader。
2. Phase 4 在报告输出中预留三线结果和融合结果结构。
3. Phase 5 建立 static runner，能按配置启用/禁用分析线。
4. Phase 6 完成传统规则线第一版。
5. Phase 7 到 Phase 10 完成 fact extraction、call graph 和 taint-lite。
6. Phase 11 实现 finding fusion。
7. Agent 分析线先保留模型和配置，等规则线与污点线稳定后接入。

该顺序可以让系统在早期就具备可运行、可测试、可对齐的静态分析能力，同时为 MCP 专用 Agent 审计能力保留扩展空间。
