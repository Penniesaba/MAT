# Rust First-Class Static Analysis Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update the Rust refactor documentation so Rust is a first-class static-analysis target alongside Python, JavaScript, and TypeScript, and record the project constraint that implementation phases must not leave empty stubs.

**Architecture:** This is a documentation-only change. `REFACTOR_PLAN.md` remains the concise roadmap and progress source of truth, while `STATIC_ANALYSIS_REFACTOR_DESIGN.md` holds design-level details for the three-line static-analysis architecture. No code, dependency, schema, or CLI behavior changes are included in this plan.

**Tech Stack:** Markdown documentation under `rust/docs/`; existing Rust static-analysis terminology and roadmap phase naming.

## Global Constraints

- Documentation language remains Chinese.
- Keep the overall roadmap document concise; do not add phase-level implementation detail to `REFACTOR_PLAN.md`.
- Rust must be documented as a first-class static-analysis language, not a future optional extension.
- Python, JavaScript, TypeScript, and Rust must all flow through the same three-line model: rule line, taint/fact line, and Agent line.
- Implementation phases must not accept empty stubs or placeholder behavior as phase completion; if a line is enabled, it must either provide complete planned functionality for that phase or fail clearly.
- Do not implement code in this documentation task.
- Do not commit unless the user explicitly asks for a commit.

---

## File Structure

- Modify: `rust/docs/REFACTOR_PLAN.md`
  - Responsibility: high-level roadmap, phase status, compatibility requirements, and decision record.
  - Changes: make Rust first-class in static analysis goals; insert an independent Rust fact extraction phase; renumber later phases; add no-empty-stub completion constraint.

- Modify: `rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md`
  - Responsibility: design-level static-analysis architecture and principles.
  - Changes: update language scope to Python/JavaScript/TypeScript/Rust; document Rust entrypoint/sink categories at design level; add Rust fixture/testing expectations; record no-empty-stub rule.

---

### Task 1: Update high-level roadmap for first-class Rust analysis

**Files:**
- Modify: `rust/docs/REFACTOR_PLAN.md`

**Interfaces:**
- Consumes: existing roadmap table and decision record.
- Produces: updated roadmap where Rust static analysis is explicit and later phases are renumbered consistently.

- [ ] **Step 1: Update compatibility requirements**

In `rust/docs/REFACTOR_PLAN.md`, change the compatibility bullet that currently says support is for Python, JavaScript, TypeScript, and metadata inputs so it explicitly includes Rust MCP server source analysis.

Target wording:

```markdown
- 支持 Python、JavaScript、TypeScript、Rust 和 metadata 输入的静态扫描，其中 Rust MCP server 源码应作为一等分析目标，而不是附加实验能力。
```

- [ ] **Step 2: Update roadmap rows**

In the phase table, replace the current Phase 7 onward block with this roadmap:

```markdown
| Phase 7：Python fact 提取 | 未开始 | 从 Python 源码中提取核心静态 facts。                                  | Python fixtures 可以产出预期的函数、导入、调用、入口、sink 和相关基础 facts。                |
| Phase 8：JS/TS fact 提取  | 未开始 | 从 JavaScript 和 TypeScript 源码中提取核心静态 facts。                 | JS/TS fixtures 可以产出预期的入口、调用、导入、sink 和相关基础 facts。                    |
| Phase 9：Rust fact 提取   | 未开始 | 从 Rust MCP server 源码中提取核心静态 facts。                          | Rust fixtures 可以产出预期的函数、导入、调用、MCP 入口、sink 和相关基础 facts。             |
| Phase 10：调用关系分析        | 未开始 | 重构 call graph、可达性分析和反向 sink 追踪基础能力。                       | Rust 可以在聚焦 fixture 上从 entrypoint 或 root function 追踪到 sink。          |
| Phase 11：轻量数据流分析       | 未开始 | 重构 taint-lite 分析能力，并让 Python、JS/TS、Rust facts 进入统一数据流。     | Rust 可以在聚焦 fixture 上识别基础的参数到 sink 传播路径。                             |
| Phase 12：Agent 分析线      | 未开始 | 接入可配置的 Agent 辅助源码分析，生成独立的候选风险结果。                         | Agent 线可以按配置读取源码、facts 和已有分析结果，并输出结构化 `AgentAnalysisResult`。        |
| Phase 13：静态结果融合与 finding 生成 | 未开始 | 将规则线、污点线和 Agent 线结果融合为最终静态 findings。                      | Rust 静态分析可以输出包含 evidence、severity、confidence、risk 和来源线索的融合 findings。 |
| Phase 14：静态分析对齐        | 未开始 | 将 Rust 静态输出与 Python 实现进行对比。                                | 主要 fixtures 和 benchmark 路径完成对比，差异被记录为 bug、改进或可接受差异。                 |
| Phase 15：动态分析兼容        | 未开始 | 通过 Rust CLI 支持完整动态分析，并按需复用现有运行时组件。                         | Rust CLI 可以完成一次动态扫描，并生成兼容报告输出。                                      |
| Phase 16：Rust 原生动态分析评估 | 未开始 | 决定是否以及如何将动态运行时组件迁移到 Rust。                                  | 单独的动态设计文档记录决策、风险和迁移路径。                                              |
| Phase 17：产品化收尾         | 未开始 | 完成 Rust 用户工作流、文档、测试、诊断和发布路径。                               | 用户可以从 `rust/` 构建、运行和测试 Rust 实现，并有清晰文档。                              |
```

- [ ] **Step 3: Add no-empty-stub progress rule**

After the existing progress status list, add:

```markdown
阶段验收不接受空实现或占位实现。某条分析线或某种语言能力如果在配置中标记为已启用，则该阶段必须实现该阶段承诺的完整功能；如果功能尚未实现，应保持禁用、返回明确错误，或在路线图中继续标记为未开始，不能用空结果伪装为完成。
```

- [ ] **Step 4: Update decision record**

Add these bullets to the decision record:

```markdown
- Rust MCP server 已经有开源 SDK 和 server 项目生态，因此 Rust 源码静态分析应作为一等目标进入重构范围。
- Python、JavaScript、TypeScript、Rust 四类源码都应进入同一套三线并行静态分析结构，最终输出统一 facts、独立三线结果和融合 findings。
- 后续实现阶段不接受空实现作为完成状态；阶段验收必须对应可运行、可测试、可审查的真实能力。
```

- [ ] **Step 5: Review roadmap consistency**

Check that all references to old Phase 11-16 numbering in `REFACTOR_PLAN.md` are updated to Phase 12-17 where applicable.

---

### Task 2: Update static-analysis design for Rust as a first-class language

**Files:**
- Modify: `rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md`

**Interfaces:**
- Consumes: existing three-line design.
- Produces: updated design where Rust participates in rule, fact/taint, Agent, fusion, testing, and implementation guidance.

- [ ] **Step 1: Update design goals**

Change the language support goal from supporting Python, JavaScript, TypeScript and later Rust extension to:

```markdown
- 支持 Python、JavaScript、TypeScript、Rust 四类 MCP server 源码分析，并支持 metadata 输入分析。
```

- [ ] **Step 2: Add first-class language principle**

In the overall architecture or three-line section, add:

```markdown
Rust 源码分析不是独立于三线结构之外的附加扫描器。Python、JavaScript、TypeScript、Rust 应使用各自适合的 parser、extractor 和规则，但最终都应输出统一 facts、统一三线结果模型，并进入同一个融合层。
```

- [ ] **Step 3: Extend traditional rule line**

In section `6.1 传统规则线`, add Rust examples at design level:

```markdown
Rust 规则线应覆盖 Rust MCP server 常见危险 API 和 SDK 模式，例如 `std::process::Command`、`tokio::process::Command`、`std::fs`、`tokio::fs`、`reqwest`、`hyper`、`std::env::var`、`rmcp`、`rust-mcp-sdk`、tool handler 注册和 JSON-RPC `tools/call` 分发逻辑。Phase 6 已经在文件发现和规则匹配层支持 `.rs` 文本扫描，后续规则库应补齐 Rust 专用 capability indicators。
```

- [ ] **Step 4: Extend taint/fact line**

In section `6.2 污点分析线`, add Rust fact extraction scope:

```markdown
Rust 污点线应先从轻量 fact extraction 开始，识别 Rust functions、impl methods、imports、calls、MCP entrypoints、sources、sinks 和 assignments。Rust parser 可在阶段实现时评估 `syn`、`tree-sitter-rust` 或 rust-analyzer syntax crates；早期目标不是完整 Rust 编译器级 symbol resolution，而是为 MCP entrypoint 到危险 sink 的可达性和 taint-lite 提供足够稳定的 facts。
```

- [ ] **Step 5: Extend Agent line**

In section `6.3 Agent 分析线`, add:

```markdown
Agent 线应能读取 Rust MCP server 源码和 Rust facts，辅助判断 tool description 与真实 Rust 行为是否一致、Rust server 是否暴露过多系统能力、参数是否进入命令/文件/网络 sink，以及 memory/vector-store 类型 server 是否存在 context over-sharing 风险。
```

- [ ] **Step 6: Update roadmap relationship section**

Replace the Phase 7 onward mapping with the same revised phase meanings used in `REFACTOR_PLAN.md`, including independent `Phase 9：Rust fact 提取` and renumbered later phases.

- [ ] **Step 7: Update testing section**

Add Rust fixture expectations to the tests section:

```markdown
- Rust fixtures 应覆盖 `rmcp` / `rust-mcp-sdk` 风格 MCP tool handler、JSON-RPC `tools/call` 分发、`std::process::Command`、`std::fs`、`reqwest`、`std::env::var` 等 sink。
- Rust fact extraction 阶段验收必须产出真实 facts，不能用空 extractor 或空 result 作为完成标准。
```

- [ ] **Step 8: Add no-empty-stub implementation constraint**

In the risks/constraints or implementation recommendations section, add:

```markdown
后续阶段不应保留空实现作为“已完成”能力。分析线 shell 可以在早期作为调度占位存在，但一旦某阶段声明实现某条线或某种语言能力，就必须提供该阶段承诺的完整、可测试行为；未实现能力应保持关闭、明确报错或继续标记为未开始。
```

---

### Task 3: Validate documentation-only change

**Files:**
- Validate: `rust/docs/REFACTOR_PLAN.md`
- Validate: `rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md`

**Interfaces:**
- Consumes: completed Tasks 1 and 2.
- Produces: confidence that docs are internally consistent and do not imply empty implementations are acceptable.

- [ ] **Step 1: Search for outdated language-scope wording**

Run:

```bash
grep -R "后续扩展 Rust\|Python、JavaScript、TypeScript，后续\|Phase 16：产品化" -n rust/docs/REFACTOR_PLAN.md rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md
```

Expected: no matches.

- [ ] **Step 2: Search for first-class Rust wording**

Run:

```bash
grep -R "Rust.*一等\|Rust fact 提取\|空实现" -n rust/docs/REFACTOR_PLAN.md rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md
```

Expected: matches in both documents.

- [ ] **Step 3: Review phase numbering manually**

Open both docs and verify:

```text
Phase 7  = Python fact 提取
Phase 8  = JS/TS fact 提取
Phase 9  = Rust fact 提取
Phase 10 = 调用关系分析
Phase 11 = 轻量数据流分析
Phase 12 = Agent 分析线
Phase 13 = 静态结果融合与 finding 生成
Phase 14 = 静态分析对齐
Phase 15 = 动态分析兼容
Phase 16 = Rust 原生动态分析评估
Phase 17 = 产品化收尾
```

- [ ] **Step 4: Report original TypeScript support in final response**

Include this concise statement in the final user-facing response:

```markdown
原系统支持 TypeScript 静态分析，但支持分层：legacy TypeScript plugin 是空实现；legacy TOML 规则层有 JS/TS 文本规则；真正较完整的 TypeScript 静态分析在 Python AST/fact pipeline 中，通过 JS/TS Tree-sitter extractor 支持 `.ts`、`.tsx`、`.mts`、`.cts`，可抽取 imports、functions、calls、MCP entrypoints、sources、sinks、assignments，并进入 call graph / taint-lite。
```

---

## Self-Review

- **Spec coverage:** This plan updates both requested docs, makes Rust first-class, adds independent Rust fact extraction, records the no-empty-stub constraint, and preserves concise roadmap/detail split.
- **Placeholder scan:** No TBD/TODO/implement-later placeholders are present. All edits include concrete wording.
- **Type consistency:** Documentation phase numbering is consistent across roadmap and design doc tasks.
