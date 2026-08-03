# Phase 7 Python Fact Extraction Design

## 目标

Phase 7 实现生产级 Rust 原生 Python fact extraction，用于替代原 Python AST extractor 的核心能力，并为后续 call graph、taint-lite、Agent evidence-aware 分析和 finding fusion 提供事实基础。

本阶段不是最小占位实现。阶段完成必须满足：Python fixtures 可以真实产出函数、导入、调用、MCP 入口、source、sink、assignment 等 facts，并且这些 facts 可通过 Rust API、静态扫描 pipeline 和 JSON 输出审查。

## 范围

Phase 7 实现 Python 源码 fact extraction 的完整产品级第一版，覆盖原系统 Python AST extractor 的主要行为：

- `FunctionFact`
- `ImportFact`
- `EntryPointFact`
- `SourceFact`
- `CallFact`
- `SinkFact`
- `AssignFact`

本阶段不实现：

- JS/TS fact extraction
- Rust fact extraction
- call graph reachability
- forward/backward taint propagation
- Agent 调用
- finding fusion
- dynamic analysis

这些能力继续保留在 Phase 8 到 Phase 15。

## 架构

新增 Rust fact extraction 层，位于 static analysis pipeline 的 file discovery 之后、三条分析线之前：

```text
File Discovery
      |
      v
Python Fact Extraction
      |
      v
FactStore / Vec<Fact>
      |
      +--> Rule Line
      +--> Taint Line (Phase 10/11 consumer)
      +--> Agent Line (Phase 12 consumer)
      |
      v
StaticAnalysisResult.facts
```

Phase 7 中，facts 是真实输出，不只是内部缓存。`StaticAnalysisResult` 新增 `facts: Vec<Fact>` 字段。JSON 输出始终保留该字段，具体是否展示在 Markdown 由已有 `report.include_facts` 控制。

## 模块设计

新增模块：

```text
rust/crates/mcp-sec-audit-core/src/static_analysis/facts/
├── mod.rs
├── ids.rs
├── python.rs
└── pipeline.rs
```

职责：

- `ids.rs`：生成 deterministic fact id，兼容原 Python ID 风格。
- `python.rs`：Python AST parser、visitor、alias resolution、entrypoint/source/sink/call/assign extraction。
- `pipeline.rs`：从 `StaticScanContext.discovered_files` 中筛选 Python 文件，读取源码并汇总 facts 和 diagnostics。
- `mod.rs`：暴露 `extract_static_facts`、`extract_python_facts` 和 diagnostics 类型。

## Parser 选择

Phase 7 使用 Rust 原生 Python parser crate，首选 `rustpython-parser`。

原因：

- 不依赖 Python runtime。
- 能直接获得 Python AST、行号和表达式结构。
- 适合在 Rust core crate 中做可测试、可移植的静态解析。
- 后续可以继续扩展到更完整的表达式和作用域分析。

## Fact ID 规则

Phase 7 对齐原系统 ID 风格：

```text
python:<rel_path>:<qualified_name>
import:<rel_path>:<line>:<imported>
entry:<rel_path>:<name>
call:<rel_path>:<line>:<column>
sink:<category>:<rel_path>:<line>
source:<rel_path>:<function_name>:<param_name>
assign:<rel_path>:<line>:<target>
```

`rel_path` 使用相对 scan root 的 POSIX 路径；如果无法计算相对路径，则使用原始路径的 POSIX 表示。

## Python 提取能力

### FunctionFact

识别：

- `def`
- `async def`
- class method
- nested function

输出：

- `language = "python"`
- `name`
- `qualified_name`
- `line`
- `end_line`
- `params`
- `decorators`
- `docstring`
- `enclosing_class`

参数应尽量保留 annotation 和 default 的表达式字符串。复杂表达式无法完整还原时，应使用稳定的 fallback 表示，而不是空字段伪装完整解析。

### ImportFact

识别：

- `import module`
- `import module as alias`
- `from module import name`
- `from module import name as alias`

同时维护 alias map：

- `import subprocess as sp` 记录 `sp -> subprocess`
- `from os import system as s` 记录 `s -> os.system`
- `from subprocess import run` 记录 `run -> subprocess.run`

### EntryPointFact

识别 MCP decorator：

- `mcp.tool`
- `mcp.resource`
- `mcp.prompt`
- `server.tool`
- `server.resource`
- `server.prompt`
- `mcp_tools`
- `mcp_tool`
- `server_tools`

支持 decorator call 和 decorator name 两种形式：

```python
@mcp.tool()
@mcp.tool
@server.resource("file://...")
```

kind 映射：

- 包含 `resource` -> `McpResource`
- 包含 `prompt` -> `McpPrompt`
- 其他 MCP decorator -> `McpTool`

### SourceFact

对 MCP entrypoint 的参数生成 source facts。

规则：

- 普通参数生成 `kind = "mcp_tool_parameter"`。
- class method 的 `self` / `cls` 不作为外部输入 source。
- source fact 关联 entrypoint 的 `function_id`。

### CallFact

识别函数内调用表达式，输出：

- caller function id
- callee 原始表达式
- normalized callee
- line
- column
- end line
- snippet
- positional args
- keyword args
- import alias resolution 结果

callee normalization 需要覆盖：

- direct call: `eval(...)`
- attribute call: `subprocess.run(...)`
- import alias: `sp.run(...) -> subprocess.run`
- from-import alias: `s(...) -> os.system`
- assignment alias: `runner = subprocess.run; runner(...) -> subprocess.run`

### SinkFact

Phase 7 必须识别初始 sink 集合：

- RCE:
  - `subprocess.run`
  - `subprocess.Popen`
  - `subprocess.call`
  - `subprocess.exec`
  - `subprocess.check_output`
  - `os.system`
  - `os.popen`
  - `os.exec`
  - `os.spawn`
  - `eval`
  - `exec`
  - `compile`
- File:
  - `open`
  - `builtins.open`
  - `io.open`
  - `pathlib.Path.open`
  - `__builtins__`
- Network:
  - `requests.get`
  - `requests.post`
  - `requests.put`
  - `requests.delete`
  - `requests.patch`
  - `urllib.request`
  - `urllib3`
  - `http.client`
  - `socket.create_connection`
  - `socket.connect`

sink 输出字段：

- `call_id`
- `category`
- `rule_id`
- `sink_name`
- `severity_base`
- `reason`
- `conditions`
- `confidence`

### AssignFact

识别函数体内简单赋值：

- `name = name`
- `name = attribute`
- `name = call`
- tuple/list destructuring 可以先提取明确的 name target，复杂 target 跳过。

assignment facts 也用于 alias resolution：

```python
runner = subprocess.run
runner(cmd)
```

应 normalized 为 `subprocess.run`。

## Diagnostics 和错误处理

新增 extraction diagnostics 类型，记录：

- file
- line
- kind
- message

错误策略：

- Python syntax error 不应导致整个 scan 崩溃，应记录 diagnostic 并继续其他文件。
- 文件读取错误是扫描环境错误，应返回 `anyhow::Error`。
- parser 不支持的 AST 节点应保守跳过。
- 如果 Python fact extraction 被显式启用并且 extractor 因内部错误无法运行，应返回明确错误，不能返回空 facts 伪装成功。

Phase 7 可以先将 diagnostics 作为 extractor API 输出并在 tests 中验证；如果 `StaticAnalysisResult` 当前只扩展 facts，不扩展 diagnostics，则 diagnostics 仍不丢失于内部 API。

## 静态扫描 Pipeline 集成

`run_static_scan()` 在 discovery 之后调用：

```rust
let facts = facts::extract_static_facts(&ctx)?;
```

然后：

- facts 写入 `StaticAnalysisResult.facts`。
- `StaticAnalysisSummary` 新增 `fact_count`。
- `empty_result()` 返回空 facts 和 `fact_count = 0`。
- `fixtures::synthetic_static_analysis_result()` 更新以包含 facts。
- JSON roundtrip tests 更新，确保 JSON 保留 `facts`。

## Taint line 空实现处理

当前 `run_taint_line()` 在 enabled 时返回空 Vec，这与“不允许空实现”冲突。

Phase 7 处理方式：

- Phase 7 不声明 taint propagation 已完成。
- 如果 `static.taint.enabled = true`，但 Phase 10/11 尚未实现 taint analyzer，`run_taint_line()` 必须返回明确错误。
- 为了保持当前默认 `scan static` 可运行，`rust/config/default.toml` 将 `static.taint.enabled` 暂时改为 `false`，直到 Phase 10/11 完成。
- 单元测试增加 enabled taint line 报错用例，防止再次出现空实现。

这符合路线图规则：未实现能力应保持关闭或明确报错，不能用空结果伪装完成。

## 报告输出

JSON：

- 始终序列化 `facts` 字段。
- 即使 `static.save_facts = false`，也保留字段但内容为空。

JSONL：

- 当 facts 存在时，可以按 fact event 输出。
- 如果当前 JSONL renderer 已有固定结构，则 Phase 7 至少保证 full JSON 中有 facts；JSONL 适配可在报告测试中明确验证。

Markdown：

- 默认不展示 facts。
- 当 `report.include_facts = true` 时展示 fact summary，而不是完整 dump。
- Markdown 至少显示 fact 总数和按 type 聚合数量，避免报告过长。

## 测试策略

Phase 7 必须新增 focused tests，至少覆盖：

1. import extraction：`import`、`import as`、`from import`、`from import as`。
2. function extraction：普通函数、async function、class method、nested function。
3. decorator extraction：`@mcp.tool()`、`@server.resource()`、`@mcp.prompt`。
4. source extraction：entrypoint 参数生成 source，`self` / `cls` 不生成 source。
5. call extraction：direct call、attribute call、args、kwargs、line、column。
6. alias normalization：import alias、from-import alias、assignment alias。
7. sink detection：subprocess、os、eval/exec/open、requests、socket。
8. assignment extraction：name、attribute、call 表达式。
9. syntax error diagnostics：坏 Python 文件不终止全局 extraction。
10. pipeline integration：只处理 Python discovered files，跳过 JS/TS/Rust/JSON。
11. static scan JSON result：`facts` 字段存在且非空。
12. taint line guard：enabled taint analyzer 在 Phase 10/11 前返回明确错误。

测试必须断言 facts 非空，并检查关键字段，不接受只检查函数返回 `Ok`。

## 验收标准

Phase 7 完成必须满足：

- `cargo fmt --all -- --check` 通过。
- `cargo test` 通过。
- Python fixture 能产出函数、导入、调用、入口、source、sink、assignment facts。
- `run_static_scan()` 对 Python target 产生非空 facts。
- JSON 输出包含 `facts`。
- 默认配置不启用尚未实现的 taint propagation。
- 显式启用 taint 时返回明确错误，而不是空 result。
- `rust/docs/REFACTOR_PLAN.md` 中 Phase 7 标记为完成。
- `CURRENT_PHASE` 更新为 `phase7-python-fact-extraction`。

## 风险和边界

生产级第一版不等于完整 Python 解释器语义。Phase 7 的完整性定义是：完整实现本阶段承诺的 extractor 行为，并覆盖原系统 Python AST extractor 的主要 facts 类型和 sink/entrypoint/alias 行为。

不在 Phase 7 内解决的语义边界包括：

- 跨文件 symbol resolution。
- 动态 import。
- monkey patching。
- runtime decorator side effects。
- 完整类型推断。
- 完整 interprocedural taint propagation。

这些边界必须通过 diagnostics、tests 和后续 phase 文档清晰记录，不能以空实现方式隐藏。