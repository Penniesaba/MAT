# 第七阶段状态说明：Python Fact Extraction

本文档记录 Rust 静态分析重构第七阶段的完成状态、能力边界和验证方式。

## 阶段状态

第七阶段已经完成：Rust-native Python fact extraction 已接入静态扫描流程，并通过聚焦测试验证。

本阶段完成的是 Python fact extraction 基础能力，不是最终完整静态分析系统。完整 call graph、完整 taint propagation、finding fusion、Agent 分析和动态分析仍属于后续阶段。

## 阶段目标

第七阶段目标是在 Rust 静态分析重构中实现 Rust-native Python fact extraction。

目标是从 Python MCP Server 源码中提取真实 facts，并把 facts 纳入统一静态分析结果模型，为后续污点分析、调用关系分析和三线融合打基础。

本阶段遵守以下约束：

- 不留下空实现作为已完成能力。
- 已启用但未实现的功能必须明确报错，不能返回空结果假装完成。
- JSON 输出保留原始 facts。
- Markdown / JSONL 是否显示 facts 由配置或 render options 控制。
- 本阶段只实现 Python fact extraction，不实现 JS/TS fact extraction、Rust fact extraction、完整 call graph、完整 taint propagation、Agent 分析、finding fusion 或动态分析。

## 已完成内容

### 1. StaticAnalysisResult 支持 facts

静态分析结果模型已经支持保存 facts：

- `StaticAnalysisResult.facts: Vec<Fact>`
- `StaticAnalysisSummary.fact_count: usize`

JSON 输出保留顶层 `facts` 字段，并在 `summary.fact_count` 中记录 fact 数量。

相关文件：

- `rust/crates/mcp-sec-audit-core/src/model/static_result.rs`
- `rust/crates/mcp-sec-audit-core/src/fixtures.rs`

### 2. Reporting 支持 facts

报告渲染选项已经支持控制 facts 展示：

- `MarkdownRenderOptions.include_facts`
- `JsonlRenderOptions.include_facts`
- Markdown summary 显示 fact count。
- Markdown 在 `include_facts = true` 时显示 fact 类型统计。
- JSONL 在 `include_facts = true` 时输出 `fact` event。

JSON 始终保留完整 facts。

相关文件：

- `rust/crates/mcp-sec-audit-core/src/reporting.rs`

### 3. Phase 7 fact extraction 模块已建立

已新增并暴露 Phase 7 相关 API：

- `extract_python_facts`
- `extract_static_facts`
- `ExtractionDiagnostic`
- `PythonExtractionResult`

相关文件：

- `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`
- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/mod.rs`
- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/ids.rs`
- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`
- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`
- `rust/crates/mcp-sec-audit-core/src/lib.rs`

### 4. RustPython parser 依赖已接入

Python fact extraction 使用 RustPython AST parser：

- `rustpython-parser = "0.4"`

相关文件：

- `rust/Cargo.toml`
- `rust/crates/mcp-sec-audit-core/Cargo.toml`

### 5. legacy-compatible fact ID 已实现

当前支持的 ID 格式包括：

- `python:<rel_path>:<qualified_name>`
- `import:<rel_path>:<line>:<imported>`
- `entry:<rel_path>:<qualified_name>`
- `call:<rel_path>:<line>:<column>`
- `sink:<category>:<rel_path>:<line>`
- `source:<rel_path>:<function_name>:<param_name>`
- `assign:<rel_path>:<line>:<target>`

相关文件：

- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/ids.rs`

### 6. Python import facts 已实现

支持：

- `import subprocess`
- `import subprocess as sp`
- `from pathlib import Path`
- `from os import path as os_path`

会产出：

- `Fact::Import`
- `ImportFact.module`
- `ImportFact.imported_name`
- `ImportFact.alias`
- `ImportKind::Import`
- `ImportKind::ImportAs`
- `ImportKind::FromImport`
- `ImportKind::FromImportAs`

import alias map 同时用于后续 call normalization。

### 7. Python function facts 已实现

支持：

- 顶层函数。
- async 函数。
- class method。
- nested function。
- qualified name。
- enclosing class。
- 参数列表、annotation、default value。
- docstring。
- decorator 文本渲染。
- start line / end line。

会产出：

- `Fact::Function`
- `FunctionFact`

### 8. MCP entrypoint facts 已实现

支持识别 MCP 装饰器并将被装饰函数标记为 MCP entrypoint。

当前识别模式包括：

- `mcp.tool`
- `mcp.resource`
- `mcp.prompt`
- `server.tool`
- `server.resource`
- `server.prompt`
- `mcp_tools`
- `mcp_tool`
- `server_tools`

会产出：

- `Fact::Entrypoint`
- `EntryPointFact.kind`
- `EntryPointFact.name`
- `EntryPointFact.function_id`
- `EntryPointEvidence`
- `EntryPointFact.params`
- `Confidence::High`

### 9. MCP 参数 source facts 已实现

对 MCP entrypoint 的非 `self` / `cls` 参数生成 source fact。

会产出：

- `Fact::Source`
- `SourceFact.kind = "mcp_tool_parameter"`
- `SourceFact.function_id`
- `SourceFact.name`
- `Confidence::High`

示例 ID：

- `source:server.py:run_command:command`
- `source:server.py:run_command:timeout`

### 10. Python call facts 已实现

支持：

- 遍历 Python 表达式中的 `ast::Expr::Call`。
- 生成 `Fact::Call`。
- 提取 callee。
- 提取 normalized callee。
- 提取 positional args。
- 提取 kwargs。
- 提取 caller function ID。
- 提取 call snippet。
- 使用 `make_call_id(root, file, line, column)` 生成 call ID。

### 11. Call alias normalization 已实现

当前 import alias map 已用于 call facts normalized callee 解析。

示例：

```python
import subprocess as sp
sp.run(command, shell=True)
```

归一化为：

```text
subprocess.run
```

同时支持：

```python
from subprocess import run
run(command)
```

归一化为：

```text
subprocess.run
```

### 12. Assignment alias bridge 已实现

已支持简单函数别名解析，例如：

```python
runner = sp.run
runner(command, shell=True)
```

在 import alias 解析后归一化为：

```text
subprocess.run
```

该能力是 Phase 7 的窄 alias bridge，不等同于完整数据流或完整赋值语义。

### 13. Assign facts 已实现

已实现：

- `Assign` 的 `Fact::Assign` 产出。
- 有 value 的 `AnnAssign` 的 `Fact::Assign` 产出。
- 简单 name / attribute / subscript target 的保守文本渲染。
- target、value、function ID、snippet、line、extractor、ID 提取。
- assignment alias map 与 assign 处理路径共享。

Phase 7 不对 tuple/list unpacking 产出 assign facts；`AugAssign` 只遍历嵌套表达式和 calls，不产出 assign fact，避免夸大数据流语义。

### 14. Sink facts 已实现

危险调用现在会从 call facts 中确定性分类为 `Fact::Sink`。这是 sink 标记，不是 taint propagation。

当前覆盖：

- command execution:
  - `subprocess.run`
  - `subprocess.Popen`
  - `os.system`
  - `os.popen`
- file write:
  - `open` 使用写入/追加/创建/更新模式时。
  - `Path.write_text`
  - `Path.write_bytes`
- dynamic execution:
  - `eval`
  - `exec`
- network / SSRF baseline:
  - `requests.get`
  - `requests.post`
  - `requests.request`
  - `httpx.get`
  - `httpx.post`
  - `httpx.request`
  - `urllib.request.urlopen`
- dynamic import / plugin loading:
  - `importlib.import_module`
  - `__import__`

每个 sink fact 包含：

- `call_id`
- `category`
- `rule_id = "python.<category>"`
- `sink_name`
- `severity_base`
- `reason`
- `conditions`
- `confidence`

### 15. Syntax diagnostics 行为已实现并测试

Python syntax error 会安全返回 diagnostic：

- 不 panic。
- 不伪造 facts。
- diagnostic 包含 file、line、kind、message。
- kind 为 `syntax_error`。

静态 fact pipeline 会将 diagnostics 汇总为明确错误，避免启用的提取流程静默返回空 facts。

### 16. `extract_static_facts` 已接入真实 Python pipeline

`extract_static_facts(ctx)` 现在会：

- 遍历 `StaticScanContext.discovered_files`。
- 只处理 Python 文件。
- 从磁盘读取源码。
- 调用 `extract_python_facts`。
- 汇总 facts。
- 将 diagnostics 汇总为明确错误。

非 Python 文件在 Phase 7 中跳过。

相关文件：

- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`

### 17. `run_static_scan` 已接入 facts

静态扫描流程现在会调用真实 fact extraction：

- `run_static_scan()` 调用 `extract_static_facts(&ctx)?`。
- `StaticAnalysisResult.facts = facts`。
- `StaticAnalysisSummary.fact_count = facts.len()`。

规则线结果仍独立产出。taint 线默认禁用，因此默认结果中 `taint_results` 为空。

相关文件：

- `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`

### 18. Taint line 空实现问题已修复

Phase 7 不实现 taint propagation，因此 taint line 默认禁用。

当前行为：

- `[static.taint].enabled = false` 时返回空 taint results。
- `[static.taint].enabled = true` 时明确报错：

```text
taint analysis line is enabled but not implemented until Phase 10/11; disable [static.taint].enabled or continue the refactor roadmap
```

这防止未实现能力在启用时用空结果伪装为成功。

相关文件：

- `rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs`

### 19. 默认配置已禁用 taint

默认配置和 Rust defaults 都将 taint 设置为 disabled：

```toml
[static.taint]
enabled = false
```

相关文件：

- `rust/config/default.toml`
- `rust/crates/mcp-sec-audit-core/src/config.rs`

### 20. Public phase 常量已更新

当前 phase 常量为：

```rust
pub const CURRENT_PHASE: &str = "phase7-python-fact-extraction";
```

相关文件：

- `rust/crates/mcp-sec-audit-core/src/lib.rs`

## 已支持 fact 类型

Phase 7 完成后，Python extractor 已支持以下 facts：

- `Fact::Import`
- `Fact::Function`
- `Fact::Entrypoint`
- `Fact::Source`
- `Fact::Call`
- `Fact::Assign`
- `Fact::Sink`

以下 fact 类型仍属于后续阶段或其他分析线：

- `Fact::Dataflow`
- `Fact::RuntimeEvent`
- `Fact::Finding`

## 已通过的聚焦验证

已通过的聚焦测试包括：

- Python import / function / entrypoint / source extraction。
- Python call facts。
- call args / kwargs。
- import alias normalization。
- simple assignment alias bridge。
- assign facts。
- sink facts。
- syntax diagnostics。
- static facts pipeline。
- static scan facts integration。
- taint disabled default。
- enabled taint explicit error。
- phase constant。

示例验证命令：

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::facts::python::tests
```

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::facts::pipeline::tests
```

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::pipeline::tests
```

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core config::tests
```

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::lines::tests
```

## 最终验证要求

完成 Phase 7 后仍应运行完整验证：

```bash
cargo fmt --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml --all -- --check
```

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml -p mcp-sec-audit-core
```

```bash
cargo run --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-cli -- scan static \
  --config /home/xiao/Project/mcp-sec-audit/rust/config/default.toml \
  --target <phase7-python-fixture> \
  --rules /home/xiao/Project/mcp-sec-audit/detection/detection/rules/keywords.toml \
  --format json
```

最终 JSON 应确认：

- `facts` 非空。
- `summary.fact_count == facts.len()`。
- `rule_results` 仍独立存在。
- `taint_results` 默认为空，因为 taint disabled。
- 显式启用 taint 时返回明确错误。

## 后续阶段边界

Phase 7 不包含以下能力：

- JavaScript / TypeScript fact extraction。
- Rust fact extraction。
- 完整 call graph。
- 完整 taint propagation。
- taint-lite finding builder。
- Agent 分析线。
- finding fusion。
- 动态分析重构。

这些能力应分别在 Phase 8 及之后阶段继续实现。
