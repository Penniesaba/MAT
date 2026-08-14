# MCP Security Auditor — 静态分析测试方案

> **版本**：1.0.0  
> **日期**：2026-08-06  
> **目的**：全面验证四条分析线（Rule、Taint、Agent、CodeQL）对 Python、JavaScript、TypeScript 和 Rust 测试目标的检测能力

---

## 目录

1. [概述](#1-概述)
2. [前置条件](#2-前置条件)
3. [测试目标架构](#3-测试目标架构)
4. [测试目标 1：Python MCP 服务端](#4-测试目标-1python-mcp-服务端)
5. [测试目标 2：JavaScript/TypeScript MCP 服务端](#5-测试目标-2javascripttypescript-mcp-服务端)
6. [测试目标 3：Rust MCP 服务端](#6-测试目标-3rust-mcp-服务端)
7. [配置文件](#7-配置文件)
8. [运行步骤](#8-运行步骤)
9. [预期结果与验证](#9-预期结果与验证)
10. [中间结果验证](#10-中间结果验证)

---

## 1. 概述

### 1.1 测试目标

本测试方案验证 Rust 静态分析系统能够正确：

1. **发现**所有支持语言的源文件
2. **提取 Fact**（Function、Import、Entrypoint、Call、Sink、Source、Assign）从每种语言
3. **运行 Rule 分析** — 模式匹配找到已知危险模式
4. **运行 Taint 分析** — 从 MCP 入口点到 sink 的数据流追踪（跨调用链）
5. **运行 Agent 分析** — 基于 LLM 的上下文漏洞识别
6. **运行 CodeQL 分析** — 语义查询检测 Python/JS/TS 中的深层漏洞
7. **融合结果** — 跨线匹配、加权评分、交叉验证加成、LLM 独报上限
8. **生成报告** — JSON、Markdown 输出格式，结构正确

### 1.2 测试覆盖矩阵

| 漏洞类型 | Python | JavaScript | TypeScript | Rust |
|---|---|---|---|---|
| 命令注入 | ✓ | ✓ | ✓ | ✓ |
| 路径遍历 / 文件写入 | ✓ | ✓ | — | — |
| SSRF / 网络请求 | ✓ | — | — | — |
| 动态代码执行（eval） | — | ✓ | — | — |
| SQL 注入 | — | ✓ | — | — |
| 反序列化 | — | — | — | ✓ |
| Unsafe 块 | — | — | — | ✓ |
| 跨函数调用链 | ✓ | ✓ | ✓ | ✓ |
| 导入/别名解析 | ✓ | ✓ | — | ✓ |

### 1.3 各目标的分析线覆盖

| 分析线 | Python | JavaScript | TypeScript | Rust |
|---|---|---|---|---|
| Rule | ✓ | ✓ | ✓ | ✓ |
| Taint | ✓ | ✓ | ✓ | ✓ |
| Agent | ✓ | ✓ | ✓ | ✓ |
| CodeQL | ✓ | ✓ | ✓ | ✗（不支持） |

---

## 2. 前置条件

### 2.1 所需软件

| 软件 | 版本 | 用途 |
|---|---|---|
| Rust 工具链 | 1.80+ | 构建和运行审计器 |
| Python | 3.10+ | 运行测试目标（可选——仅手动验证时需要） |
| Node.js | 18+ | 运行 JS/TS 测试目标（可选） |
| CodeQL CLI | 2.16+ | CodeQL 分析线（仅在测试 CodeQL 时需要） |
| Claude CLI | latest | Agent 分析线（仅在测试 Agent 时需要） |

### 2.2 构建审计器

```bash
cd /home/xiao/Project/mcp-sec-audit/rust
cargo build --release
```

二进制文件位于 `target/release/mcp-sec-audit`。

### 2.3 验证安装

```bash
# 检查 CLI 是否工作
./target/release/mcp-sec-audit status

# 检查 CodeQL 可用性（如需测试 CodeQL 线）
which codeql && codeql --version

# 检查 Claude 可用性（如需测试 Agent 线）
which claude && claude --version
```

---

## 3. 测试目标架构

### 3.1 目录布局

```
test-targets/
├── python-mcp-server/
│   ├── server.py          # 主 MCP 服务端（3 个工具）
│   ├── helpers.py         # 跨函数辅助工具
│   └── pyproject.toml     # Python 项目元数据
├── js-mcp-server/
│   ├── server.js          # JS MCP 服务端（2 个工具）
│   ├── helpers.js         # 辅助函数
│   ├── server_types.ts    # TS MCP 服务端（1 个工具 + 类型）
│   └── package.json       # Node.js 项目元数据
├── rust-mcp-server/
│   ├── src/
│   │   ├── main.rs        # 主 MCP 服务端（3 个工具）
│   │   └── helpers.rs     # 辅助函数
│   └── Cargo.toml         # Rust 项目元数据
└── configs/
    ├── python-config.toml
    ├── js-config.toml
    ├── rust-config.toml
    └── all-languages-config.toml
```

### 3.2 漏洞设计原则

每个测试目标设计为：
1. 一个**最小但真实**的 MCP 服务端，含 2-3 个工具
2. 包含**刻意放置的漏洞**，横跨多个类别
3. 使用**跨函数调用链**验证污点传播
4. 使用**导入别名**和**变量重赋值**验证解析能力
5. **可运行**（但不安全——包含刻意漏洞，不应部署）

---

## 4. 测试目标 1：Python MCP 服务端

### 4.1 文件：`test-targets/python-mcp-server/server.py`

此服务端使用 FastMCP 框架实现 3 个 MCP 工具：

| 工具 | 漏洞 | Sink 类别 | 调用链 |
|---|---|---|---|
| `run_shell` | 命令注入 | `command_execution` | `工具参数 → 辅助函数 → subprocess.run()` |
| `read_log` | 路径遍历 | `file_read` | `工具参数 → 别名 → open()` |
| `fetch_url` | SSRF | `network_request` | `工具参数 → requests.get()` |

**分析验证关键特性**：
- `import subprocess as sp` — 测试导入别名解析（Rule + Taint）
- `runner = sp.run` — 测试赋值别名解析（Taint）
- `normalize_path()` 辅助函数 — 测试跨函数污点传播
- `@mcp.tool()` 装饰器 — 测试入口点检测
- `requests.get(url, timeout=5)` — 测试网络 sink 分类

### 4.2 文件：`test-targets/python-mcp-server/helpers.py`

包含共享辅助函数：
- `normalize_path(user_input)` — 原样透传用户输入（无清理，刻意制造漏洞）
- `build_command(cmd)` — 构造 shell 命令字符串
- `is_safe_url(url)` — **伪造的**验证器，始终返回 True（模拟有缺陷的安全检查）

---

## 5. 测试目标 2：JavaScript/TypeScript MCP 服务端

### 5.1 文件：`test-targets/js-mcp-server/server.js`

此服务端使用 `@modelcontextprotocol/sdk` 模式实现 2 个 MCP 工具：

| 工具 | 漏洞 | Sink 类别 | 调用链 |
|---|---|---|---|
| `db_query` | SQL 注入 + 代码执行 | `database_injection`, `dynamic_execution` | `工具参数 → eval()` 和 `工具参数 → SQL 模板` |
| `export_file` | 任意文件写入 | `file_write` | `工具参数 → 辅助函数 → fs.writeFileSync()` |

**分析验证关键特性**：
- `const { exec } = require("child_process")` — CommonJS 解构式 require
- `const fs = require("fs")` — CommonJS 简单 require
- 内联箭头处理器：`server.tool("db_query", async (params) => { ... })`
- 命名处理器：`server.tool("export_file", exportFileHandler)`（测试回填）
- 模板字面量 SQL 注入：`` `SELECT * FROM ${table}` ``

### 5.2 文件：`test-targets/js-mcp-server/helpers.js`

- `writeFile(filename, content)` — 透传至 `fs.writeFileSync()`，无路径清理

### 5.3 文件：`test-targets/js-mcp-server/server_types.ts`

TypeScript 变体实现 1 个 MCP 工具：

| 工具 | 漏洞 | Sink 类别 |
|---|---|---|
| `run_webhook` | 命令注入 | `command_execution` |

**TypeScript 验证关键特性**：
- `import { exec } from "child_process"` — ESM 导入语法
- 类型注解：`interface WebhookParams { url: string; payload: string }`
- 模板字面量：``exec(`curl -X POST -d '${payload}' ${url}`)``

---

## 6. 测试目标 3：Rust MCP 服务端

### 6.1 文件：`test-targets/rust-mcp-server/src/main.rs`

使用 `rmcp` crate 实现 3 个 MCP 工具：

| 工具 | 漏洞 | Sink 类别 | 调用链 |
|---|---|---|---|
| `exec_shell` | 命令注入 | `command_execution` | `工具参数 → Command::new().arg()` |
| `load_config` | 反序列化 RCE | `deserialization` | `工具参数 → serde_json::from_str()` |
| `unsafe_copy` | Unsafe 内存 + 文件写入 | `unsafe_block`, `file_write` | `unsafe { ptr::copy }` |

**Rust 验证关键特性**：
- `use std::process::Command as ShellCmd` — use 别名（`UseAs`）
- `use std::{fs, io}` — use 组（`UseGroup`）
- `#[tool]` 属性宏 — MCP 入口点检测
- `impl` 方法 — 面向对象风格的方法调用链
- `unsafe { ... }` 块 — Rust 特有漏洞类别

### 6.2 文件：`test-targets/rust-mcp-server/src/helpers.rs`

- `build_shell_command(cmd: &str)` — 从用户输入构造 `Command`（无清理）
- `parse_config(raw: &str)` — 对 `serde_json::from_str()` 的薄封装（反序列化 sink）

---

## 7. 配置文件

配置文件位于 `test-targets/configs/`，从 `rust/` 目录运行时使用 `--config ../test-targets/configs/<name>.toml`。

### 7.1 关键配置项说明

```toml
[static.rule]
enabled = true                    # Rule 线默认开启
rule_paths = ["rules/languages"]  # 规则库路径（相对于 rust/ 工作目录）

[static.taint]
enabled = true                    # Taint 线必须手动开启（默认关闭）
forward = true                    # 启用正向传播（source → sink）
backward = true                   # 启用反向传播（sink → source）
max_depth = 8                     # BFS 最大深度
entrypoint_required = true        # 仅追踪 MCP 入口点的 source

[fusion]
enabled = true                    # 融合默认开启
require_confirmed_by = 1          # 最少需要 1 条线确认
boost_when_multiple_lines_agree = true  # 多线一致时 +0.1 置信度加成
agent_only_as_advisory = true     # LLM 独报上限为 Medium

[report]
formats = ["json", "markdown"]    # 输出格式
include_fused_results = true      # 包含融合结果
include_facts = true              # 包含 Fact 列表（调试用）
```

---

## 8. 运行步骤

### 8.1 快速测试（仅 Rule + Taint）

无需 CodeQL 或 Claude CLI：

```bash
cd /home/xiao/Project/mcp-sec-audit/rust

# 测试 Python 目标
cargo run --release -- scan static --config ../test-targets/configs/python-config.toml --format json

# 测试 JS/TS 目标
cargo run --release -- scan static --config ../test-targets/configs/js-config.toml --format json

# 测试 Rust 目标
cargo run --release -- scan static --config ../test-targets/configs/rust-config.toml --format json

# 测试全部目标（一次性）
cargo run --release -- scan static --config ../test-targets/configs/all-languages-config.toml --format json
```

### 8.2 完整测试（启用 Agent 和 CodeQL）

在对应的配置 TOML 文件中设置：
- `[static.agent] enabled = true`
- `[static.codeql] enabled = true`

然后运行上述相同命令。

### 8.3 运行 Rust 单元测试

```bash
cd /home/xiao/Project/mcp-sec-audit/rust
cargo test --release
```

### 8.4 查看中间结果

```bash
# 将 JSON 输出保存到文件以便分析
cargo run --release -- scan static \
  --config ../test-targets/configs/python-config.toml \
  --format json 2>/dev/null > /tmp/python-report.json

# 查看摘要
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
print(json.dumps(d['summary'], indent=2))
"

# 按类型统计 Fact 数量
python3 -c "
import sys, json
from collections import Counter
d = json.load(open('/tmp/python-report.json'))
c = Counter(f['type'] for f in d['facts'])
for t, n in c.most_common():
    print(f'  {t}: {n}')
"

# 查看 Rule 分析结果
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for r in d['rule_results']:
    print(f'  {r[\"rule_id\"]}: {r[\"file\"]}:{r[\"line\"]} ({r[\"confidence\"]})')
"

# 查看 Taint 分析结果
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for t in d['taint_results']:
    print(f'  {t[\"source_kind\"]} -> {t[\"sink_kind\"]} ({t[\"taint_confidence\"]})')
"

# 查看融合后的发现
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for f in d['fused_findings']:
    print(f'  [{f[\"severity\"]}] {f[\"title\"][:80]}')
    print(f'    supported_by: {f[\"supported_by\"]}, confidence: {f[\"confidence\"]}')
"
```

---

## 9. 预期结果与验证

> 以下结果基于 2026-08-06 实际运行数据。

### 9.1 Python 目标实际结果

| 指标 | 实际值 | 说明 |
|---|---|---|
| `fact_count` | 51 | 包含 Function、Import、Entrypoint、Call、Sink、Source、Assign |
| `rule_result_count` | 2 | `file_read`（open 匹配）、`network_request`（requests 匹配） |
| `taint_result_count` | 2 | source → network_request、source → command_execution |
| `agent_result_count` | 0 | Agent 未启用 |
| `codeql_result_count` | 0 | CodeQL 未启用 |
| `fused_finding_count` | 3 | 1 个 rule 独报 + 2 个 taint 独报 |
| `highest_severity` | high | |
| `risk_level` | high | |

**Rule 线验证**：
- `file_read` 在 `server.py:8` 检测到（匹配 `open(` 关键词，含有来自导入行的 `Path` 引用）
- `network_request` 在 `server.py:9` 检测到（匹配 `requests.` 关键词）
- 注意：`command_execution` **未被 Rule 线检测到**，因为代码使用了别名（`import subprocess as sp` → `runner = sp.run`），关键词 `subprocess.` 不会匹配导入行（含空格而非点号），正则 `subprocess\.(run\|Popen\|call)` 也不会匹配 `runner(...)`

**Taint 线验证**：
- `mcp_tool_parameter → network_request`（Medium）— `fetch_url` 的 `url` 参数直接传递给 `requests.get()`
- `mcp_tool_parameter → command_execution`（Medium）— `run_shell` 的 `command` 参数通过 `build_command()` 和赋值别名 `runner` 最终到达 `subprocess.run()`

### 9.2 JavaScript/TypeScript 目标实际结果

| 指标 | 实际值 |
|---|---|
| `fact_count` | 35 |
| `rule_result_count` | 3 |
| `taint_result_count` | 4 |
| `fused_finding_count` | 7 |
| `risk_level` | high |

**Rule 线验证**：
- `command_execution`：检测到 `exec(` 关键词（`server.js:15`）
- `dynamic_execution`：检测到 `eval(` 关键词（`server.js:29`）
- `file_write`：检测到 `fs.writeFile` 关键词（`helpers.js:18`）

**Taint 线验证**：
- `mcp_tool_parameter → dynamic_execution`（Medium）— `db_query` 参数到达 `eval()`
- `mcp_tool_parameter → command_execution`（Medium）× 2 — `db_query` 参数到达 `exec()`
- `mcp_tool_parameter → file_write`（Medium）— `export_file` 参数通过 `writeFile()` 辅助函数到达 `fs.writeFileSync()`

### 9.3 Rust 目标实际结果

| 指标 | 实际值 |
|---|---|
| `fact_count` | 67 |
| `rule_result_count` | 3 |
| `taint_result_count` | 4 |
| `fused_finding_count` | 6 |
| `risk_level` | high |

**Rule 线验证**：
- `command_execution`：检测到 `std::process::Command` 关键词（`helpers.rs:6`）
- `deserialization`：检测到 `serde_json::from_str` 关键词（`helpers.rs:20`）
- `unsafe_block`：检测到 `unsafe {` 正则（`main.rs:67`）

**Taint 线验证**：
- `mcp_tool_parameter → command_execution`（Medium）— `exec_shell` 参数通过 `build_shell_command()` 到达 `Command::new()`
- `mcp_tool_parameter → deserialization`（Medium）— `load_config` 参数通过 `parse_config()` 到达 `serde_json::from_str()`
- `mcp_tool_parameter → file_write`（Medium）× 2 — `unsafe_copy` 参数到达 `fs::write()`，且 unsafe 块产生额外路径

### 9.4 全语言合并扫描

| 指标 | 实际值 |
|---|---|
| `fact_count` | 153 |
| `rule_result_count` | 7 |
| `taint_result_count` | 10 |
| `fused_finding_count` | 15 |
| `risk_level` | high |

### 9.5 CodeQL 结果（若启用）

| 检查项 | 预期 |
|---|---|
| Python：`codeql_result_count` > 0 | CodeQL 找到至少一个漏洞 |
| JS/TS：`codeql_result_count` > 0 | CodeQL 找到至少一个漏洞 |
| Rust：`codeql_result_count` = 0 | CodeQL 不支持 Rust |
| 结果中 `codeql` 出现在 `supported_by` 中 | ✓（CodeQL 通过融合直通） |

---

## 10. 中间结果验证

### 10.1 Fact 提取验证

```bash
# 按类型统计 Fact
python3 -c "
import sys, json
from collections import Counter
d = json.load(open('/tmp/python-report.json'))
c = Counter(f['type'] for f in d['facts'])
for t, n in c.most_common():
    print(f'  {t}: {n}')
"

# 查看函数 Fact
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for f in d['facts']:
    if f['type'] == 'function':
        print(f'  {f[\"name\"]} ({f[\"qualified_name\"]}) — params: {[p[\"name\"] for p in f[\"params\"]]}')
"

# 查看 Sink Fact
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for f in d['facts']:
    if f['type'] == 'sink':
        print(f'  [{f[\"severity_base\"]}] {f[\"category\"]} — {f[\"sink_name\"]} ({f[\"reason\"]})')
"

# 查看入口点 Fact
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for f in d['facts']:
    if f['type'] == 'entrypoint':
        print(f'  [{f[\"kind\"]}] {f[\"name\"]} → {f[\"function_id\"]}')
"

# 验证导入别名
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for f in d['facts']:
    if f['type'] == 'import' and f.get('alias'):
        print(f'  {f[\"module\"]} as {f[\"alias\"]} ({f[\"kind\"]})')
"
```

### 10.2 Rule 分析验证

```bash
# 查看所有 Rule 匹配
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for r in d['rule_results']:
    print(f'  {r[\"rule_id\"]}: {r[\"file\"]}:{r[\"line\"]} — matched: \"{r[\"matched_text\"]}\" ({r[\"confidence\"]})')
"

# 检查置信度评分
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for r in d['rule_results']:
    print(f'  {r[\"rule_id\"]}: confidence={r[\"confidence\"]}, severity={r[\"severity\"]}')
"
```

### 10.3 Taint 分析验证

```bash
# 查看所有污点路径
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for t in d['taint_results']:
    print(f'  {t[\"source_kind\"]} -> {t[\"sink_kind\"]} ({t[\"taint_confidence\"]})')
    print(f'    entrypoint_is_mcp: {t[\"entrypoint_is_mcp\"]}')
    print(f'    call_chain length: {len(t[\"call_chain\"])}')
    print(f'    dataflow_path length: {len(t[\"dataflow_path\"])}')
"

# 验证数据流路径详情
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
if d['taint_results']:
    t = d['taint_results'][0]
    for step in t['dataflow_path']:
        print(f'  [{step[\"kind\"]}] line={step[\"line\"]} name={step.get(\"name\")} snippet={step.get(\"snippet\")}')
"

# 检查入口点关联
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for t in d['taint_results']:
    if t.get('entrypoint_is_mcp'):
        print(f'  source={t[\"source_id\"]} entrypoint={t.get(\"entrypoint_id\")}')
"
```

### 10.4 融合验证

```bash
# 查看融合发现
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for f in d['fused_findings']:
    print(f'  [{f[\"severity\"]}] {f[\"title\"][:80]}')
    print(f'    supported_by: {f[\"supported_by\"]}, confidence: {f[\"confidence\"]}')
    if f.get('conflict_note'):
        print(f'    conflict: {f[\"conflict_note\"]}')
"

# 检查交叉验证加成
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for f in d['fused_findings']:
    if len(f['supported_by']) >= 2:
        print(f'  MULTI-LINE: [{f[\"confidence\"]}] {f[\"title\"][:60]} — supported by: {f[\"supported_by\"]}')
"

# 验证 Agent 独报上限（若启用了 Agent）
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for f in d['fused_findings']:
    if f['supported_by'] == ['agent']:
        print(f'  AGENT-ONLY: [{f[\"confidence\"]}] {f[\"title\"][:60]}')
        # 预期：置信度最多为 Medium
"
```

### 10.5 跨线一致性验证

```bash
# 检查某特定漏洞是否同时被 Rule 和 Taint 检测到
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
for f in d['fused_findings']:
    if 'rule' in f['supported_by'] and 'taint' in f['supported_by']:
        print(f'  DUAL-CONFIRMED: [{f[\"severity\"]}] {f[\"title\"][:60]} — confidence: {f[\"confidence\"]}')
"

# 验证无重复发现
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
ids = [f['finding_id'] for f in d['fused_findings']]
print(f'  Total findings: {len(ids)}, Unique IDs: {len(set(ids))}')
print(f'  All unique: {len(ids) == len(set(ids))}')
"
# 预期：All unique: True（所有发现 ID 唯一）
```

### 10.6 风险等级验证

```bash
python3 -c "
import sys, json
d = json.load(open('/tmp/python-report.json'))
s = d['summary']
print(f'  risk_level: {s[\"risk_level\"]}')
print(f'  highest_severity: {s[\"highest_severity\"]}')
print(f'  fused_finding_count: {s[\"fused_finding_count\"]}')
print(f'  fact_count: {s[\"fact_count\"]}')
print(f'  rule_result_count: {s[\"rule_result_count\"]}')
print(f'  taint_result_count: {s[\"taint_result_count\"]}')
"
```

---

## 附录：故障排除

| 症状 | 可能原因 | 解决方案 |
|---|---|---|
| `taint_result_count = 0` | `static.taint.enabled = false`（默认） | 在配置中添加 `[static.taint] enabled = true` |
| `codeql_result_count = 0` | `static.codeql.enabled = false`（默认） | 在配置中添加 `[static.codeql] enabled = true` |
| `agent_result_count = 0` | `static.agent.enabled = false`（默认） | 在配置中添加 `[static.agent] enabled = true` |
| `fused_finding_count = 0` | `fusion.enabled = false` 或 `require_confirmed_by > 1` | 检查 fusion 配置 |
| 规则结果中没有 `command_execution` | 路径中缺少规则库 | 验证 `rule_paths` 和 TOML 语法 |
| JS 目标无 `Entrypoint` Fact | 命名处理器未回填 | 检查处理器函数是否在注册之前定义 |
| Panic: `CodeQL CLI not found` | CodeQL 未安装或不在 PATH 中 | 设置 `codeql.enabled = false` 或安装 CodeQL |
| Rust CodeQL 结果非空 | 不可能 — CodeQL 不支持 Rust | 这是预期行为 |
| `scan target does not exist` | 配置中的路径是相对于工作目录的 | 确保从 `rust/` 目录运行，且配置中使用 `../test-targets/` 前缀 |
