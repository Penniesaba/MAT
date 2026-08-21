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
7. [配置文件与字段详解](#7-配置文件与字段详解)
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

## 7. 配置文件与字段详解

静态扫描通过位置参数 `[CONFIG]` 触发；扫描目标、规则路径、输出格式与输出路径全部由配置文件决定。运行时进度信息走 **stderr**，报告按 `[report].formats` 列表**写文件**到 `[report].output` 指定的基础路径（自动追加扩展名 `.json`/`.jsonl`/`.md`）。

### 7.1 配置文件清单

| 配置文件 | 目标 | `[report].output` | 输出产物 |
|---|---|---|---|
| `python-config.toml` | Python MCP 服务端 | `/tmp/python-report` | `/tmp/python-report.json` |
| `js-config.toml` | JS/TS MCP 服务端 | `/tmp/js-report` | `/tmp/js-report.json`、`/tmp/js-report.md` |
| `rust-config.toml` | Rust MCP 服务端 | `/tmp/rust-report` | `/tmp/rust-report.json`、`/tmp/rust-report.md` |
| `all-languages-config.toml` | 三种目标一次性扫描 | `/tmp/all-report` | `/tmp/all-report.json`、`/tmp/all-report.md` |

### 7.2 字段详解

以下默认值对应 `rust/config/default.toml`（与 Rust 代码 `Default` 实现一致）。类型 `string[]` 表示字符串数组。

#### `[scan]` — 扫描范围

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `targets` | string[] | `["."]` | 待扫描的目录/文件路径，相对于工作目录（从 `rust/` 运行） |
| `exclude` | string[] | `["node_modules","target",".venv","dist"]` | 跳过这些名字的目录 |
| `languages` | string[] | `["python","javascript","typescript","rust"]` | 参与分析的语言 |

#### `[static]` — 静态分析总开关

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | bool | `true` | 静态分析总开关；`false` 时返回空结果 |
| `save_facts` | bool | `true` | 是否在结果中保留提取出的 facts |

#### `[static.rule]` — Rule 分析线（模式匹配）

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | bool | `true` | 是否启用规则线 |
| `rule_paths` | string[] | `["rules/mcp","rules/languages"]` | TOML 规则库目录（相对于 `rust/`） |

#### `[static.taint]` — Taint 分析线（数据流追踪）

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | bool | `false` | 污点线**默认关闭**，需手动开启 |
| `forward` | bool | `true` | 正向传播（source → sink） |
| `backward` | bool | `true` | 反向传播（sink → source） |
| `max_depth` | u32 | `8` | BFS 传播最大深度 |
| `entrypoint_required` | bool | `true` | 仅追踪 MCP 入口点产生的 source（`false` 会放宽到任意 source） |

#### `[static.agent]` — Agent 分析线（调用外部 LLM）

| 字段                     | 类型       | 默认         | 含义                          |
| ---------------------- | -------- | ---------- | --------------------------- |
| `enabled`              | bool     | `false`    | 是否启用 Agent 线（会调用外部 LLM CLI） |
| `provider`             | string   | `"claude"` | LLM CLI 工具名                 |
| `prompt_template_path` | string?  | 无          | 自定义 prompt 模板路径（缺省用内置模板）    |
| `max_turns`            | u32      | `30`       | Agent 最大探索轮次                |
| `timeout_seconds`      | u64      | `600`      | 单次调用超时（秒）                   |
| `extra_args`           | string[] | `[]`       | 追加传给 provider 的参数           |

#### `[static.codeql]` — CodeQL 分析线（语义查询）

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | bool | `false` | 是否启用 CodeQL 线（会调用 codeql CLI 建库+查询） |
| `binary` | string | `"codeql"` | CodeQL CLI 可执行文件路径（缺省用 PATH 上的 `codeql`） |
| `query_pack_path` | string? | 无 | 自定义查询包路径（缺省用内置查询包） |
| `timeout_seconds` | u64 | `1200` | 超时（秒），建库+查询耗时较长 |
| `extra_args` | string[] | `[]` | 追加传给 codeql 的参数 |

#### `[dynamic]` — 动态分析（本阶段暂未实现）

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | bool | `false` | 动态分析开关 |
| `sandbox` | string | `"existing_python_runtime"` | 沙箱类型 |
| `timeout_seconds` | u64 | `120` | 超时（秒） |

#### `[fusion]` — 结果融合

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `enabled` | bool | `true` | 融合开关；`false` 时无融合 findings |
| `require_confirmed_by` | u32 | `1` | 一组最少需要 N 条线确认，少于 N 会被过滤 |
| `boost_when_multiple_lines_agree` | bool | `true` | ≥2 条线一致时置信度 +0.1 |
| `agent_only_as_advisory` | bool | `true` | 仅 agent 独报时置信度上限为 Medium |
| `line_proximity` | u32 | `5` | stage-1 匹配的文件+行号近邻阈值 |
| `rule_weight` | u32 | `3` | Rule 线在加权评分中的权重 |
| `taint_weight` | u32 | `2` | Taint 线权重 |
| `agent_weight` | u32 | `1` | Agent 线权重 |
| `codeql_weight` | u32 | `4` | CodeQL 线权重 |

#### `[report]` — 报告输出

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `output` | string | `"report"` | 输出基础路径（不含扩展名），按 `formats` 写 `<output>.<ext>`；支持 `<timestamp>` 占位符替换为 UTC `YYYYMMDD-HHMMSS` |
| `formats` | string[] | `["json","markdown"]` | 输出格式，取值 `json`/`jsonl`/`markdown` |
| `include_fused_results` | bool | `true` | 是否包含融合 findings |
| `include_raw_rule_results` | bool | `true` | 是否包含 Rule 线原始结果 |
| `include_raw_taint_results` | bool | `true` | 是否包含 Taint 线原始结果 |
| `include_raw_agent_results` | bool | `true` | 是否包含 Agent 线原始结果 |
| `include_raw_codeql_results` | bool | `true` | 是否包含 CodeQL 线原始结果 |
| `include_facts` | bool | `false` | 是否包含 facts 列表（调试用） |

> **注意**：`[report]` 里 `include_raw_*` / `include_facts` 若在手工写的配置中**省略**，TOML 反序列化会按 `false` 处理（`include_fused_results` 例外，省略时按 `true`）。建议在配置中显式写出，避免歧义。

---

## 8. 运行步骤

### 8.1 快速测试（仅 Rule + Taint）

无需 CodeQL 或 Claude CLI：

```bash
cd /home/xiao/Project/mcp-sec-audit/rust

# 测试 Python 目标（进度走 stderr，报告写入 /tmp/python-report.json）
cargo run --release ../test-targets/configs/python-config.toml

# 测试 JS/TS 目标（报告写入 /tmp/js-report.json、/tmp/js-report.md）
cargo run --release ../test-targets/configs/js-config.toml

# 测试 Rust 目标（报告写入 /tmp/rust-report.json、/tmp/rust-report.md）
cargo run --release ../test-targets/configs/rust-config.toml

# 测试全部目标（一次性，报告写入 /tmp/all-report.json、/tmp/all-report.md）
cargo run --release ../test-targets/configs/all-languages-config.toml
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
# 报告已直接写入 /tmp/python-report.json（由 [report].output + formats 决定）
cargo run --release ../test-targets/configs/python-config.toml

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
| 结果中 `codeql` 出现在 `supported_by` 中 | ✓（CodeQL 作为对等线路参与四线融合） |

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
| 报错 `unexpected argument '--format'` | CLI 已精简为单一 `[CONFIG]` 位置参数 | 改用 `[report].formats` / `[report].output` 控制输出 |
| 运行后没有看到报告文件 | 未配置 `[report].output` 或 `formats` 为空 | 设置 `[report].output` 基础路径，并确认 `formats` 非空 |
