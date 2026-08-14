# MCP-Sec-Audit 运行操作手册

> 从零开始，一步步把项目跑起来并看到检测效果。

---

## 目录

1. [环境准备](#1-环境准备)
2. [安装依赖](#2-安装依赖)
3. [验证安装：跑通单元测试](#3-验证安装跑通单元测试)
4. [快速体验：静态分析 Demo](#4-快速体验静态分析-demo)
5. [使用 CLI 命令行工具](#5-使用-cli-命令行工具)
6. [用内置 Demo 目标看效果](#6-用内置-demo-目标看效果)
7. [理解检测输出](#7-理解检测输出)
8. [可选：动态分析（需要 Docker）](#8-可选动态分析需要-docker)
9. [常见问题排查](#9-常见问题排查)

---

## 1. 环境准备

### 1.1 系统要求

| 组件 | 要求 | 说明 |
|------|------|------|
| 操作系统 | Linux (推荐 Ubuntu 22.04+) | eBPF 功能需要 Linux 内核 ≥ 4.4 |
| Python | **3.13+** | 项目硬性要求 |
| 包管理器 | uv | 推荐使用 uv 管理 Python 环境和依赖 |
| Git | 任意版本 | 克隆仓库 |

### 1.2 检查 Python 版本

```bash
python3 --version
# 输出必须 >= 3.13。如果不是，需要安装/升级。
```

**如果 Python 版本不够**（Ubuntu）：

```bash
# 方法1: 用 deadsnakes PPA 安装
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install python3.13 python3.13-dev -y

# 方法2: 用 pyenv
curl https://pyenv.run | bash
pyenv install 3.13.0
pyenv global 3.13.0
```

### 1.3 克隆项目

```bash
cd ~
git clone https://github.com/nyit-vancouver/mcp-sec-audit.git
cd mcp-sec-audit
```

---

## 2. 安装依赖

### 2.1 创建虚拟环境（推荐）

```bash
cd detection
uv venv
source .venv/bin/activate
```

### 2.2 安装核心依赖

```bash
# 使用 uv 安装（更快、更可靠）
uv pip install -e .
```

### 2.3 验证安装

```bash
uv run python -c "import detection; print('detection OK')"
uv run python -c "import analysis; print('analysis OK')"
uv run python -c "import tree_sitter; print('tree-sitter OK')"
```

三条命令都输出 `OK` 即安装成功。

### 2.4 安装可选依赖（动态分析用，可跳过）

```bash
# Docker SDK（动态分析需要）
uv pip install docker

# BCC（eBPF，仅动态分析需要，必须 Linux）
sudo apt install bpfcc-tools python3-bpfcc -y
```

---

## 3. 验证安装：跑通单元测试

这是最快的验证方式——确认整个系统能正常工作：

```bash
# 确保在 detection/ 目录下，虚拟环境已激活
cd ~/mcp-sec-audit/detection

# 跑所有单元测试
uv run pytest tests/unit/ -v

# 如果只跑一个最核心的测试
uv run pytest tests/unit/test_python_ast_extractor.py -v
```

**预期输出**：

```
collected 15 items

tests/unit/test_python_ast_extractor.py::test_extract_subprocess_run PASSED
tests/unit/test_python_ast_extractor.py::test_extract_os_system PASSED
tests/unit/test_python_ast_extractor.py::test_extract_eval PASSED
...
========================= 15 passed =========================
```

---

## 4. 快速体验：静态分析 Demo

这是最快看到效果的方法——**不需要命令行，直接运行一个 Python 脚本**：

```bash
cd ~/mcp-sec-audit/detection

# 运行内置的静态分析演示（自动创建恶意样本并检测）
uv run python -m examples.static_analysis_test
```

**预期输出**（关键部分）：

```
╔══════════════════════════════════════════════════════════════╗
║  MCP Security Static Analysis Test                           ║
╚══════════════════════════════════════════════════════════════╝

Creating sample malicious MCP tool...
Tool created at: /tmp/mcp-test-xxxxx/

============================================================
STATIC ANALYSIS RESULTS
============================================================

Server: mcp-test-xxxxx
Risk Level: HIGH
Total Score: 85.0/100

Detected Capabilities (7):
  • command_exec
    Confidence: 0.70
    Weight: 25.0
    Sources: ['static']
    Evidence:
      - /tmp/.../server.py:subprocess.run
      - /tmp/.../server.py:os.system

  • file_read
    Confidence: 0.65
    Weight: 15.0

  • network_outbound
    ...

DETECTED SECURITY ISSUES
============================================================
  ✓ Command execution detected
  ✓ File read operations detected
  ✓ Network operations detected
```

> 如果能看到上面的输出，说明**静态分析已完全跑通**。

---

## 5. 使用 CLI 命令行工具

CLI 是正式使用本工具的方式。

### 5.1 基本用法

```bash
cd ~/mcp-sec-audit/detection

# 静态分析单个文件
uv run python -m detection.cli /path/to/target.py --pipeline static

# 静态分析整个目录（递归扫描所有 .py/.js/.ts 文件）
uv run python -m detection.cli /path/to/project/ --pipeline static

# 指定输出格式
uv run python -m detection.cli /path/to/target --pipeline static --format markdown
uv run python -m detection.cli /path/to/target --pipeline static --format json

# 保存到文件
uv run python -m detection.cli /path/to/target --pipeline static -o result.md
uv run python -m detection.cli /path/to/target --pipeline static -o result.json
```

### 5.2 CLI 参数说明

```
usage: uv run python -m detection.cli TARGET [options]

位置参数:
  TARGET            要分析的目标路径（文件或目录）

可选参数:
  --pipeline {static,dynamic,rag}  选择分析管线（默认: static）
  --format {markdown,json}         输出格式（默认: markdown）
  -o, --output PATH               输出文件路径（默认: 打印到终端）
  --policy-dir PATH               缓解策略目录（默认: detection/mitigation/policy_templates）
  --rules PATH                    规则文件路径（默认: detection/rules/keywords.toml）
```

---

## 6. 用内置 Demo 目标看效果

项目自带了一个精心构造的漏洞 MCP 服务器，包含 6 种不同的安全漏洞。

### 6.1 分析 Python Demo

```bash
cd ~/mcp-sec-audit/detection

# 对 demo 目标运行静态分析
uv run python -m detection.cli examples/demo-target/server.py --pipeline static
```

**预期输出**：

```markdown
# Detection Summary — server.py

- Total Score: 92.50
- Risk Level: critical

## Findings
- **Potential rce via run_shell_command → subprocess.run** (1.00) — Category: rce (sources: static)
- **Potential rce via system_call → os.system** (1.00) — Category: rce (sources: static)
- **Potential rce via evaluate_expression → eval** (1.00) — Category: rce (sources: static)
- **Potential file via read_file → builtins.open** (1.00) — Category: file (sources: static)
- **Potential network via fetch_url → requests.get** (1.00) — Category: network (sources: static)
- **file_read** (0.65) — Category: file_read (sources: static)
- **network_outbound** (0.70) — Category: network_outbound (sources: static)
- **command_exec** (0.85) — Category: command_exec (sources: static)
```

### 6.2 分析 JavaScript Demo

```bash
uv run python -m detection.cli examples/demo-target/server.js --pipeline static
```

会对 JS 文件运行同样的分析流程，检测 `child_process.exec`、`eval`、`fs.readFile`、`fetch` 等。

### 6.3 分析整个 Demo 目录

```bash
uv run python -m detection.cli examples/demo-target/ --pipeline static
```

会同时扫描 `server.py` 和 `server.js`，合并输出结果。

### 6.4 输出 JSON 格式

```bash
uv run python -m detection.cli examples/demo-target/ --pipeline static --format json
```

输出标准 JSON，便于程序化处理。

---

## 7. 理解检测输出

### 7.1 风险等级说明

| 风险等级 | 分数范围 | 含义 |
|----------|---------|------|
| `low` | 0–24 | 低风险，基本安全 |
| `medium` | 25–49 | 中风险，有一些可疑操作 |
| `high` | 50–74 | 高风险，存在明确的安全威胁 |
| `critical` | 75–100 | 严重，存在高危漏洞 |

### 7.2 每条发现的解读

```markdown
- **Potential rce via run_shell_command → subprocess.run** (0.75) — Category: rce (sources: static)
  │                                                           │              │            │
  │                                                           │              │            └── 证据来源
  │                                                           │              └── 漏洞类别
  │                                                           └── 置信度 (0.0–1.0)
  └── 发现标题（模板: Potential <类别> via <入口> → <危险函数>）
```

### 7.3 AST 引擎 vs 传统插件的区别

在输出中，你会看到两种风格的发���：

**AST 引擎产生的发现**（精准、有调用链）：
```
- Potential rce via run_shell_command → subprocess.run (1.00)
```

**传统插件产生的发现**（粗粒度、基于关键词）：
```
- command_exec (0.85)
- file_read (0.65)
- network_outbound (0.70)
```

二者互补——AST 引擎给你精确的调用链证据，传统插件做广度覆盖。

---

## 8. 可选：动态分析（需要 Docker）

> 动态分析需要 Docker + 特权容器 + Linux eBPF。如果只是想快速体验静态分析，可以跳过此节。

### 8.1 前提条件检查

```bash
# 1. 确认 Docker 可用
docker ps

# 2. 确认 Linux 内核支持 eBPF（≥ 4.4）
uname -r

# 3. 确认 debugfs 已挂载
ls /sys/kernel/debug/tracing
```

### 8.2 构建沙箱镜像

```bash
cd ~/mcp-sec-audit/detection/sandbox

# 用 docker-compose 构建（推荐）
docker-compose build

# 或者用 docker build
docker build -t mcp-security-sandbox:latest .
```

构建过程大约需要 3–5 分钟（首次需要下载 Ubuntu 镜像和 BCC 依赖）。

### 8.3 运行动态分析

```bash
cd ~/mcp-sec-audit/detection

# 动态分析 Python 脚本
uv run python -m detection.cli examples/demo-target/server.py --pipeline dynamic

# 或者更简单的——直接对任意 Python 脚本运行
python3 -c "
import subprocess, os
subprocess.run(['ls', '-la'])
with open('/etc/passwd') as f: print(f.read()[:100])
" > /tmp/test_malicious.py

uv run python -m detection.cli /tmp/test_malicious.py --pipeline dynamic
```

### 8.4 预期动态分析输出

```markdown
# Detection Summary — server.py

- Total Score: 88.50
- Risk Level: critical

## Findings
- **command_exec** (0.90) — Command execution detected at runtime (sources: dynamic)
- **file_read** (0.90) — File read operations detected at runtime (sources: dynamic)
- **network_outbound** (0.68) — Outbound network connections detected (sources: dynamic)

## Notes
=== Dynamic Analysis Telemetry ===

Execution time: 32.15s
Exit code: 0

Captured events: 47
  - File operations: 15
  - Network activity: 2
  - Process management: 12
  - Command executions: 3

⚠️  Executed Commands:
  - /bin/bash
  - /usr/bin/wget
  ...

⚠️  Sensitive paths accessed:
  - /etc/passwd
  - /etc/shadow

Full logs saved to: logs/server.py_events.cef
```

---

## 9. 常见问题排查

### 9.1 `ModuleNotFoundError: No module named 'detection'`

**原因**：没有激活虚拟环境或在错误目录。

**解决**：
```bash
cd ~/mcp-sec-audit/detection
source .venv/bin/activate
uv pip install -e .
```

### 9.2 `ModuleNotFoundError: No module named 'tree_sitter'`

**原因**：tree-sitter 没安装。

**解决**：
```bash
uv pip install tree-sitter tree-sitter-javascript tree-sitter-typescript
```

### 9.3 `ModuleNotFoundError: No module named 'analysis'`

**原因**：Python 找不到 analysis 包。

**解决**：在运行命令前确保项目根在 sys.path 中：
```bash
cd ~/mcp-sec-audit/detection
PYTHONPATH=".:$PYTHONPATH" uv run python -m detection.cli ...
```

或者更简单——直接从 detection/ 目录运行，引擎已经有自动路径修复逻辑。

### 9.4 静态分析没有发现任何结果

**可能原因**：
1. 目标文件没有危险函数调用
2. 目标文件有语法错误（提取器会跳过）
3. 是纯文本文件而非 Python/JS/TS

**诊断**：用 demo 目标验证系统是否正常：
```bash
uv run python -m detection.cli examples/demo-target/server.py --pipeline static
# 应该输出 ≥ 5 条发现
```

### 9.5 `Docker not available`

**原因**：Docker 没启动或没安装。

**解决**：
```bash
sudo systemctl start docker
sudo systemctl enable docker
docker ps  # 验证
```

### 9.6 `Python version 3.13 required`

**原因**：系统 Python 版本不够。

**解决**：使用 uv + 虚拟环境：
```bash
uv venv --python 3.13
source .venv/bin/activate
uv pip install -e .
```

---

## 附录：快速命令汇总

```bash
# ==== 环境搭建（一次性） ====
cd ~/mcp-sec-audit/detection
uv venv
source .venv/bin/activate
uv pip install -e .

# ==== 验证 ====
uv run pytest tests/unit/ -v

# ==== 快速体验 ====
uv run python -m examples.static_analysis_test

# ==== 分析你自己的文件 ====
uv run python -m detection.cli /path/to/your/file.py --pipeline static
uv run python -m detection.cli /path/to/your/project/ --pipeline static -o report.md

# ==== 分析内置 Demo（推荐新手） ====
uv run python -m detection.cli examples/demo-target/server.py --pipeline static
uv run python -m detection.cli examples/demo-target/server.js --pipeline static
uv run python -m detection.cli examples/demo-target/ --pipeline static --format json

# ==== 动态分析（需要 Docker） ====
cd sandbox && docker-compose build && cd ..
uv run python -m detection.cli examples/demo-target/ --pipeline dynamic
```

---

> **下一步**：阅读 `docs/STATIC_ANALYSIS_DEEP_DIVE.md` 和 `docs/DYNAMIC_ANALYSIS_DEEP_DIVE.md` 来理解每个检测结果背后的技术原理。
