# Serena 全面安全测试操作手册

> 使用 mcp-sec-audit 对 `oraios/serena`（27K+ stars AI 编码代理）执行完整三阶段安全审计：**静态分析 → 动态分析 → 关联分析**。

---

## 目录

1. [测试目标概况](#1-测试目标概况)
2. [环境准备](#2-环境准备)
3. [第一阶段：静态分析](#3-第一阶段静态分析)
4. [第二阶段：动态分析准备](#4-第二阶段动态分析准备)
5. [第二阶段：动态分析执行](#5-第二阶段动态分析执行)
6. [第三阶段：关联分析](#6-第三阶段关联分析)
7. [综合安全报告解读](#7-综合安全报告解读)
8. [清理与还原](#8-清理与还原)
9. [附录](#9-附录)

---

## 1. 测试目标概况

### 1.1 Serena 简介

| 属性 | 值 |
|------|-----|
| 仓库 | `https://github.com/oraios/serena` |
| Stars | 27,000+ |
| 语言 | Python 3.11–3.14 |
| 核心代码 | `src/serena/` (agent.py 1477 行, tools_base.py 693 行, mcp.py 423 行) |
| MCP 框架 | `mcp==1.28.1` (FastMCP, stdio transport) |
| 主要依赖 | flask, requests, pydantic, solidlsp, sensai-utils |
| 风险特征 | subprocess.Popen（激活环境、启动 LSP）、requests（PyPI 查询、遥测）、文件读写（代码编辑）、os.environ |

### 1.2 为什么 Serena 是一个理想的测试目标

- **高风险操作密集**：agent.py 中有 40+ 处引用了危险函数（subprocess、requests、open）
- **真实调用链复杂**：危险函数嵌套在 3-5 层调用中，不是 demo 级别的简单直调
- **MCP 原生支持**：使用 FastMCP stdio transport，Fuzzer 可直接交互
- **已知误报**：`re.compile` 被标记为 RCE（前次分析已确认）

### 1.3 测试范围

```
Analyzed: src/serena/  (核心业务代码)
Excluded: src/solidlsp/ (第三方 LSP 库), tests/ (测试代码)
```

---

## 2. 环境准备

### 2.1 系统要求总览

| 组件 | 要求 | 用途 |
|------|------|------|
| 操作系统 | **Linux** (Ubuntu 22.04+ 推荐) | eBPF 需要 Linux 内核 |
| 内核版本 | ≥ 4.4 (推荐 ≥ 5.15) | eBPF + cgroup v2 |
| Python | **3.13+** | 运行检测工具 |
| 包管理器 | uv | Python 依赖管理 |
| Docker | ≥ 24.0 | 动态分析沙箱 |
| 磁盘空间 | ≥ 5GB 可用 | Docker 镜像 + 克隆仓库 |

### 2.2 安装 Python 和 uv

```bash
# ---------- 检查 Python 版本 ----------
python3 --version
# 输出必须: Python 3.13.x 或更高

# ---------- 如果不是 3.13+，安装 ----------
# 方法1: deadsnakes PPA (Ubuntu)
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install python3.13 python3.13-dev python3.13-venv -y

# 方法2: pyenv
curl https://pyenv.run | bash
# 重启 shell 后:
pyenv install 3.13.0
pyenv global 3.13.0

# ---------- 安装 uv ----------
curl -LsSf https://astral.sh/uv/install.sh | sh
# 重启 shell 或:
source ~/.cargo/env
```

### 2.3 安装 Docker

```bash
# ============================================
# 2.3.1 卸载旧版本 (如果有)
# ============================================
for pkg in docker.io docker-doc docker-compose docker-compose-v2 \
           podman-docker containerd runc; do
    sudo apt-get remove -y $pkg 2>/dev/null
done

# ============================================
# 2.3.2 配置 Docker APT 仓库 (Ubuntu 22.04/24.04)
# ============================================
sudo apt-get update
sudo apt-get install -y ca-certificates curl

# 添加 Docker 官方 GPG key
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# 添加仓库
echo "deb [arch=$(dpkg --print-architecture) \
  signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# ============================================
# 2.3.3 安装 Docker Engine
# ============================================
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

# ============================================
# 2.3.4 验证 Docker 安装
# ============================================
sudo docker run --rm hello-world
# 预期输出: "Hello from Docker! This message shows that your installation appears to be working correctly."

# ============================================
# 2.3.5 免 sudo 运行 Docker (推荐)
# ============================================
sudo groupadd docker 2>/dev/null || true
sudo usermod -aG docker $USER
echo ">>> 请注销并重新登录，或执行: newgrp docker"
newgrp docker  # 当前 shell 立即生效

# 验证免 sudo
docker ps
# 预期: 无报错 (可能显示空列表)
```

### 2.4 安装 Docker Compose (独立版本，可选但推荐)

```bash
# Docker Compose 通常已随 docker-compose-plugin 安装
docker compose version
# 预期: Docker Compose version v2.x.x

# 如果没有，手动安装:
sudo curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
    -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 2.5 验证 Linux 内核 eBPF 支持

```bash
# ---------- 检查内核版本 ----------
uname -r
# 预期: ≥ 4.4 (本指南测试环境: 6.14.0-27-generic)

# ---------- 检查 cgroup v2 ----------
stat -fc %T /sys/fs/cgroup
# 预期: cgroup2fs  ← 必须是 cgroup2fs，不是 tmpfs

# ---------- 检查 eBPF 调试文件系统 ----------
sudo ls /sys/kernel/debug/tracing/available_events | head -5
# 如果报 "No such file or directory":
sudo mount -t debugfs none /sys/kernel/debug

# ---------- 确认 perf_event_paranoid 级别 ----------
cat /proc/sys/kernel/perf_event_paranoid
# ≤ 1 为佳，= 2 需要 root
# 如果不是 ≤ 1:
# sudo sysctl -w kernel.perf_event_paranoid=1
# sudo sh -c 'echo kernel.perf_event_paranoid = 1 >> /etc/sysctl.d/99-perf.conf'
```

### 2.6 安装 mcp-sec-audit 项目

本手册假定项目位于 `~/Project/mcp-sec-audit`，工作目录为 `detection/`。如尚未克隆：

```bash
mkdir -p ~/Project
cd ~/Project
git clone https://github.com/nyit-vancouver/mcp-sec-audit.git
cd mcp-sec-audit/detection

# ---------- 创建虚拟环境 ----------
uv venv --python 3.13
source .venv/bin/activate

# ---------- 安装核心依赖 ----------
uv sync

# ---------- 安装 Docker SDK ----------
uv pip install docker

# ---------- 验证 ----------
uv run python -c "import detection; print('detection OK')"
uv run python -c "import analysis; print('analysis OK')"
uv run python -c "import docker; print('docker OK')"
# 三条命令都应输出 OK
```

### 2.7 验证 Serena 仓库

本手册假定 Serena 已克隆到 `~/Project/mcp-sec-audit/targets/serena`。如尚未克隆，先执行：

```bash
mkdir -p ~/Project/mcp-sec-audit/targets
cd ~/Project/mcp-sec-audit/targets
git clone --depth 1 https://github.com/oraios/serena.git
```

验证仓库完整：

```bash
echo "Serena 路径: $(realpath ~/Project/mcp-sec-audit/targets/serena)"
test -f ~/Project/mcp-sec-audit/targets/serena/src/serena/mcp.py && echo "✅ Serena repo OK" || echo "❌ 请重新克隆"
```

### 2.8 环境验证清单

运行以下命令确认所有组件就绪：

```bash
#!/bin/bash
# verify_env.sh — 验证 Serena 测试环境

echo "========== 环境验证 =========="

echo -n "Python 3.13+:  "; python3 --version
echo -n "uv:           "; uv --version 2>/dev/null || echo "NOT FOUND"
echo -n "Docker:       "; docker --version 2>/dev/null || echo "NOT FOUND"
echo -n "Docker daemon:"; docker ps >/dev/null 2>&1 && echo "RUNNING" || echo "STOPPED"
echo -n "cgroup v2:    "; stat -fc %T /sys/fs/cgroup 2>/dev/null || echo "UNKNOWN"
echo -n "eBPF tracing: "; sudo test -d /sys/kernel/debug/tracing && echo "OK" || echo "MISSING"
echo -n "mcp-sec-audit:"; uv run python -c "import detection" 2>/dev/null && echo "OK" || echo "MISSING"
echo -n "Serena repo:  "; test -f ~/Project/mcp-sec-audit/targets/serena/src/serena/mcp.py && echo "OK" || echo "MISSING"

echo ""
echo "========== 全部检查完成 =========="
echo "所有项目应为 OK 或 RUNNING"
echo "如有 NOT FOUND / STOPPED / MISSING，请回退到对应章节重新配置。"
```

---

## 3. 第一阶段：静态分析

### 3.1 快速预扫描（确认工具可用）

```bash
cd ~/Project/mcp-sec-audit/detection
SERENA_SRC=~/Project/mcp-sec-audit/targets/serena/src/serena

# 快速 Markdown 输出
uv run python -m detection.cli "$SERENA_SRC" \
    --pipeline static \
    --format markdown
```

**预期输出**（前 30 行）：

```markdown
# Detection Summary — serena

- Total Score: 104.45
- Risk Level: critical

## Findings
- **command_exec** (0.99) — Ability to spawn shell commands or subprocesses.
- **file_read** (0.99) — Ability to read from the filesystem.
- **file_write** (0.99) — Ability to write files to the filesystem.
- **network_outbound** (0.99) — Ability to perform outbound network requests.
- **network_inbound** (0.55) — Ability to create network listeners or servers.
- **env_access** (0.99) — Ability to read environment variables.
- **Potential network in SerenaAgent._send_usage_info via requests.get** (0.60) ...
- **Potential rce in SerenaAgent._run_project_activation_command via subprocess.Popen** (0.60) ...
...
```

### 3.2 生成 JSON 格式详细报告

```bash
cd ~/Project/mcp-sec-audit/detection
SERENA_SRC=~/Project/mcp-sec-audit/targets/serena/src/serena
OUTPUT_DIR=~/serena-security-test/results
mkdir -p "$OUTPUT_DIR"

# JSON 格式 — 方便程序化处理
uv run python -m detection.cli "$SERENA_SRC" \
    --pipeline static \
    --format json \
    -o "$OUTPUT_DIR/01-static-analysis.json"

echo "静态分析报告已保存到: $OUTPUT_DIR/01-static-analysis.json"
```

### 3.3 分析报告摘要

```bash
cd ~/serena-security-test

python3 << 'PYEOF'
import json
from collections import Counter

with open("results/01-static-analysis.json") as f:
    data = json.load(f)

findings = data["findings"]
print(f"Server:      {data['server']}")
print(f"Risk Level:  {data['risk_level']}")
print(f"Total Score: {data['total_score']:.2f}")
print(f"Findings:    {len(findings)}")
print()

# 按来源分类
legacy = [f for f in findings if f['metadata'].get('category', '') == '']
ast = [f for f in findings if f['metadata'].get('category', '') != '']
print(f"  Legacy plugin detections: {len(legacy)}")
print(f"  AST engine detections:    {len(ast)}")

# 按类别统计
cats = Counter(f['metadata'].get('category', 'unknown') for f in findings)
print(f"\n  Categories:")
for cat, count in cats.most_common():
    print(f"    {cat}: {count}")

# Legacy findings
print(f"\n=== Legacy 插件发现 (能力级别检测) ===")
for f in legacy:
    print(f"  [{f['confidence']:.2f}] {f['name']}")

# AST findings grouped by category
print(f"\n=== AST 引擎发现 (精确调用链) ===")
for cat in ['rce', 'network', 'file']:
    cat_findings = [f for f in ast if f['metadata'].get('category') == cat]
    if cat_findings:
        print(f"\n  --- {cat.upper()} ({len(cat_findings)} 条) ---")
        for f in cat_findings:
            print(f"  [{f['confidence']:.2f}] {f['name']}")
            if f.get('evidence'):
                for e in f['evidence'][:2]:  # 只显示前2条证据
                    print(f"      {e}")
PYEOF
```

### 3.4 静态分析发现分类

运行上述脚本后，你将看到约 28 条发现。下面逐类解读：

#### 🟢 绿区：合法的功能需求（6 条 Legacy 发现）

| 发现 | 置信度 | 解读 |
|------|--------|------|
| `command_exec` | 0.99 | Serena 需要执行 Shell 命令（激活虚拟环境、启动 LSP、运行项目命令） |
| `file_read` | 0.99 | 编码代理必须读取源代码文件 |
| `file_write` | 0.99 | 编码代理必须编辑/写入文件 |
| `network_outbound` | 0.99 | 查询 PyPI、发送遥测数据、下载资源 |
| `network_inbound` | 0.55 | 启动 Flask dashboard 本地服务器 |
| `env_access` | 0.99 | 读取环境变量获取项目配置 |

> 这 6 条 legacy 发现告诉你 **Serena 有能力做这些事**——它们是功能需求，不是漏洞。评分 104.45 中的主要贡献来自这些发现。

#### 🟡 黄区：需要人工审查（4 条 Network + 4 条关键 RCE）

| 发现 | Sink | 审查要点 |
|------|------|----------|
| `SerenaAgent._send_usage_info` | `requests.get` | 遥测数据是否包含敏感信息？端点是否可被劫持？ |
| `ProjectServerClient.__init__` | `requests.get` | 本地 HTTP 通信（localhost），风险较低 |
| `ProjectServerClient.query_project` | `requests.post` | 同上，本地通信 |
| `PyPIPackageInfo.get_latest_version` | `requests.get` | 查询 `https://pypi.org`（固定 API），风险极低 |
| `SerenaAgent._run_project_activation_command` | `subprocess.Popen` | ⚠️ **重点审查** — 用户可配置 activation_command |
| `ModeCommands.create` | `subprocess.run` | ⚠️ **重点审查** — mode 配置文件中的命令 |
| `execute_shell_command` | `subprocess.Popen` | ⚠️ **重点审查** — 通用 Shell 执行工具 |
| `SerenaDashboardTrayManager._open_dashboard` | `subprocess.Popen` | 固定内部命令，风险低 |

#### 🔴 红区：确认误报（8 条）

| 发现 | 实际代码 | 原因 |
|------|----------|------|
| `MemoryManager.__init__` (2条) | `re.compile(r"...")` | Sink 规则将 `re.compile` 匹配为 `compile()` 代码注入 |
| `<module>` | `re.compile(r"...")` | 同上 |
| `search_files.process_single_file` | `re.compile(r"...")` | 同上 |
| `GlobMatcher.__init__` | `re.compile(r"...")` | 同上 |
| `MultiFileContentReplacer` (2条) | `re.compile(r"...")` | 同上 |
| `find_text_coordinates` | `re.compile(r"...")` | 同上 |

> 共计 8 条 `re.compile` 误报，占 AST RCE 发现的 44%。人工审查时直接排除。

### 3.5 对单个关键文件做精细分析

```bash
cd ~/Project/mcp-sec-audit/detection

# 分析 agent.py (核心文件, 1477 行)
uv run python -m detection.cli \
    ~/Project/mcp-sec-audit/targets/serena/src/serena/agent.py \
    --pipeline static \
    --format markdown

# 分析 mcp.py (MCP 入口, 423 行)
uv run python -m detection.cli \
    ~/Project/mcp-sec-audit/targets/serena/src/serena/mcp.py \
    --pipeline static \
    --format markdown
```

### 3.6 排除测试目录的精确分析

```bash
cd ~/Project/mcp-sec-audit/detection

# 只分析非测试、非 solidlsp 的核心代码
for f in ~/Project/mcp-sec-audit/targets/serena/src/serena/*.py; do
    filename=$(basename "$f")
    echo "=== $filename ==="
    uv run python -m detection.cli "$f" \
        --pipeline static \
        --format json 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); \
            print(f'  {d[\"risk_level\"]} (score={d[\"total_score\"]:.1f}, findings={len(d[\"findings\"])})')"
done
```

---

## 4. 第二阶段：动态分析准备

动态分析通过 Docker 沙箱 + eBPF 内核监控在隔离环境中**真实运行** Serena 的 MCP 服务器，观察其实际行为。

### 4.1 理解动态分析流程

```
                        ┌─────────────────────────────────┐
                        │   Serena 源代码                   │
                        │   src/serena/mcp.py              │
                        │   (FastMCP stdio transport)       │
                        └──────────────┬──────────────────┘
                                       │
                        ┌──────────────▼──────────────────┐
                        │   setup.sh                       │
                        │   安装 pip 依赖                   │
                        │   (mcp, flask, solidlsp, etc.)    │
                        └──────────────┬──────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │              Docker Container (--privileged)     │
              │                                                 │
              │  ┌──────────────────────────────────────────┐   │
              │  │  entrypoint.sh                            │   │
              │  │  1. 创建 cgroup /sys/fs/cgroup/mcp-target │   │
              │  │  2. 计算 cgroup inode ID                 │   │
              │  │  3. 运行 /target/setup.sh (安装依赖)      │   │
              │  │  4. 启动 eBPF Monitor (后台)             │   │
              │  │  5. 启动 Fuzzer → MCP handshake → fuzz   │   │
              │  └──────────────────────────────────────────┘   │
              │                    │                             │
              │     ┌──────────────┼──────────────┐              │
              │     │              │              │              │
              │  ┌──▼──┐    ┌─────▼─────┐  ┌────▼────┐         │
              │  │eBPF │    │  Fuzzer   │  │ Serena  │         │
              │  │7探针│    │ JSON-RPC  │  │ MCP Srv │         │
              │  │内核 │    │  stdio    │  │ Python  │         │
              │  └──┬──┘    └───────────┘  └─────────┘         │
              │     │                                           │
              │     ▼                                           │
              │  CEF Logs → /logs/events.cef                    │
              └─────────────────────────────────────────────────┘
                                       │
                        ┌──────────────▼──────────────────┐
                        │  CEF Parser                       │
                        │  extractors/dynamic.py            │
                        │  → RuntimeEventFact[]             │
                        └──────────────┬──────────────────┘
                                       │
                        ┌──────────────▼──────────────────┐
                        │  DynamicBehaviorAnalyzer          │
                        │  → CapabilityFinding[]            │
                        └──────────────────────────────────┘
```

### 4.2 编写 Serena 专用 setup.sh

由于 Serena 有复杂的 pip 依赖（mcp, flask, solidlsp 等），需要编写 `setup.sh` 来预装依赖：

```bash
cat > ~/serena-security-test/setup.sh << 'SETUP_EOF'
#!/bin/bash
#
# Serena MCP Server — Dynamic Analysis Setup Script
#
# 此脚本在 Docker 沙箱内的 /target 目录执行
# 负责: 安装 Python 依赖，准备 MCP 运行环境
#

set -euo pipefail

echo "[setup] Installing Serena dependencies..."

# 确保 pip 可用
pip3 install --no-cache-dir --upgrade pip 2>/dev/null || true

# 安装 Serena 核心依赖 (从 pyproject.toml 提取)
# 注意: solidlsp 是本地包，需要从 src/ 安装
pip3 install --no-cache-dir \
    "requests==2.33.0" \
    "overrides==7.7.0" \
    "python-dotenv==1.2.2" \
    "mcp==1.28.1" \
    "flask==3.1.3" \
    "pydantic==2.12.5" \
    "pyyaml==6.0.2" \
    "jinja2==3.1.6" \
    "docstring-parser" \
    "pydantic-settings" \
    "sensai-utils" \
    2>&1 | tail -3

# 安装 solidlsp (Serena 内的本地 LSP 库)
if [ -d "/target/src/solidlsp" ]; then
    echo "[setup] Installing solidlsp from local source..."
    pip3 install --no-cache-dir -e /target 2>&1 | tail -5 || {
        echo "[setup] WARNING: solidlsp install failed, continuing anyway..."
    }
fi

# 验证关键包
echo "[setup] Verifying installations..."
python3 -c "import mcp; print(f'  mcp version: {mcp.__version__}')" 2>/dev/null || echo "  mcp: NOT FOUND"
python3 -c "import flask; print(f'  flask version: {flask.__version__}')" 2>/dev/null || echo "  flask: NOT FOUND"
python3 -c "import requests; print(f'  requests version: {requests.__version__}')" 2>/dev/null || echo "  requests: NOT FOUND"

echo "[setup] Complete."
SETUP_EOF

chmod +x ~/serena-security-test/setup.sh
echo "setup.sh 已创建: ~/serena-security-test/setup.sh"
```

### 4.3 准备动态分析目标目录

```bash
# 创建独立的 analysis-target 目录 (包含 setup.sh + Serena 源码)
TARGET_DIR=~/serena-security-test/analysis-target
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"

# 复制整个 Serena 仓库到目标目录
cp -r ~/Project/mcp-sec-audit/targets/serena/* "$TARGET_DIR/"
cp ~/serena-security-test/setup.sh "$TARGET_DIR/"

# 验证
echo "目标目录结构:"
ls "$TARGET_DIR"
echo ""
echo "setup.sh: $(test -f $TARGET_DIR/setup.sh && echo 'OK' || echo 'MISSING')"
echo "mcp.py:   $(test -f $TARGET_DIR/src/serena/mcp.py && echo 'OK' || echo 'MISSING')"
```

### 4.4 构建 Docker 沙箱镜像

```bash
cd ~/Project/mcp-sec-audit/detection/sandbox

# 查看 Dockerfile (确认内容)
cat Dockerfile

# 构建沙箱镜像 (首次构建约 5-8 分钟)
docker build -t mcp-security-sandbox:latest .

# 验证构建
docker images | grep mcp-security-sandbox
# 预期: mcp-security-sandbox   latest   <IMAGE_ID>   ...   ~1.5GB
```

**构建过程关键步骤**：
1. 拉取 `ubuntu:22.04` 基础镜像
2. 安装 BCC/eBPF 工具链 (bpfcc-tools, linux-headers)
3. 安装 Node.js 20.x (用于分析 JS/TS MCP 服务器)
4. 安装 Python 3 及 pip
5. 复制监控脚本 (ebpf_monitor.py, bpf_programs.c, fuzzer.py, entrypoint.sh)

> **如果构建失败**：最常见的问题是网络问题导致 apt 下载失败。重试即可；如果持续失败，可以配置 Docker 使用国内镜像源。

### 4.5 理解 Fuzzer 与 Serena 的交互

Serena 使用 FastMCP stdio transport。Fuzzer (`sandbox/monitors/fuzzer.py`) 的工作流程：

```
1. subprocess.Popen("python3 scripts/mcp_server.py", stdin=PIPE, stdout=PIPE)
2. JSON-RPC initialize request  →  Serena 响应
3. JSON-RPC tools/list request  →  Serena 返回可用工具列表
4. 对每个工具的每个 string 参数，发送测试 payload:
   - 路径遍历: "../../../etc/passwd", "/etc/shadow"
   - 命令注入: "; id", "$(id)", "| id"
   - JS 注入:  "require('child_process').execSync('id')"
5. eBPF 探针在内核层捕获所有系统调用
6. 输出 CEF 格式日志到 /logs/events.cef
```

**Serena 暴露的 MCP 工具**（部分列表）：

| 工具名 | 功能 | 风险参数 |
|--------|------|----------|
| `execute_shell_command` | 执行 Shell 命令 | `command: str` |
| `search_for_pattern` | 正则搜索 | `pattern: str` |
| `find_symbol` | 查找符号 | `name_path: str` |
| `replace_content` | 替换文件内容 | `replacement: str` |
| `read_file` | 读取文件 | `relative_path: str` |
| `write_file` | 写入文件 | `content: str` |
| `activate_project` | 激活项目 | 触发 subprocess.Popen |

---

## 5. 第二阶段：动态分析执行

### 5.1 方式一：CLI 一键执行（推荐）

```bash
cd ~/Project/mcp-sec-audit/detection

uv run python -m detection.cli \
    ~/serena-security-test/analysis-target/ \
    --pipeline dynamic \
    --format json \
    -o ~/serena-security-test/results/02-dynamic-analysis.json
```

**CLI 内部执行流程**：
1. `run_dynamic_pipeline()` 被调用
2. 自动检测执行模式 → 发现 `package.json` 或 MCP 模式 → 返回 `"mcp_fuzz"`
3. 创建 `TriggerPlan` (基于静态分析结果)
4. 初始化 `DockerSandboxProvider`
5. 调用 `sandbox.run()`:
   - 将 `analysis-target/` 复制到临时目录
   - 挂载 Docker volumes: `/target` (源码), `/logs` (CEF 输出), `/monitor` (监控脚本)
   - 启动容器 (`--privileged`, `--pid=host`)
   - `entrypoint.sh` 运行 → 执行 `setup.sh` → 启动 eBPF → Fuzzer fuzz Serena
   - 等待 timeout (默认 30s) 或容器退出
6. 收集 CEF 日志 → `extractors/dynamic.py` 解析为 `RuntimeEventFact`
7. `DynamicBehaviorAnalyzer.analyze()` 生成 `CapabilityFinding`
8. 输出结果

### 5.2 方式二：手动分步执行（调试用）

如果 CLI 方式出错，可以手动分步执行来排查问题：

```bash
# Step 1: 准备目标目录 (与 4.3 相同)
TARGET_DIR=~/serena-security-test/analysis-target

# Step 2: 运行 Docker 容器 (手动控制)
docker run --privileged --rm \
    --pid=host \
    --network=bridge \
    --memory="2g" \
    --pids-limit=512 \
    -v "$TARGET_DIR:/target" \
    -v ~/serena-security-test/logs:/logs \
    -v ~/mcp-sec-audit/detection/sandbox/monitors:/monitor:ro \
    -e MONITOR_TIMEOUT=60 \
    -e MODE=mcp_fuzz \
    mcp-security-sandbox:latest

# Step 3: 查看 CEF 日志
echo "========== CEF Logs =========="
cat ~/serena-security-test/logs/events.cef 2>/dev/null || echo "(No CEF logs generated)"

echo ""
echo "========== Log Summary =========="
grep -c "^CEF:" ~/serena-security-test/logs/events.cef 2>/dev/null || echo "0 CEF events"
```

### 5.3 预期动态分析输出

CLI 执行成功后，JSON 输出示例：

```json
{
  "server": "analysis-target",
  "total_score": 45.0,
  "risk_level": "medium",
  "findings": [
    {
      "name": "command_exec",
      "confidence": 0.90,
      "score_weight": 25.0,
      "sources": ["dynamic"],
      "evidence": [
        "Process execution: python3 -c ...",
        "Command: /usr/bin/python3"
      ]
    },
    {
      "name": "file_write",
      "confidence": 0.78,
      "score_weight": 15.0,
      "sources": ["dynamic"],
      "evidence": [
        "File write: /tmp/serena_test_file",
        "File write: /target/sandbox-workspace/..."
      ]
    }
  ],
  "notes": "=== Dynamic Analysis Telemetry ===\n\nExecution time: 45.23s\n..."
}
```

### 5.4 解读 CEF 日志

```bash
cd ~/serena-security-test

# 查看所有 CEF 事件
cat logs/events.cef | head -50

# 按事件类型统计
echo "=== Event Type Summary ==="
grep "^CEF:" logs/events.cef | awk -F'|' '{print $5}' | sort | uniq -c | sort -rn

# 查看执行的命令
echo ""
echo "=== Executed Commands ==="
grep "PROC_EXEC" logs/events.cef | grep -oP 'dproc=\S+' | sort -u

# 查看访问的文件
echo ""
echo "=== Accessed Files ==="
grep "FILE_" logs/events.cef | grep -oP 'fname=\S+' | sort -u | head -20

# 查看网络连接
echo ""
echo "=== Network Connections ==="
grep "NET_" logs/events.cef | grep -oP 'dst=\S+' | sort -u
```

**CEF 日志格式解析**：

```
CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Suspicious Command Execution|8|
  rt=2025-05-01T12:00:00.000 suser=root sproc=bash spid=1234 outcome=success
  dproc=/usr/bin/python3 command_args=python3 -c "import subprocess; subprocess.run(['ls'])"
  ustack=0x7f3a...|0x7f3a... target_path=/target/src/serena/agent.py
```

| 字段 | 含义 |
|------|------|
| `CEF:0` | CEF 版本 |
| `PROC_EXEC` | 事件类型 (PROC_EXEC / FILE_OPEN / FILE_WRITE / NET_CONNECT 等) |
| `dproc=` | 执行的进程路径 |
| `command_args=` | 命令行参数 |
| `ustack=` | 用户态调用栈 (十六进制地址) |
| `target_path=` | 触发事件的目标源文件 |
| `fname=` | 操作的文件路径 (FILE_* 事件) |
| `dst=` `dpt=` | 网络目的地 IP 和端口 (NET_* 事件) |

---

## 6. 第三阶段：关联分析

### 6.1 什么是关联分析

关联分析将 **静态发现的"潜在"风险**与 **动态观察到的"真实"行为**进行匹配：

```
Static Finding (POTENTIAL):
  "Potential rce via execute_shell_command → subprocess.Popen"
       │                                    │
       │ 同一 Sink？同一文件？同一类别？      │
       │                                    │
       ▼                                    ▼
Dynamic Event (OBSERVED):
  PROC_EXEC: /usr/bin/python3 -c "import subprocess; subprocess.run(['id'])"
       │
       ▼
Correlated Finding (CONFIRMED):
  "RCE via execute_shell_command → subprocess.Popen" 
  confidence: 0.60 → 1.0
  status: POTENTIAL → CONFIRMED
  severity: HIGH → CRITICAL (if ≥2 event categories matched)
```

### 6.2 使用 AST 引擎做关联

```bash
cd ~/Project/mcp-sec-audit/detection

# 方式一：通过 engine.py 直接调用 (支持动静态关联)
uv run python3 << 'PYEOF'
import json
from pathlib import Path
from analysis.engine import run_ast_analysis_with_dynamic

static_json = Path.home() / "serena-security-test/results/01-static-analysis.json"
cef_log = Path.home() / "serena-security-test/logs/events.cef"

if not cef_log.exists():
    print("CEF log not found. Run dynamic analysis first.")
    exit(1)

# 加载静态结果中的 findings
with open(static_json) as f:
    static_data = json.load(f)

# 运行关联分析
correlated = run_ast_analysis_with_dynamic(
    target_root=Path.home() / "serena-security-test/analysis-target",
    dynamic_log=cef_log,
)

print(f"Correlated findings: {len(correlated)}")
for f in correlated:
    status = f.get('status', 'potential')
    confidence = f.get('confidence', 0)
    print(f"  [{status}] {f.get('title', f.get('name', '?'))} (conf={confidence:.2f})")
PYEOF
```

### 6.3 方式二：两阶段自动流水线

```bash
cd ~/Project/mcp-sec-audit/detection

# 两阶段流水线: 先静态 → 如果高风险则自动触发动态 → 合并结果
uv run python -c "
from pathlib import Path
from detection.pipelines.dynamic import run_two_stage_pipeline
from detection.core.registry import DetectorRegistry
import json

registry = DetectorRegistry()
target = Path.home() / 'serena-security-test/analysis-target'
policy_dir = Path('detection/mitigation/policy_templates')

result = run_two_stage_pipeline(
    target_path=target,
    registry=registry,
    policy_dir=policy_dir,
    risk_threshold=50.0,    # 静态评分 ≥ 50 才触发动态
    dynamic_timeout=60,     # 沙箱超时 60 秒
)

# 保存最终结果
output = Path.home() / 'serena-security-test/results/03-correlated-analysis.json'
output.write_text(json.dumps({
    'server': result.server_name,
    'risk_level': result.risk_level,
    'total_score': result.total_score,
    'findings': [
        {
            'name': f.name,
            'confidence': f.confidence,
            'score_weight': f.score_weight,
            'sources': [s.value for s in f.sources],
            'evidence': f.evidence,
        }
        for f in result.findings
    ],
    'notes': result.notes,
}, indent=2, ensure_ascii=False))

print(f'Final report: {output}')
print(f'Risk: {result.risk_level} | Score: {result.total_score:.2f} | Findings: {len(result.findings)}')
"
```

### 6.4 关联分析升级规则

| 匹配级别 | 条件 | 效果 |
|----------|------|------|
| **Exact Match** | ustack 包含 sink 源文件名，或 target_path 与 sink 参数重叠 | POTENTIAL → CONFIRMED, confidence → HIGH |
| **Category Match** | category 匹配（如静态 rce + 动态 PROC_EXEC） | POTENTIAL → CONFIRMED, confidence → MEDIUM |
| **No Match** | 静态发现无对应运行时事件 | 保持 POTENTIAL |
| **Multi-Category** | ≥2 种不同事件类型匹配 | Severity 自动升级一级 |

---

## 7. 综合安全报告解读

### 7.1 生成最终报告

```bash
cd ~/serena-security-test

python3 << 'PYEOF'
import json
from pathlib import Path

# 加载三个阶段的报告
results = {}
for phase in ['01-static-analysis', '02-dynamic-analysis', '03-correlated-analysis']:
    path = Path(f'results/{phase}.json')
    if path.exists():
        with open(path) as f:
            results[phase] = json.load(f)

print("=" * 70)
print("  SERENA 安全审计最终报告")
print("=" * 70)
print(f"  目标: oraios/serena (27K+ stars)")
print(f"  分析时间: 2026-08")
print()

for phase, data in results.items():
    findings = data.get('findings', [])
    print(f"  [{phase}]")
    print(f"    Risk: {data['risk_level']:10s} | Score: {data['total_score']:7.2f} | Findings: {len(findings)}")
print()

# 综合风险矩阵
print("  ╔══════════════════════════════════════════════════════════╗")
print("  ║  综合风险矩阵                                              ║")
print("  ╠══════════════════╦══════════╦══════════╦═════════════════╣")
print("  ║  类别             ║ 静态     ║ 动态     ║ 评估            ║")
print("  ╠══════════════════╬══════════╬══════════╬═════════════════╣")
print("  ║  命令执行 (RCE)   ║ 18 条    ║ 待确认   ║ ⚠️ 需审查       ║")
print("  ║  文件操作         ║ 0 条*    ║ 待确认   ║ 🟢 功能需求     ║")
print("  ║  网络请求         ║ 4 条     ║ 待确认   ║ 🟡 多数合理     ║")
print("  ║  环境变量访问     ║ 1 条     ║ 待确认   ║ 🟢 配置需要     ║")
print("  ║  能力级 (legacy)  ║ 6 条     ║ 待确认   ║ 🟢 核心功能     ║")
print("  ╚══════════════════╩══════════╩══════════╩═════════════════╝")
print()
print("  * 文件操作发现全部来自 legacy 插件 (file_read, file_write)")
print()

# 高风险发现详情
print("  ╔══════════════════════════════════════════════════════════╗")
print("  ║  TOP 5 高危发现 (需优先审查)                              ║")
print("  ╚══════════════════════════════════════════════════════════╝")
print()
print("  1. execute_shell_command → subprocess.Popen")
print("     ▸ 用户通过 MCP 工具直接控制 shell 命令")
print("     ▸ 建议: 实现命令白名单 + 参数沙箱化")
print()
print("  2. ModeCommands.create → subprocess.run")
print("     ▸ mode 配置文件中的命令被直接执行")
print("     ▸ 建议: 验证 mode 配置文件来源，限制可执行命令")
print()
print("  3. _run_project_activation_command → subprocess.Popen")
print("     ▸ 项目级 activation_command 可被恶意配置篡改")
print("     ▸ 建议: 在执行前对 activation_command 做安全校验")
print()
print("  4. _send_usage_info → requests.get")
print("     ▸ 遥测端点固定但可能泄露项目路径信息")
print("     ▸ 建议: 审查遥测数据内容，确保不包含敏感路径")
print()
print("  5. SerenaDashboardTrayManager → subprocess.Popen")
print("     ▸ 启动本地 dashboard，命令路径固定, 风险低")
print("     ▸ 建议: 使用绝对路径而非相对路径")

print()
print("  ╔══════════════════════════════════════════════════════════╗")
print("  ║  误报排除                                                 ║")
print("  ╚══════════════════════════════════════════════════════════╝")
print()
print("  已排除 8 条 re.compile() → RCE 误报 (44% of AST RCE findings)")
print("  建议: 在审查时搜索 're.compile' 并批量标记为误报")
print()
print("=" * 70)
PYEOF
```

### 7.2 Serena 安全态势总结

#### 整体评估: ⚠️ MEDIUM-HIGH 风险

Serena 的风险**来源于其功能本质**而非代码缺陷。作为一个 AI 编码代理,它必须具备执行命令、读写文件、访问网络的能力。

#### 真正的安全关注点

| 严重度 | 关注点 | 问题 |
|:---:|--------|------|
| 🔴 高 | `execute_shell_command` MCP 工具 | 任何能调用此工具的 AI 助手都可以在宿主机执行任意 Shell 命令 |
| 🔴 高 | `ModeCommands.create` | mode 配置文件中的命令可能被供应链攻击注入 |
| 🟡 中 | `_run_project_activation_command` | 项目根目录的 `.venv` 激活脚本可能被篡改 |
| 🟡 中 | 遥测数据 (`_send_usage_info`) | 可能泄露项目结构、文件路径 |
| 🟢 低 | Dashboard 启动 | 本地通信，攻击面小 |
| 🟢 低 | PyPI 查询 | 查询固定公开 API |

#### 缓解建议

1. **命令执行白名单** — 限制 `execute_shell_command` 只能执行预定义的命令集
2. **Mode 配置签名验证** — 对 mode 配置文件做数字签名，防止篡改
3. **activation_command 沙箱** — 在独立 cgroup 中执行，限制文件系统和网络访问
4. **遥测数据最小化** — 仅发送匿名化的使用统计，不包含路径信息

---

## 8. 清理与还原

```bash
# ---------- 停止并删除所有相关容器 ----------
docker ps -a --filter "ancestor=mcp-security-sandbox:latest" --format '{{.ID}}' \
    | xargs -r docker rm -f

# ---------- 清理分析结果 (如需保留请跳过) ----------
# rm -rf ~/serena-security-test/results/*
# rm -rf ~/serena-security-test/logs/*

# ---------- 清理 Docker 镜像 (释放约 1.5GB) ----------
# docker rmi mcp-security-sandbox:latest

# ---------- 清理临时分析目标目录 ----------
# rm -rf ~/serena-security-test/analysis-target

echo "清理完成。保留的目录:"
ls -la ~/serena-security-test/
```

---

## 9. 附录

### 9.1 快速命令汇总

```bash
############################################################
# 一键执行: Serena 完整安全测试
############################################################

SERENA_SRC=~/Project/mcp-sec-audit/targets/serena/src/serena
RESULTS=~/serena-security-test/results
TARGET=~/serena-security-test/analysis-target
AUDIT=~/mcp-sec-audit/detection
mkdir -p $RESULTS

# --- Phase 1: Static Analysis ---
cd $AUDIT
echo "=== Phase 1: Static Analysis ==="
uv run python -m detection.cli "$SERENA_SRC" \
    --pipeline static --format json \
    -o "$RESULTS/01-static-analysis.json"
echo "Done: $RESULTS/01-static-analysis.json"

# --- Phase 2: Dynamic Analysis (requires Docker) ---
echo ""
echo "=== Phase 2: Dynamic Analysis ==="
uv run python -m detection.cli "$TARGET" \
    --pipeline dynamic --format json \
    -o "$RESULTS/02-dynamic-analysis.json"
echo "Done: $RESULTS/02-dynamic-analysis.json"
echo "CEF logs: ~/serena-security-test/logs/events.cef"

# --- Phase 3: Correlation ---
echo ""
echo "=== Phase 3: Correlation ==="
# See section 6.3 for the two-stage pipeline script
echo "Run the two-stage pipeline script from Section 6.3"

# --- Quick Summary ---
echo ""
echo "=== Quick Summary ==="
python3 -c "
import json
for phase in ['01-static-analysis', '02-dynamic-analysis', '03-correlated-analysis']:
    try:
        with open(f'$RESULTS/{phase}.json') as f:
            d = json.load(f)
        print(f'{phase}: {d[\"risk_level\"]:10s} score={d[\"total_score\"]:6.2f} findings={len(d[\"findings\"])}')
    except FileNotFoundError:
        print(f'{phase}: (not yet run)')
"
```

### 9.2 常见问题排查

| 问题 | 原因 | 解决 |
|------|------|------|
| `No supported files found` | 目标路径不包含 .py/.js/.ts 文件 | 用 `find <path> -name "*.py"` 确认源码位置 |
| `Docker not available` | Docker daemon 未运行 | `sudo systemctl start docker` |
| `Sandbox image not found` | 未构建沙箱镜像 | `cd ~/Project/mcp-sec-audit/detection/sandbox && docker build -t mcp-security-sandbox:latest .` |
| `BPF tracing not available` | 容器未以 `--privileged` 运行 | 确认 docker_provider.py 中 `privileged=True` |
| `cgroup v2 not detected` | 系统使用 cgroup v1 | 检查 `/sys/fs/cgroup/cgroup.controllers` 是否存在 |
| `ModuleNotFoundError: solidlsp` | setup.sh 未成功安装 | 检查 setup.sh 日志，手动 `pip install -e /target` |
| `perf_event_paranoid=2` | 非 root 无法使用 eBPF | `sudo sysctl -w kernel.perf_event_paranoid=1` |
| `Fuzzer timeout` | Serena 启动太慢或 MCP handshake 失败 | 增加 `MONITOR_TIMEOUT` 到 90s |
| `re.compile → RCE 误报` | Sink 规则 bug | 手动过滤: `grep -v "re.compile"` |
| `Total Score 很高但无真实漏洞` | legacy 发现权重过高 | 降低 keywords.toml 中的 weight 值 |

### 9.3 性能基准

| 操作 | 时间 | 备注 |
|------|------|------|
| 克隆 Serena (--depth 1) | ~15s | 约 50MB |
| 静态分析 Serena (28 发现) | ~5s | 纯 CPU，无网络 |
| 构建沙箱镜像 (首次) | 5-8min | 下载 Ubuntu + BCC 依赖 |
| 动态分析 (mcp_fuzz, 60s) | ~90s | 含容器启动 + setup + fuzz |
| 两阶段流水线 (完整) | ~2min | 静态 + 动态 + 关联 |

### 9.4 相关文档

| 文档 | 内容 |
|------|------|
| `docs/STATIC_ANALYSIS_DEEP_DIVE.md` | 静态分析技术深度解读 |
| `docs/DYNAMIC_ANALYSIS_DEEP_DIVE.md` | 动态分析技术深度解读 |
| `docs/REAL_MCP_ANALYSIS_GUIDE.md` | 真实 MCP 仓库分析对比 |
| `detection/sandbox/README.md` | 沙箱使用说明 |
| `detection/README.md` | 检测引擎总览 |
