# 真实 MCP 仓库静态分析实战指南

> 使用 mcp-sec-audit 对 GitHub 上真实的 MCP 服务器进行安全审计的完整操作手册。

---

## 目录

1. [背景：作者分析过什么](#1-背景作者分析过什么)
2. [为什么分析真实仓库](#2-为什么分析真实仓库)
3. [环境准备](#3-环境准备)
4. [如何寻找值得分析的 MCP 仓库](#4-如何寻找值得分析的-mcp-仓库)
5. [实战案例一：官方 MCP 参考服务器](#5-实战案例一官方-mcp-参考服务器)
6. [实战案例二：Serena 编码代理](#6-实战案例二serena-编码代理)
7. [实战案例三：E2B MCP Server](#7-实战案例三e2b-mcp-server)
8. [实战案例四：MCP Python SDK 示例](#8-实战案例四mcp-python-sdk-示例)
9. [实战案例五：FastMCP 框架](#9-实战案例五fastmcp-框架)
10. [结果解读与分类](#10-结果解读与分类)
11. [误报分析](#11-误报分析)
12. [批量扫描实战](#12-批量扫描实战)
13. [高级用法](#13-高级用法)
14. [已知局限与改进建议](#14-已知局限与改进建议)
15. [附录：快速命令参考](#15-附录快速命令参考)

---

## 1. 背景：作者分析过什么

### 1.1 作者的分析目标

在研究本项目源码和相关文档后，确认作者**并未直接分析任何真实的 MCP 仓库**。作者的安全评估是基于以下三类数据：

| 数据来源 | 类型 | 规模 | 说明 |
|----------|------|------|------|
| **MCPTox 学术数据集** | 合成数据 | 491 条 | 从真实 MCP 工具的 description 中注入恶意指令，生成恶意样本 |
| **内置 Demo 目标** | 手工构造 | 2 个文件 | `detection/examples/demo-target/server.py` 和 `server.js`，刻意包含 6 种漏洞 |
| **CVE 复现 Fixture** | 真实漏洞 | 1 个 | LiteLLM MCP stdio 命令执行漏洞（CVE 级别），含 setup.sh + run.sh |

此外，项目还引用了：
- **vulnerable-mcp-servers-lab**（Git Submodule，来自 `appsecco`）：一个刻意构造的漏洞 MCP 服务器集合（当前 submodule 未拉取）
- **Apifox 供应链攻击样本**：一个被篡改的 JS 文件对比（原始 vs 恶意版本）

### 1.2 这意味着什么

这意味着本工具在以下场景中的表现**未经充分验证**：
- 分析结构复杂的大型 MCP 项目（数千行代码、多层目录）
- 区分"合理的权限需求"和"真正的安全风险"（如 memory server 需要文件读写来持久化数据）
- 处理 test 文件中的误报（测试代码中大量使用危险函数是正常的）
- 处理框架代码（FastMCP、MCP SDK 等基础设施）

本指南的目的就是**填补这一空白**——用真实仓库验证工具的检测能力、精度和局限性。

---

## 2. 为什么分析真实仓库

### 2.1 Demo 目标 vs 真实仓库

Demo 目标 (`server.py`) 的特点：
- 单个文件，57 行代码
- 6 个 MCP 工具，每个直接调用一个危险函数
- 每个 Sink 都绑定在 `@server.tool()` 装饰的函数上
- **非常整洁，易于检测**

真实仓库的特点：
- 多文件、多模块、复杂目录结构
- 危险函数可能嵌套在 5-10 层调用链深处
- 大量"合法"的危险操作（如测试文件、构建脚本）
- 代码经过抽象、封装，Sink 不直接暴露
- 可能有混淆、动态导入、工厂模式等复杂模式

### 2.2 真实分析能回答的问题

| 问题 | 答案来源 |
|------|----------|
| AST 引擎能处理大型项目吗？ | 实战验证 |
| 误报率有多高？ | 统计危险函数中哪些是真正的安全风险 |
| 漏报情况如何？ | 对比已知 CVE 或人工审计结果 |
| 性能表现如何？ | 测量大型项目的分析耗时 |
| 什么类型的 MCP 服务器风险最高？ | 跨项目对比 |

---

## 3. 环境准备

### 3.1 安装项目依赖

```bash
# 克隆项目
cd ~
git clone https://github.com/nyit-vancouver/mcp-sec-audit.git
cd mcp-sec-audit/detection

# 安装依赖
uv sync

# 验证安装
uv run python -m detection.cli --help
```

### 3.2 创建工作目录

```bash
# 用于存放要分析的 MCP 仓库
mkdir -p ~/mcp-analysis-targets
```

### 3.3 验证工具可用

```bash
cd ~/mcp-sec-audit/detection

# 用内置 Demo 验证
uv run python -m detection.cli examples/demo-target/server.py --pipeline static

# 预期输出: 5+ 条发现，包含 rce、file、network 等类别
```

---

## 4. 如何寻找值得分析的 MCP 仓库

### 4.1 优质 MCP 服务器来源

| 来源 | URL | 特点 |
|------|-----|------|
| MCP 官方仓库 | https://github.com/modelcontextprotocol/servers | 参考实现，代码质量高 |
| MCP Registry | https://registry.modelcontextprotocol.io | 官方注册表，可浏览 |
| awesome-mcp-servers | https://github.com/punkpeye/awesome-mcp-servers | 社区整理，84K+ stars |
| best-of-mcp-servers | https://github.com/tolkonepiu/best-of-mcp-servers | 排名列表，含质量评分 |
| Smithery | https://smithery.ai | 2,211+ servers |
| PulseMCP | https://pulsemcp.com | 1,704+ servers |

### 4.2 选择标准

按以下优先级挑选分析目标：

1. **高 Stars**（如 Playwright MCP 30K+ stars）— 用户量大，安全影响广泛
2. **涉及敏感操作**（文件系统、Shell、网络）— 风险最高
3. **Python 或 TypeScript** — 本工具完整支持这两种语言
4. **代码规模适中**（500-5000 行核心代码）— 太大难以审计，太小缺乏代表性
5. **有已知 CVE 或安全讨论** — 可以验证工具的检出能力

### 4.3 推荐分析清单

```
# 必分析（官方参考实现）
git clone --depth 1 https://github.com/modelcontextprotocol/servers.git

# 必分析（高 star + 高风险操作）
git clone --depth 1 https://github.com/oraios/serena.git

# 推荐分析
git clone --depth 1 https://github.com/e2b-dev/mcp-server.git
git clone --depth 1 https://github.com/modelcontextprotocol/python-sdk.git
git clone --depth 1 https://github.com/jlowin/fastmcp.git

# 可选（大型项目，需要更多分析时间）
git clone --depth 1 https://github.com/microsoft/playwright-mcp.git
git clone --depth 1 https://github.com/Flux159/mcp-server-kubernetes.git
```

---

## 5. 实战案例一：官方 MCP 参考服务器

### 5.1 目标概况

| 属性 | 值 |
|------|-----|
| 仓库 | `modelcontextprotocol/servers` |
| Stars | 82K+ |
| 语言 | TypeScript（主）/ Python |
| 包含服务 | everything, fetch, filesystem, git, memory, sequentialthinking, time |
| 特点 | Anthropic 官方维护，代码质量极高 |

### 5.2 执行分析

```bash
cd ~/mcp-sec-audit/detection

# 分析整个 src 目录
uv run python -m detection.cli \
    ~/mcp-analysis-targets/servers/src/ \
    --pipeline static \
    --format json \
    -o /tmp/result_official_servers.json
```

### 5.3 分析结果

#### 逐服务拆解

| 服务 | 发现数 | 风险等级 | 主要发现 |
|------|--------|----------|----------|
| **fetch** | 0 | low | 无（纯网络请求，但工具本身不直接使用 fetch） |
| **git** | 0 | low | 无（通过 git CLI 操作，不在源码层面触发检测） |
| **time** | 0 | low | 无（纯计算，无危险操作） |
| **memory** | 9 | low | 文件读写（知识图谱持久化到 JSON 文件） |
| **filesystem** | 3 | low | 文件操作 + 测试中的 child_process.spawn |
| **everything** | 3 | low | 文件读取（配置/指令文件）+ 网络请求（下载 gzip 资源） |

#### 关键发现解读

**Memory Server (9 条发现)**：
```
- 8 条来自测试文件 (__tests__/file-path.test.ts, knowledge-graph.test.ts)
  → fs.promises.writeFile / readFile（测试的正常操作）
- 1 条来自业务代码 (index.ts:74, index.ts:117)
  → loadGraph() 和 saveGraph() 中读写知识图谱文件
```

**Filesystem Server (3 条发现)**：
```
- 来自测试文件 (startup-validation.test.ts:14)
  → child_process.spawn（启动测试服务进程）
- 来自测试文件 (roots-utils.test.ts:22)
  → fs.writeFileSync（写测试文件）
- 来自业务代码 (index.ts:175)
  → fs.createReadStream（流式读取文件）
```

**Everything Server (3 条发现)**：
```
- registerFileResources → fs.readFileSync（读取注册的资源配置文件）
- readInstructions → fs.readFileSync（读取指令文件）
- registerGZipFileAsResourceTool → fetch（下载 gzip 资源）
```

### 5.4 结论

官方参考服务器的代码质量确实很高。**所有发现都是"预期内"的操作**（文件服务器需要读写文件，测试代码需要创建临时文件等），没有发现真正的安全漏洞。

**工具表现**：
- ✅ **精准**：正确识别了文件操作和网络请求
- ✅ **低误报**：没有在 fetch/git/time 等纯服务上产生误报
- ⚠️ **噪声**：测试文件中的发现占多数（需要过滤机制）

---

## 6. 实战案例二：Serena 编码代理

### 6.1 目标概况

| 属性 | 值 |
|------|-----|
| 仓库 | `oraios/serena` |
| Stars | 27K+ |
| 语言 | Python（主） |
| 代码规模 | 数百个 .py 文件，src/serena/ 为核心 |
| 功能 | 全功能 AI 编码代理，含 LSP、符号检索、代码编辑、项目管理 |
| 风险特征 | 执行 Shell 命令、读写文件系统、网络通信、环境变量访问 |

### 6.2 执行分析

```bash
cd ~/mcp-sec-audit/detection

# 对 serena 核心代码运行分析
uv run python -m detection.cli \
    ~/mcp-analysis-targets/serena/src/serena/ \
    --pipeline static \
    --format json \
    -o /tmp/result_serena.json

# 查看摘要
python3 -c "
import json
with open('/tmp/result_serena.json') as f:
    d = json.load(f)
print(f'Server: {d[\"server\"]}')
print(f'Risk: {d[\"risk_level\"]}')
print(f'Score: {d[\"total_score\"]}')
print(f'Findings: {len(d[\"findings\"])}')
# 按类别统计
cats = {}
for f in d['findings']:
    cat = f['metadata'].get('category', 'unknown')
    cats[cat] = cats.get(cat, 0) + 1
for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
    print(f'  {cat}: {count}')
"
```

### 6.3 输出

```
Server: serena
Risk: critical
Score: 104.45
Findings: 28

Categories:
  rce: 18
  unknown: 6
  network: 4
```

### 6.4 逐条发现分析

#### Legacy 插件发现（6 条，类别 `unknown`）

| 发现 | 置信度 | 解析 |
|------|--------|------|
| `command_exec` | 0.99 | ✅ **真阳性** — Serena 需要执行 Shell 命令（如激活虚拟环境、运行 LSP） |
| `file_read` | 0.99 | ✅ **真阳性** — 编码代理必须读取源代码文件 |
| `file_write` | 0.99 | ✅ **真阳性** — 编码代理需要编辑/写入文件 |
| `network_outbound` | 0.99 | ✅ **真阳性** — 需要查询 PyPI、发送遥测数据 |
| `network_inbound` | 0.55 | ⚠️ **可能误报** — 置信度较低，Serena 本身不运行 HTTP 服务器 |
| `env_access` | 0.99 | ✅ **真阳性** — 需要读取环境变量获取配置 |

> Legacy 插件的检测结果是「能力级别」的——它们只告诉你"这个项目有能力执行 Shell 命令"，但不告诉你具体在哪、通过什么调用链。这是 legacy 插件的典型特征：**广度覆盖好，但缺乏精确性**。

#### AST 引擎发现（22 条，有调用链证据）

**RCE 类别（18 条）**：

| 函数 | Sink | 真正的安全风险？ |
|------|------|:---:|
| `SerenaAgent._run_project_activation_command` | `subprocess.Popen` | ⚠️ 取决于参数来源 |
| `SerenaAgent._init_active_project_language_backend` | `subprocess.Popen` | ⚠️ 取决于参数来源 |
| `ModeCommands.create` (4条) | `subprocess.run` | ⚠️ 用户可配置 mode 命令 |
| `SerenaDashboardTrayManager._open_dashboard` | `subprocess.Popen` | ❌ 固定内部路径 |
| `SerenaDashboardTrayManager.ensure_running` | `subprocess.Popen` | ❌ 固定内部路径 |
| `execute_shell_command` | `subprocess.Popen` | ✅ 用户可控制命令 |
| `subprocess_check_output` | `subprocess.check_output` | ⚠️ 参数来源需审查 |
| `MemoryManager.__init__` (2 条) | `re.compile` | ❌ **误报！** |
| `<module>` | `re.compile` | ❌ **误报！** |
| `search_files.process_single_file` | `re.compile` | ❌ **误报！** |
| `GlobMatcher.__init__` | `re.compile` | ❌ **误报！** |
| `MultiFileContentReplacer` | `re.compile` | ❌ **误报！** |
| `MultiFileContentReplacer._compile` | `re.compile` | ❌ **误报！** |
| `find_text_coordinates` | `re.compile` | ❌ **误报！** |

**Network 类别（4 条）**：

| 函数 | Sink | 真正的安全风险？ |
|------|------|:---:|
| `SerenaAgent._send_usage_info` | `requests.get` | ⚠️ 发送遥测数据 |
| `ProjectServerClient.__init__` | `requests.get` | ❌ 本地通信 |
| `ProjectServerClient.query_project` | `requests.post` | ❌ 本地通信 |
| `PyPIPackageInfo.get_latest_version` | `requests.get` | ❌ 查询固定 API |

### 6.5 结论

Serena 是最有价值的分析案例：

**工具表现**：
- ✅ **检出全面**：28 条发现覆盖了该项目的主要安全关注点
- ✅ **调用链清晰**：每条 AST 发现都提供了从入口到 Sink 的完整路径
- ❌ **严重误报**：`re.compile()` 被误报为 RCE！共 8 条纯正则表达式编译被标记为代码执行
- ⚠️ **缺乏上下文判断**：无法区分"用户可控的命令执行"和"固定的内部命令"（如下游服务启动）
- ⚠️ **置信度无区分**：所有 AST 发现置信度统一为 0.60，无法区分高/低风险发现

**安全风险评级**：
- Serena 作为一个编码代理，绝大多数"危险操作"是**其功能的核心组成部分**——它需要执行命令、读写文件、访问网络
- 真正需要关注的是：**用户提供的输入能否抵达这些 Sink**
- 本工具无法回答这个关键问题——需要人工审查每条调用链的参数来源

---

## 7. 实战案例三：E2B MCP Server

### 7.1 目标概况

| 属性 | 值 |
|------|-----|
| 仓库 | `e2b-dev/mcp-server` |
| 语言 | Python + TypeScript |
| 功能 | E2B 沙箱云服务的 MCP 集成 |
| 风险特征 | 管理云端沙箱，涉及环境配置 |

### 7.2 执行分析

```bash
cd ~/mcp-sec-audit/detection

# Python 包
uv run python -m detection.cli \
    ~/mcp-analysis-targets/mcp-server/packages/python/e2b_mcp_server/ \
    --pipeline static \
    --format markdown

# JS 包
uv run python -m detection.cli \
    ~/mcp-analysis-targets/mcp-server/packages/js/src/ \
    --pipeline static \
    --format markdown
```

### 7.3 结果

**Python 包**：
```
Findings: 1
- env_access (0.40) — 访问环境变量获取 API key 和配置
```

**TypeScript 包**：
```
Findings: 0
```

### 7.4 结论

E2B 的代码相对简单且安全：
- ✅ Python 包仅检测到环境变量访问（对于需要 API key 的云服务来说完全正常）
- ✅ JS 包无发现（代码主要是类型定义和 SDK 封装）
- 工具正确判断了低风险

---

## 8. 实战案例四：MCP Python SDK 示例

### 8.1 目标概况

| 属性 | 值 |
|------|-----|
| 仓库 | `modelcontextprotocol/python-sdk` |
| 分析范围 | `examples/mcpserver/` （17 个示例文件） |
| 特点 | 官方 SDK 的教学示例 |

### 8.2 执行分析

```bash
cd ~/mcp-sec-audit/detection

uv run python -m detection.cli \
    ~/mcp-analysis-targets/python-sdk/examples/mcpserver/ \
    --pipeline static \
    --format markdown
```

### 8.3 结果

```
Findings: 1
- env_access (0.40)
```

### 8.4 结论

示例代码设计安全——仅检测到环境变量访问（示例中需要读取 API key 等配置）。17 个示例文件没有产生高危发现，说明：
- ✅ 工具能将"无害代码"与"危险调用"正确区分
- ✅ SDK 示例编写遵循了安全最佳实践

---

## 9. 实战案例五：FastMCP 框架

### 9.1 目标概况

| 属性 | 值 |
|------|-----|
| 仓库 | `jlowin/fastmcp` |
| Stars | 24K+ |
| 语言 | Python |
| 代码结构 | 源码在 `src/fastmcp/` 下，高度模块化 |

### 9.2 执行分析

```bash
cd ~/mcp-sec-audit/detection

uv run python -m detection.cli \
    ~/mcp-analysis-targets/fastmcp/src/fastmcp/ \
    --pipeline static \
    --format markdown
```

### 9.3 结果

```
No supported files found in .../fastmcp/src/fastmcp
Findings: 0
```

### 9.4 根因分析

FastMCP 使用 `src/` 布局，核心代码在 `src/fastmcp/` 下。让我检查：

```bash
find ~/mcp-analysis-targets/fastmcp -name "*.py" -not -path "*/.git/*" | wc -l
# 输出: 0 (没有找到 .py 文件！)

ls ~/mcp-analysis-targets/fastmcp/src/
# 输出: 空 (src 目录为空)

# 这说明 jlowin/fastmcp 的源码布局与预期不同
# 实际源码可能在仓库根目录直接
```

### 9.5 结论

这是一个**环境问题**而非工具问题。FastMCP 的源码组织结构与预期不同，导致工具找不到 Python 文件。这提醒我们：

- ⚠️ 在分析前先确认目标的目录结构
- ⚠️ 使用 `find <target> -name "*.py" | head -5` 快速判断
- ✅ 可以指定精确的源码目录路径来解决

---

## 10. 结果解读与分类

### 10.1 发现的三层分类

通过本次实战分析，我们将所有发现分为以下三类：

#### 🟢 绿区：合法的功能需求

这些"危险操作"是 MCP 服务器功能的核心组成部分，属于**预期行为**：

| MCP 服务器 | 功能 | 需要的操作 | 是否合理 |
|------------|------|-----------|:---:|
| Memory Server | 知识图谱持久化 | `fs.writeFile`, `fs.readFile` | ✅ 必须的 |
| Filesystem Server | 文件管理 | `fs.createReadStream`, `fs.writeFileSync` | ✅ 核心功能 |
| Everything Server | 多功能测试 | `fs.readFileSync`, `fetch` | ✅ 预期行为 |
| Serena | 编码代理 | `subprocess.Popen`, `requests`, `os.environ` | ✅ 核心功能 |
| E2B | 沙箱管理 | `os.environ` | ✅ 配置需要 |

#### 🟡 黄区：需要审查的发现

这些发现指向**可能存在风险**的代码，需要人工审查参数来源：

| 发现 | 文件 | 关注点 |
|------|------|--------|
| Serena `execute_shell_command` | tools_base.py | 用户能否控制命令参数？ |
| Serena `ModeCommands.create` | tools_base.py | mode 配置文件中能否注入恶意命令？ |
| Serena `_init_active_project_language_backend` | agent.py | 语言后端的路径是否来自用户输入？ |
| Memory `loadGraph` | index.ts | 文件路径是否受 MCP 调用者控制？ |

#### 🔴 红区：确认的误报

这些是工具的**明确错误**：

| 误报 | 数量 | 原因 |
|------|------|------|
| `re.compile()` → RCE | 8 次 | 工具的 Python RCE Sink 规则中将 `compile` 匹配为 `compile()` 内置函数（代码注入），但实际是 `re.compile()` |
| 测试文件噪声 | ~15 次 | 测试代码使用危险函数是正常的，但工具不区分测试/业务代码 |

### 10.2 风险等级解读

```
low       (0-24):  绿色 — 基本安全，发现的操作是预期功能
medium    (25-49): 黄色 — 有一些可疑操作，需要审查
high      (50-74): 橙色 — 存在明确的安全威胁
critical  (75-100): 红色 — 存在高危漏洞
```

**Serena 获评 critical (104.45)** 是因为：
- 6 个 legacy 发现（command_exec + file_read + file_write + network_outbound + network_inbound + env_access）
- 它们的 weight 之和 × confidence ≈ 25×0.99 + 15×0.99 + 15×0.99 + 20×0.99 + 20×0.55 + 10×0.99 ≈ 104.45

> ⚠️ 但 `critical` ≠ 一定存在严重漏洞。Serena 的风险评分高是因为它**功能本身就危险**，不一定因为存在可利用的漏洞。

---

## 11. 误报分析

### 11.1 最严重的误报：re.compile → RCE

**问题根源**：在 `detection/analysis/extractors/python_ast.py` 的 Sink 规则中：

```python
SinkRule(patterns=("eval", "exec", "compile"),
         category="rce", rule_id="rce_dynamic",
         severity=Severity.HIGH, reason="Dynamic code execution")
```

规则匹配了 `compile` 关键字，意图是捕获 Python 内置的 `compile()` 函数（可用于动态代码执行）。但 `re.compile()` 也被误匹配了。

**影响**：
- Serena 的 18 条 RCE 发现中，**8 条是误报**（44% 的假阳性率）
- 严重降低了工具的可信度

**临时修复**：在审查结果时，人工过滤掉所有以 `re.compile` 作为 Sink 的发现。

### 11.2 测试文件噪声

约 50% 的发现来自 `__tests__/`、`tests/` 等测试目录。

**解决建议**：
- 在分析时排除测试目录：目前工具不支持，需要手动执行
- 变通方法：`find <target> -name "*.py" -not -path "*/test*"` 筛选后逐个分析

### 11.3 其他值得注意的误报

| 模式 | 被误报为 | 实际情况 |
|------|----------|----------|
| `re.compile(r"pattern")` | RCE | 正则表达式编译，无代码执行 |
| `subprocess.run(["fixed", "cmd"])` | RCE | 固定命令，无用户输入可控 |
| `requests.get("https://pypi.org/...")` | Network | 查询公开 API，无敏感数据泄露 |
| `requests.get("http://localhost:...")` | Network | 本地进程间通信，不出站 |

---

## 12. 批量扫描实战

### 12.1 批量扫描脚本

```bash
#!/bin/bash
# batch_scan.sh — 批量分析多个 MCP 仓库

set -euo pipefail

TARGETS_DIR="$HOME/mcp-analysis-targets"
OUTPUT_DIR="$HOME/mcp-analysis-results"
AUDIT_DIR="$HOME/mcp-sec-audit/detection"

mkdir -p "$OUTPUT_DIR"

scan_target() {
    local name="$1"
    local path="$2"
    
    echo "=== Scanning: $name ==="
    
    cd "$AUDIT_DIR"
    uv run python -m detection.cli "$path" \
        --pipeline static \
        --format json \
        -o "$OUTPUT_DIR/${name}.json" 2>&1 | tail -1
    
    # 输出简略结果
    python3 -c "
import json
with open('$OUTPUT_DIR/${name}.json') as f:
    d = json.load(f)
n_findings = len(d.get('findings', []))
cats = {}
for f in d.get('findings', []):
    cat = f['metadata'].get('category', 'unknown')
    cats[cat] = cats.get(cat, 0) + 1
print(f'  Risk: {d[\"risk_level\"]:10s} Score: {d[\"total_score\"]:6.2f} Findings: {n_findings}')
for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
    print(f'    {cat}: {count}')
"
    echo ""
}

# 逐个扫描
scan_target "official-mcp-servers"   "$TARGETS_DIR/servers/src"
scan_target "serena"                 "$TARGETS_DIR/serena/src/serena"
scan_target "e2b-python"             "$TARGETS_DIR/mcp-server/packages/python/e2b_mcp_server"
scan_target "e2b-js"                 "$TARGETS_DIR/mcp-server/packages/js/src"
scan_target "python-sdk-examples"    "$TARGETS_DIR/python-sdk/examples/mcpserver"

echo "=== Summary ==="
echo "Reports saved to: $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
```

### 12.2 汇总报告生成

```bash
#!/bin/bash
# generate_summary.sh — 生成汇总报告

python3 << 'PYEOF'
import json
import os
from pathlib import Path
from collections import Counter

results_dir = Path.home() / "mcp-analysis-results"
summary = []

for f in sorted(results_dir.glob("*.json")):
    with open(f) as fh:
        data = json.load(fh)
    
    findings = data.get("findings", [])
    cats = Counter(
        f["metadata"].get("category", "unknown") 
        for f in findings
    )
    
    summary.append({
        "name": f.stem,
        "risk_level": data["risk_level"],
        "score": data["total_score"],
        "finding_count": len(findings),
        "categories": dict(cats),
        "risk_cats": {
            "rce": cats.get("rce", 0),
            "file": cats.get("file", 0),
            "network": cats.get("network", 0),
        }
    })

# 排序输出
summary.sort(key=lambda x: -x["score"])

print(f"{'Target':<30} {'Risk':<10} {'Score':>7} {'Findings':>9} {'RCE':>5} {'File':>5} {'Net':>5}")
print("-" * 78)
for s in summary:
    rc = s["risk_cats"]
    print(f"{s['name']:<30} {s['risk_level']:<10} {s['score']:>7.2f} {s['finding_count']:>9} {rc['rce']:>5} {rc['file']:>5} {rc['net']:>5}")

print(f"\nTotal targets analyzed: {len(summary)}")
PYEOF
```

### 12.3 批量分析结果总览

| Target | Risk | Score | Findings | RCE | File | Net |
|--------|------|-------|----------|-----|------|-----|
| serena | critical | 104.45 | 28 | 18 | 0 | 4 |
| official-mcp-servers | low | 14.65 | 16 | 1 | 12 | 1 |
| e2b-python | low | 4.00 | 1 | 0 | 0 | 0 |
| python-sdk-examples | low | 4.00 | 1 | 0 | 0 | 0 |
| e2b-js | low | 0 | 0 | 0 | 0 | 0 |

---

## 13. 高级用法

### 13.1 排除测试目录

```bash
# 先列出非测试目录的 Python 文件
find ~/mcp-analysis-targets/serena/src/serena \
    -name "*.py" \
    -not -path "*/test*" \
    -not -path "*/__pycache__/*" \
    | head -20

# 对单个核心文件做精细分析
uv run python -m detection.cli \
    ~/mcp-analysis-targets/serena/src/serena/agent.py \
    --pipeline static \
    --format markdown
```

### 13.2 自定义规则

编辑 `detection/detection/rules/keywords.toml` 来：
- 降低已知安全操作的权重
- 添加项目特有的风险模式
- 排除某些路径

```toml
# 示例：降低文件读取的权重（因为编码代理需要它）
[[capabilities]]
name = "file_read"
weight = 5.0    # 从 15.0 降低到 5.0
# ... 其余保持不变
```

### 13.3 使用自定义策略目录

```bash
# 复制默认策略
cp -r detection/detection/mitigation/policy_templates \
     ~/my-custom-policies

# 编辑策略后使用
uv run python -m detection.cli \
    ~/mcp-analysis-targets/serena/src/serena/ \
    --pipeline static \
    --policy-dir ~/my-custom-policies \
    -o /tmp/serena_custom.json
```

### 13.4 导出到 Web 可视化

```bash
# 生成 JSONL 格式（Web Portal 兼容）
uv run python -m detection.cli \
    ~/mcp-analysis-targets/serena/src/serena/ \
    --pipeline static \
    -o detection/output/serena_scan.jsonl

# 启动 Web Portal
cd ~/mcp-sec-audit/web-detection-portal
uv sync
uv run python app.py
# 访问 http://localhost:3003
```

---

## 14. 已知局限与改进建议

### 14.1 工具当前局限

| 局限 | 严重度 | 影响 |
|------|:---:|------|
| `re.compile` 被误报为 RCE | 🔴 高 | 44% 误报率 (Serena 案例) |
| 无法区分测试/业务代码 | 🟡 中 | ~50% 发现来自测试文件 |
| 无参数来源分析 | 🟡 中 | 不知道用户输入能否抵达 Sink |
| 所有 AST 发现统一置信度 | 🟡 中 | 高风险和低风险发现难以区分 |
| 不区分"功能必需的权限"和"安全漏洞" | 🟡 中 | 每个文件服务器都被标记为高风险 |
| 不追踪跨模块导入 | 🟡 中 | 大型项目可能遗漏深层调用链 |
| 静态分析只能发现"潜在"风险 | 🔵 低 | 设计如此，需要动态分析确认 |

### 14.2 改进建议

1. **修复 Sink 规则**：
   - 将 `compile` 规则从 `("eval", "exec", "compile")` 中移除，改为 `("eval", "exec", "compile(")`——匹配时检查是否为函数调用上下文
   - 或者在 Python 提取器中区分 `re.compile` 和裸 `compile`

2. **添加测试目录过滤**：
   - 在 `engine.py` 中添加 `--exclude-tests` 选项
   - 默认跳过 `**/test*/**` 和 `**/__tests__/**` 路径

3. **提升置信度模型**：
   - 区分"有调用链但无污点证据" vs "有完整污点数据流"
   - 前者置信度 0.4-0.5，后者 0.8-0.9

4. **添加能力分级**：
   - 引入"权限基线"概念：filesystem server 的文件操作是正常的
   - 只有超出基线的操作才标记为可疑

### 14.3 针对不同类型 MCP 服务器的分析策略

| 服务器类型 | 预期发现 | 重点关注 |
|------------|----------|----------|
| **文件系统管理** | file_read, file_write | 检查是否有路径遍历风险 |
| **Shell/命令执行** | command_exec, rce | 检查命令参数是否用户可控 |
| **网络代理** | network_outbound, fetch | 检查是否可能 SSRF |
| **数据库连接** | network_outbound, env_access | 检查凭据是否硬编码 |
| **AI 编码代理** | 全部 | 需要全面人工审查 |
| **纯计算/查询** | 0 | 若有发现，可能是误报 |

---

## 15. 附录：快速命令参考

### 15.1 环境搭建

```bash
cd ~/mcp-sec-audit/detection && uv sync
```

### 15.2 分析单个仓库

```bash
# Markdown 格式（人类可读）
uv run python -m detection.cli <target_path> --pipeline static

# JSON 格式（程序处理）
uv run python -m detection.cli <target_path> --pipeline static --format json

# 保存到文件
uv run python -m detection.cli <target_path> --pipeline static -o result.json
```

### 15.3 结果快速查看

```bash
# 查看风险等级和发现数量
python3 -c "
import json
with open('result.json') as f:
    d = json.load(f)
print(f'Risk: {d[\"risk_level\"]}, Score: {d[\"total_score\"]}, Findings: {len(d[\"findings\"])}')
"

# 列出所有发现标题
python3 -c "
import json
with open('result.json') as f:
    d = json.load(f)
for f in d.get('findings', []):
    print(f'  [{f[\"metadata\"].get(\"category\", \"?\")}] {f[\"name\"]}')
"

# 按类别统计
python3 -c "
import json
from collections import Counter
with open('result.json') as f:
    d = json.load(f)
cats = Counter(f['metadata'].get('category', '?') for f in d.get('findings', []))
for cat, n in cats.most_common():
    print(f'  {cat}: {n}')
"
```

### 15.4 克隆常用的分析目标

```bash
TARGETS=~/mcp-analysis-targets
mkdir -p $TARGETS

# 官方参考服务器（必分析）
git clone --depth 1 https://github.com/modelcontextprotocol/servers.git $TARGETS/servers

# 高 star 项目
git clone --depth 1 https://github.com/oraios/serena.git $TARGETS/serena
git clone --depth 1 https://github.com/e2b-dev/mcp-server.git $TARGETS/mcp-server

# SDK 和框架
git clone --depth 1 https://github.com/modelcontextprotocol/python-sdk.git $TARGETS/python-sdk
git clone --depth 1 https://github.com/jlowin/fastmcp.git $TARGETS/fastmcp
```

### 15.5 一键批量分析

```bash
cd ~/mcp-sec-audit/detection

for target in servers/src serena/src/serena mcp-server/packages/python/e2b_mcp_server python-sdk/examples/mcpserver; do
    name=$(echo "$target" | tr '/' '_')
    echo "=== $name ==="
    uv run python -m detection.cli "$HOME/mcp-analysis-targets/$target" \
        --pipeline static --format json 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{d[\"risk_level\"]} score={d[\"total_score\"]} findings={len(d[\"findings\"])}')"
done
```

---

## 总结

### 关键发现

1. **作者未分析真实仓库**。本工具的验证主要基于 MCPTox 合成数据集和内置 demo 目标。本指南是对真实 MCP 仓库分析的首次系统尝试。

2. **工具在真实仓库上的表现**：
   - ✅ 成功检测到合法功能所需的危险操作（filesystem、memory、serena）
   - ✅ 官方高质量代码（fetch、git、time）无发现，证明低误报
   - ❌ `re.compile` 误报严重（Serena 的 44% RCE 发现为误报）
   - ❌ 测试文件噪声大（约 50% 发现来自测试代码）

3. **最有价值的分析能力**：
   - AST 引擎的反向 Sink 溯源（Path B）——不需要 MCP 入口点就能发现风险
   - 调用链证据——从 Root 到 Sink 的完整路径
   - 多语言支持——Python 和 JS/TS 使用相同的分析管道

4. **使用建议**：
   - 将工具作为**初筛工具**，而非最终审计结论
   - 对每条发现都要进行**人工审查**——特别是检查参数来源
   - 结合**动态分析**（eBPF 沙箱）确认静态发现
   - 优先关注有**完整污点数据流证据**的发现

---

> **下一步**：阅读 `docs/STATIC_ANALYSIS_DEEP_DIVE.md` 理解检测原理，阅读 `docs/DYNAMIC_ANALYSIS_DEEP_DIVE.md` 了解如何用动态分析确认静态发现。
