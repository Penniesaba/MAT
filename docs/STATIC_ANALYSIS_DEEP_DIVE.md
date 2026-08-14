# MCP-Sec-Audit 静态分析技术深度解读

> 本文档面向源码漏洞挖掘初学者，从底层原理开始，逐层深入讲解本项目的静态分析子系统。

---

## 目录

1. [项目概览](#1-项目概览)
2. [目录结构与各文件职责](#2-目录结构与各文件职责)
3. [静态分析架构总览](#3-静态分析架构总览)
4. [核心概念与专业名词解释](#4-核心概念与专业名词解释)
5. [数据模型层 — Fact Schema](#5-数据模型层--fact-schema)
6. [事实存储层 — Fact Store](#6-事实存储层--fact-store)
7. [事实ID生成层](#7-事实id生成层)
8. [提取层 — 从源代码到安全事实](#8-提取层--从源代码到安全事实)
    - [8.1 Python AST 提取器](#81-python-ast-提取器)
    - [8.2 JS/TS Tree-sitter 提取器](#82-jsts-tree-sitter-提取器)
9. [分析Pass层 — 从事实到漏洞结论](#9-分析pass层--从事实到漏洞结论)
    - [9.1 调用图构建 (Call Graph)](#91-调用图构建-call-graph)
    - [9.2 可达性分析 (Reachability)](#92-可达性分析-reachability)
    - [9.3 Taint-Lite 数据流分析](#93-taint-lite-数据流分析)
    - [9.4 反向Sink溯源 (Reverse Sink Trace)](#94-反向sink溯源-reverse-sink-trace)
    - [9.5 漏洞构建器 (Finding Builder)](#95-漏洞构建器-finding-builder)
    - [9.6 动态关联分析 (Dynamic Correlation)](#96-动态关联分析-dynamic-correlation)
10. [适配层 — FindingFact → CapabilityFinding](#10-适配层--findingfact--capabilityfinding)
11. [传统插件系统](#11-传统插件系统)
12. [端到端完整流程](#12-端到端完整流程)
13. [Sink规则与检测逻辑详解](#13-sink规则与检测逻辑详解)
14. [总结](#14-总结)

---

## 1. 项目概览

本项目（mcp-sec-audit）是一个 **MCP (Model Context Protocol) 服务器的安全审计工具**。它的核心功能是：

- **输入**：一个 MCP 服务器的源代码仓库（Python 或 JavaScript/TypeScript）
- **输出**：一份安全检测报告，包含发现的安全风险、风险等级、缓解建议

检测手段分为三类流水线（pipeline）：

| 流水线 | 说明 |
|--------|------|
| `static` | **静态分析**（本文重点） — 不运行代码，直接分析源代码 |
| `dynamic` | 动态分析 — 在沙箱中运行代码，用 eBPF 监控系统调用 |
| `rag` | RAG 增强分析 — 结合知识库做语义级检测 |

---

## 2. 目录结构与各文件职责

```
mcp-sec-audit/
├── detection/                          # 核心检测引擎
│   ├── pyproject.toml                  # Python项目配置
│   │
│   ├── detection/                      # 检测框架主包
│   │   ├── cli.py                      # 命令行入口，解析参数，调度各流水线
│   │   ├── __init__.py
│   │   │
│   │   ├── core/                       # 核心基础设施
│   │   │   ├── models.py               # 通用数据模型 (CapabilityFinding, DetectionResult)
│   │   │   ├── registry.py             # 检测器注册表 (插件式架构)
│   │   │   └── session.py              # 检测会话上下文
│   │   │
│   │   ├── pipelines/                  # 三大流水线调度器
│   │   │   ├── static.py               # ★ 静态分析流水线入口
│   │   │   ├── dynamic.py              # 动态分析流水线
│   │   │   └── rag.py                  # RAG增强流水线
│   │   │
│   │   ├── rules/                      # 规则系统
│   │   │   ├── loader.py               # TOML规则文件加载器
│   │   │   └── keywords.toml           # ★ 检测规则定义 (TOML格式)
│   │   │
│   │   ├── plugins/                    # 传统插件检测器
│   │   │   └── static/
│   │   │       ├── python/__init__.py  # ★ Python关键词/正则检测插件
│   │   │       ├── metadata/__init__.py
│   │   │       └── typescript/__init__.py
│   │   │
│   │   ├── mitigation/                 # 缓解建议引擎
│   │   ├── reporting/                  # 报告生成
│   │   └── knowledge/                  # RAG知识库服务
│   │
│   ├── analysis/                       # ★★★ 静态分析核心引擎（AST分析）★★★
│   │   ├── engine.py                   # ★ AST分析引擎入口 & 分析流水线调度
│   │   │
│   │   ├── facts/                      # 安全事实数据层
│   │   │   ├── schema.py               # ★ 所有事实的数据类定义 (Fact, SinkFact...)
│   │   │   ├── store.py                # 事实的内存存储 (FactStore)
│   │   │   ├── ids.py                  # 事实ID生成 (全局唯一标识)
│   │   │   └── serialization.py        # 事实的序列化/反序列化
│   │   │
│   │   ├── extractors/                 # 事实提取器（解析源代码→事实）
│   │   │   ├── python_ast.py           # ★ Python AST提取器
│   │   │   ├── javascript_ts_tree_sitter.py  # ★ JS/TS Tree-sitter提取器
│   │   │   └── dynamic.py              # CEF动态日志解析器
│   │   │
│   │   ├── passes/                     # 分析Pass（对事实做计算分析）
│   │   │   ├── call_graph.py           # ★ 调用图构建 + 可达性分析
│   │   │   ├── taint_lite.py           # ★ 轻量级污点数据流分析
│   │   │   ├── reverse_sink_trace.py   # ★ 反向Sink溯源（无入口点时的兜底策略）
│   │   │   ├── finding_builder.py      # ★ 从分析结果构建FindingFact
│   │   │   └── dynamic_correlation.py  # 动静态关联分析
│   │   │
│   │   └── adapters/                   # 适配层
│   │       └── finding_adapter.py      # ★ FindingFact → CapabilityFinding 转换
│   │
│   ├── sandbox/                        # 沙箱（动态分析用）
│   ├── tests/                          # 测试
│   └── examples/                       # 示例
│
├── web-detection-portal/               # Web检测结果展示前端
└── docs/                               # 文档
```

> ★ 标记的是静态分析的核心文件，理解这些文件就能掌握整个静态分析系统的运作原理。

---

## 3. 静态分析架构总览

静态分析流水线采用 **"双轨并行"** 架构：传统插件系统（legacy detectors）和新 AST 分析引擎（shadow mode）同时运行。

```
                        ┌─────────────────────────┐
                        │   CLI (cli.py)           │
                        │   --pipeline static      │
                        └───────────┬─────────────┘
                                    │
                        ┌───────────▼─────────────┐
                        │  static.py               │
                        │  run_static_pipeline()    │
                        └───────────┬─────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │                               │
        ┌───────────▼──────────┐     ┌──────────────▼──────────────┐
        │ 传统插件检测器         │     │  AST 分析引擎 (shadow mode)  │
        │ (keywords.toml规则)   │     │  engine.py::run_ast_analysis │
        │                       │     │                              │
        │ Python关键词扫描       │     │  提取层  →  分析Pass  →  适配层│
        │ Metadata关键词扫描     │     │                              │
        └───────────┬──────────┘     └──────────────┬──────────────┘
                    │                               │
                    └───────────────┬───────────────┘
                                    │
                        ┌───────────▼─────────────┐
                        │  综合评分 + 缓解建议      │
                        │  DetectionResult         │
                        └─────────────────────────┘
```

**AST 分析引擎内部流水线**（核心）：

```
源代码文件 (*.py, *.js, *.ts)
    │
    ▼
┌──────────────────────────────────────────────┐
│  Phase 1: 提取 (Extraction)                   │
│  python_ast.py / javascript_ts_tree_sitter.py │
│  产出: FunctionFact, ImportFact, CallFact,    │
│         EntryPointFact, SinkFact, SourceFact  │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Phase 2: 调用图构建 (Call Graph)             │
│  call_graph.py::build_call_graph()            │
│  产出: CallGraph (函数间调用关系图)            │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Phase 3: 可达性 + 数据流分析                 │
│  ├─ Path A (正向): 入口→Sink可达性 + 污点分析 │
│  └─ Path B (反向): Sink→根函数溯源            │
│  产出: FindingFact[]                          │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Phase 4: 适配输出                            │
│  finding_adapter.py                           │
│  FindingFact → CapabilityFinding              │
└──────────────────────────────────────────────┘
```

---

## 4. 核心概念与专业名词解释

在深入代码之前，先理解以下所有专业术语（从底层原理讲起）：

### 4.1 AST (Abstract Syntax Tree, 抽象语法树)

**底层原理**：当你写下一段代码比如 `x = 1 + 2`，计算机不能直接理解这段文本。编译器/解释器的第一步就是把文本转换成树状结构：

```
       Assign
       /    \
    Name(x)  BinOp(+)
             /      \
        Constant(1) Constant(2)
```

**为什么安全分析要用 AST？**
- 纯文本搜索 `eval(` 会匹配到注释、字符串中的 `"eval("`，产生误报
- AST 能精确区分：这是真正的函数调用，还是字符串里的文字？
- 能获取结构化信息：谁是调用者？参数是什么？在第几行？

Python 用标准库 `ast` 模块解析 Python 代码，JS/TS 用 `tree-sitter` 库解析。

### 4.2 Sink (汇点/危险函数)

**定义**：程序中可能产生安全风险的函数调用点。

**为什么叫 Sink？** 在数据流分析中，数据从 Source（源，如用户输入）流向 Sink（汇，如命令执行函数）。如果不受信任的数据（污点数据）到达了 Sink，就产生了安全漏洞。

**本项目中的 Sink 举例**：
- `subprocess.run()` / `os.system()` — 命令注入（RCE）
- `eval()` / `exec()` — 代码注入
- `open()` — 文件访问
- `requests.get()` — 网络请求

### 4.3 Source (源点/不受信任输入)

**定义**：程序中接受外部不可信数据的位置。

在本项目的 MCP 上下文中，MCP Tool 的函数参数是 Source——因为调用方（可能是恶意用户）完全控制传入的参数值。

### 4.4 EntryPoint (入口点)

**定义**：对外暴露的可被外部调用的函数。

在本项目的 MCP 上下文中，被 `@mcp.tool()` 或 `server.tool()` 等装饰器标记的函数就是入口点。

### 4.5 Fact (安全事实)

**定义**：从代码中提取的原子级安全相关信息片段。每个 Fact 是不可分割的最小分析单元。

本项目定义了多种 Fact 类型（详见第5节），核心思想是：**把代码分析转化为对结构化数据的查询和计算**。

### 4.6 Call Graph (调用图)

**定义**：一张有向图，节点是函数，边是调用关系（A → B 表示 A 调用了 B）。

**底层原理**：静态分析无法真正执行代码，所以需要"猜测"函数调用关系。通过对所有 `CallFact` 建立索引，构建出一个图结构。

### 4.7 Reachability Analysis (可达性分析)

**定义**：判断从入口点（EntryPoint）是否存在一条调用路径到达危险函数（Sink）。

**算法**：BFS（广度优先搜索），从入口点函数出发，沿着调用图的边遍历，检查是否能到达包含 Sink 的函数。

### 4.8 Taint Analysis (污点分析)

**定义**：追踪不受信任的数据（污点数据）如何在程序中传播。

**Taint-Lite（轻量污点分析）**：完整污点分析需要处理指针别名、对象字段敏感、上下文敏感等复杂情况，计算成本极高。本项目采用"Taint-Lite"策略——只处理两种简单情况：
1. 同一函数内：参数直接传给 Sink
2. 跨函数一跳：调用者参数 → 被调用者参数 → Sink

### 4.9 BFS (Breadth-First Search, 广度优先搜索)

**定义**：图遍历算法，按层逐层访问节点。类比：水波扩散。

```
        A
       / \
      B   C     BFS顺序: A → B → C → D → E
     /     \
    D       E
```

在可达性分析中，从入口函数出发 BFS 遍历调用图，可以找到所有可达的 Sink。

### 4.10 Tree-sitter

**定义**：一个增量式解析器生成框架，可用于为任何编程语言生成解析器。

**为什么不用 JS 的 `acorn` 或 TypeScript 的编译器？**
- Tree-sitter 容错性极强——即使代码有语法错误也能部分解析
- 统一 API 处理 JS/TS/TSX
- 速度快，适合批量分析

### 4.11 CEF (Common Event Format, 通用事件格式)

**定义**：一种标准化的日志格式，用于安全事件记录。

格式：`CEF:Version|Vendor|Product|Version|SigID|Name|Severity|Extensions`

本项目用 CEF 格式解析 eBPF 监控器产生的运行时事件日志。

### 4.12 eBPF (extended Berkeley Packet Filter)

**定义**：Linux 内核中的虚拟机，允许在内核态安全地运行沙箱程序，拦截系统调用。

在本项目中，动态分析阶段用 eBPF 监控沙箱中运行的 MCP 服务器进程发起的 `execve`（执行命令）、`open`（打开文件）、`connect`（网络连接）等系统调用。

### 4.13 MCP (Model Context Protocol)

**定义**：Anthropic 提出的开放协议，允许 AI 助手安全地调用外部工具、访问资源和模板。

在本项目中，MCP 服务器的入口点正是暴露给 AI 助手的那些工具函数（tool）、资源（resource）和提示模板（prompt）。

### 4.14 Shadow Mode (影子模式)

**定义**：新旧系统并行运行，以验证新系统正确性的部署策略。

在本项目中，"shadow mode" 指 AST 分析引擎与传统关键词插件系统**同时运行**，各自独立产出发现在的设计。

---

## 5. 数据模型层 — Fact Schema

**文件位置**: `detection/analysis/facts/schema.py`

这是整个静态分析系统的数据骨架。所有分析都在这些数据结构上进行。

### 5.1 基础类 Fact

```python
@dataclass(slots=True)
class Fact:
    type: str       # 事实类型: "function", "call", "sink", "entrypoint" 等
    id: str         # 全局唯一ID，格式: <type>:<relative_path>:<qualifier>
    file: str       # 相对项目根目录的文件路径
    line: int       # 源代码行号
    extractor: str  # 提取器名称: "python_ast" 或 "javascript_ts_tree_sitter"
```

所有具体事实类型都继承 `Fact`。使用 `@dataclass(slots=True)` 减少内存开销。

### 5.2 具体事实类型一览

| Fact 类型 | 用途 | 关键字段 |
|-----------|------|----------|
| `FunctionFact` | 函数/方法定义 | `name`, `qualified_name`, `params`, `decorators`, `enclosing_class` |
| `ImportFact` | import 语句 | `module`, `imported_name`, `alias`, `kind` |
| `CallFact` | 函数调用 | `caller`（谁调用）, `callee`（调用了谁）, `normalized_callee`, `args` |
| `EntryPointFact` | MCP入口点 | `kind`（tool/resource/prompt）, `function_id`, `params` |
| `SinkFact` | 危险函数调用 | `call_id`, `category`（rce/file/network）, `severity_base`, `rule_id` |
| `SourceFact` | 不可信数据源 | `kind`, `function_id`, `name`（参数名） |
| `AssignFact` | 变量赋值 | `function_id`, `target`, `value`, `snippet` |
| `DataFlowFact` | 数据流路径 | `source_id`, `sink_id`, `path`（PathStep列表） |
| `FindingFact` | 最终漏洞结论 | `title`, `category`, `severity`, `call_chain`, `dataflows` |
| `RuntimeEventFact` | 运行时事件 | `kind`, `syscall`, `command`, `pid`, `ustack` |

### 5.3 数据流建模

从 Source 到 Sink 的数据流通过 `PathStep` 描述每一步：

```
用户参数 cmd ────→ 变量赋值 out = cmd ────→ subprocess.run(out)
     │                    │                         │
  PathStep(          PathStep(                 PathStep(
    kind=PARAM,        kind=ASSIGN,              kind=CALL_ARG,
    name="cmd"         from_="cmd",              arg_index=0
  )                    to="out"                )
                     )
```

### 5.4 枚举类型

```python
class Severity(str, Enum):
    CRITICAL = "critical"   # 严重
    HIGH = "high"           # 高危
    MEDIUM = "medium"       # 中危
    LOW = "low"             # 低危

class Confidence(str, Enum):
    HIGH = "high"           # 高置信度
    MEDIUM = "medium"       # 中置信度
    LOW = "low"             # 低置信度

class FindingStatus(str, Enum):
    POTENTIAL = "potential"     # 静态分析发现的可疑点
    CONFIRMED = "confirmed"     # 经动态分析确认
    RUNTIME_ONLY = "runtime_only"  # 仅在运行时观察到

class EntryPointKind(str, Enum):
    MCP_TOOL = "mcp_tool"
    MCP_RESOURCE = "mcp_resource"
    MCP_PROMPT = "mcp_prompt"
```

### 5.5 实战：用一段真实代码模拟所有 Fact 的实例化

> **这是理解 Fact 最关键的一节。** 我们用一段完整的 MCP 工具代码，逐一展示每种 Fact 在提取之后究竟是什么样子——每个字段填了什么值、为什么填这个值。

#### 5.5.1 源文件

假设被分析的文件是 `/home/user/mcp-server/src/tools.py`，项目根目录是 `/home/user/mcp-server`：

```python
# src/tools.py（第1行起）

1  import subprocess
2  from os import system as sys_cmd
3  from mcp.server import Server
4
5  server = Server("my-server")
6
7  @server.tool()
8  def run_command(cmd: str, timeout: int = 30):
9      """Execute a shell command with timeout."""
10     command = cmd.strip()
11     subprocess.run(command, shell=True, timeout=timeout)
12
13 def helper_cleanup(path: str):
14     sys_cmd(f"rm -rf {path}")
```

**解析上下文**：

| 变量 | 值 |
|------|-----|
| `root` | `Path("/home/user/mcp-server")` |
| `file` | `Path("/home/user/mcp-server/src/tools.py")` |
| 相对路径 | `"src/tools.py"` |

---

#### 5.5.2 ImportFact — 导入语句的实例化

提取器遇到第 1 行的 `import subprocess` 会创建：

```python
ImportFact(
    type           = "import",
    id             = "import:src/tools.py:1:subprocess",
    file           = "src/tools.py",
    line           = 1,
    extractor      = "python_ast",

    language       = "python",
    module         = "subprocess",
    imported_name  = None,              # import subprocess 没有"导入的具体名字"
    alias          = None,              # 没有用 as 起别名
    kind           = ImportKind.IMPORT, # 枚举值: "import"
)
```

提取器遇到第 2 行的 `from os import system as sys_cmd` 会创建：

```python
ImportFact(
    type           = "import",
    id             = "import:src/tools.py:2:os.system",
    file           = "src/tools.py",
    line           = 2,
    extractor      = "python_ast",

    language       = "python",
    module         = "os",
    imported_name  = "system",           # 从 os 中导入的具体名字
    alias          = "sys_cmd",          # 起了别名
    kind           = ImportKind.FROM_IMPORT_AS,  # from X import Y as Z
)
```

**同时**，提取器内部维护的别名映射表也会更新：

```python
# _import_aliases 字典:
{
    "subprocess": "subprocess",           # import subprocess
    "sys_cmd":    "os.system",            # from os import system as sys_cmd
}
```

---

#### 5.5.3 FunctionFact — 函数定义的实例化

提取器遇到第 8 行 `def run_command(cmd: str, timeout: int = 30)`：

```python
FunctionFact(
    type            = "function",
    id              = "python:src/tools.py:run_command",
    file            = "src/tools.py",
    line            = 8,
    extractor       = "python_ast",

    language        = "python",
    name            = "run_command",        # 函数名（不含类前缀）
    qualified_name  = "run_command",        # 完全限定名（这里不在类中，所以就是函数名）
    end_line        = 11,                   # 函数体结束行
    params          = [
        ParamInfo(
            name       = "cmd",
            annotation = "str",             # 类型注解 str
            default    = None,              # 没有默认值
        ),
        ParamInfo(
            name       = "timeout",
            annotation = "int",             # 类型注解 int
            default    = "30",              # 默认值 30 的字符串表示
        ),
    ],
    decorators      = ["server.tool"],      # 装饰器列表
    docstring       = "Execute a shell command with timeout.",
    enclosing_class = None,                 # 不在类中
)
```

提取器遇到第 13 行 `def helper_cleanup(path: str)`：

```python
FunctionFact(
    type            = "function",
    id              = "python:src/tools.py:helper_cleanup",
    file            = "src/tools.py",
    line            = 13,
    extractor       = "python_ast",

    language        = "python",
    name            = "helper_cleanup",
    qualified_name  = "helper_cleanup",
    end_line        = 14,
    params          = [
        ParamInfo(
            name       = "path",
            annotation = "str",
            default    = None,
        ),
    ],
    decorators      = [],                   # 没有装饰器
    docstring       = None,
    enclosing_class = None,
)
```

---

#### 5.5.4 EntryPointFact — MCP入口点的实例化

函数 `run_command` 有 `@server.tool()` 装饰器，匹配 MCP 入口模式。提取器创建：

```python
EntryPointFact(
    type        = "entrypoint",
    id          = "entry:src/tools.py:run_command",
    file        = "src/tools.py",
    line        = 8,
    extractor   = "python_ast",

    kind        = EntryPointKind.MCP_TOOL,       # 推断为 tool 类型
    name        = "run_command",                 # 入口点名称（通常等于函数名）
    function_id = "python:src/tools.py:run_command",  # 指向对应的 FunctionFact
    evidence    = EntryPointEvidence(
        kind = "decorator",                     # 通过装饰器识别
        text = "server.tool",                   # 命中的装饰器文本
    ),
    params      = ["cmd", "timeout"],           # 入口参数名列表
    confidence  = Confidence.HIGH,
)
```

> **注意**：函数 `helper_cleanup` 没有 MCP 装饰器，因此不会产生 `EntryPointFact`。但 Path B（反向溯源）仍然能够检测到它的风险（见 §9.4）。

---

#### 5.5.5 SourceFact — 不可信数据源的实例化

入口函数 `run_command` 有参数 `cmd` 和 `timeout`，每个参数都创建一个 `SourceFact`：

```python
# 参数 cmd 对应的 SourceFact:
SourceFact(
    type        = "source",
    id          = "source:src/tools.py:run_command:cmd",
    file        = "src/tools.py",
    line        = 8,
    extractor   = "python_ast",

    kind        = "mcp_tool_parameter",           # 这是一个 MCP 工具参数
    function_id = "python:src/tools.py:run_command",
    name        = "cmd",                          # 参数名
    confidence  = Confidence.HIGH,
)

# 参数 timeout 对应的 SourceFact:
SourceFact(
    type        = "source",
    id          = "source:src/tools.py:run_command:timeout",
    file        = "src/tools.py",
    line        = 8,
    extractor   = "python_ast",

    kind        = "mcp_tool_parameter",
    function_id = "python:src/tools.py:run_command",
    name        = "timeout",
    confidence  = Confidence.HIGH,
)
```

> `*args` 和 `**kwargs` 参数会被跳过——因为没法精确追踪具体的变量名。

---

#### 5.5.6 AssignFact — 变量赋值的实例化

提取器遇到第 10 行 `command = cmd.strip()`，且当前在函数 `run_command` 体内：

```python
AssignFact(
    type        = "assign",
    id          = "assign:src/tools.py:10:command",
    file        = "src/tools.py",
    line        = 10,
    extractor   = "python_ast",

    function_id = "python:src/tools.py:run_command",  # 在哪个函数内
    target      = "command",                           # 左边被赋值的变量
    value       = "cmd",                               # 右边被解析后的源变量
    snippet     = "command = cmd.strip()",             # 原始代码片段
)
```

> **重要**：只有 `target = Name` 或 `target = Name.Attribute` 形式的赋值才产生 `AssignFact`。纯字面量赋值（如 `x = "hello"`）不产生——因为它们不传递污点数据。

---

#### 5.5.7 CallFact — 函数调用的实例化

提取器遇到第 11 行 `subprocess.run(command, shell=True, timeout=timeout)`，创建：

```python
CallFact(
    type            = "call",
    id              = "call:src/tools.py:11:4",
    file            = "src/tools.py",
    line            = 11,
    extractor       = "python_ast",

    caller          = "python:src/tools.py:run_command",  # 谁发起的调用
    callee          = "subprocess.run",                    # 原始调用表达式
    normalized_callee = "subprocess.run",                  # 别名解析后的规范名
    column          = 4,
    end_line        = 11,
    snippet         = "subprocess.run(command, shell=True, timeout=timeout)",
    args            = [
        CallArg(index=0, expr="command", kind="name"),     # 第0个位置参数
        CallArg(index=1, expr="True",    kind="name"),     # shell=True → 解析为 name(True)
        CallArg(index=2, expr="timeout", kind="name"),     # timeout=timeout
    ],
    kwargs          = {},                                  # 关键字参数被展平到 args 中了
    resolution      = None,                                # subprocess.run 不是 import 别名
)
```

提取器遇到第 14 行 `sys_cmd(f"rm -rf {path}")`：

```python
CallFact(
    type            = "call",
    id              = "call:src/tools.py:14:4",
    file            = "src/tools.py",
    line            = 14,
    extractor       = "python_ast",

    caller          = "python:src/tools.py:helper_cleanup",
    callee          = "sys_cmd",                           # 原始调用名
    normalized_callee = "os.system",                       # ★ 别名解析! sys_cmd → os.system
    column          = 4,
    end_line        = 14,
    snippet         = 'sys_cmd(f"rm -rf {path}")',
    args            = [
        CallArg(index=0, expr='f"rm -rf {path}"', kind="binop"),
    ],
    kwargs          = {},
    resolution      = CallResolution(
        import_alias = "sys_cmd",                          # 通过 import 别名解析
        confidence   = Confidence.HIGH,
    ),
)
```

> **别名解析链**：`sys_cmd` → 查 `_import_aliases` → 找到 `"sys_cmd": "os.system"` → `normalized_callee = "os.system"`。这就是 §8.1.3 中描述的符号解析在起作用。

---

#### 5.5.8 SinkFact — 危险函数匹配的实例化

第 11 行的 `subprocess.run(...)` 匹配到 Sink 规则 `rce_subprocess`：

```python
SinkFact(
    type          = "sink",
    id            = "sink:rce:src/tools.py:11",
    file          = "src/tools.py",
    line          = 11,
    extractor     = "python_ast",

    call_id       = "call:src/tools.py:11:4",       # 指向对应的 CallFact
    category      = "rce",                           # 漏洞类别: Remote Code Execution
    rule_id       = "rce_subprocess",                # 命中规则ID
    sink_name     = "subprocess.run",                # 危险函数名
    severity_base = Severity.HIGH,                   # 基础严重度
    reason        = "Executes external commands",    # 风险原因
    conditions    = {},                              # 附加条件（此处无）
    confidence    = Confidence.HIGH,
)
```

第 14 行的 `sys_cmd(...)` 解析后是 `os.system`，匹配到 Sink 规则 `rce_os`：

```python
SinkFact(
    type          = "sink",
    id            = "sink:rce:src/tools.py:14",
    file          = "src/tools.py",
    line          = 14,
    extractor     = "python_ast",

    call_id       = "call:src/tools.py:14:4",
    category      = "rce",
    rule_id       = "rce_os",
    sink_name     = "os.system",
    severity_base = Severity.HIGH,
    reason        = "Executes external commands via os module",
    conditions    = {},
    confidence    = Confidence.HIGH,
)
```

---

#### 5.5.9 提取完成后的全量事实清单

经过 `PythonFactExtractor`，该文件产生的 **全部 11 条事实**：

```
Fact #1  ImportFact      import:src/tools.py:1:subprocess           import subprocess
Fact #2  ImportFact      import:src/tools.py:2:os.system             from os import system as sys_cmd
Fact #3  ImportFact      import:src/tools.py:3:mcp.server.Server     from mcp.server import Server
Fact #4  FunctionFact    python:src/tools.py:run_command             def run_command(cmd, timeout)
Fact #5  FunctionFact    python:src/tools.py:helper_cleanup          def helper_cleanup(path)
Fact #6  EntryPointFact  entry:src/tools.py:run_command              MCP入口！
Fact #7  SourceFact      source:src/tools.py:run_command:cmd         参数cmd = 污点源
Fact #8  SourceFact      source:src/tools.py:run_command:timeout     参数timeout = 污点源
Fact #9  AssignFact      assign:src/tools.py:10:command              command = cmd.strip()
Fact #10 CallFact+Sink   call:src/tools.py:11:4 + sink:rce:...:11    subprocess.run(command) ← Sink!
Fact #11 CallFact+Sink   call:src/tools.py:14:4 + sink:rce:...:14    sys_cmd(...) → os.system(...) ← Sink!
```

#### 5.5.10 从事实到关系的可视化

这些事实之间不是孤立的——它们通过 ID 引用构成了一个关系网络：

```
                        EntryPointFact
                     id="entry:...run_command"
                     function_id ─────────────┐
                                              │
                        FunctionFact          │
                     id="python:...run_command"◄─┘
                     params=[cmd, timeout]
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
      SourceFact    SourceFact    AssignFact
      name="cmd"    name="timeout" target="command"
      id="source:   id="source:    value="cmd"
      ...cmd"       ...timeout"    id="assign:...10:command"
            │                       │
            │    ┌──────────────────┘
            │    │
            ▼    ▼
          CallFact
      id="call:...11:4"
      callee="subprocess.run"
      args=[command, True, timeout]
      caller=run_command ◄────────────── 属于 run_command 函数
            │
            ▼
          SinkFact
      id="sink:rce:...11"
      call_id="call:...11:4" ◄────────── 指向同一个调用
      category="rce"
      severity=HIGH


      (Path B 还会发现 helper_cleanup → os.system 这条链)
```

#### 5.5.11 关键理解

1. **Fact 是"从代码中摘出的原子事实卡片"**。每张卡片只记录一种类型的信息（谁导入了什么、谁定义了函数、谁调用了危险函数等）。

2. **Fact 之间通过 ID 字符串互相引用**。例如 `SinkFact.call_id` 指向 `CallFact.id`，`EntryPointFact.function_id` 指向 `FunctionFact.id`。这比内存指针更灵活——Fact 可以跨进程、跨文件序列化。

3. **提取器不关心安全结论**。它只负责"忠实地记录看到了什么"。有没有漏洞、严重不严重——那是后续 Pass 层的工作。

4. **同一个代码位置可能产生多个 Fact**。第 11 行的 `subprocess.run(command)` 同时产生了 `CallFact` 和 `SinkFact`，因为这两种信息关注的是不同的维度——调用关系 vs 安全风险。

5. **所有字段都有明确的含义和用途**：
   - `type` 和 `id` 用于分类和引用
   - `file` 和 `line` 用于定位源代码
   - 具体字段（如 `caller`、`callee`、`category`）用于后续分析计算
   - `confidence` 和 `severity` 用于评分

---

## 6. 事实存储层 — Fact Store

**文件位置**: `detection/analysis/facts/store.py`

`FactStore` 是一个**内存键值存储**，提供：

```python
class FactStore:
    _facts: dict[str, Fact]   # fact_id → Fact 的哈希表

    def add(self, fact)       # 添加（如有重复ID则报错）
    def add_or_update(self, fact)  # 添加或覆盖
    def get(self, fact_id)    # 按ID获取
    def query(self, type=None, file=None, language=None)  # 多条件查询
    def all_facts(self)       # 获取全部
```

**设计要点**：
- **去重保护**：`add()` 遇到重复 ID 会抛出 `DuplicateFactError`，防止同一事实被重复计算
- **多维度查询**：支持按 type（类型）、file（文件）、language（语言）过滤
- **当前实现中**：引擎直接使用 Python list 而非 FactStore 来管理 facts，因为流式处理更灵活

---

## 7. 事实ID生成层

**文件位置**: `detection/analysis/facts/ids.py`

每个 Fact 需要一个全局唯一的 ID，格式为：

```
<type>:<project_relative_path>:<qualifier>
```

**ID 生成函数**：

| 函数                   | ID 格式                                        | 示例             |
| -------------------- | -------------------------------------------- | -------------- |
| `make_function_id`   | `python:src/server.py:run_cmd`               | 函数标识           |
| `make_call_id`       | `call:src/server.py:15:4`                    | 调用位置(line:col) |
| `make_sink_id`       | `sink:rce:src/server.py:15`                  | 漏洞类别:文件:行      |
| `make_entrypoint_id` | `entry:src/server.py:my_tool`                | 入口名称           |
| `make_source_id`     | `source:src/server.py:run_cmd:cmd`           | 源参数            |
| `make_finding_id`    | `finding:rce:ep_my_tool_sink_subprocess_run` | 最终漏洞           |
| `make_assign_id`     | `assign:src/server.py:20:command`            | 赋值语句           |
| `make_dataflow_id`   | `flow:cmd-to-subprocess`                     | 数据流            |
| `make_import_id`     | `import:src/server.py:1:subprocess`          | 导入语句           |

**设计关键**：ID 是**确定性的**（同样的输入产生同样的 ID），不是随机生成的。这样同一个代码片段多次分析会产生相同的 ID，支持增量分析和去重。

---

## 8. 提取层 — 从源代码到安全事实

这是静态分析的**第一阶段**，负责将源代码文本转换为结构化的 Fact 对象。

### 8.1 Python AST 提取器

**文件位置**: `detection/analysis/extractors/python_ast.py`

#### 8.1.1 核心原理

Python 标准库的 `ast` 模块可以将 Python 源码解析为 AST（抽象语法树）。提取器通过**访问者模式（Visitor Pattern）**遍历 AST 节点，在关键节点上提取安全信息。

```python
class PythonFactExtractor(ast.NodeVisitor):
    def visit_FunctionDef(self, node)   # 遇到函数定义时触发
    def visit_Call(self, node)          # 遇到函数调用时触发
    def visit_Assign(self, node)        # 遇到赋值语句时触发
    def visit_ClassDef(self, node)      # 遇到类定义时触发
```

#### 8.1.2 提取流程

```
Python源码
    │
    ├── 1. ast.parse(source) → AST树
    │      失败处理: SyntaxError → 记录错误，跳过该文件
    │
    ├── 2. _extract_imports(tree) — 提取所有import语句
    │      import subprocess         → ImportFact(module="subprocess", kind=IMPORT)
    │      from os import system     → ImportFact(module="os", imported_name="system")
    │      同时维护 _import_aliases 字典用于后续符号解析
    │
    ├── 3. generic_visit(tree) — 遍历所有节点
    │      │
    │      ├── 遇到 FunctionDef/AsyncFunctionDef:
    │      │   ├─ 创建 FunctionFact (name, qualified_name, params, decorators)
    │      │   ├─ 检查装饰器是否为MCP入口 (@mcp.tool, @server.tool等)
    │      │   ├─ 如果是入口→创建 EntryPointFact + 每个参数的 SourceFact
    │      │   └─ 维护 _function_stack / _class_stack 用于限定名构建
    │      │
    │      ├── 遇到 ClassDef:
    │      │   └─ 维护 _class_stack 用于后续方法的类限定名
    │      │
    │      ├── 遇到 Call:
    │      │   ├─ 提取 callee 字符串 (如 "subprocess.run")
    │      │   ├─ _resolve_callee() 符号解析: 别名 → 真名
    │      │   │   (例: s = os.system; s("ls") → 解析为 os.system("ls"))
    │      │   ├─ 创建 CallFact (caller, callee, normalized_callee, args, kwargs)
    │      │   └─ _check_sink() 检查是否为危险函数 → 创建 SinkFact
    │      │
    │      └── 遇到 Assign:
    │          ├─ x = y (名称到名称)     → 记录 _assignment_aliases
    │          ├─ x = module.func        → 记录赋值别名
    │          └─ 在函数内 → 创建 AssignFact
    │
    └── 4. 返回 (facts, errors)
```

#### 8.1.3 关键实现细节

**符号解析（Alias Resolution）**：

```python
# 代码示例:
from os import system
s = system      # x = y 赋值别名
s("ls")         # s 需要被解析为 os.system

# 解析算法 (_resolve_callee):
# 1. 拆分 callee 字符串: "s" → parts = ["s"]
# 2. 查找 _import_aliases: 没有直接匹配
# 3. 查找 _assignment_aliases: "s" → "system"
# 4. 继续查找 _import_aliases: "system" → "os.system"
# 5. 结果: normalized_callee = "os.system"
```

最多迭代 10 次防止别名循环导致的死循环。

**MCP入口点检测**：

```python
_MCP_DECORATOR_PATTERNS = (
    "mcp.tool", "mcp.resource", "mcp.prompt",
    "server.tool", "server.resource", "server.prompt",
    "mcp_tools", "mcp_tool", "server_tools",
)
```

检测逻辑 (`_is_mcp_decorator`)：
- 点分隔模式（如 `mcp.tool`）：精确匹配或作为后缀匹配
- 下划线模式（如 `mcp_tool`）：仅在标识符边界匹配，避免 `my_mcp_tool` 被误匹配

**Sink规则**：

```python
_SINK_RULES = [
    SinkRule(patterns=("subprocess.run", "subprocess.Popen", ...),
             category="rce", rule_id="rce_subprocess",
             severity=Severity.HIGH, reason="Executes external commands"),
    SinkRule(patterns=("os.system", "os.popen", ...),
             category="rce", rule_id="rce_os", ...),
    SinkRule(patterns=("eval", "exec", "compile"),
             category="rce", rule_id="rce_dynamic", ...),
    # ... 还有 file_access, network_access 等
]
```

#### 8.1.4 优雅失败（Graceful Failure）

单个文件的解析失败不会影响其他文件：

```python
try:
    tree = ast.parse(source, filename=str(self.file))
except SyntaxError as e:
    self.errors.append(ExtractionError(...))
    return [], self.errors   # 返回空列表，继续处理下一个文件
```

---

### 8.2 JS/TS Tree-sitter 提取器

**文件位置**: `detection/analysis/extractors/javascript_ts_tree_sitter.py`

#### 8.2.1 核心原理

JavaScript/TypeScript 不像 Python 有内置 `ast` 模块，因此使用 **Tree-sitter** 第三方库。

Tree-sitter 提供：
- 语言无关的解析器框架
- 容错解析（即使代码不完整也能产生部分AST）
- 增量解析（只重新解析修改部分）

三种解析器按文件扩展名选择：

```python
.js/.mjs/.cjs → tree_sitter_javascript (JavaScript 解析器)
.ts/.mts/.cts → tree_sitter_typescript (TypeScript 解析器)
.tsx/.mtsx/.ctsx → tree_sitter_typescript (TSX 解析器)
```

#### 8.2.2 与 Python 提取器的关键差异

| 方面 | Python 提取器 | JS/TS 提取器 |
|------|--------------|-------------|
| 解析方式 | `ast.NodeVisitor`（自动递归） | 手动 `_walk_node()` 递归 |
| 函数定义 | 只处理 `def`/`async def` | 处理 `function_declaration`、`method_definition`、`variable_declarator`（箭头函数/函数表达式） |
| 导入方式 | `import`/`from import` | ESM `import` + CommonJS `require()` + 解构 `const {x} = require()` |
| MCP入口检测 | 装饰器模式 `@mcp.tool()` | 调用注册模式 `server.tool("name", handler)` |

#### 8.2.3 MCP入口点检测的特殊处理

JS/TS 的 MCP 入口点是通过调用注册：

```javascript
server.tool("my_tool", async (params) => {
    exec(params.cmd);  // ← 危险！
});
```

提取器对此做了精细处理：

1. **内联箭头函数**：立即为箭头函数创建 `FunctionFact`，参数创建 `SourceFact`
2. **命名函数引用**：记录 `handler_name → entrypoint_id` 映射，在 `_process_named_handlers()` 后处理阶段为引用函数生成 `SourceFact`
3. **调用者上下文追踪**：通过 `_current_mcp_handler_id` 确保箭头函数体内的调用被正确归属到 MCP 入口函数

#### 8.2.4 JS/TS 特有 Sink 规则

```python
_SINK_RULES = [
    SinkRule(patterns=("child_process.exec", "child_process.execSync",
                       "child_process.spawn", ...),
             category="rce", rule_id="rce_child_process", ...),
    SinkRule(patterns=("eval", "Function", "new Function"),
             category="rce", rule_id="rce_dynamic", ...),
    SinkRule(patterns=("fs.readFile", "fs.writeFile", ...),
             category="file", rule_id="file_access", ...),
    SinkRule(patterns=("http.request", "fetch", "axios", ...),
             category="network", rule_id="network_access", ...),
]
```

---

## 9. 分析Pass层 — 从事实到漏洞结论

有了提取层产生的结构化 Fact，分析 Pass 层负责计算和推导出最终的安全漏洞。

#### Pass 概念

"Pass" 是编译器领域的术语，指对中间表示（IR）进行一次遍历处理。在这里，每个 Pass 接收 Fact 列表，输出更高级的分析结果。

### 9.1 调用图构建 (Call Graph)

**文件位置**: `detection/analysis/passes/call_graph.py`

#### 9.1.1 数据结构

```python
class CallGraph:
    calls_by_caller: dict[str, list[CallFact]]
    # 按调用者索引: function_id → 该函数发起的所有调用

    call_by_id: dict[str, CallFact]
    # 按调用ID索引: call_id → CallFact

    callee_by_call_id: dict[str, str | None]
    # 按调用ID索引解析后的被调用者: call_id → callee_function_id

    function_by_id: dict[str, list[CallFact]]
    # 反向索引: function_id → 所有调用该函数的 CallFact
    # "谁调用了这个函数？"
```

#### 9.1.2 构建算法

```
build_call_graph(facts):

  Pass 1: 建立符号表
    遍历所有 FunctionFact:
      symbol_table[(file, func_name)] = func_id
      known_function_ids.add(func_id)

  Pass 2: 索引 CallFact
    遍历所有 CallFact:
      ┌─ call_by_id[call.id] = call
      │
      ├─ 按调用者分组:
      │   calls_by_caller[call.caller].append(call)
      │
      ├─ 解析被调用者:
      │   callee_func_id = _resolve_callee_function_id(call, symbol_table)
      │   callee_by_call_id[call.id] = callee_func_id
      │   解析逻辑:
      │   - 如果 callee 已经是 function_id 格式 → 直接使用
      │   - 否则在符号表中查找 (caller_file, callee_name)
      │   - 找到 → 返回 function_id
      │   - 未找到 → None (可能是外部库函数)
      │
      └─ 反向索引:
          function_by_id[callee_func_id].append(call)
```

#### 9.1.3 核心难点：被调用者解析

```python
# 场景1: 同文件本地调用 → 可解析
# file: server.py
def helper(x):    # FunctionFact(id="python:server.py:helper")
    return x

def main():
    helper(42)    # CallFact(callee="helper")
                  # 在符号表中查 ("server.py", "helper") → "python:server.py:helper" ✓

# 场景2: 外部库调用 → 不可解析
import subprocess
subprocess.run(...)  # CallFact(callee="subprocess.run")
                     # "subprocess.run" 不在本地符号表中 → None
                     # 但这正是Sink检测的工作——不需要解析到函数内部
```

---

### 9.2 可达性分析 (Reachability)

**文件位置**: `detection/analysis/passes/call_graph.py` 的后半部分

#### 9.2.1 核心问题

**给定**：EntryPoint → 函数A → ... → 函数N → Sink

**问题**：是否存在一条调用路径从入口函数到达 Sink？

#### 9.2.2 BFS 可达性算法

```python
def _bfs_find_sinks(start_func_id, graph, sink_to_calls):

    frontier = [(start_func_id, [])]   # (当前函数, 调用链路)
    visited = {start_func_id}          # 防止环路

    while frontier:
        current_func_id, chain = frontier.pop(0)  # 队列头部出队

        for call in graph.calls_by_caller[current_func_id]:
            link = CallChainLink(call_id, caller, callee, snippet, line)
            new_chain = chain + [link]   # 追加到路径

            # ★ 检查: 这个调用本身是不是 Sink?
            if call.id in sink_to_calls:
                results.append((sink, new_chain))

            # 继续BFS到被调用者
            if callee_func_id and callee_func_id not in visited:
                visited.add(callee_func_id)
                frontier.append((callee_func_id, new_chain))
```

**图解**：

```
入口函数 handle_tool()
    │
    ├──→ 调用 process_data()
    │         │
    │         ├──→ 调用 sanitize()    ← 安全函数
    │         │
    │         └──→ 调用 save_to_file()
    │                    │
    │                    └──→ open("file.txt", "w")  ← Sink!
    │
    └──→ 调用 exec_cmd()
              │
              └──→ subprocess.run(cmd)  ← Sink!
```

BFS 会找到两条路径：
- `handle_tool → process_data → save_to_file → open` (文件写入)
- `handle_tool → exec_cmd → subprocess.run` (命令执行)

结果结构：

```python
ReachabilityResult(
    entrypoint_id="entry:server.py:handle_tool",
    entrypoint_function_id="python:server.py:handle_tool",
    sink_id="sink:rce:server.py:25",
    call_chain=[
        CallChainLink(call_id="call:server.py:20:4", ...),
        CallChainLink(call_id="call:server.py:25:8", ...),
    ],
)
```

---

### 9.3 Taint-Lite 数据流分析

**文件位置**: `detection/analysis/passes/taint_lite.py`

#### 9.3.1 设计哲学

完整的污点分析需要处理：
- 指针别名：`a = b` 后修改 `a` 也影响 `b`
- 对象字段敏感：`obj.x = tainted` → `sink(obj.y)` 安全，`sink(obj.x)` 危险
- 上下文敏感：同一函数在不同调用上下文中的行为差异
- 路径敏感：if/else 分支中的不同传播路径

这些分析成本极高且容易产生大量误报。**Taint-Lite 采用"宁漏报不误报"策略**，只处理两种高置信度模式：

#### 9.3.2 模式A：同函数直接传递

```python
@mcp.tool()
def run_command(cmd: str):     # cmd 是 SourceFact
    subprocess.run(cmd)        # cmd 直接传给 Sink → 污点数据流成立!
```

检测逻辑：检查 Sink 调用的参数中是否有名称与 Source 参数名相同的参数。

#### 9.3.3 模式B：同函数赋值传递

```python
@mcp.tool()
def run_command(cmd: str):     # cmd 是 SourceFact
    command = cmd.strip()      # AssignFact(target="command", value="cmd")
    subprocess.run(command)    # command 传给 Sink → 污点数据流成立!
```

检测逻辑：查找 AssignFact，看是否有 `target=cmd` && `value=source_name` 的赋值，且 target 变量被传给 Sink。

#### 9.3.4 模式C：跨函数一跳传递

```python
@mcp.tool()
def run_command(user_input: str):   # user_input 是 SourceFact
    execute(user_input)             # 作为第0个参数传给 helper

def execute(cmd: str):              # cmd 接收第0个参数
    subprocess.run(cmd)             # → 污点数据流成立!
```

检测逻辑：
1. 找到调用链中第一个调用（`execute(user_input)`）
2. 确认 `user_input` 在第 N 个参数位置
3. 在被调用函数中找到第 N 个参数，追踪到 Sink

#### 9.3.5 输出：DataFlowFact

```python
DataFlowFact(
    type="dataflow",
    id="flow:cmd-to-subprocess",
    source_id="source:server.py:run_command:cmd",
    sink_id="sink:rce:server.py:15",
    path=[
        PathStep(kind=PARAM,  line=10, name="cmd", function="run_command"),
        PathStep(kind=CALL_ARG, line=10, call_id="call:...", arg_index=0),
        PathStep(kind=PARAM,  line=15, name="cmd", function="subprocess.run"),
    ],
    confidence=HIGH,
)
```

---

### 9.4 反向Sink溯源 (Reverse Sink Trace)

**文件位置**: `detection/analysis/passes/reverse_sink_trace.py`

#### 9.4.1 为什么需要反向分析？

正向分析（Path A）依赖 MCP 入口点（EntryPoint）。但很多危险代码没有 MCP 入口点：

```python
# 这是一个被篡改的依赖包的代码——没有MCP入口点，但仍然是危险的!
import os

def cleanup_temp():
    os.system("rm -rf /tmp/*")     # 危险但不会被Path A检测到
```

**反向分析策略**：不再从入口出发找 Sink，而是从 Sink 出发找调用根。

#### 9.4.2 算法详解

```
对于每个 SinkFact:
  1. 获取 Sink 调用的直接 caller (包含 Sink 调用的函数)
  2. 通过 graph.function_by_id 反向查询: "谁调用了当前函数?"
  3. BFS向上追溯, 直到:
     a) 没有函数调用者（仅被<module>调用）→ 这是根函数
     b) 达到最大深度 (MAX_DEPTH=10)
  4. 构建从根函数到Sink的正向调用链
  5. 生成 FindingFact
```

**图解**：

```
module-level code (<module>)
    │
    └──→ 调用 cleanup_temp()
              │
              └──→ os.system("rm -rf /tmp/*")  ← Sink

反向追溯过程:
  os.system (Sink) → 被 cleanup_temp() 调用 → 被 <module> 调用 → 到达根
```

**去重逻辑**：如果某个 Sink 已经被 Path A（正向分析）覆盖，则跳过：

```python
covered_sink_ids = {f.sink_id for f in findings if f.sink_id}
root_chains = [rc for rc in root_chains if rc.sink_id not in covered_sink_ids]
```

---

### 9.5 漏洞构建器 (Finding Builder)

**文件位置**: `detection/analysis/passes/finding_builder.py`

#### 9.5.1 功能

将 `ReachabilityResult`（可达性分析结果）转换为 `FindingFact`（最终漏洞结论）。

#### 9.5.2 构建过程

```python
class FindingFactsBuilder:
    def build(self, reachability_results, dataflows=None):
        for result in reachability_results:
            sink_fact = self._sink_by_id.get(result.sink_id)
            ep_fact = self._ep_by_id.get(result.entrypoint_id)

            finding = FindingFact(
                type="finding",
                id=make_finding_id(category, name),   # finding:rce:ep_xx_sink_yy
                title=f"Potential {category} via {ep} → {sink}",
                severity=sink.severity_base,            # 继承Sink的严重度
                confidence=sink.confidence,             # 继承Sink的置信度
                status=FindingStatus.POTENTIAL,         # 静态分析默认为"潜在"
                entrypoint_id=result.entrypoint_id,
                sink_id=result.sink_id,
                call_chain=序列化的调用链,
                evidence=[                              # 人类可读的证据列表
                    "Entrypoint: my_tool (function=..., kind=mcp_tool)",
                    "Sink: subprocess.run (category=rce, ...)",
                    "Call chain: 2 hops first='...' last='...'",
                ],
                dataflows=关联的DataFlowFact ID列表,
            )
```

#### 9.5.3 两个 Builder 的区别

- `build_finding_facts()` (finding_builder.py): 为正分析 Path A 服务，使用 EntryPointFact 元数据
- `build_sink_root_findings()` (reverse_sink_trace.py): 为反分析 Path B 服务，使用 Root Function 元数据，Confidence 固定为 MEDIUM

---

### 9.6 动态关联分析 (Dynamic Correlation)

**文件位置**: `detection/analysis/passes/dynamic_correlation.py`

#### 9.6.1 功能

将静态分析的 `FindingFact`（POTENTIAL 状态）与沙箱运行时观察到的 `RuntimeEventFact` 进行关联，将可信度提升为 CONFIRMED。

#### 9.6.2 关联逻辑

```
匹配精度分为两级:

Level 1 - Exact Match (精确匹配):
  条件: (category == event.kind 对应的类别)
       AND (event.ustack 包含 sink 所在文件名     ← "ustack归因"
            OR event.target_path 与 sink arguments 重叠)

Level 2 - Category Match (类别匹配):
  条件: 仅 category 与 event.kind 类别匹配
```

#### 9.6.3 升级规则

| 匹配级别 | 结果 | 置信度 |
|----------|------|--------|
| Exact Match | POTENTIAL → CONFIRMED | HIGH |
| Category Match | POTENTIAL → CONFIRMED | HIGH |
| 无匹配 | 保持 POTENTIAL | 不变 |
| 多类别匹配 (≥2种event) | Severity 升级一级 | — |
| 未匹配的RuntimeEvent | 创建 RUNTIME_ONLY FindingFact | MEDIUM |

---

## 10. 适配层 — FindingFact → CapabilityFinding

**文件位置**: `detection/analysis/adapters/finding_adapter.py`

#### 为什么需要适配？

新 AST 引擎产生 `FindingFact`，传统报告系统期望 `CapabilityFinding`。适配层就是桥梁：

```python
def finding_to_capability(finding: FindingFact) -> CapabilityFinding:
    score_weight = SEVERITY_SCORE_WEIGHTS[finding.severity]
    # CRITICAL→1.0, HIGH→0.75, MEDIUM→0.5, LOW→0.25

    confidence = CONFIDENCE_SCORES[finding.confidence]
    # HIGH→1.0, MEDIUM→0.6, LOW→0.3

    return CapabilityFinding(
        name=finding.title,
        description=f"Category: {category} | ...",
        score_weight=score_weight,
        confidence=confidence,
        sources=[EvidenceSource.STATIC],
        evidence=finding.evidence,
        metadata={finding_id, status, category, entrypoint_id, sink_id},
    )
```

---

## 11. 传统插件系统

在 AST 分析引擎之外，本项目还有一个更简单的**传统插件系统**，配置驱动，基于关键词和正则匹配。

### 11.1 规则文件

**文件位置**: `detection/detection/rules/keywords.toml`

```toml
[[capabilities]]
name = "command_exec"
description = "Ability to spawn shell commands or subprocesses."
weight = 25.0
base_confidence = 0.4

  [[capabilities.indicators]]
  languages = ["python"]
  type = "keyword"
  patterns = ["subprocess.", "os.system(", "os.popen("]

  [[capabilities.indicators]]
  languages = ["python"]
  type = "regex"
  pattern = "subprocess\\.(run|Popen|call)"

  [[capabilities.indicators]]
  languages = ["metadata"]
  type = "keyword"
  case_sensitive = false
  patterns = ["exec", "bash", "eval", "shell", "rm -rf"]
```

支持的检测能力：
- `command_exec` — 命令执行
- `file_read` / `file_write` — 文件读写
- `network_outbound` / `network_inbound` — 网络访问
- `env_access` — 敏感环境变量读取
- `param_override` / `tool_sequence_hijack` — 行为操控
- `prompt_injection` — 提示注入

### 11.2 Python 插件执行

**文件位置**: `detection/detection/plugins/static/python/__init__.py`

```python
class _PythonRuleDetector:
    def __call__(self, session):
        # 1. 递归收集所有 .py 文件
        # 2. 对每个文件、每条规则、每个指示器做匹配
        #    - keyword: 子字符串查找（支持大小写敏感/不敏感）
        #    - regex: 正则匹配
        # 3. 计算置信度:
        #    confidence = base + 0.1×files + 0.05×(hits-files) + boost
        #    cap at 0.99
        # 4. 返回 CapabilityFinding 列表
```

置信度计算公式：
- `base`: 规则的 base_confidence
- `+0.1 × 命中文件数`：文件越多越可疑
- `+0.05 × (命中次数-文件数)`：同一文件多次命中加分
- `+boost`: 各指示器的 confidence_boost 之和
- 上限 0.99

---

## 12. 端到端完整流程

让我们跟踪一个完整的安全检测案例从头到尾：

### 12.1 输入

```python
# target/server.py — 一个简单的MCP工具服务器
import subprocess

@mcp.tool()
def run_shell_command(command: str):
    """执行用户提供的shell命令"""
    cmd = command.strip()
    subprocess.run(cmd, shell=True)
```

### 12.2 CLI 入口

```bash
python -m detection /path/to/target --pipeline static
```

### 12.3 流水线调度

`detection/detection/pipelines/static.py::run_static_pipeline()`:

```python
def run_static_pipeline(target_path, registry, policy_dir):
    session = DetectionSession(target_path=target_path)
    findings = []

    # 轨1: 传统插件
    for detector in registry.detectors_for("static"):
        findings.extend(detector(session))

    # 轨2: AST引擎 (shadow mode)
    ast_findings = _get_ast_findings(target_path)
    findings.extend(ast_findings)

    # 评分 + 缓解
    score = sum(f.score_weight * f.confidence for f in findings)
    risk_level = _score_to_risk_level(score)
    mitigations = MitigationEngine(policy_dir).recommendations(findings)

    return DetectionResult(...)
```

### 12.4 AST 引擎执行

`detection/analysis/engine.py::run_ast_analysis()`:

#### Step 1: 文件发现

```python
_resolve_files(Path("/path/to/target"))
# → (Path("/path/to/target"), [Path("target/server.py")])
```

#### Step 2: 事实提取

`extract_python_facts(root="target", file="server.py", source=...)`:

```
提取结果:

1. ImportFact:
   type="import", id="import:server.py:1:subprocess",
   module="subprocess", imported_name=None, kind=IMPORT

2. FunctionFact:
   type="function", id="python:server.py:run_shell_command",
   name="run_shell_command", qualified_name="run_shell_command",
   params=[ParamInfo(name="command")],
   decorators=["mcp.tool"]

3. EntryPointFact:  (装饰器匹配 MCP_PATTERNS)
   type="entrypoint", id="entry:server.py:run_shell_command",
   kind=MCP_TOOL, function_id="python:server.py:run_shell_command",
   params=["command"]

4. SourceFact:  (入口函数参数 = 不可信源)
   type="source", id="source:server.py:run_shell_command:command",
   kind="mcp_tool_parameter", function_id="python:server.py:run_shell_command",
   name="command"

5. AssignFact:  (cmd = command.strip())
   type="assign", id="assign:server.py:6:cmd",
   function_id="python:server.py:run_shell_command",
   target="cmd", value="command"

6. CallFact:  (subprocess.run(cmd, shell=True))
   type="call", id="call:server.py:7:4",
   caller="python:server.py:run_shell_command",
   callee="subprocess.run", normalized_callee="subprocess.run",
   args=[CallArg(index=0, expr="cmd", kind="name"),
         CallArg(index=1, expr="True", kind="name")],
   kwargs={}

7. SinkFact:  (匹配 _SINK_RULES 中的 rce_subprocess)
   type="sink", id="sink:rce:server.py:7",
   call_id="call:server.py:7:4",
   category="rce", rule_id="rce_subprocess",
   sink_name="subprocess.run", severity_base=HIGH
```

#### Step 3: 调用图构建

```python
graph = build_call_graph(all_facts)
# calls_by_caller["python:server.py:run_shell_command"] = [CallFact(...)]
# call_by_id["call:server.py:7:4"] = CallFact(...)
# callee_by_call_id["call:server.py:7:4"] = None (subprocess.run 不是本地函数)
```

#### Step 4: 可达性分析 (Path A)

```python
entrypoints = [EntryPointFact(id="entry:server.py:run_shell_command", ...)]
sinks = [SinkFact(id="sink:rce:server.py:7", call_id="call:server.py:7:4", ...)]

reachability_results = find_reachable_sinks(entrypoints, sinks, graph)
# 找到: CallFact 的 caller == entrypoint 的 function_id
# 且 call_id 匹配 SinkFact 的 call_id → 可达!
# 调用链长度 = 0 (直接调用，没有中间函数)
```

#### Step 5: 污点分析

```python
dataflows = build_taint_lite_dataflows(facts, reachability_results)

# 匹配 AssignFact: target="cmd", value="command"
# command 是 SourceFact 名字 → cmd 来自污点源
# cmd 被传给 subprocess.run → 数据流成立!

# 产出:
DataFlowFact(
    id="flow:command-to-subprocess",
    source_id="source:server.py:run_shell_command:command",
    sink_id="sink:rce:server.py:7",
    path=[
        PathStep(kind=PARAM, name="command", function="run_shell_command"),
        PathStep(kind=ASSIGN, from_="command", to="cmd"),
        PathStep(kind=CALL_ARG, call_id="call:server.py:7:4", arg_index=0),
    ]
)
```

#### Step 6: 构建 FindingFact

```python
findings = build_finding_facts(reachability_results, facts, dataflows)

FindingFact(
    type="finding",
    id="finding:rce:ep_run_shell_command_sink_subprocess_run",
    title="Potential rce via run_shell_command → subprocess.run",
    category="rce",
    severity=HIGH,
    confidence=HIGH,
    status=POTENTIAL,
    call_chain=[{call_id, caller_func_id, snippet, line}],
    dataflows=["flow:command-to-subprocess"],
    evidence=["Entrypoint: run_shell_command (...)",
              "Sink: subprocess.run (category=rce, rule=rce_subprocess, ...)",
              "Call chain: 0 hops (...)"],
)
```

#### Step 7: 适配输出

```python
CapabilityFinding(
    name="Potential rce via run_shell_command → subprocess.run",
    description="Category: rce",
    score_weight=0.75,    # HIGH → 0.75
    confidence=1.0,       # HIGH → 1.0
    sources=[STATIC],
    evidence=[...],
    metadata={finding_id, status, category, ...},
)
```

### 12.5 最终报告

```markdown
Risk Level: HIGH
Total Score: 75.0

Findings:
- Potential rce via run_shell_command → subprocess.run
  Category: rce | Confidence: HIGH
  Evidence: ...

Mitigations:
- Consider using subprocess with whitelisted command list
- ...
```

---

## 13. Sink规则与检测逻辑详解

### 13.1 硬编码 Sink 规则（AST提取器）

```python
# python_ast.py 中的 _SINK_RULES:
rce_subprocess:  subprocess.run, subprocess.Popen, subprocess.call, subprocess.check_output
rce_os:          os.system, os.popen, os.exec, os.spawn
rce_dynamic:     eval, exec, compile
file_access:     open, io.open, pathlib.Path.open
network_access:  requests.get/post/put/delete, urllib.request, http.client
network_socket:  socket.create_connection, socket.connect
```

### 13.2 TOML规则（传统插件）

```toml
# keywords.toml 中的 capabilities:
command_exec:       subprocess.*, os.system, child_process, exec(), spawn()
file_read:          open(), fs.readFile, fs.readdir
file_write:         fs.writeFile, fs.appendFile
network_outbound:   requests.*, fetch(), axios.*
network_inbound:    Flask(), express(), http.createServer
env_access:         os.environ, process.env
prompt_injection:   "ignore the user", "priority higher than", "do not follow"
param_override:     "override", "force", "always set", "regardless of user"
tool_sequence_hijack: "before calling", "must first", "always call"
```

### 13.3 两层检测的关系

```
传统插件 (keywords.toml):
  - 粗粒度: 文件级关键词/正则匹配
  - 快: 不需要构建AST
  - 无法建立调用链和数据流关系
  - 适合快速筛选和metadata分析

AST引擎 (python_ast.py, jsts_tree_sitter.py):
  - 细粒度: 结构化分析
  - 建立函数调用图、数据流路径
  - 能区分函数定义内的调用 vs 注释/字符串
  - 能证明从入口到Sink的可达性和数据流
```

---

## 14. 总结

### 14.1 整个静态分析系统的核心思想

用一句话概括：**将源代码转换为结构化事实（Facts），然后在事实之上计算安全结论。**

```
文本代码 ──Extraction──▶ 结构化事实 ──Analysis Passes──▶ 安全结论
 (不可直接计算)         (可查询、索引、遍历)          (人类可读的漏洞报告)
```

### 14.2 关键设计决策

1. **双轨并行（传统+AST）**：渐进式架构演进，避免一次性重写的风险
2. **Taint-Lite而非完整污点分析**：在覆盖面（召回率）和误报率之间取平衡
3. **正向+反向双路径分析**：Path A（入口→Sink）利用MCP特定知识；Path B（Sink→根）作为通用兜底
4. **多语言统一事实模型**：Python和JS/TS使用相同的Fact类型，分析Pass跨语言复用
5. **确定性ID**：支持增量分析和缓存
6. **优雅失败**：单个文件失败不影响整体

### 14.3 数据流图总结

```
                          CLI (cli.py)
                              │
                   ┌──────────┴──────────┐
                   │  static pipeline     │
                   │  (static.py)         │
                   └──────────┬──────────┘
                              │
              ┌───────────────┼───────────────┐
              │                               │
    ┌─────────▼─────────┐          ┌──────────▼──────────┐
    │ Legacy Plugins     │          │  AST Engine          │
    │ (keywords.toml)    │          │  (engine.py)         │
    │                    │          │                      │
    │ keywords.toml      │          │  ① extractors/       │
    │   → RuleBook       │          │     python_ast.py    │
    │   → Plugin         │          │     jsts_ts.py       │
    │   → CapFinding[]   │          │     → Facts[]        │
    │                    │          │                      │
    └─────────┬──────────┘          │  ② passes/           │
              │                     │     call_graph.py    │
              │                     │     → CallGraph      │
              │                     │                      │
              │                     │  ③ passes/           │
              │                     │     taint_lite.py    │
              │                     │     reverse_sink.py  │
              │                     │     → DataFlowFact[] │
              │                     │                      │
              │                     │  ④ passes/           │
              │                     │     finding_builder  │
              │                     │     → FindingFact[]  │
              │                     │                      │
              │                     │  ⑤ adapters/         │
              │                     │     finding_adapter  │
              │                     │     → CapFinding[]   │
              │                     │                      │
              └─────────┬───────────┴──────────┬──────────┘
                        │                      │
                        │    ┌─────────────────┘
                        │    │
              ┌─────────▼────▼─────────┐
              │  Scoring + Mitigation   │
              │  → DetectionResult      │
              └─────────┬──────────────┘
                        │
              ┌─────────▼─────────────┐
              │  Report Generation     │
              │  (markdown / json)     │
              └───────────────────────┘
```

---

> **延伸阅读建议**：
> - 如果想深入了解 Python AST，阅读 Python 官方文档 `ast` 模块
> - 如果想了解 Tree-sitter，访问 https://tree-sitter.github.io/
> - 如果想了解静态污点分析的完整理论，可以搜索 "taint analysis data flow" 相关论文
> - 项目中 `detection/tests/` 目录下有各模块的单元测试，是理解各组件行为的最佳入手点
