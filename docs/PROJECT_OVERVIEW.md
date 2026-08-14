# MCP-Sec-Audit 项目全貌

> 一个面向 MCP (Model Context Protocol) 服务器的混合动静态安全审计工具（研究原型）。

---

## 一句话概括

**输入**一个 MCP 服务器的源代码仓库（Python / JS / TS），**输出**一份结构化的安全检测报告——包含漏洞类型、风险等级、调用链证据和缓解建议。

---

## 检测能力矩阵

| 能力 | 技术手段 | 说明 |
|------|----------|------|
| **命令执行 (RCE)** | AST + 调用图 + 污点分析 + eBPF | 检测 `subprocess.run`、`os.system`、`eval`、`exec`、`child_process.exec` 等 |
| **文件读写** | AST Parser + eBPF 文件探针 | 检测 `open()`、`fs.readFile`、路径遍历 + 运行时敏感文件访问 |
| **网络外联** | AST + eBPF connect 探针 | 检测 `requests`、`fetch()`、`http.request` + 实际外连 IP |
| **环境变量窃取** | AST + 关键词扫描 | 检测 `os.environ`、`process.env` 访问 |
| **提示注入** | 关键词匹配 (TOML) | 检测 MCP tool description 中的 `ignore the user` 等注入指令 |
| **参数覆盖** | 关键词匹配 (TOML) | 检测 `override`、`force`、`always set` 等越权语义 |
| **工具链劫持** | 关键词匹配 (TOML) | 检测 `before calling`、`must first` 等强制调用链操控 |

---

## 三条分析管线

```
                            ┌──────────────────────────┐
                            │          CLI              │
                            │  python -m detection      │
                            │  --pipeline static|dynamic│
                            │  --format markdown|json   │
                            └──────────┬───────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
    ┌─────────▼─────────┐   ┌─────────▼─────────┐   ┌─────────▼─────────┐
    │  Static Pipeline  │   │ Dynamic Pipeline  │   │   RAG Pipeline    │
    │  (纯源码分析)       │   │ (沙箱+内核监控)    │   │  (知识库增强)      │
    │                    │   │                  │   │                   │
    │ • 传统关键词扫描    │   │ • Docker 隔离执行  │   │ • 知识图谱查询     │
    │ • AST 提取引擎     │   │ • eBPF 内核探针   │   │ • 语义级检测       │
    │ • 调用图+可达性    │   │ • MCP Fuzzer     │   │ • LLM 判定        │
    │ • 污点数据流分析    │   │ • 行为分析器       │   │                   │
    │ • 反向Sink溯源     │   │ • CEF 日志输出    │   │                   │
    └─────────┬──────────┘   └─────────┬──────────┘   └─────────┬──────────┘
              │                        │                        │
              └────────────────────────┼────────────────────────┘
                                       │
                            ┌──────────▼───────────┐
                            │    DetectionResult    │
                            │  • findings           │
                            │  • total_score        │
                            │  • risk_level         │
                            │  • mitigations        │
                            └──────────┬───────────┘
                                       │
                            ┌──────────▼───────────┐
                            │    ReportBuilder      │
                            │  markdown / json /    │
                            │  jsonl (web portal)   │
                            └──────────────────────┘
```

---

## 静态分析引擎架构

```
源代码文件 (*.py, *.js, *.ts, *.mjs, *.tsx)
    │
    ▼
┌──────────────────────────────────────────┐
│  Phase 1: 提取 (Extractors)              │
│  • python_ast.py — Python ast.NodeVisitor│
│  • javascript_ts_tree_sitter.py — TS     │
│  产出: FunctionFact, ImportFact, CallFact│
│        EntryPointFact, SinkFact, SrcFact │
│        AssignFact                        │
└──────────────────┬───────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────┐
│  Phase 2: 调用图 (Call Graph)            │
│  • call_graph.py — build_call_graph()    │
│  符号解析 + 调用关系索引                  │
│  产出: CallGraph (正向+反向索引)          │
└──────────────────┬───────────────────────┘
                   │
          ┌────────┴────────┐
          ▼                 ▼
┌──────────────────┐  ┌──────────────────────┐
│ Path A: 正向分析  │  │ Path B: 反向溯源     │
│ EntryPoint→Sink  │  │ Sink→Root Function  │
│ 可达性 + 污点分析 │  │ (无MCP入口时兜底)    │
└────────┬─────────┘  └──────────┬───────────┘
         │                       │
         └───────────┬───────────┘
                     ▼
┌──────────────────────────────────────────┐
│  Phase 3: Finding Builder                │
│  → FindingFact (title, severity,         │
│     call_chain, evidence, dataflows)     │
└──────────────────┬───────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────┐
│  Phase 4: Adapter                        │
│  FindingFact → CapabilityFinding         │
└──────────────────────────────────────────┘
```

---

## 动态分析引擎架构

```
Docker 容器 (privileged, Ubuntu 22.04)
    │
    ├── entrypoint.sh: 创建 cgroup → 启动 Monitor → 启动 Fuzzer
    │
    ├── eBPF Monitor (Python, 用户态)
    │   └── 加载 bpf_programs.c → perf buffer poll → CEF 日志
    │
    ├── MCP Fuzzer (Python)
    │   └── MCP handshake → tools/list → 注入 payload → tools/call
    │
    └── Linux Kernel
        └── eBPF 探针: openat/read/write/unlinkat/execve/connect/fork
            └── cgroup v2 边界过滤 (is_target)
```

---

## 目录结构速览

```
mcp-sec-audit/
│
├── README.md                           # 项目主 README（架构图 + 摘要）
├── docs/                               # 文档
│   ├── PROJECT_OVERVIEW.md             # ← 本文件（项目全貌）
│   ├── STATIC_ANALYSIS_DEEP_DIVE.md    # 静态分析技术深度解读
│   ├── DYNAMIC_ANALYSIS_DEEP_DIVE.md   # 动态分析技术深度解读
│   └── RUN_GUIDE.md                    # 操作手册
│
├── detection/                          # ★ 核心检测引擎
│   ├── pyproject.toml                  # Python 项目配置 + 依赖声明
│   │
│   ├── detection/                      # 检测框架主包
│   │   ├── cli.py                      # 命令行入口
│   │   ├── core/models.py              # CapabilityFinding, DetectionResult
│   │   ├── core/registry.py            # 插件注册表
│   │   ├── core/session.py             # 检测会话
│   │   ├── pipelines/static.py         # 静态管线入口
│   │   ├── pipelines/dynamic.py        # 动态管线入口 + 两阶段
│   │   ├── pipelines/rag.py            # RAG 管线
│   │   ├── rules/loader.py             # TOML 规则加载
│   │   ├── rules/keywords.toml         # 检测规则定义
│   │   ├── plugins/static/             # 传统静态插件
│   │   ├── plugins/dynamic/            # 动态行为分析器
│   │   ├── plugins/rag/                # RAG 插件
│   │   ├── sandbox/runner.py           # 沙箱抽象协议
│   │   ├── sandbox/providers/docker_provider.py  # Docker 沙箱
│   │   ├── mitigation/                 # 缓解建议引擎
│   │   ├── reporting/                  # 报告生成 (markdown/json)
│   │   └── knowledge/                  # RAG 知识库
│   │
│   ├── analysis/                       # AST 静态分析核心引擎
│   │   ├── engine.py                   # 引擎入口
│   │   ├── facts/schema.py             # 10 种 Fact 数据模型
│   │   ├── facts/store.py              # 内存存储
│   │   ├── facts/ids.py                # 确定性 ID 生成
│   │   ├── facts/serialization.py      # JSON/JSONL 序列化
│   │   ├── extractors/python_ast.py    # Python AST 提取器
│   │   ├── extractors/javascript_ts_tree_sitter.py  # JS/TS 提取器
│   │   ├── extractors/dynamic.py        # CEF 日志解析器
│   │   ├── passes/call_graph.py        # 调用图 + 可达性
│   │   ├── passes/taint_lite.py        # 轻量污点分析
│   │   ├── passes/reverse_sink_trace.py # 反向 Sink 溯源
│   │   ├── passes/finding_builder.py   # 漏洞构建器
│   │   ├── passes/dynamic_correlation.py # 动静态关联
│   │   └── adapters/finding_adapter.py # FindingFact→CapFinding
│   │
│   ├── sandbox/                        # 容器内组件
│   │   ├── Dockerfile                  # 沙箱镜像
│   │   ├── docker-compose.yml          # 容器编排
│   │   └── monitors/
│   │       ├── entrypoint.sh           # 容器入口
│   │       ├── ebpf_monitor.py         # eBPF 监控器
│   │       ├── bpf_programs.c          # eBPF 内核探针
│   │       └── fuzzer.py              # MCP Fuzzer
│   │
│   ├── tests/                          # 测试
│   │   ├── unit/                       # 单元测试
│   │   ├── integration/                # 集成测试
│   │   └── benchmark_apifox_supply_chain.py
│   │
│   └── examples/                       # 示例 + 基准数据
│       ├── static_analysis_test.py     # 静态分析快速体验
│       ├── dynamic_analysis_demo.py    # 动态分析演示
│       └── benchmarks/                 # 基准测试数据集
│
└── web-detection-portal/               # Web 检测结果展示前端
    ├── app.py
    ├── detector.py
    └── main.py
```

---

## 关键技术点

| 技术 | 用途 | 所在文件 |
|------|------|----------|
| Python `ast` 模块 | 解析 Python 源码为 AST | `extractors/python_ast.py` |
| Tree-sitter | 解析 JS/TS 源码为 CST | `extractors/javascript_ts_tree_sitter.py` |
| 调用图 + BFS | 入口 → Sink 可达性 | `passes/call_graph.py` |
| 反向 BFS | Sink → 根函数溯源 | `passes/reverse_sink_trace.py` |
| Taint-Lite | 污点数据流分析 | `passes/taint_lite.py` |
| eBPF + BCC | 内核级系统调用监控 | `monitors/bpf_programs.c` + `ebpf_monitor.py` |
| cgroup v2 | 目标进程识别与过滤 | `monitors/entrypoint.sh` |
| MCP JSON-RPC | 协议感知的 Fuzz | `monitors/fuzzer.py` |
| CEF 格式 | 标准化安全事件日志 | `ebpf_monitor.py` |
| Docker SDK | 沙箱生命周期管理 | `providers/docker_provider.py` |

---

## 相关文档

| 文档 | 内容 |
|------|------|
| `docs/STATIC_ANALYSIS_DEEP_DIVE.md` | 静态分析完整技术解读（1827 行） |
| `docs/DYNAMIC_ANALYSIS_DEEP_DIVE.md` | 动态分析完整技术解读（1530 行） |
| `docs/RUN_GUIDE.md` | 运行操作手册 |
| `detection/sandbox/README.md` | 沙箱使用说明 |
