# 快速开始: Docker + eBPF 动态分析

5 分钟上手 MCP Security 动态监控系统

## 前置条件检查

```bash
# 1. 检查 Linux 内核版本 (需要 >= 4.4)
uname -r

# 2. 检查 Docker 是否运行
docker ps

# 3. 检查 BPF 支持
ls /sys/kernel/debug/tracing

# 如果上述目录不存在，挂载 debugfs:
sudo mount -t debugfs none /sys/kernel/debug
```

## 第一步: 构建沙箱镜像

```bash
cd /Users/xin/Developer/python/mcp-security/detection/sandbox

# 使用 Docker Compose (推荐)
docker-compose build

# 或使用 Docker CLI
docker build -t mcp-security-sandbox:latest .
```

**构建时间**: 约 5-10 分钟（首次构建需要下载 BCC 和 Python 3.13）

## 第二步: 验证安装

```bash
# 测试容器是否正常启动
docker-compose run --rm mcp-sandbox python3 -c "print('Sandbox works!')"

# 预期输出:
# [*] MCP Security Dynamic Analysis Sandbox
# [*] Timeout: 30s
# [*] Starting eBPF monitor...
# Sandbox works!
```

## 第三步: 运行示例分析

### 方法 A: 使用 Python API

```python
from pathlib import Path
from detection.pipelines.dynamic import run_two_stage_pipeline
from detection.core.registry import DetectorRegistry
from detection.plugins.static.python import register as register_python

# 初始化
registry = DetectorRegistry()
register_python(registry)

# 运行两阶段分析
result = run_two_stage_pipeline(
    target_path=Path("/path/to/your/mcp/tool"),
    registry=registry,
    policy_dir=Path("detection/mitigation/templates"),
    risk_threshold=50.0,  # 静态评分 ≥ 50 才进入动态沙箱
    dynamic_timeout=30
)

# 查看结果
print(f"风险等级: {result.risk_level}")
print(f"总分: {result.total_score}")
print(f"发现数: {len(result.findings)}")

for finding in result.findings:
    print(f"\n{finding.name}:")
    print(f"  置信度: {finding.confidence:.2f}")
    print(f"  证据源: {[s.value for s in finding.sources]}")
    for evidence in finding.evidence[:3]:
        print(f"  - {evidence}")
```

### 方法 B: 使用演示脚本

```bash
cd /Users/xin/Developer/python/mcp-security/detection

# 运行完整演示（会创建测试样本并运行分析）
python examples/dynamic_analysis_demo.py
```

**预期输出**:
```
╔══════════════════════════════════════════════════════════════╗
║  MCP Security Dynamic Analysis Demo                          ║
║  Docker + eBPF Runtime Behavior Monitoring                   ║
╚══════════════════════════════════════════════════════════════╝

Creating sample malicious MCP tool...
Tool created at: /tmp/mcp-malicious-xxx

============================================================
PHASE 1: STATIC ANALYSIS
============================================================

Server: mcp-malicious-xxx
Risk Level: HIGH
Total Score: 65.0/100

Detected Capabilities (3):
  • command_exec
    Confidence: 0.85
    Evidence: subprocess.run

  • file_read
    Confidence: 0.72
    Evidence: open('/etc/passwd')

  • network_outbound
    Confidence: 0.68
    Evidence: urllib.request

============================================================
PHASE 2: DYNAMIC ANALYSIS
============================================================

Starting Docker sandbox with eBPF monitoring...

Server: mcp-malicious-xxx
Risk Level: CRITICAL
Total Score: 78.5/100

Runtime Capabilities (4):
  • command_exec [static, dynamic]
    Confidence: 0.92
    - Executed: bash
    - Executed: whoami

  • file_read [static, dynamic]
    Confidence: 0.88
    - ⚠️  Sensitive file read: /etc/passwd

=== Dynamic Analysis Telemetry ===

Execution time: 2.34s
Exit code: 0

Captured events: 127
  - File operations: 45
  - Network activity: 8
  - Process management: 12

⚠️  Sensitive paths accessed:
  - /etc/passwd
```

## 常见用例

### 1. 分析单个 MCP 工具

```python
from detection.sandbox.providers import DockerSandboxProvider
from detection.plugins.dynamic import analyze_behavior

# 运行沙箱
sandbox = DockerSandboxProvider()
result = sandbox.run(Path("/path/to/tool"), timeout=30)

# 分析行为
findings = analyze_behavior(result.logs, Path("/path/to/tool"))

# 查看发现
for finding in findings:
    print(f"{finding.name}: {finding.confidence:.2f}")
```

### 2. 批量扫描 MCP 工具集合

```python
from pathlib import Path

tools = [
    Path("/tools/tool1"),
    Path("/tools/tool2"),
    Path("/tools/tool3"),
]

for tool in tools:
    result = run_two_stage_pipeline(
        target_path=tool,
        registry=registry,
        policy_dir=policy_dir,
        risk_threshold=50.0
    )

    print(f"{tool.name}: {result.risk_level} ({result.total_score})")
```

### 3. 仅运行动态分析（跳过静态）

```python
from detection.pipelines.dynamic import run_dynamic_pipeline

result = run_dynamic_pipeline(
    target_path=Path("/path/to/tool"),
    registry=registry,
    timeout=45
)
```

### 4. 完全网络隔离测试

```python
sandbox = DockerSandboxProvider(network_mode="none")
result = sandbox.run(Path("/path/to/tool"), timeout=30)

# 网络事件应该为 0（除了 loopback）
net_events = result.telemetry.get("network_events", 0)
print(f"Network events detected: {net_events}")
```

## 配置调优

### 降低资源消耗

编辑 `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      cpus: '1.0'      # 减少到 1 核
      memory: 1G       # 减少到 1GB
      pids: 256        # 减少进程限制
```

### 调整监控超时

```python
result = run_two_stage_pipeline(
    target_path=tool_path,
    registry=registry,
    policy_dir=policy_dir,
    dynamic_timeout=15  # 从 30s 减少到 15s
)
```

### 提高风险阈值

只对高风险目标进行动态分析:

```python
result = run_two_stage_pipeline(
    target_path=tool_path,
    registry=registry,
    policy_dir=policy_dir,
    risk_threshold=70.0  # 从 50 提高到 70
)
```

## 查看 CEF 日志

动态分析生成的原始 CEF 日志位于:

```bash
# 日志路径 (取决于挂载配置)
cat /tmp/mcp-sandbox-*/logs/events.cef

# 或在 Docker Compose 中查看
docker-compose logs mcp-sandbox
```

**CEF 日志示例**:
```
CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_READ|File Read|5|rt=2025-01-20T10:15:23.456 suser=root sproc=python dst=/etc/passwd act=read bytesIn=2048

CEF:0|MCP-Security|Dynamic-Detector|1.0|NET_CONNECT|Outbound Connection|7|rt=2025-01-20T10:15:24.789 sproc=python dst=192.168.1.100:4444 proto=tcp outcome=success

CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Command Execution|8|rt=2025-01-20T10:15:25.012 sproc=python dproc=bash cs1=/bin/bash cs1Label=Command
```

## 集成到 CI/CD

### GitHub Actions 示例

```yaml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker
        uses: docker/setup-buildx-action@v2

      - name: Build sandbox
        run: |
          cd detection/sandbox
          docker-compose build

      - name: Run security scan
        run: |
          python examples/dynamic_analysis_demo.py

      - name: Check results
        run: |
          # 如果检测到高风险，失败构建
          if grep -q "CRITICAL" scan_results.txt; then
            exit 1
          fi
```

## 故障排查

### 问题: "Docker not available"

**解决**:
```bash
# 启动 Docker
sudo systemctl start docker

# 检查权限
sudo usermod -aG docker $USER
newgrp docker
```

### 问题: "BPF tracing not available"

**解决**:
```bash
# 挂载 debugfs
sudo mount -t debugfs none /sys/kernel/debug

# 检查内核版本
uname -r  # 应该 >= 4.4

# 如果内核太旧，升级:
sudo apt update && sudo apt upgrade
```

### 问题: 容器启动失败

**检查**:
```bash
# 查看容器日志
docker logs <container_id>

# 检查特权模式
docker inspect <container_id> | grep -i privileged

# 手动启动测试
docker run --privileged --rm mcp-security-sandbox:latest python3 -c "print('test')"
```

### 问题: 性能较慢

**优化**:
1. 减少监控超时: `dynamic_timeout=15`
2. 提高风险阈值: `risk_threshold=70.0`
3. 使用 SSD 存储
4. 增加 Docker 资源限制

## 下一步

- 📖 阅读完整文档: `sandbox/README.md`
- 🔧 查看实现细节: `docs/DYNAMIC_ANALYSIS.md`
- 🧪 运行集成测试: `pytest tests/integration/test_dynamic_pipeline.py -v`
- 📊 查看项目状态: `README.md`

## 获取帮助

- GitHub Issues: https://github.com/your-org/mcp-security/issues
- 文档: `detection/docs/`
- 示例: `detection/examples/`

---

**祝你使用愉快！** 🚀
