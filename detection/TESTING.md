# Testing MCP Security Detection Tools

本文档介绍如何测试 MCP Security 检测工具（包括静态分析和动态分析）。

## 快速测试（推荐）

### 1. 静态分析测试（无需 Docker）

最简单的测试方式，只需要 Python 环境：

```bash
cd /Users/xin/Developer/python/mcp-security/detection
python examples/static_analysis_test.py
```

**预期输出：**
```
╔══════════════════════════════════════════════════════════════╗
║  MCP Security Static Analysis Test                           ║
║  Testing detection capabilities without Docker                ║
╚══════════════════════════════════════════════════════════════╝

Creating sample malicious MCP tool...
Tool created at: /tmp/mcp-test-xxx

============================================================
STATIC ANALYSIS RESULTS
============================================================

Server: mcp-test-xxx
Risk Level: MEDIUM
Total Score: 38.0/100

Detected Capabilities (4):

  • command_exec
    Confidence: 0.55
    Weight: 25.0
    Sources: ['static']
    Evidence:
      - subprocess.
      - subprocess.run

  • file_read
    Confidence: 0.50
    Weight: 15.0
    Sources: ['static']
    Evidence:
      - open(
      - open('/etc/passwd', 'r')

  • file_write
    Confidence: 0.45
    Weight: 15.0

  • network_outbound
    Confidence: 0.50
    Weight: 20.0
    Evidence:
      - urllib.request

🛡️  Recommended Mitigations (8):
1. Run the server inside a Docker container with no-new-privileges.
2. Disable outbound networking or restrict to vetted destinations.
3. Mount sensitive directories as read-only overlays or exclude them entirely.

============================================================
DETECTED SECURITY ISSUES
============================================================
  ✓ Command execution detected
  ✓ File read operations detected
  ✓ Network operations detected
```

**验证成功标准：**
- ✅ 检测到 4 个能力（command_exec, file_read, file_write, network_outbound）
- ✅ 风险等级为 MEDIUM
- ✅ 总分约为 38-40/100
- ✅ 生成了缓解建议

---

## 2. 完整演示（包含动态分析）

需要 Docker 和 eBPF 支持：

```bash
cd /Users/xin/Developer/python/mcp-security/detection
python examples/dynamic_analysis_demo.py
```

**注意：** 
- 如果没有 Docker，动态分析部分会跳过，但静态分析仍然会运行
- 动态分析需要 Linux 系统和 kernel >= 4.4

---

## 3. 单元测试

运行集成测试（需要 Docker）：

```bash
cd /Users/xin/Developer/python/mcp-security/detection
python -m pytest tests/integration/test_dynamic_pipeline.py::TestDynamicPipeline
```

---

## 测试组件说明

### 静态分析能力

静态分析器可以检测以下内容：

1. **命令执行 (command_exec)**
   - `subprocess.run`, `os.system`, `shell=True`
   - 置信度基于检测到的模式数量

2. **文件读取 (file_read)**
   - `open()`, `read()`, 文件路径访问
   - 敏感文件（如 `/etc/passwd`）会提升置信度

3. **文件写入 (file_write)**
   - `open()` with write mode, `write()`

4. **网络通信 (network_outbound)**
   - `urllib.request`, `requests`, `socket`
   - HTTP/HTTPS 连接

5. **环境变量读取 (env_read)**
   - `os.getenv()`, `os.environ`

### 动态分析能力（需要 Docker + eBPF）

动态分析通过运行时监控检测：

1. **实际的系统调用**
   - 进程执行 (execve)
   - 文件操作 (open, read, write)
   - 网络连接 (connect, sendto)

2. **敏感路径访问**
   - `/etc/passwd`, `/.ssh/`, `/.aws/`
   - 凭证文件

3. **网络目标**
   - 实际连接的 IP 和端口
   - 排除 localhost

---

## 构建 Docker 沙箱（可选）

如果想测试动态分析，需要先构建沙箱镜像：

### 前置条件

1. **Docker 已安装并运行**
   ```bash
   docker --version
   docker ps
   ```

2. **Linux 系统** (macOS 和 Windows 上 eBPF 支持有限)

### 构建步骤

```bash
cd /Users/xin/Developer/python/mcp-security/detection/sandbox

# 方法 1: 使用 docker-compose（推荐）
docker-compose build

# 方法 2: 使用 docker CLI
docker build -t mcp-security-sandbox:latest .
```

构建时间：约 5-10 分钟（首次构建）

### 验证构建

```bash
docker images | grep mcp-security-sandbox
# 应该看到: mcp-security-sandbox   latest   xxx   xxx   xxx
```

---

## 故障排查

### 问题：ModuleNotFoundError

```
ModuleNotFoundError: No module named 'detection'
```

**解决：** 确保在 detection 目录下运行：
```bash
cd /Users/xin/Developer/python/mcp-security/detection
python examples/static_analysis_test.py
```

### 问题：Docker not available

```
RuntimeError: Docker Python SDK not available
```

**解决：** 
1. 安装 Docker SDK: `pip install docker`
2. 或者只运行静态分析测试（不需要 Docker）

### 问题：Sandbox image not found

```
RuntimeError: Sandbox image 'mcp-security-sandbox:latest' not found
```

**解决：** 构建沙箱镜像（见上面的"构建 Docker 沙箱"部分）

---

## 测试自定义 MCP 工具

### 测试自己的 MCP 工具

```python
from pathlib import Path
from detection.core.registry import DetectorRegistry
from detection.pipelines.static import run_static_pipeline
from detection.plugins.static.python import register as register_python
from detection.rules import load_rulebook

# 加载规则
rules_path = Path("detection/rules/keywords.toml")
rulebook = load_rulebook(rules_path)

# 设置注册表
registry = DetectorRegistry()
register_python(registry, rulebook)

# 分析你的工具
tool_path = Path("/path/to/your/mcp/tool")
policy_dir = Path("detection/mitigation/templates")
result = run_static_pipeline(tool_path, registry, policy_dir)

# 查看结果
print(f"Risk Level: {result.risk_level}")
print(f"Total Score: {result.total_score}")
print(f"Findings: {len(result.findings)}")

for finding in result.findings:
    print(f"\n{finding.name}: {finding.confidence:.2f}")
    for evidence in finding.evidence[:3]:
        print(f"  - {evidence}")
```

---

## 性能基准

在标准测试用例上：

- **静态分析**: < 1 秒
- **动态分析**: 5-20 秒（取决于工具复杂度）
- **两阶段分析**: 静态 + 动态时间

---

## 下一步

- 📖 查看 [QUICKSTART.md](sandbox/QUICKSTART.md) 了解详细的动态分析配置
- 🔧 查看 [README.md](README.md) 了解整体架构
- 🐛 提交问题到 GitHub Issues

---

**测试成功？** 现在可以：
1. 分析真实的 MCP 工具
2. 集成到 CI/CD 管道
3. 自定义检测规则（编辑 `detection/rules/keywords.toml`）
