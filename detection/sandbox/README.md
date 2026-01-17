# MCP Security Dynamic Analysis Sandbox

Docker-based sandbox with eBPF monitoring for runtime behavior analysis of MCP servers.

## Overview

This sandbox provides **kernel-level monitoring** of MCP tool execution using eBPF (Berkeley Packet Filter), capturing:

- **File system operations**: open, read, write, unlink
- **Network activity**: socket creation, connections, send/recv
- **Process management**: execve, fork, clone
- **Environment access**: getenv (via uprobe)

All events are logged in **CEF (Common Event Format)** for integration with SIEM systems.

## Architecture

```
┌────────────────────────────────────────┐
│  Detection Pipeline (Host)             │
│  ├─ Static Analysis → Risk Score       │
│  └─ Dynamic Analysis (if score ≥ 50)   │
│      ↓                                  │
│  ┌──────────────────────────────────┐  │
│  │  DockerSandboxProvider           │  │
│  └──────────────────────────────────┘  │
└─────────────────┬──────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│  Docker Container (Privileged)          │
│  ├─ Ubuntu 22.04 + BCC + Python 3.13    │
│  ├─ eBPF Probes (kernel hooks)          │
│  │   └─ Attached to syscalls            │
│  ├─ Target MCP Tool (isolated)          │
│  └─ CEF Logger → /logs/events.cef       │
└─────────────────────────────────────────┘
```

## Prerequisites

### System Requirements

- **Linux host** with kernel ≥ 4.4 (for eBPF support)
  - Recommended: kernel ≥ 5.x
- **Docker** daemon running
- **Privileged container** support (required for eBPF)

### Check Kernel Version

```bash
uname -r  # Should be >= 4.4
```

### Check BPF Support

```bash
ls /sys/kernel/debug/tracing  # Should exist
```

## Quick Start

### 1. Build the Sandbox Image

```bash
cd /Users/xin/Developer/python/mcp-security/detection/sandbox

# Option A: Docker Compose (recommended)
docker-compose build

# Option B: Docker CLI
docker build -t mcp-security-sandbox:latest .
```

### 2. Test the Sandbox

```bash
# Run a simple test
docker-compose run --rm mcp-sandbox python3 -c "print('Hello from sandbox')"
```

### 3. Use in Detection Pipeline

```python
from pathlib import Path
from detection.pipelines.dynamic import run_two_stage_pipeline
from detection.core.registry import DetectorRegistry

# Two-stage detection (recommended)
registry = DetectorRegistry()
result = run_two_stage_pipeline(
    target_path=Path("/path/to/mcp/tool"),
    registry=registry,
    policy_dir=Path("detection/mitigation/templates"),
    risk_threshold=50.0,  # Only run dynamic if static score ≥ 50
    dynamic_timeout=30,   # Sandbox timeout in seconds
)

print(f"Risk: {result.risk_level} (score: {result.total_score})")
print(f"Findings: {len(result.findings)}")
```

## Configuration

### Environment Variables

Set in `docker-compose.yml` or pass to `DockerSandboxProvider`:

| Variable          | Default | Description                              |
| ----------------- | ------- | ---------------------------------------- |
| `MONITOR_TIMEOUT` | `30`    | Max execution time (seconds)             |
| `LOG_LEVEL`       | `INFO`  | Logging verbosity                        |
| `CEF_VERSION`     | `0`     | CEF format version                       |
| `DEVICE_VENDOR`   | `MCP-Security` | CEF device vendor field           |
| `DEVICE_PRODUCT`  | `Dynamic-Detector` | CEF device product field      |

### Resource Limits

Prevent resource exhaustion (fork bombs, memory leaks):

```yaml
# docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '2.0'      # Max 2 CPU cores
      memory: 2G       # Max 2GB RAM
      pids: 512        # Max 512 processes
```

### Network Isolation

```yaml
# docker-compose.yml
networks:
  isolated_net:
    internal: true  # Set to true for complete isolation (no internet)
```

## CEF Log Format

Events are logged in Common Event Format (CEF) for SIEM integration:

### Example: File Read

```
CEF:0|MCP-Security|Dynamic-Detector|1.0|FILE_READ|Sensitive File Access|9|rt=2025-01-20T10:15:23.456 suser=root sproc=python spid=1234 dst=/etc/passwd act=read outcome=success bytesIn=2048
```

### Example: Network Connection

```
CEF:0|MCP-Security|Dynamic-Detector|1.0|NET_CONNECT|Outbound Connection|7|rt=2025-01-20T10:15:24.789 suser=root sproc=python spid=1234 dst=192.168.1.100:4444 proto=tcp outcome=success
```

### Example: Command Execution

```
CEF:0|MCP-Security|Dynamic-Detector|1.0|PROC_EXEC|Suspicious Command Execution|8|rt=2025-01-20T10:15:25.012 suser=root sproc=python spid=1234 dproc=bash cs1=/bin/bash cs1Label=Command
```

## Advanced Usage

### Manual Sandbox Execution

```python
from pathlib import Path
from detection.sandbox.providers import DockerSandboxProvider

# Initialize sandbox
sandbox = DockerSandboxProvider(
    image="mcp-security-sandbox:latest",
    network_mode="none",  # Complete network isolation
    resource_limits={
        "cpu_quota": 100000,
        "mem_limit": "1g",
        "pids_limit": 256,
    }
)

# Run target
result = sandbox.run(
    target_path=Path("/path/to/malicious/tool"),
    timeout=60
)

# Access telemetry
print(f"Exit code: {result.exit_code}")
print(f"Total events: {result.telemetry['total_events']}")
print(f"Sensitive paths: {result.telemetry['sensitive_paths']}")
print(f"Network destinations: {result.telemetry['network_destinations']}")

# Access raw CEF logs
with open("/tmp/logs/events.cef") as f:
    cef_logs = f.read()
```

### Dynamic-Only Analysis

Skip static analysis and run dynamic directly:

```python
from detection.pipelines.dynamic import run_dynamic_pipeline

result = run_dynamic_pipeline(
    target_path=Path("/path/to/tool"),
    registry=registry,
    timeout=45
)
```

### Custom Behavior Analysis

```python
from detection.plugins.dynamic import DynamicBehaviorAnalyzer

analyzer = DynamicBehaviorAnalyzer(
    capability_weights={
        "command_exec": 30.0,   # Increase weight
        "file_read": 10.0,
        # ... other capabilities
    }
)

findings = analyzer.analyze(cef_logs, target_path)
```

## Troubleshooting

### Error: "BPF tracing not available"

**Cause**: BPF filesystem not mounted or insufficient privileges.

**Solution**:
```bash
# Check if debugfs is mounted
mount | grep debugfs

# If not, mount it
sudo mount -t debugfs none /sys/kernel/debug
```

### Error: "Docker daemon not running"

**Solution**:
```bash
# Start Docker
sudo systemctl start docker

# Enable on boot
sudo systemctl enable docker
```

### Error: "Image not found"

**Solution**: Build the image first (see Quick Start step 1)

### Permission Denied Errors

**Cause**: Container needs privileged mode for eBPF.

**Solution**: Ensure `privileged: true` in docker-compose.yml

### High CPU Usage

**Cause**: eBPF probes generate many events.

**Solution**:
- Reduce timeout
- Add event filtering in `ebpf_monitor.py`
- Limit probe scope

## Security Considerations

### Sandbox Safety

The sandbox uses multiple isolation layers:

1. **Container isolation**: Docker namespace/cgroup separation
2. **Network isolation**: Configurable (bridge/none/host)
3. **Resource limits**: CPU/memory/PID caps
4. **Read-only target mount**: Prevents target modification

### Privileged Container Risks

eBPF requires `--privileged` mode, which:

- ✅ **Safe for**: Dedicated analysis hosts, CI/CD pipelines
- ⚠️ **Risk**: Container escape vulnerabilities
- 🚫 **Not for**: Multi-tenant production environments

**Mitigation**:
- Run sandbox on dedicated VM/host
- Use AppArmor/SELinux profiles
- Regular security updates

## Performance

### Benchmark Results

Tested on Ubuntu 22.04, 4-core CPU, 8GB RAM:

| Metric               | Value        |
| -------------------- | ------------ |
| Startup overhead     | ~2 seconds   |
| Event capture rate   | ~10k events/sec |
| CPU overhead         | 5-15% per core |
| Memory overhead      | ~100-200 MB  |

### Optimization Tips

1. **Use two-stage pipeline**: Skip dynamic for low-risk targets
2. **Tune timeout**: 30s is usually sufficient
3. **Limit network scope**: Use `network_mode: "none"` when possible
4. **Batch analysis**: Run multiple analyses in parallel (different containers)

## Integration

### CI/CD Pipeline

```yaml
# .github/workflows/security-scan.yml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build sandbox
        run: |
          cd detection/sandbox
          docker-compose build

      - name: Run dynamic analysis
        run: |
          python -m detection.cli scan \
            --target ./my-mcp-tool \
            --pipeline two-stage \
            --risk-threshold 50
```

### SIEM Integration

Forward CEF logs to your SIEM (Splunk, ArcSight, QRadar):

```bash
# Using syslog-ng
tail -f /logs/events.cef | \
  syslog-ng -F --no-caps \
    --source stdin \
    --destination syslog://siem.example.com:514
```

## Contributing

To extend the sandbox:

1. **Add new syscall hooks**: Edit `monitors/bpf_programs.c`
2. **Enhance analysis**: Modify `plugins/dynamic/__init__.py`
3. **Add capabilities**: Update `rules/keywords.toml`

## License

See main project LICENSE file.

## References

- [eBPF Documentation](https://ebpf.io/)
- [BCC (BPF Compiler Collection)](https://github.com/iovisor/bcc)
- [CEF Format Specification](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
