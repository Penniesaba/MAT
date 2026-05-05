# LiteLLM MCP stdio Command Execution Benchmark Fixture

## Overview

This fixture reproduces the **LiteLLM MCP stdio command execution** risk pattern for detector-driven dynamic analysis inside a Docker sandbox.

**Purpose**: Detector benchmark target — not a real attack tool. Used with `detection/cli.py ... --pipeline dynamic` inside an eBPF-monitored sandbox.

## What It Does

1. `setup.sh` installs LiteLLM with proxy support (`litellm[proxy]==1.83.6`).
2. `run.sh` starts a local LiteLLM proxy and sends an MCP stdio payload that executes:
   ```python
   open('/tmp/litellm_mcp_detector_poc','w').write('executed')
   ```
   The payload uses `transport: stdio`, `command: python3`, and passes the Python one-liner as args.

## Security Boundaries

| Property | Value |
|---|---|
| Payload target | `/tmp/litellm_mcp_detector_poc` inside container |
| No host access | True — file is container-local `/tmp` |
| No network exfiltration | True — no outbound connections |
| No destructive commands | True — only writes harmless file |
| Self-contained | True — no external dependencies |

## Expected Detector Behavior

The eBPF monitor should capture:
- `command_exec` event for `python3 -c ...`
- `file_write` event for `/tmp/litellm_mcp_detector_poc`
- `process` events correlated to the target cgroup

## Usage

```bash
# Inside Docker sandbox (setup runs automatically via entrypoint.sh pre-monitor hook)
docker run --privileged --rm \
  -v $(pwd)/detection/examples/benchmarks/recent-mcp/litellm-mcp-stdio-command-exec:/target \
  ghcr.io/your/sandbox-image

# Manual execution order
docker exec <container> /target/setup.sh
docker exec <container> /target/run.sh
```

## File Structure

```
litellm-mcp-stdio-command-exec/
├── README.md       # This file
├── setup.sh        # Installs litellm[proxy]==1.83.6
└── run.sh          # Starts proxy, sends MCP stdio payload, verifies file
```

## Exit Codes

- `0` — File `/tmp/litellm_mcp_detector_poc` was created (success)
- `1` — File was not created (failure — command may have been blocked)