#!/bin/bash
#
# MCP Security Sandbox Entrypoint
#
# This script:
# 1. Starts eBPF monitoring in background
# 2. Executes the Fuzzer which wraps the target MCP tool
# 3. Waits for analysis to complete
# 4. Exits with status

set -e

MONITOR_TIMEOUT=${MONITOR_TIMEOUT:-30}
LOG_LEVEL=${LOG_LEVEL:-INFO}

echo "[*] MCP Security Dynamic Analysis Sandbox"
echo "[*] Timeout: ${MONITOR_TIMEOUT}s"
echo "[*] Log Level: ${LOG_LEVEL}"

# Mount debugfs if not already mounted (required for eBPF tracing)
if [ ! -d "/sys/kernel/debug/tracing" ]; then
    echo "[*] Mounting debugfs for eBPF tracing..."
    mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
fi

# Check if BPF filesystem is mounted
if [ ! -d "/sys/kernel/debug/tracing" ]; then
    echo "[ERROR] BPF tracing not available. Is the container running with --privileged?"
    exit 1
fi

# Check if target directory exists
if [ ! -d "/target" ]; then
    echo "[ERROR] Target directory /target not mounted"
    exit 1
fi

# Start eBPF monitor in background
echo "[*] Starting eBPF monitor..."
python3 /monitor/ebpf_monitor.py &
MONITOR_PID=$!

# Give monitor time to attach probes
sleep 2

# Determine Target Command
TARGET_CMD=""

# Priority 1: run.sh
if [ -f "/target/run.sh" ]; then
    echo "[*] Found run.sh"
    chmod +x /target/run.sh
    TARGET_CMD="/target/run.sh"

# Priority 2: Node.js package
elif [ -f "/target/package.json" ]; then
    echo "[*] Found package.json"
    if [ ! -d "/target/node_modules" ]; then
        echo "[*] Installing Node dependencies..."
        # We need to write to /target, assumed writable
        cd /target && npm install && cd /
    fi
    TARGET_CMD="node /target/index.js"

# Priority 3: Special case for filesystem-actions (needs argument)
elif [ -f "/target/vulnerable-mcp-server-filesystem-workspace-actions-mcp.py" ]; then
    echo "[*] Found filesystem-actions server"
    if [ ! -d "/target/sandbox-workspace" ]; then
        mkdir -p /target/sandbox-workspace
    fi
    TARGET_CMD="python3 /target/vulnerable-mcp-server-filesystem-workspace-actions-mcp.py /target/sandbox-workspace"

# Priority 4: Generic Python script
else
    SCRIPT=$(find /target -name "*.py" -type f | head -n 1)
    if [ -n "$SCRIPT" ]; then
        echo "[*] Found Python script: $SCRIPT"
        TARGET_CMD="python3 $SCRIPT"
    fi
fi

if [ -z "$TARGET_CMD" ]; then
    echo "[ERROR] No runnable target found in /target"
    kill $MONITOR_PID 2>/dev/null || true
    exit 1
fi

echo "[*] Starting Fuzzer against: $TARGET_CMD"

# Run Fuzzer (which runs Target) with timeout
# We use 'timeout' command to enforce the limit
timeout ${MONITOR_TIMEOUT} python3 /monitor/fuzzer.py $TARGET_CMD &
FUZZER_PID=$!

# Wait for Fuzzer
wait $FUZZER_PID
EXIT_CODE=$?

# If timeout occurred (exit code 124), that's fine, we just stop
if [ $EXIT_CODE -eq 124 ]; then
    echo "[*] Analysis timed out (expected)"
    EXIT_CODE=0
fi

# Stop monitor
kill $MONITOR_PID 2>/dev/null || true
wait $MONITOR_PID 2>/dev/null || true

echo "[*] Analysis complete. Logs written to /logs/events.cef"

# Copy any additional logs from target
if [ -d "/target/logs" ]; then
    cp -r /target/logs/* /logs/ 2>/dev/null || true
fi

exit $EXIT_CODE
