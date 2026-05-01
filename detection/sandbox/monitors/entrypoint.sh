#!/bin/bash
#
# MCP Security Sandbox Entrypoint
#
# This script:
# 1. Starts eBPF monitoring in background
# 2. Executes the Fuzzer which wraps the target MCP tool OR direct execution
# 3. Waits for analysis to complete
# 4. Exits with status

set -e

MONITOR_TIMEOUT=${MONITOR_TIMEOUT:-30}
LOG_LEVEL=${LOG_LEVEL:-INFO}
MODE=${MODE:-"mcp_fuzz"}

echo "[*] MCP Security Dynamic Analysis Sandbox"
echo "[*] Timeout: ${MONITOR_TIMEOUT}s"
echo "[*] Log Level: ${LOG_LEVEL}"
echo "[*] Mode: ${MODE}"

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

if [ "$MODE" = "direct_exec" ]; then
    echo "[*] Mode: direct_exec"

    # Determine target
    EXEC_CMD=""
    if [ -n "$TARGET_CMD" ]; then
        EXEC_CMD="$TARGET_CMD"
    elif [ -f "/target/run.sh" ]; then
        chmod +x /target/run.sh
        EXEC_CMD="/target/run.sh"
    else
        # Auto-detect: prefer .js, then .py
        JS_FILE=$(find /target -name "*.js" -not -path "*/node_modules/*" -type f | head -n 1)
        PY_FILE=$(find /target -name "*.py" -type f | head -n 1)
        if [ -n "$JS_FILE" ]; then
            EXEC_CMD="node $JS_FILE"
        elif [ -n "$PY_FILE" ]; then
            EXEC_CMD="python3 $PY_FILE"
        fi
    fi

    if [ -z "$EXEC_CMD" ]; then
        echo "[ERROR] No target to execute in direct_exec mode"
        kill $MONITOR_PID 2>/dev/null || true
        exit 1
    fi

    echo "[*] Executing: $EXEC_CMD"
    timeout ${MONITOR_TIMEOUT} $EXEC_CMD || true

else
    # mcp_fuzz mode (existing behavior)
    echo "[*] Mode: mcp_fuzz"

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
fi

# Stop monitor
kill $MONITOR_PID 2>/dev/null || true
wait $MONITOR_PID 2>/dev/null || true

echo "[*] Analysis complete. Logs written to /logs/events.cef"

# Copy any additional logs from target
if [ -d "/target/logs" ]; then
    cp -r /target/logs/* /logs/ 2>/dev/null || true
fi

exit ${EXIT_CODE:-0}
