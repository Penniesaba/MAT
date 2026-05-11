#!/bin/bash
#
# MCP Security Sandbox Entrypoint
#
# This script:
# 1. Phase 1: Prepares target (npm install etc.) - BEFORE monitor starts
# 2. Phase 2: Starts eBPF monitoring in background
# 3. Phase 3: Executes the Fuzzer or direct execution
# 4. Waits for analysis to complete
# 5. Exits with status

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

# Allow BPF perf event attachment (required for tracepoints)
echo 0 > /proc/sys/kernel/perf_event_paranoid 2>/dev/null || true

# Check if target directory exists
if [ ! -d "/target" ]; then
    echo "[ERROR] Target directory /target not mounted"
    exit 1
fi

# ============================================================================
# Phase 1: Prepare cgroup boundary + target (BEFORE monitor starts)
# ============================================================================

# Verify cgroup v2 is in use and /sys/fs/cgroup is writable
if [ ! -f "/sys/fs/cgroup/cgroup.controllers" ] && [ ! -d "/sys/fs/cgroup/unified" ]; then
    echo "[ERROR] cgroup v2 not detected. This sandbox requires cgroup v2."
    exit 1
fi

if [ ! -w "/sys/fs/cgroup" ]; then
    echo "[ERROR] /sys/fs/cgroup is not writable."
    exit 1
fi

# Create target cgroup for the MCP server
MCP_TARGET_CGROUP_PATH="/sys/fs/cgroup/mcp-target"
if [ ! -d "$MCP_TARGET_CGROUP_PATH" ]; then
    mkdir -p "$MCP_TARGET_CGROUP_PATH"
fi

# Verify cgroup.procs is writable
if [ ! -w "$MCP_TARGET_CGROUP_PATH/cgroup.procs" ]; then
    echo "[ERROR] $MCP_TARGET_CGROUP_PATH/cgroup.procs is not writable."
    exit 1
fi

# Compute cgroup inode number (used by eBPF to correlate PIDs)
MCP_TARGET_CGROUP_ID=$(stat -c "%i" "$MCP_TARGET_CGROUP_PATH" 2>/dev/null)
if [ -z "$MCP_TARGET_CGROUP_ID" ]; then
    echo "[ERROR] Failed to stat $MCP_TARGET_CGROUP_PATH"
    exit 1
fi

export MCP_TARGET_CGROUP_PATH
export MCP_TARGET_CGROUP_ID

echo "[*] Target cgroup: $MCP_TARGET_CGROUP_PATH (id=$MCP_TARGET_CGROUP_ID)"

# Prepare target command
TARGET_CMD=()
TARGET_CMD_DISPLAY=""

if [ -f "/target/run.sh" ]; then
    chmod +x /target/run.sh
    TARGET_CMD=("/target/run.sh")
    TARGET_CMD_DISPLAY="/target/run.sh"
elif [ -f "/target/package.json" ]; then
    if [ ! -d "/target/node_modules" ]; then
        echo "[*] Installing Node dependencies..."
        cd /target && npm install && cd /
    fi
    TARGET_CMD=("node" "/target/index.js")
    TARGET_CMD_DISPLAY="node /target/index.js"
elif [ -f "/target/vulnerable-mcp-server-filesystem-workspace-actions-mcp.py" ]; then
    if [ ! -d "/target/sandbox-workspace" ]; then
        mkdir -p /target/sandbox-workspace
    fi
    TARGET_CMD=("python3" "/target/vulnerable-mcp-server-filesystem-workspace-actions-mcp.py" "/target/sandbox-workspace")
    TARGET_CMD_DISPLAY="python3 /target/vulnerable-mcp-server-filesystem-workspace-actions-mcp.py /target/sandbox-workspace"
else
    JS_FILE=$(find /target -name "*.js" -not -path "*/node_modules/*" -type f | head -n 1)
    if [ -n "$JS_FILE" ]; then
        TARGET_CMD=("node" "$JS_FILE")
        TARGET_CMD_DISPLAY="node $JS_FILE"
    else
        SCRIPT=$(find /target -name "*.py" -type f | head -n 1)
        if [ -n "$SCRIPT" ]; then
            TARGET_CMD=("python3" "$SCRIPT")
            TARGET_CMD_DISPLAY="python3 $SCRIPT"
        fi
    fi
fi

if [ ${#TARGET_CMD[@]} -eq 0 ]; then
    echo "[ERROR] No runnable target found in /target"
    exit 1
fi

# ============================================================================
# Pre-Monitor Setup Hook
# ============================================================================

if [ -f "/target/setup.sh" ]; then
    chmod +x /target/setup.sh
    echo "[*] Running target setup before monitor..."
    /target/setup.sh
fi

# ============================================================================
# Phase 2: Start eBPF monitor
# ============================================================================


echo "[*] Starting eBPF monitor..."
python3 /monitor/ebpf_monitor.py &
MONITOR_PID=$!
sleep 2

# ============================================================================
# Phase 3: Execute target
# ============================================================================
if [ "$MODE" = "direct_exec" ]; then
    echo "[*] Mode: direct_exec, executing: $TARGET_CMD_DISPLAY"

    # Add ourselves to the target cgroup, then exec the target command.
    # timeout returns 124 on timeout, which we normalize to 0 per monitor semantics.
    set +e
    timeout ${MONITOR_TIMEOUT} bash -lc 'set -e; echo $$ > "$MCP_TARGET_CGROUP_PATH/cgroup.procs"; exec "$@"' _ "${TARGET_CMD[@]}"
    EXIT_CODE=$?
    set -e
    if [ $EXIT_CODE -eq 124 ]; then
        echo "[*] Analysis timed out (expected)"
        EXIT_CODE=0
    fi
else
    echo "[*] Mode: mcp_fuzz, fuzzer targeting: $TARGET_CMD_DISPLAY"

    # Run Fuzzer (which runs Target) with timeout
    timeout ${MONITOR_TIMEOUT} python3 /monitor/fuzzer.py "${TARGET_CMD[@]}" &
    FUZZER_PID=$!

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