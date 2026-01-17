#!/bin/bash
#
# MCP Security Sandbox Entrypoint
#
# This script:
# 1. Starts eBPF monitoring in background
# 2. Executes the target MCP tool
# 3. Waits for monitoring to complete
# 4. Exits with target's exit code

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

# Find and execute target MCP tool
# Look for common entry points: server.py, main.py, __main__.py
TARGET_SCRIPT=""
for candidate in "/target/server.py" "/target/main.py" "/target/__main__.py" "/target/src/server.py"; do
    if [ -f "$candidate" ]; then
        TARGET_SCRIPT="$candidate"
        break
    fi
done

# If no standard entry point found, try to find any Python file
if [ -z "$TARGET_SCRIPT" ]; then
    TARGET_SCRIPT=$(find /target -name "*.py" -type f | head -n 1)
fi

if [ -z "$TARGET_SCRIPT" ]; then
    echo "[ERROR] No Python entry point found in /target"
    kill $MONITOR_PID 2>/dev/null || true
    exit 1
fi

echo "[*] Executing target: $TARGET_SCRIPT"

# Execute target in background with timeout
timeout ${MONITOR_TIMEOUT} python3 "$TARGET_SCRIPT" &
TARGET_PID=$!

# Wait for either monitor or target to finish
wait $TARGET_PID
TARGET_EXIT_CODE=$?

# Stop monitor
kill $MONITOR_PID 2>/dev/null || true
wait $MONITOR_PID 2>/dev/null || true

echo "[*] Target exited with code: $TARGET_EXIT_CODE"
echo "[*] Analysis complete. Logs written to /logs/events.cef"

# Copy any additional logs from target
if [ -d "/target/logs" ]; then
    cp -r /target/logs/* /logs/ 2>/dev/null || true
fi

exit $TARGET_EXIT_CODE
