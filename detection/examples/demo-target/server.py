"""
Demo MCP Server — intentionally vulnerable for security testing.

This file contains multiple security issues that the mcp-sec-audit
static analysis engine should detect:

  1. RCE via subprocess.run with user input
  2. RCE via os.system with user input
  3. Dynamic code execution via eval()
  4. File read operations
  5. Network outbound requests
  6. Environment variable access
"""

import subprocess
import os
import json
import requests
from mcp.server import Server

server = Server("demo-server")


# ─── Vulnerability 1: RCE via subprocess.run ───────────────────────────
@server.tool()
def run_shell_command(command: str):
    """Execute an arbitrary shell command. (DANGEROUS)"""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


# ─── Vulnerability 2: RCE via os.system ─────────────────────────────────
@server.tool()
def system_call(cmd: str):
    """Run a system command via os.system. (DANGEROUS)"""
    return os.system(cmd)


# ─── Vulnerability 3: Dynamic code execution ────────────────────────────
@server.tool()
def evaluate_expression(expression: str):
    """Evaluate a Python expression dynamically. (DANGEROUS — eval injection)"""
    return eval(expression)


# ─── Vulnerability 4: File read with user-controlled path ───────────────
@server.tool()
def read_file(filepath: str):
    """Read a file from the filesystem. (DANGEROUS — path traversal)"""
    with open(filepath, "r") as f:
        return f.read()


# ─── Vulnerability 5: Network outbound ──────────────────────────────────
@server.tool()
def fetch_url(url: str):
    """Fetch content from an external URL. (DANGEROUS — SSRF)"""
    response = requests.get(url, timeout=10)
    return response.text


# ─── Vulnerability 6: Environment variable access ───────────────────────
@server.tool()
def get_secret(var_name: str):
    """Read an environment variable. (DANGEROUS — credential leak)"""
    return os.environ.get(var_name, "not set")


# ─── Non-entry but dangerous helper ─────────────────────────────────────
# (This won't be caught by Path A — MCP forward analysis —
#  but WILL be caught by Path B — reverse sink trace)

def dangerous_cleanup():
    """A helper function that deletes files — no MCP entrypoint."""
    os.system("rm -rf /tmp/important_data")


# ─── Benign function (should NOT trigger findings) ──────────────────────
def safe_greeting(name: str) -> str:
    """A harmless greeting function."""
    return f"Hello, {name}! Welcome to the demo server."


if __name__ == "__main__":
    print("[demo-server] MCP server ready (not actually starting — for static analysis demo only)")
