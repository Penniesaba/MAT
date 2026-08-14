"""Test MCP server with intentional vulnerabilities for static analysis validation.

This file is a deliberately vulnerable MCP server designed to test all four
analysis lines (Rule, Taint, Agent, CodeQL) of the MCP Security Auditor.

Vulnerabilities:
  - run_shell:   Command Injection via subprocess
  - read_log:    Path Traversal via open()
  - fetch_url:   SSRF via requests.get()

Design features for analysis validation:
  - Import aliases (import subprocess as sp) → tests alias resolution
  - Assignment aliases (runner = sp.run) → tests variable tracking
  - Cross-function helpers (normalize_path, build_command) → tests taint propagation
  - MCP decorators (@mcp.tool()) → tests entrypoint detection
  - Fake validators (is_safe_url) → tests that taint flows through "validator" functions
"""

import subprocess as sp
from pathlib import Path

import requests

# Fake MCP framework — mimics FastMCP decorator pattern
class MockMCP:
    def tool(self, name: str = None):
        def decorator(func):
            func._mcp_tool = True
            func._mcp_name = name or func.__name__
            return func
        return decorator

mcp = MockMCP()


# ---------------------------------------------------------------------------
# Helpers (cross-function call chain targets)
# ---------------------------------------------------------------------------

def normalize_path(user_input: str) -> str:
    """Normalize a file path from user input.

    DELIBERATELY VULNERABLE: passes user input through without sanitization.
    This function exists specifically to test cross-function taint propagation.
    """
    # No path sanitization — taint should flow through this
    return user_input.strip()


def build_command(cmd: str) -> str:
    """Build a shell command string from user input.

    DELIBERATELY VULNERABLE: wraps user input in a shell command with no escaping.
    """
    return f"sh -c '{cmd}'"


def is_safe_url(url: str) -> bool:
    """Check if a URL is 'safe' to fetch.

    DELIBERATELY BROKEN: always returns True, simulating a flawed security check.
    Tests that taint analysis doesn't get blocked by 'validator' functions.
    """
    # BUG: always returns True — no actual validation
    return True


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def run_shell(command: str) -> dict:
    """Execute a shell command.

    Vulnerability: Command Injection
    - User input flows directly to subprocess execution
    - Uses import alias: sp.run
    - Uses assignment alias: runner = sp.run
    - Crosses function boundary: build_command()
    """
    # Assignment alias — tests variable tracking
    runner = sp.run
    command_text = command.strip()
    cmd_string = build_command(command_text)
    result = runner(cmd_string, shell=True, capture_output=True, text=True)
    return {"stdout": result.stdout, "stderr": result.stderr}


@mcp.tool()
def read_log(filename: str) -> dict:
    """Read a log file.

    Vulnerability: Path Traversal
    - User input flows to file open() through normalize_path()
    - normalize_path() is a cross-function call that doesn't sanitize
    """
    safe_path = normalize_path(filename)
    log_dir = Path("/var/log")
    full_path = log_dir / safe_path
    content = open(full_path, "r").read()
    return {"content": content, "path": str(full_path)}


@mcp.tool()
def fetch_url(url: str) -> dict:
    """Fetch content from a URL.

    Vulnerability: SSRF (Server-Side Request Forgery)
    - User-controlled URL passed directly to requests.get()
    - is_safe_url() is a deliberately broken validator that always returns True
    """
    if not is_safe_url(url):
        return {"error": "URL rejected by safety check"}
    response = requests.get(url, timeout=5)
    return {"status_code": response.status_code, "body": response.text[:1000]}
