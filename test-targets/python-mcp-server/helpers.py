"""Helper functions for the test MCP server.

These are deliberately placed in a separate file to test cross-file
import resolution and taint propagation across module boundaries.
"""

import subprocess as sp
from pathlib import Path


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
