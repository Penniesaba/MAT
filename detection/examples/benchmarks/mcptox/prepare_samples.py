"""Split MCPTox pure_tool.json into per-tool JSON files with keyword tags.

This script processes the MCPTox dataset from https://arxiv.org/abs/2508.14925
and splits it into individual sample files for benchmarking.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List

SUSPICIOUS_KEYWORDS: Dict[str, List[str]] = {
    "command_exec": [
        "exec",
        "bash",
        "eval",
        "shell",
        "chmod",
        "chown",
        "rm -rf",
    ],
    "file_read": [
        "~/.ssh",
        "~/.cursor",
        "/etc/passwd",
        "read file",
        "extract",
        "steal",
    ],
    "file_write": [
        "overwrite",
        "write",
        "append",
        "log",
        "modify",
    ],
    "network_outbound": [
        "http://",
        "https://",
        "curl",
        "post",
        "upload",
    ],
    "network_inbound": [
        "listen",
        "webhook",
        "callback",
        "port",
        "server",
    ],
    "env_access": [
        "api key",
        "environment variable",
        "secret",
        "token",
        "credential",
    ],
    "param_override": [
        "override",
        "force",
        "must set",
        "replace",
        "regardless of user",
        "always set",
        "ignore user input",
    ],
    "tool_sequence_hijack": [
        "before calling",
        "must first",
        "prior to using",
        "pre-authorization",
        "always call",
        "call first",
    ],
    "prompt_injection": [
        "ignore the user",
        "priority higher than",
        "do not follow",
        "follow the instructions below",
        "this description's priority",
        "disregard the user's",
    ],
}


def normalize_slug(name: str) -> str:
    """Convert name to filesystem-safe slug."""
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", name.strip())
    slug = re.sub(r"_+", "_", slug).strip("_")
    return slug.lower() or "sample"


def detect_keywords(text: str) -> List[dict]:
    """Detect high-risk keywords in text."""
    lower = text.lower()
    matches = []
    for capability, keywords in SUSPICIOUS_KEYWORDS.items():
        hit_words = sorted({kw for kw in keywords if kw.lower() in lower})
        if hit_words:
            matches.append({"capability": capability, "keywords": hit_words})
    return matches


def write_sample(base_dir: Path, server: str, key: str, record: dict) -> Path:
    """Write a single sample JSON file with keyword tags."""
    folder = base_dir / normalize_slug(server or "unknown")
    folder.mkdir(parents=True, exist_ok=True)
    slug = normalize_slug(key)
    content = record.get("tool_content", "")
    record["high_risk_indicators"] = detect_keywords(content)
    output_path = folder / f"{slug}.json"
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(record, fh, ensure_ascii=False, indent=2)
    return output_path


def prepare_mcptox_samples(
    pure_tool_json: Path, output_dir: Path
) -> tuple[int, Path]:
    """
    Split pure_tool.json into individual sample files.

    Args:
        pure_tool_json: Path to source pure_tool.json
        output_dir: Directory to write samples (will create samples/ subdirectory)

    Returns:
        Tuple of (sample_count, samples_directory_path)
    """
    if not pure_tool_json.exists():
        raise FileNotFoundError(f"Source file not found: {pure_tool_json}")

    samples_dir = output_dir / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)

    with pure_tool_json.open("r", encoding="utf-8") as fh:
        entries = json.load(fh)

    sample_count = 0
    for group in entries:
        for key, record in group.items():
            server = record.get("server_name", "unknown")
            write_sample(samples_dir, server, key, record)
            sample_count += 1

    return sample_count, samples_dir


def main() -> None:
    """CLI entry point."""
    script_dir = Path(__file__).parent
    pure_tool_json = script_dir / "pure_tool.json"
    output_dir = script_dir

    count, samples_dir = prepare_mcptox_samples(pure_tool_json, output_dir)
    print(f"✓ Generated {count} MCPTox samples in {samples_dir}")


if __name__ == "__main__":
    main()
