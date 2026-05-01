"""Apifox Supply Chain Attack Detection Benchmark.

This script runs a three-layer detection pipeline against Apifox poisoning samples:
- Layer 1: JS Tree-sitter Extractor (extract_jsts_facts)
- Layer 2: AST Engine (run_ast_analysis)
- Layer 3: Legacy Keyword Matching (keywords.toml JS indicators)

Sample files:
  - 01-deobfuscated-malicious-payload.js  (10KB, deobfuscated C2 beacon)
  - 02-apifox-event.js                    (188B, Stage-1 loader)
  - 03-02ab429d.js                        (3.6KB, Stage-2 info stealer)
  - apifox-app-event-tracking.min.js.malicious (80KB, obfuscated original)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import NamedTuple

# Add both paths so `analysis.` and `detection.` both resolve correctly.
# Repo root -> enables `analysis.engine` bare imports (used internally by detection.analysis)
# Detection package -> enables `detection.rules.loader` etc.
_repo_root = Path(__file__).resolve().parents[2]
_detection_pkg = _repo_root / "detection"
sys.path.insert(0, str(_repo_root))    # for `analysis.xxx` bare imports
sys.path.insert(0, str(_detection_pkg))  # for `detection.xxx` imports

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SAMPLES_DIR = _repo_root / "detection" / "examples" / "benchmarks" / "supply-chain-attacks" / "apifox"
RULES_FILE = _repo_root / "detection" / "detection" / "rules" / "keywords.toml"

from analysis.extractors.javascript_ts_tree_sitter import extract_jsts_facts
from analysis.engine import run_ast_analysis
from detection.rules.loader import load_rulebook

SAMPLE_FILES = [
    "01-deobfuscated-malicious-payload.js",
    "02-apifox-event.js",
    "03-02ab429d.js",
    "apifox-app-event-tracking.min.js.malicious",
]

# ---------------------------------------------------------------------------
# Layer 3: Keyword Matching (simulates _PythonRuleDetector logic for JS)
# ---------------------------------------------------------------------------

class KeywordMatch(NamedTuple):
    capability: str
    pattern: str
    line: int


def _build_js_keywords_index(rulebook) -> dict[str, list[str]]:
    """Build a language->capability->patterns index from keywords.toml RuleBook."""
    index: dict[str, dict[str, list[str]]] = {}
    # Use for_language() to get rules that have TypeScript/JS indicators
    for lang in ("javascript", "typescript"):
        rules = rulebook.for_language(lang)
        index[lang] = {}
        for cap_name, cap_rule in rules.items():
            js_patterns = []
            for indicator in cap_rule.indicators:
                if "javascript" in indicator.languages or "typescript" in indicator.languages:
                    js_patterns.extend(list(indicator.patterns))
            if js_patterns:
                index[lang][cap_name] = js_patterns
    return index


def run_keyword_scan(source: str) -> list[KeywordMatch]:
    """Scan source for JS keyword indicators from keywords.toml."""
    rulebook = load_rulebook(RULES_FILE)
    js_index = _build_js_keywords_index(rulebook)

    matches: list[KeywordMatch] = []
    lines = source.split("\n")
    for lineno, line in enumerate(lines, 1):
        for lang in ("javascript", "typescript"):
            if lang not in js_index:
                continue
            for cap_name, patterns in js_index[lang].items():
                for pat in patterns:
                    if pat in line:
                        matches.append(KeywordMatch(cap_name, pat, lineno))
    return matches


# ---------------------------------------------------------------------------
# Layer 1: JS Tree-sitter Extractor
# ---------------------------------------------------------------------------

def run_jsts_extractor(file_path: Path) -> dict:
    """Run extract_jsts_facts and summarize results."""
    source = file_path.read_text(encoding="utf-8", errors="replace")
    root = file_path.parent.parent.parent  # detection/
    facts, errors = extract_jsts_facts(root, file_path, source)

    # Count by type
    type_counts: dict[str, int] = {}
    sink_details: list[str] = []
    entry_points: list[str] = []
    sources: list[str] = []
    imports: list[str] = []
    calls: list[str] = []

    for f in facts:
        t = f.type
        type_counts[t] = type_counts.get(t, 0) + 1
        if t == "sink":
            sink_details.append(f"{f.sink_name} [{f.category}]")
        elif t == "entrypoint":
            entry_points.append(f"{f.name} ({f.kind})")
        elif t == "source":
            sources.append(f.name)
        elif t == "import":
            imported = f.imported_name or f.module
            imports.append(f"{imported} ({f.kind})")
        elif t == "call":
            calls.append(f.callee)

    return {
        "total_facts": len(facts),
        "type_counts": type_counts,
        "sinks": sink_details,
        "entrypoints": entry_points,
        "sources": sources,
        "imports": imports[:10],  # cap at 10
        "calls": calls[:20],  # cap at 20
        "errors": len(errors),
    }


# ---------------------------------------------------------------------------
# Layer 2: AST Engine
# ---------------------------------------------------------------------------

def run_ast_engine(file_path: Path) -> dict:
    """Run run_ast_analysis and summarize findings."""
    findings = run_ast_analysis(file_path)

    finding_details: list[str] = []
    for f in findings:
        finding_details.append(f"{f.name} (confidence={f.confidence:.2f})")

    return {
        "total_findings": len(findings),
        "findings": finding_details,
    }


# ---------------------------------------------------------------------------
# Main Benchmark
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Apifox Supply Chain Attack Detection Benchmark ===\n")

    total_facts = 0
    total_findings = 0
    total_keyword_matches = 0

    for sample_name in SAMPLE_FILES:
        file_path = SAMPLES_DIR / sample_name
        if not file_path.exists():
            print(f"⚠ File not found: {file_path}")
            continue

        print(f"File: {sample_name}")
        print("-" * 60)

        # Layer 1
        l1 = run_jsts_extractor(file_path)
        total_facts += l1["total_facts"]
        print(f"  Layer 1 - JS Extractor: {l1['total_facts']} facts")
        type_summary = ", ".join(f"{k}={v}" for k, v in l1["type_counts"].items())
        print(f"    Types: {type_summary}")
        if l1["sinks"]:
            print(f"    Sinks found: {l1['sinks']}")
        else:
            print(f"    Sinks found: none")
        if l1["entrypoints"]:
            print(f"    Entry points: {l1['entrypoints']}")
        else:
            print(f"    Entry points: none")
        if l1["sources"]:
            print(f"    Sources: {l1['sources']}")
        else:
            print(f"    Sources: none")

        # Layer 2
        l2 = run_ast_engine(file_path)
        total_findings += l2["total_findings"]
        print(f"  Layer 2 - AST Engine: {l2['total_findings']} findings")
        if l2["findings"]:
            for f in l2["findings"]:
                print(f"    - {f}")
        else:
            print("    - (no findings — likely no entrypoints or no reachability)")

        # Layer 3
        source = file_path.read_text(encoding="utf-8", errors="replace")
        l3_matches = run_keyword_scan(source)
        total_keyword_matches += len(l3_matches)
        print(f"  Layer 3 - Legacy Keywords: {len(l3_matches)} matches")
        if l3_matches:
            # Group by capability
            by_cap: dict[str, list[str]] = {}
            for m in l3_matches:
                by_cap.setdefault(m.capability, []).append(f"{m.pattern}@L{m.line}")
            for cap, items in by_cap.items():
                print(f"    [{cap}]: {items}")
        else:
            print("    - (no keyword matches)")

        print()

    # Summary
    sample_count = len(SAMPLE_FILES)
    detection_rate = 0.0
    if sample_count > 0:
        files_with_detection = (
            (1 if total_facts > 0 else 0) +
            (1 if total_findings > 0 else 0) +
            (1 if total_keyword_matches > 0 else 0)
        )
        detection_rate = min(100.0, (files_with_detection / sample_count) * 100)

    print("=" * 60)
    print("=== Summary ===")
    print(f"Total facts extracted: {total_facts}")
    print(f"Total findings (AST): {total_findings}")
    print(f"Total keyword matches: {total_keyword_matches}")
    print(f"Detection rate: {detection_rate:.0f}%")
    print("=" * 60)


if __name__ == "__main__":
    main()