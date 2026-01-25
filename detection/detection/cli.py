"""Command-line interface for running detection pipelines."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from detection.core.registry import DetectorRegistry
from detection.pipelines import (
    run_dynamic_pipeline,
    run_rag_pipeline,
    run_static_pipeline,
)
from detection.reporting import ReportBuilder
from detection.rules import RuleBook, load_rulebook


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP security detection toolkit.")
    parser.add_argument("target", type=Path, help="Path to the MCP server repository.")
    parser.add_argument(
        "--pipeline", choices=["static", "dynamic", "rag"], default="static"
    )
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Output file path. If not specified, prints to stdout. Use .json or .jsonl extension for web portal compatibility."
    )
    parser.add_argument(
        "--policy-dir", type=Path, default=Path("detection/mitigation/policy_templates")
    )
    parser.add_argument(
        "--rules", type=Path, default=Path("detection/rules/keywords.toml")
    )
    args = parser.parse_args()

    registry = DetectorRegistry()
    rulebook = load_rulebook(args.rules)
    _load_builtin_plugins(registry, rulebook)

    if args.pipeline == "static":
        result = run_static_pipeline(args.target, registry, args.policy_dir)
    elif args.pipeline == "dynamic":
        result = run_dynamic_pipeline(args.target, registry)
    else:
        result = run_rag_pipeline(args.target, registry)

    # Generate report
    report = ReportBuilder(format_=args.format).render(result)

    # Output handling
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)

        # If output is .jsonl, append in JSONL format for web portal compatibility
        if args.output.suffix == ".jsonl":
            # Convert result to dict for JSONL
            result_dict = {
                "sample": str(args.target),
                "risk_level": result.risk_level,
                "total_score": result.total_score,
                "findings": [
                    {
                        "name": f.name,
                        "confidence": f.confidence,
                        "score_weight": f.score_weight,
                        "evidence": list(f.evidence),
                    }
                    for f in result.findings
                ],
            }
            with args.output.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(result_dict, ensure_ascii=False) + "\n")
            print(f"✓ Result appended to {args.output}")
        else:
            # Write full report (markdown or json)
            args.output.write_text(report, encoding="utf-8")
            print(f"✓ Report saved to {args.output}")
    else:
        print(report)


def _load_builtin_plugins(registry: DetectorRegistry, rulebook: RuleBook) -> None:
    from detection.plugins.static import python as python_static
    from detection.plugins.static import metadata as metadata_static

    python_static.register(registry, rulebook)
    metadata_static.register(registry, rulebook)
    # Future phases will import additional plugins here.


if __name__ == "__main__":
    main()
