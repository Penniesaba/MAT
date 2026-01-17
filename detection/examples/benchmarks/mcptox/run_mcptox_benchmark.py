"""MCPTox Detection Benchmark - Performance evaluation against academic dataset.

This script runs static detection against all 491 MCPTox samples
(from https://arxiv.org/abs/2508.14925) and generates a performance report.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict, List

# Add detection package to path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from detection.core.models import DetectionResult
from detection.core.registry import DetectorRegistry
from detection.pipelines import run_static_pipeline
from detection.plugins.static import metadata as metadata_static
from detection.plugins.static import python as python_static
from detection.rules import load_rulebook

from examples.benchmarks.mcptox.prepare_samples import prepare_mcptox_samples

# Paths
MCPTOX_DIR = Path(__file__).parent
PURE_TOOL_JSON = MCPTOX_DIR / "pure_tool.json"
SAMPLES_DIR = MCPTOX_DIR / "samples"
OUTPUT_DIR = MCPTOX_DIR / "output"
OUTPUT_FILE = OUTPUT_DIR / "per_file_detection.jsonl"
SUMMARY_FILE = OUTPUT_DIR / "per_file_detection_summary.json"
REPORT_FILE = OUTPUT_DIR / "benchmark_report.md"

PROJECT_ROOT = Path(__file__).resolve().parents[3]
RULES_FILE = PROJECT_ROOT / "detection" / "rules" / "keywords.toml"
POLICY_DIR = PROJECT_ROOT / "detection" / "mitigation" / "policy_templates"

EXCLUDE_FILES = {
    "per_file_detection.jsonl",
    "per_file_detection_summary.json",
    "benchmark_report.md",
}


def build_registry() -> DetectorRegistry:
    """Build detector registry with static analyzers."""
    registry = DetectorRegistry()
    rulebook = load_rulebook(RULES_FILE)
    python_static.register(registry, rulebook)
    metadata_static.register(registry, rulebook)
    return registry


def evaluate_sample(
    sample_path: Path, registry: DetectorRegistry
) -> DetectionResult:
    """Run static detection on a single sample file."""
    with tempfile.TemporaryDirectory(prefix="mcptox-sample-") as temp_dir:
        temp_dir_path = Path(temp_dir)
        target_dir = temp_dir_path / "target"
        target_dir.mkdir()
        shutil.copy2(sample_path, target_dir / sample_path.name)
        result = run_static_pipeline(target_dir, registry, POLICY_DIR)

    # Remap evidence paths
    for finding in result.findings:
        remapped: List[str] = []
        for entry in finding.evidence:
            parts = entry.split(":", 1)
            snippet = parts[1] if len(parts) == 2 else entry
            remapped.append(f"{sample_path.name}:{snippet}")
        finding.evidence = remapped
        finding.metadata = {"files": [str(sample_path.relative_to(MCPTOX_DIR))]}

    result.notes = None
    result.server_name = sample_path.name
    return result


def serialize_result(result: DetectionResult, sample_path: Path) -> Dict[str, object]:
    """Convert DetectionResult to JSON-serializable dict."""
    return {
        "sample": str(sample_path.relative_to(MCPTOX_DIR)),
        "risk_level": result.risk_level,
        "total_score": result.total_score,
        "findings": [
            {
                "name": finding.name,
                "confidence": finding.confidence,
                "score_weight": finding.score_weight,
                "evidence": list(finding.evidence),
            }
            for finding in result.findings
        ],
    }


def generate_markdown_report(
    sample_count: int, coverage: Dict[str, int]
) -> str:
    """Generate markdown benchmark report."""
    total_detections = sum(coverage.values())
    coverage_pct = (total_detections / sample_count) * 100 if sample_count > 0 else 0

    report = f"""# MCPTox Detection Benchmark Report

**Dataset:** MCPTox (https://arxiv.org/abs/2508.14925)
**Samples Analyzed:** {sample_count}
**Total Detections:** {total_detections}
**Overall Coverage:** {coverage_pct:.1f}%

## Capability Detection Statistics

| Capability | Detections | Coverage (%) |
|-----------|------------|-------------|
"""

    for capability in sorted(coverage.keys()):
        count = coverage[capability]
        pct = (count / sample_count) * 100
        report += f"| {capability:30s} | {count:10d} | {pct:12.1f} |\n"

    report += f"""
## Detection Distribution

```
Total Samples: {sample_count}
Samples with Findings: {min(total_detections, sample_count)}
```

## Interpretation

- **High Coverage (>80%):** Excellent detection for this capability type
- **Medium Coverage (50-80%):** Good detection, room for improvement
- **Low Coverage (<50%):** Needs attention, potential blind spots

## Data Files

- Source: `mcptox/pure_tool.json`
- Samples: `mcptox/samples/` ({sample_count} files, auto-generated)
- Results: `mcptox/per_file_detection.jsonl`
- Summary: `mcptox/per_file_detection_summary.json`
"""

    return report


def main() -> None:
    """Run MCPTox benchmark."""
    print("=" * 60)
    print("MCPTox Detection Benchmark")
    print("=" * 60)

    # Ensure output directory exists
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Step 1: Prepare samples
    if not SAMPLES_DIR.exists() or not any(SAMPLES_DIR.rglob("*.json")):
        print(f"\n→ Generating samples from {PURE_TOOL_JSON.name}...")
        count, _ = prepare_mcptox_samples(PURE_TOOL_JSON, MCPTOX_DIR)
        print(f"  ✓ Generated {count} samples")
    else:
        existing_count = len([
            f for f in SAMPLES_DIR.rglob("*.json")
            if f.name not in EXCLUDE_FILES
        ])
        print(f"\n→ Using existing samples ({existing_count} files)")

    # Step 2: Collect samples
    samples = sorted(
        path
        for path in SAMPLES_DIR.rglob("*.json")
        if path.name not in EXCLUDE_FILES
    )

    if not samples:
        print("\n✗ No sample files found!")
        sys.exit(1)

    print(f"\n→ Running detection on {len(samples)} samples...")

    # Step 3: Run detection
    registry = build_registry()
    OUTPUT_FILE.unlink(missing_ok=True)

    coverage: Dict[str, int] = {}
    with OUTPUT_FILE.open("w", encoding="utf-8") as fh:
        for i, sample_path in enumerate(samples, 1):
            if i % 50 == 0 or i == len(samples):
                print(f"  Progress: {i}/{len(samples)} ({i*100//len(samples)}%)")

            result = evaluate_sample(sample_path, registry)

            # Track capability coverage
            for finding in result.findings:
                coverage[finding.name] = coverage.get(finding.name, 0) + 1

            # Serialize with high_risk_indicators
            serialized = serialize_result(result, sample_path)
            data = json.loads(sample_path.read_text(encoding="utf-8"))
            serialized["high_risk_indicators"] = data.get("high_risk_indicators", [])

            fh.write(json.dumps(serialized, ensure_ascii=False))
            fh.write("\n")

    # Step 4: Generate summary
    summary_payload = {
        "samples": len(samples),
        "capability_coverage": coverage,
        "output": str(OUTPUT_FILE.name),
    }
    SUMMARY_FILE.write_text(
        json.dumps(summary_payload, indent=2), encoding="utf-8"
    )

    # Step 5: Generate markdown report
    markdown = generate_markdown_report(len(samples), coverage)
    REPORT_FILE.write_text(markdown, encoding="utf-8")

    # Step 6: Print summary
    print("\n" + "=" * 60)
    print("Benchmark Results")
    print("=" * 60)
    print(f"Samples analyzed: {len(samples)}")
    print(f"\nCapability Detection:")
    for capability, count in sorted(coverage.items(), key=lambda x: -x[1]):
        coverage_pct = (count / len(samples)) * 100
        print(f"  {capability:30s}: {count:3d} ({coverage_pct:5.1f}%)")

    print(f"\nResults saved to:")
    print(f"  - {OUTPUT_FILE.name}")
    print(f"  - {SUMMARY_FILE.name}")
    print(f"  - {REPORT_FILE.name}")
    print("=" * 60)


if __name__ == "__main__":
    main()
