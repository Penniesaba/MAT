# Detection Benchmarks

Performance evaluation of the MCP Security Detection Framework against academic datasets.

## MCPTox Benchmark

### Overview

Validates detection accuracy against the **MCPTox dataset** from academic research:
- **Paper:** https://arxiv.org/abs/2508.14925
- **Samples:** 491 malicious tool descriptions
- **Coverage:** Infrastructure capabilities + semantic attacks

### Running the Benchmark

```bash
# From detection/ directory
uv run mcptox-benchmark
```

**First run:** Auto-generates 491 sample files from `pure_tool.json` (~5 seconds)
**Subsequent runs:** Reuses existing samples, regenerates detection results

### Output Files

All generated files are saved to `examples/benchmarks/mcptox/` (gitignored):

- `samples/` - 491 JSON sample files (auto-generated)
- `per_file_detection.jsonl` - Detailed findings for each sample
- `per_file_detection_summary.json` - Capability coverage statistics
- `benchmark_report.md` - Human-readable performance summary

### Version Control

Only the source data is tracked:
- ✅ `pure_tool.json` (298KB, original dataset)
- ✅ `.gitignore` (ignores all generated files)
- ❌ `samples/` directory (491 files, regenerated on demand)
- ❌ Result files (JSON/JSONL/MD, regenerated each run)

### Interpreting Results

The benchmark measures **detection coverage** per capability:

- **High (>80%):** Excellent detection, most samples caught
- **Medium (50-80%):** Good baseline, some gaps remain
- **Low (<50%):** Needs improvement, significant blind spots

**Note:** Coverage > 100% means multiple capabilities detected per sample (expected for complex attacks).

## Adding New Benchmarks

To add a new benchmark dataset:

1. Create `examples/benchmarks/<dataset_name>/`
2. Add source data + `.gitignore` (ignore generated files)
3. Write `run_<dataset_name>_benchmark.py`
4. Follow the MCPTox pattern for consistency
