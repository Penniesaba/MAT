#!/bin/bash

# Check if detection results already exist
RESULT_FILE="/app/detection/examples/benchmarks/mcptox/output/per_file_detection.jsonl"

if [ -f "$RESULT_FILE" ]; then
    echo "Detection results already exist at $RESULT_FILE"
    echo "Skipping benchmark run."
    exit 0
fi

echo "No existing results found. Running benchmark..."
uv run mcptox-benchmark
