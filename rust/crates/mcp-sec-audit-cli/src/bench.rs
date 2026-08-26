//! CLI entry point for the `bench` subcommand.

use std::path::Path;

use anyhow::Result;
use mcp_sec_audit_core::{BenchMetrics, BenchOptions, run_bench};
use tokio_util::sync::CancellationToken;

pub async fn run(
    manifest: &Path,
    tolerance: u32,
    max_parallel: usize,
    cancel: CancellationToken,
) -> Result<BenchMetrics> {
    let opts = BenchOptions { tolerance, max_parallel };
    let metrics = run_bench(manifest, &opts, cancel).await?;
    Ok(metrics)
}
