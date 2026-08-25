//! CLI entry point for the `batch` subcommand.
//!
//! Loads the batch config, initializes logging, and hands off to the v5
//! parallel multi-repository orchestrator. Logging is configured from the
//! batch file's shared `[logging]` section, carried by the flattened
//! single-repo base on the loaded batch config.

use std::path::Path;

use anyhow::Result;
use mcp_sec_audit_core::{BatchSummary, load_batch_config, run_batch};
use tokio_util::sync::CancellationToken;

/// Loads `config`, initializes logging from its `[logging]` section, and runs
/// the parallel batch. Cancellation (Ctrl-C, or the orchestrator's own
/// `fail_fast` abort) is honoured through `cancel`.
pub async fn run(config: &Path, cancel: CancellationToken) -> Result<BatchSummary> {
    let cfg = load_batch_config(config)?;
    crate::logging::init(&cfg.runtime.logging)?;
    run_batch(cfg, cancel).await
}
