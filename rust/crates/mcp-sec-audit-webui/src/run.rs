//! Launch a scan (batch or single) and pipe its events into the RunManager.

use mcp_sec_audit_core::events::EventSink;
use mcp_sec_audit_core::runctx::Progress;
use mcp_sec_audit_core::{BatchConfig, RuntimeConfig, RunContext, RunId, run_batch, run_static_scan_async};

use crate::state::RunManager;

/// A single active run. `handle` is the join handle of the driving task.
pub struct ActiveRun {
    pub handle: tokio::task::JoinHandle<()>,
}

/// Start a batch run. The returned task drives `run_batch`, recording every
/// event through `manager.record`.
///
/// The async pipeline future is `!Send` (it holds a `tracing::EnteredSpan`
/// across `.await` points), so it cannot be driven by `tokio::spawn`. Like the
/// batch orchestrator's `run_repo` and the CLI's batch path, we drive it on a
/// per-run `current_thread` runtime inside `spawn_blocking`.
pub fn start_batch(manager: RunManager, batch: BatchConfig) -> ActiveRun {
    let mgr = manager.clone();
    let cancel = manager.cancel_token();
    let handle = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build batch runtime");
        rt.block_on(async move {
            let (events, mut rx) = EventSink::broadcast();
            // Forward every emitted event into the manager (record + rebroadcast).
            let fwd = mgr.clone();
            let forwarder = tokio::spawn(async move {
                while let Ok(ev) = rx.recv().await {
                    fwd.record(ev);
                }
            });
            let result = run_batch(batch, cancel, events).await;
            // Drain whatever the forwarder may still be reading, then let it finish.
            drop(mgr);
            let _ = forwarder.await;
            let _ = result;
        });
    });
    ActiveRun { handle }
}

/// Start a single-repo run (target = `config.scan.targets`).
pub fn start_single(manager: RunManager, config: RuntimeConfig) -> ActiveRun {
    let mgr = manager.clone();
    let cancel = manager.cancel_token();
    let handle = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build single runtime");
        rt.block_on(async move {
            let (events, mut rx) = EventSink::broadcast();
            let fwd = mgr.clone();
            let forwarder = tokio::spawn(async move {
                while let Ok(ev) = rx.recv().await {
                    fwd.record(ev);
                }
            });
            let run_ctx = RunContext::for_repo(
                RunId::new(),
                Progress::noop(),
                events.scoped("single"),
                cancel,
                None,
                None,
            );
            let result = run_static_scan_async(&config, &[], None, &run_ctx).await;
            // Close the event channel before awaiting the forwarder: unlike
            // `run_batch`, `run_static_scan_async` borrows its `RunContext`, so
            // both `events` and `run_ctx.events` still hold `broadcast::Sender`
            // clones here. The forwarder only exits when every sender drops
            // (the channel closes), so drop them explicitly.
            drop(run_ctx);
            drop(events);
            drop(mgr);
            let _ = forwarder.await;
            let _ = result;
        });
    });
    ActiveRun { handle }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_single_spawns_without_panicking() {
        let mgr = RunManager::new();
        let mut cfg = RuntimeConfig::default();
        cfg.static_.enabled = false; // empty-result fast path
        let run = start_single(mgr, cfg);
        // Await the driving task: a panic (or a failed runtime build) surfaces
        // as an `Err` join result here.
        run.handle.await.expect("single run task should not panic");
    }
}
