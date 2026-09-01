//! v6 web UI server: configure, run, and monitor MCP security audits.

pub mod events;
pub mod log_capture;
pub mod run;
pub mod server;
pub mod state;
pub mod toml_import;

use anyhow::Result;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Start the web server, blocking until it shuts down.
pub async fn serve(addr: &str, open_browser: bool) -> Result<()> {
    let manager = crate::state::RunManager::new();

    // The webui owns the tracing subscriber: `CaptureLayer` folds every tracing
    // line into the WS stream as an `AnalysisEvent::Log` (attributed to the
    // nearest `repo` span), while the fmt layer keeps terminal output live.
    // `try_init` is fine to error if a subscriber is already set (the CLI never
    // calls its `logging::init` on the webui path).
    tracing_subscriber::registry()
        .with(crate::log_capture::CaptureLayer::new(manager.clone()))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init()
        .map_err(|e| anyhow::anyhow!("tracing subscriber init failed: {e}"))?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;

    if open_browser {
        // Best-effort: don't fail the server if a browser can't be opened.
        let url = format!("http://{local}");
        let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    }

    tracing::info!(target: "mcp_sec_audit::webui", addr = %local, "web ui listening");
    axum::serve(listener, server::build_router(manager)).await?;
    Ok(())
}
