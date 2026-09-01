//! v6 web UI server: configure, run, and monitor MCP security audits.

pub mod events;
pub mod log_capture;
pub mod run;
pub mod server;
pub mod state;
pub mod toml_import;

use anyhow::Result;

/// Start the web server, blocking until it shuts down.
pub async fn serve(addr: &str, open_browser: bool) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;

    if open_browser {
        // Best-effort: don't fail the server if a browser can't be opened.
        let url = format!("http://{local}");
        let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    }

    tracing::info!(target: "mcp_sec_audit::webui", addr = %local, "web ui listening");
    axum::serve(listener, server::build_router()).await?;
    Ok(())
}
