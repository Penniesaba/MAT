//! v6 web UI server: configure, run, and monitor MCP security audits.

pub mod events;
pub mod log_capture;
pub mod run;
pub mod server;
pub mod state;
pub mod toml_import;

use anyhow::Result;

/// Start the web server, blocking until it shuts down.
pub async fn serve(_addr: &str, _open_browser: bool) -> Result<()> {
    // filled in Task 10
    Ok(())
}
