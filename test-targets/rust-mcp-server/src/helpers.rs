//! Helper functions for the Rust test MCP server.
//!
//! These are deliberately in a separate module to test cross-file
//! use resolution and taint propagation across module boundaries.

use std::process::Command;

/// Build a shell command string from user input.
///
/// DELIBERATELY VULNERABLE: wraps user input in a shell invocation
/// with no escaping or sanitization. This exists specifically to
/// test cross-function taint propagation.
pub fn build_shell_command(cmd: &str) -> String {
    // No sanitization — taint should flow through this function
    format!("sh -c '{}'", cmd)
}

/// Parse a JSON config string.
///
/// Thin wrapper around serde_json::from_str that provides no additional
/// validation. Tests that the deserialization sink is detected through
/// a cross-function call.
pub fn parse_config(raw: &str) -> Result<serde_json::Value, serde_json::Error> {
    // Direct passthrough — taint should flow to the deserialization sink
    serde_json::from_str(raw)
}
