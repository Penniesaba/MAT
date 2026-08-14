//! Test MCP server (Rust) with intentional vulnerabilities.
//!
//! This file demonstrates:
//!   - use alias (UseAs)
//!   - use group (UseGroup)
//!   - #[tool] attribute macro for MCP entrypoint detection
//!   - impl method calls
//!   - unsafe blocks
//!
//! Vulnerabilities:
//!   - exec_shell:  Command Injection via std::process::Command
//!   - load_config: Deserialization RCE via serde_json::from_str
//!   - unsafe_copy: Unsafe memory operation + file write

use std::process::Command as ShellCmd;
use std::{fs, io};

mod helpers;
use helpers::{build_shell_command, parse_config};

// Fake MCP framework — mimics rmcp attribute macro pattern
// The #[tool] attribute marks functions as MCP tools for entrypoint detection.

/// Execute a shell command.
///
/// VULNERABILITY: Command Injection
/// - User input flows to Command::new().arg() without sanitization
/// - Uses use alias: ShellCmd (= std::process::Command)
/// - Crosses function boundary: build_shell_command()
#[tool]
fn exec_shell(command: String) -> Result<String, String> {
    let shell_cmd = build_shell_command(&command);
    let output = ShellCmd::new("sh")
        .arg("-c")
        .arg(&shell_cmd)
        .output()
        .map_err(|e| format!("Command failed: {}", e))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Load configuration from a JSON string.
///
/// VULNERABILITY: Deserialization RCE
/// - User-controlled JSON is deserialized without schema validation
/// - serde_json::from_str can trigger arbitrary code via #[serde] tricks
#[tool]
fn load_config(config_json: String) -> Result<String, String> {
    // Cross-function: parse_config wraps serde_json::from_str
    let config: serde_json::Value = parse_config(&config_json)
        .map_err(|e| format!("Config parse error: {}", e))?;

    Ok(format!("Config loaded: {:?}", config))
}

/// Copy data to a file using unsafe pointer operations.
///
/// VULNERABILITY: Unsafe block + File Write
/// - Uses unsafe pointer copy (memory safety violation)
/// - Writes to a user-controlled path
#[tool]
fn unsafe_copy(data: String, dest_path: String) -> Result<String, String> {
    let bytes = data.as_bytes();
    let len = bytes.len();

    // VULNERABILITY: Unsafe block — raw pointer manipulation
    let copied = unsafe {
        let src = bytes.as_ptr();
        let mut buf = Vec::with_capacity(len);
        let dst = buf.as_mut_ptr();
        std::ptr::copy_nonoverlapping(src, dst, len);
        buf.set_len(len);
        buf
    };

    // VULNERABILITY: File write with user-controlled path
    fs::write(&dest_path, &copied)
        .map_err(|e| format!("Write failed: {}", e))?;

    Ok(format!("Copied {} bytes to {}", len, dest_path))
}

fn main() {
    println!("Test MCP server (Rust) — for static analysis validation only.");
    println!("This server is deliberately vulnerable and should NOT be deployed.");
}
