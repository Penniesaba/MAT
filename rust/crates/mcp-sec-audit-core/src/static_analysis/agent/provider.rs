use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

/// Configuration for a single agent run.
pub struct AgentRunConfig {
    /// Working directory (project root).
    pub working_dir: String,
    /// Rendered prompt to pass to the agent.
    pub prompt: String,
    /// CLI binary name (e.g., "claude").
    pub provider_binary: String,
    /// Maximum tool-use turns the agent may take.
    pub max_turns: u32,
    /// Wall-clock timeout for the agent process.
    pub timeout_seconds: u64,
    /// Extra CLI arguments (e.g., ["--model", "sonnet"]).
    pub extra_args: Vec<String>,
}

/// Output from a completed (or timed-out) agent run.
#[derive(Debug)]
pub struct AgentRunOutput {
    pub stdout: String,
    /// Captured for diagnostics; not yet surfaced in reports.
    #[allow(dead_code)]
    pub stderr: String,
    #[allow(dead_code)]
    pub exit_code: i32,
    #[allow(dead_code)]
    pub duration: Duration,
    /// True if the process was killed due to timeout.
    pub timed_out: bool,
}

/// Pluggable agent backend.
pub trait AgentProvider {
    /// Execute an agent run with the given configuration.
    fn run(&self, config: &AgentRunConfig) -> Result<AgentRunOutput>;
}

/// Default provider: invokes an agent CLI as a subprocess.
pub struct CliAgentProvider;

/// True when `binary` is a known agent CLI that understands the injected
/// flags (`-p <prompt>`, `--max-turns N`, `--output-format text`).
///
/// These flags are specific to CLI agents (e.g. `claude`). Injecting them
/// into an arbitrary subprocess would make the command fail immediately
/// (e.g. GNU `sleep` rejects `-p`), so they are only added for known agent
/// CLIs. Additional agent CLIs that accept these flags can be added here.
fn is_agent_cli(binary: &str) -> bool {
    let name = std::path::Path::new(binary)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(binary);
    matches!(name, "claude" | "claude.exe")
}

impl AgentProvider for CliAgentProvider {
    fn run(&self, config: &AgentRunConfig) -> Result<AgentRunOutput> {
        let start = Instant::now();

        let mut cmd = Command::new(&config.provider_binary);
        if is_agent_cli(&config.provider_binary) {
            cmd.arg("-p")
                .arg(&config.prompt)
                .arg("--max-turns")
                .arg(config.max_turns.to_string())
                .arg("--output-format")
                .arg("text");
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for arg in &config.extra_args {
            cmd.arg(arg);
        }

        if !config.working_dir.is_empty() {
            cmd.current_dir(&config.working_dir);
        }

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "agent provider '{}' not found in PATH. \
                     Ensure the CLI tool is installed.",
                    config.provider_binary
                )
            } else {
                anyhow::anyhow!("failed to spawn agent process: {}", e)
            }
        })?;

        // Read stdout/stderr and wait in a separate thread so we can timeout
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut stdout = String::new();
            let mut stderr = String::new();

            // Read pipes — these are available until process exits
            if let Some(mut out) = child.stdout.take() {
                use std::io::Read;
                let _ = out.read_to_string(&mut stdout);
            }
            if let Some(mut err) = child.stderr.take() {
                use std::io::Read;
                let _ = err.read_to_string(&mut stderr);
            }

            let status = child.wait();
            let exit_code = status.ok().and_then(|s| s.code()).unwrap_or(-1);
            let _ = tx.send((stdout, stderr, exit_code));
        });

        let timeout = Duration::from_secs(config.timeout_seconds);
        match rx.recv_timeout(timeout) {
            Ok((stdout, stderr, exit_code)) => {
                let duration = start.elapsed();
                Ok(AgentRunOutput {
                    stdout,
                    stderr,
                    exit_code,
                    duration,
                    timed_out: false,
                })
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let duration = start.elapsed();
                Ok(AgentRunOutput {
                    stdout: String::new(),
                    stderr: "agent process timed out".to_string(),
                    exit_code: -1,
                    duration,
                    timed_out: true,
                })
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("agent process communication channel disconnected");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_not_found_returns_error() {
        let config = AgentRunConfig {
            working_dir: ".".to_string(),
            prompt: "test".to_string(),
            provider_binary: "nonexistent-agent-cli-xyz".to_string(),
            max_turns: 5,
            timeout_seconds: 5,
            extra_args: vec![],
        };
        let provider = CliAgentProvider;
        let err = provider
            .run(&config)
            .expect_err("nonexistent binary should fail");
        assert!(err.to_string().contains("not found in PATH"));
    }

    #[test]
    fn timeout_happens_for_sleeping_process() {
        let config = AgentRunConfig {
            working_dir: ".".to_string(),
            prompt: "test".to_string(),
            provider_binary: "sleep".to_string(),
            max_turns: 5,
            timeout_seconds: 1,
            extra_args: vec!["10".to_string()], // sleep 10 — will timeout
        };
        let provider = CliAgentProvider;
        let output = provider.run(&config).expect("run with timeout");
        assert!(output.timed_out);
    }
}
