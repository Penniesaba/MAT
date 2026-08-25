use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::process::Command;
use tokio::time::timeout;

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

impl CliAgentProvider {
    /// Execute an agent run with the given configuration.
    ///
    /// Spawns the CLI as a `tokio::process::Child` with `kill_on_drop(true)`,
    /// so that when the wall-clock timeout fires and the `Child` is dropped
    /// (by the `timeout` future being cancelled), the OS reaps the child
    /// rather than leaking it as an orphan.
    pub(crate) async fn run(&self, config: &AgentRunConfig) -> Result<AgentRunOutput> {
        let start = Instant::now();

        let mut cmd = Command::new(&config.provider_binary);
        if is_agent_cli(&config.provider_binary) {
            cmd.arg("-p")
                .arg(&config.prompt)
                .arg("--max-turns")
                .arg(config.max_turns.to_string())
                .arg("--output-format")
                .arg("text");
            if !config.working_dir.is_empty() {
                // Grant the agent read access to the scan root. claude's
                // headless permission model blocks reads outside the cwd /
                // --add-dir set; pinning --add-dir to the scan root keeps every
                // target file readable even across sibling directories.
                cmd.arg("--add-dir").arg(&config.working_dir);
            }
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true); // ← key: timeout branch reaps the child

        for arg in &config.extra_args {
            cmd.arg(arg);
        }

        if !config.working_dir.is_empty() {
            cmd.current_dir(&config.working_dir);
        }

        let child = cmd.spawn().map_err(|e| {
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

        match timeout(
            Duration::from_secs(config.timeout_seconds),
            child.wait_with_output(),
        )
        .await
        {
            Ok(Ok(output)) => {
                let duration = start.elapsed();
                Ok(AgentRunOutput {
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                    exit_code: output.status.code().unwrap_or(-1),
                    duration,
                    timed_out: false,
                })
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("agent process failed: {e}")),
            Err(_elapsed) => {
                // `child` was moved into `wait_with_output`, so cancelling the
                // timeout future drops it here; `kill_on_drop(true)` reaps it.
                let duration = start.elapsed();
                Ok(AgentRunOutput {
                    stdout: String::new(),
                    stderr: "agent process timed out".to_string(),
                    exit_code: -1,
                    duration,
                    timed_out: true,
                })
            }
        }
    }

    /// Synchronous shell around [`Self::run`] for callers that have not yet
    /// migrated to the async pipeline (Task 7).
    pub(crate) fn run_blocking(&self, config: &AgentRunConfig) -> Result<AgentRunOutput> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.run(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_agent_run_config() -> AgentRunConfig {
        AgentRunConfig {
            working_dir: ".".to_string(),
            prompt: String::new(),
            provider_binary: "true".to_string(),
            max_turns: 1,
            timeout_seconds: 5,
            extra_args: Vec::new(),
        }
    }

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
            .run_blocking(&config)
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
        let output = provider.run_blocking(&config).expect("run with timeout");
        assert!(output.timed_out);
    }

    #[tokio::test]
    async fn agent_timeout_kills_the_child_process() {
        let provider = CliAgentProvider;
        let config = AgentRunConfig {
            provider_binary: "sleep".into(),
            extra_args: vec!["30".into()],
            timeout_seconds: 1,
            ..minimal_agent_run_config()
        };
        let started = std::time::Instant::now();
        let out = provider.run(&config).await.expect("run");
        assert!(out.timed_out);
        assert!(started.elapsed().as_secs() < 5, "must not wait for the child");

        // The child must have been reclaimed by `kill_on_drop`. `pgrep -f`
        // matches the full command line, and the pattern `sleep 30` would
        // appear verbatim in pgrep's own argv (`pgrep -f "sleep 30"`), which
        // some procps versions then self-match. The bracket form `sleep [3]0`
        // is a regex that still matches a leaked `sleep 30` child but does not
        // literally appear in pgrep's own command line, so the check cannot
        // match itself.
        let ps = std::process::Command::new("pgrep")
            .arg("-f")
            .arg("sleep [3]0")
            .output()
            .expect("pgrep");
        assert!(
            ps.stdout.is_empty(),
            "child leaked after timeout: {}",
            String::from_utf8_lossy(&ps.stdout)
        );
    }
}
