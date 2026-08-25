use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use crate::RunId;

use super::models::MadPack;
use super::queries::QueryPack;

/// Info about a successfully created CodeQL database.
#[derive(Debug, Clone)]
pub struct DatabaseInfo {
    pub path: PathBuf,
    /// Language the database was created for.
    pub language: String,
}

/// Default provider: shells out to the `codeql` CLI.
pub(crate) struct CliCodeqlProvider {
    binary: String,
    run_id: RunId,
}

impl CliCodeqlProvider {
    pub(crate) fn new(binary: String, run_id: RunId) -> Self {
        Self { binary, run_id }
    }

    /// The per-run CodeQL database directory for a language. Keyed by [`RunId`]
    /// so concurrent repositories in one process never share a database.
    fn db_dir(&self, language: &str) -> PathBuf {
        self.run_id.temp_dir("codeql").join("db").join(language)
    }

    /// The per-run SARIF output path for a language.
    fn sarif_path(&self, language: &str) -> PathBuf {
        self.run_id.temp_dir("sarif").join(format!("{language}.sarif"))
    }

    /// Check whether the CodeQL CLI is available.
    pub(crate) fn check_available(&self) -> bool {
        std::process::Command::new(&self.binary)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Parse the installed CodeQL CLI version from `codeql --version`.
    pub(crate) fn codeql_version(&self) -> Option<(u32, u32, u32)> {
        let output = std::process::Command::new(&self.binary)
            .arg("--version")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        parse_codeql_version(&String::from_utf8_lossy(&output.stdout))
    }

    /// Create a CodeQL database from source files.
    ///
    /// Spawns `codeql database create` with `kill_on_drop(true)` and waits for
    /// it under a wall-clock timeout, so a stuck `database create` cannot leak a
    /// multi-GB orphan (design §2.3). `cancel` is the batch `CancellationToken`
    /// (a never-cancelled token on the single-repo path).
    pub(crate) async fn create_database(
        &self,
        source_dir: &Path,
        language: &str,
        timeout_seconds: u64,
        cancel: &CancellationToken,
    ) -> Result<DatabaseInfo> {
        let db_dir = self.db_dir(language);

        std::fs::create_dir_all(&db_dir)?;

        let mut cmd = Command::new(&self.binary);
        cmd.arg("database")
            .arg("create")
            .arg(&db_dir)
            .arg("--language")
            .arg(language)
            .arg("--source-root")
            .arg(source_dir)
            .arg("--overwrite")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true); // ← key: timeout/cancel branch reaps the child

        let child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "codeql CLI not found at '{}'. Set [static.codeql].binary or add it to \
                     PATH. Install CodeQL: \
                     https://github.com/github/codeql-cli-binaries/releases",
                    self.binary
                )
            } else {
                anyhow::anyhow!("failed to spawn codeql: {}", e)
            }
        })?;

        // Wait for the child to exit, the timeout to fire, or the batch
        // cancellation token to be cancelled. On timeout/cancel the `child`
        // future is dropped and `kill_on_drop(true)` reaps the subprocess.
        let output = tokio::select! {
            res = tokio::time::timeout(
                Duration::from_secs(timeout_seconds),
                child.wait_with_output(),
            ) => res,
            _ = cancel.cancelled() => {
                bail!("cancelled");
            }
        };

        let output = match output {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => bail!("codeql database create process failed: {e}"),
            Err(_elapsed) => {
                bail!("codeql database create timed out after {}s", timeout_seconds)
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "codeql database create failed for language '{}': {}",
                language,
                stderr.trim()
            );
        }

        Ok(DatabaseInfo {
            path: db_dir,
            language: language.to_string(),
        })
    }

    /// Synchronous shell around [`Self::create_database`], used only by the
    /// synchronous unit tests now that the pipeline calls the async form.
    #[cfg(test)]
    pub(crate) fn create_database_blocking(
        &self,
        source_dir: &Path,
        language: &str,
        timeout_seconds: u64,
    ) -> Result<DatabaseInfo> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.create_database(
                source_dir,
                language,
                timeout_seconds,
                &CancellationToken::new(),
            ))
    }

    /// Run CodeQL analysis on a database and return SARIF JSON.
    pub(crate) async fn run_analysis(
        &self,
        db: &DatabaseInfo,
        queries: &QueryPack,
        timeout_seconds: u64,
        extra_args: &[String],
        model_packs: &[&MadPack],
        cancel: &CancellationToken,
    ) -> Result<String> {
        // `--output=-` (SARIF to stdout) is unreliable across CodeQL versions,
        // so write to a temp file and read it back instead.
        let output_path = self.sarif_path(&db.language);
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut cmd = Command::new(&self.binary);
        cmd.arg("database")
            .arg("analyze")
            .arg(&db.path)
            .arg("--format=sarif-latest")
            .arg("--output")
            .arg(&output_path);

        // Model packs (MaD) are injected before the query files so standard
        // queries can resolve the sinkModel extensions. `--model-packs` takes a
        // pack name, so point `--additional-packs` at the pack's directory and
        // reference the pack by name.
        for mp in model_packs {
            cmd.arg("--additional-packs").arg(&mp.search_path);
            cmd.arg("--model-packs").arg(&mp.name);
        }

        // Query files are already language-native (per-language pack).
        for qf in &queries.query_files {
            cmd.arg(qf);
        }

        // Standard suite refs are already scoped to this database's language.
        for suite in &queries.suite_refs {
            cmd.arg(suite);
        }

        // Extra args from config
        for arg in extra_args {
            cmd.arg(arg);
        }

        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true); // ← key: timeout branch reaps the child

        let child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn codeql analyze: {}", e))?;

        // Wait for the child to exit, the timeout to fire, or the batch
        // cancellation token to be cancelled. On timeout/cancel the `child`
        // future is dropped and `kill_on_drop(true)` reaps the subprocess.
        let result = tokio::select! {
            res = tokio::time::timeout(
                Duration::from_secs(timeout_seconds),
                child.wait_with_output(),
            ) => res,
            _ = cancel.cancelled() => {
                bail!("cancelled");
            }
        };

        match result {
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                if exit_code != 0 {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    bail!(
                        "codeql analyze failed (exit code {}): {}",
                        exit_code,
                        stderr.trim()
                    );
                }
                let sarif = std::fs::read_to_string(&output_path).map_err(|e| {
                    anyhow::anyhow!(
                        "failed to read CodeQL SARIF output '{}': {}",
                        output_path.display(),
                        e
                    )
                })?;
                let _ = std::fs::remove_file(&output_path);
                Ok(sarif)
            }
            Ok(Err(e)) => bail!("codeql analyze process failed: {e}"),
            Err(_elapsed) => bail!("codeql analyze timed out after {}s", timeout_seconds),
        }
    }

    /// Synchronous shell around [`Self::run_analysis`], used only by the
    /// synchronous unit tests now that the pipeline calls the async form.
    #[cfg(test)]
    pub(crate) fn run_analysis_blocking(
        &self,
        db: &DatabaseInfo,
        queries: &QueryPack,
        timeout_seconds: u64,
        extra_args: &[String],
        model_packs: &[&MadPack],
    ) -> Result<String> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.run_analysis(
                db,
                queries,
                timeout_seconds,
                extra_args,
                model_packs,
                &CancellationToken::new(),
            ))
    }
}

/// Parse a `(major, minor, patch)` tuple from the first line of
/// `codeql --version` output (e.g. "CodeQL command-line toolchain release 2.26.3.").
pub(crate) fn parse_codeql_version(stdout: &str) -> Option<(u32, u32, u32)> {
    let line = stdout.lines().next()?;
    let after_release = line.split("release ").nth(1)?;
    let version = after_release
        .split_whitespace()
        .next()?
        .trim_end_matches('.');
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codeql_db_dirs_differ_across_runs_in_one_process() {
        let a = CliCodeqlProvider::new("codeql".into(), RunId::new());
        let b = CliCodeqlProvider::new("codeql".into(), RunId::new());
        assert_ne!(
            a.db_dir("python"),
            b.db_dir("python"),
            "same-process runs must not share a CodeQL database"
        );
        assert_ne!(a.sarif_path("python"), b.sarif_path("python"));
    }

    #[test]
    fn missing_codeql_cli_errors_on_database_create() {
        // Use a binary that cannot exist so the test is deterministic
        // regardless of whether CodeQL is installed on the host.
        let provider = CliCodeqlProvider::new("__codeql_definitely_missing__".to_string(), RunId::new());
        if provider.check_available() {
            return; // unexpected, but skip rather than fail
        }
        let tmp = std::env::temp_dir().join("mcp-sec-audit-codeql-test-missing");
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        let err = provider
            .create_database_blocking(&tmp, "python", 60)
            .expect_err("codeql database create should fail when CLI not found");
        assert!(
            err.to_string().contains("codeql CLI not found"),
            "unexpected error message: {}",
            err
        );
    }

    /// Mirror of the agent provider's `agent_timeout_kills_the_child_process`:
    /// a `codeql database create` that never finishes (a stub binary that
    /// `exec sleep 30`) must be killed when the 1s timeout fires, not leaked as
    /// an orphan (design §2.3).
    #[cfg(unix)]
    #[tokio::test]
    async fn create_database_timeout_kills_the_child_process() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "mcp-sec-audit-codeql-timeout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        // `exec` replaces the stub shell with `sleep 30`, so `kill_on_drop`
        // kills the sleeper directly rather than leaving it orphaned under the
        // shell.
        let stub = dir.join("codeql-stub.sh");
        std::fs::write(&stub, "#!/bin/sh\nexec sleep 30\n").expect("write stub");
        let mut perms = std::fs::metadata(&stub).expect("stub metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&stub, perms).expect("chmod stub");

        let provider = CliCodeqlProvider::new(stub.display().to_string(), RunId::new());
        let started = std::time::Instant::now();
        let err = provider
            .create_database(&dir, "python", 1, &CancellationToken::new())
            .await
            .expect_err("database create should time out");
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
        assert!(
            started.elapsed().as_secs() < 5,
            "must not wait for the child"
        );

        // The child must have been reclaimed by `kill_on_drop` (see the agent
        // timeout test for why the `[3]0` bracket form is used).
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

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pre_cancelled_token_cancels_create_database_promptly() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "mcp-sec-audit-codeql-cancel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let stub = dir.join("codeql-stub.sh");
        std::fs::write(&stub, "#!/bin/sh\nexec sleep 30\n").expect("write stub");
        let mut perms = std::fs::metadata(&stub).expect("stub metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&stub, perms).expect("chmod stub");

        let provider = CliCodeqlProvider::new(stub.display().to_string(), RunId::new());
        let cancel = CancellationToken::new();
        cancel.cancel();

        let started = std::time::Instant::now();
        let err = provider
            .create_database(&dir, "python", 30, &cancel)
            .await
            .expect_err("pre-cancelled token must yield an error");
        assert!(
            err.to_string().contains("cancelled"),
            "expected a cancellation error, got: {err}"
        );
        assert!(
            started.elapsed().as_secs() < 5,
            "must return promptly, not wait for the child"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn parses_codeql_version_line() {
        let stdout = "CodeQL command-line toolchain release 2.26.2.\nCopyright (C) ...\n";
        assert_eq!(parse_codeql_version(stdout), Some((2, 26, 2)));
    }

    #[test]
    fn parses_three_component_version_without_trailing_dot() {
        assert_eq!(
            parse_codeql_version("CodeQL release 2.26.3"),
            Some((2, 26, 3))
        );
    }

    #[test]
    fn unparseable_version_returns_none() {
        assert_eq!(parse_codeql_version("not a version line"), None);
    }
}
