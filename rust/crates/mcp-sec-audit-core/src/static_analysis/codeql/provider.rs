use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};

use super::models::MadPack;
use super::queries::QueryPack;

/// Info about a successfully created CodeQL database.
#[derive(Debug, Clone)]
pub struct DatabaseInfo {
    pub path: PathBuf,
    /// Language the database was created for.
    pub language: String,
}

/// Pluggable CodeQL backend.
pub trait CodeqlProvider {
    /// Check whether the CodeQL CLI is available.
    fn check_available(&self) -> bool;

    /// Create a CodeQL database from source files.
    fn create_database(&self, source_dir: &Path, language: &str) -> Result<DatabaseInfo>;

    /// Run CodeQL analysis on a database and return SARIF JSON.
    fn run_analysis(
        &self,
        db: &DatabaseInfo,
        queries: &QueryPack,
        timeout_seconds: u64,
        extra_args: &[String],
        model_packs: &[MadPack],
    ) -> Result<String>;
}

/// Default provider: shells out to the `codeql` CLI.
pub struct CliCodeqlProvider {
    binary: String,
}

impl CliCodeqlProvider {
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
        }
    }
}

impl CodeqlProvider for CliCodeqlProvider {
    fn check_available(&self) -> bool {
        Command::new(&self.binary)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn create_database(&self, source_dir: &Path, language: &str) -> Result<DatabaseInfo> {
        let db_dir = std::env::temp_dir()
            .join("mcp-sec-audit-codeql")
            .join(format!("db-{}", std::process::id()))
            .join(language);

        // Reuse a cached database when one already exists for this process +
        // language, so a re-created session does not re-extract the source.
        if db_dir.join("codeql-database.yml").exists() {
            return Ok(DatabaseInfo {
                path: db_dir,
                language: language.to_string(),
            });
        }

        std::fs::create_dir_all(&db_dir)?;

        let output = Command::new(&self.binary)
            .arg("database")
            .arg("create")
            .arg(&db_dir)
            .arg("--language")
            .arg(language)
            .arg("--source-root")
            .arg(source_dir)
            .arg("--overwrite")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|e| {
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

    fn run_analysis(
        &self,
        db: &DatabaseInfo,
        queries: &QueryPack,
        timeout_seconds: u64,
        extra_args: &[String],
        model_packs: &[MadPack],
    ) -> Result<String> {
        // `--output=-` (SARIF to stdout) is unreliable across CodeQL versions,
        // so write to a temp file and read it back instead.
        let output_path = std::env::temp_dir().join(format!(
            "mcp-sec-audit-sarif-{}-{}.sarif",
            std::process::id(),
            db.language
        ));

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
            .stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            anyhow::anyhow!("failed to spawn codeql analyze: {}", e)
        })?;

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut stdout = String::new();
            let mut stderr = String::new();
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

        let timeout = Duration::from_secs(timeout_seconds);
        match rx.recv_timeout(timeout) {
            Ok((_stdout, stderr, exit_code)) => {
                if exit_code != 0 {
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
            Err(mpsc::RecvTimeoutError::Timeout) => {
                bail!("codeql analyze timed out after {}s", timeout_seconds)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("codeql analyze process communication channel disconnected")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_codeql_cli_errors_on_database_create() {
        // Use a binary that cannot exist so the test is deterministic
        // regardless of whether CodeQL is installed on the host.
        let provider = CliCodeqlProvider::new("__codeql_definitely_missing__");
        if provider.check_available() {
            return; // unexpected, but skip rather than fail
        }
        let tmp = std::env::temp_dir().join("mcp-sec-audit-codeql-test-missing");
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        let err = provider
            .create_database(&tmp, "python")
            .expect_err("codeql database create should fail when CLI not found");
        assert!(
            err.to_string().contains("codeql CLI not found"),
            "unexpected error message: {}",
            err
        );
    }
}
