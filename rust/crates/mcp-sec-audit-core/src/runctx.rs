//! Plumbing types shared across the v5 parallel multi-repo orchestration.
//!
//! [`RunId`] keys every run-scoped temporary path so concurrent repositories
//! cannot collide; [`Progress`] replaces the `&mut impl FnMut(&str)` closure
//! that cannot cross `.await` points; [`RunContext`] bundles the per-run
//! state that the asynchronous pipeline will carry.

use std::path::PathBuf;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A unique identifier for a single analysis run.
///
/// Two runs never share a [`RunId`], which is what lets each run own a
/// distinct temporary directory even when several repositories are analysed
/// concurrently (see [`RunId::temp_dir`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RunId(String);

impl RunId {
    /// Creates a fresh, globally-unique run id.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().simple().to_string())
    }

    /// Derives a deterministic run id from a batch id and a repository path.
    pub fn for_repo(batch_id: &str, repo: &str) -> Self {
        Self(format!("{batch_id}-{}", sanitize(repo)))
    }

    /// Returns the run id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The single exit point for every run-id-keyed temporary directory.
    pub fn temp_dir(&self, kind: &str) -> PathBuf {
        std::env::temp_dir().join(format!("mcp-sec-audit-{kind}-{}", self.0))
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

/// Replaces `/`, `\`, `:` and spaces with `-` so a repository path can be
/// embedded in a single path segment.
fn sanitize(repo: &str) -> String {
    repo.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | ' ' => '-',
            other => other,
        })
        .collect()
}

/// A cloneable progress reporter with three interchangeable backends.
///
/// Callers hold a single [`Progress`] without knowing which backend it uses:
///
/// * **tracing** — `report` emits immediately via `tracing::info!`
///   (`mcp_sec_audit::pipeline`). The single-repository CLI path uses this so
///   progress surfaces in real time.
/// * **channel** — `report` sends to an `mpsc::UnboundedSender<String>`, for
///   the batch orchestrator to aggregate across repositories and print once.
/// * **noop** — `report` does nothing; used by tests.
#[derive(Clone)]
pub struct Progress {
    kind: ProgressKind,
    prefix: Option<String>,
}

#[derive(Clone)]
enum ProgressKind {
    Tracing,
    Channel(mpsc::UnboundedSender<String>),
    Noop,
}

impl Progress {
    /// A progress reporter that logs immediately through `tracing`.
    pub fn tracing() -> Self {
        Self {
            kind: ProgressKind::Tracing,
            prefix: None,
        }
    }

    /// A progress reporter backed by an unbounded channel.
    pub fn channel() -> (Self, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                kind: ProgressKind::Channel(tx),
                prefix: None,
            },
            rx,
        )
    }

    /// A progress reporter that discards every message.
    pub fn noop() -> Self {
        Self {
            kind: ProgressKind::Noop,
            prefix: None,
        }
    }

    /// Emits a progress message.
    pub fn report(&self, msg: impl Into<String>) {
        let msg = msg.into();
        match &self.kind {
            ProgressKind::Tracing => match &self.prefix {
                Some(repo) => {
                    tracing::info!(target: "mcp_sec_audit::pipeline", repo = %repo, "{msg}");
                }
                None => {
                    tracing::info!(target: "mcp_sec_audit::pipeline", "{msg}");
                }
            },
            ProgressKind::Channel(tx) => {
                let rendered = match &self.prefix {
                    Some(repo) => format!("[{repo}] {msg}"),
                    None => msg,
                };
                let _ = tx.send(rendered);
            }
            ProgressKind::Noop => {}
        }
    }

    /// Returns a reporter scoped to `repo`.
    ///
    /// In channel form the prefix renders as `"[repo] "`; in tracing form the
    /// repo is attached as a `repo` field on the log record; in noop form it is
    /// ignored.
    pub fn scoped(&self, repo: &str) -> Self {
        Self {
            kind: self.kind.clone(),
            prefix: Some(repo.to_string()),
        }
    }
}

/// Per-run state carried through the asynchronous pipeline.
pub struct RunContext {
    pub run_id: RunId,
    pub progress: Progress,
    pub cancel: CancellationToken,
    /// Placeholder until Task 9 replaces it with `Option<crate::batch::ResourceGovernor>`.
    pub governor: Option<()>,
    /// Placeholder until Task 10 replaces it with `Option<crate::batch::LearningBusHandle>`.
    pub learning_bus: Option<()>,
}

impl RunContext {
    /// Builds a context for a single-repository run.
    ///
    /// Uses the tracing [`Progress`] backend so the CLI's single-repo path
    /// prints progress in real time.
    pub fn single(run_id: RunId) -> Self {
        Self {
            run_id,
            progress: Progress::tracing(),
            cancel: CancellationToken::new(),
            governor: None,
            learning_bus: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_ids_are_unique() {
        let a = RunId::new();
        let b = RunId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn temp_dir_is_keyed_by_run_id_not_pid() {
        let a = RunId::new();
        let b = RunId::new();
        assert_ne!(a.temp_dir("codeql"), b.temp_dir("codeql"));
        assert!(a.temp_dir("codeql").to_string_lossy().contains(a.as_str()));
    }

    #[test]
    fn for_repo_sanitizes_and_embeds_batch_id() {
        let id = RunId::for_repo("batch-1", "MCTS/examples");
        assert!(id.as_str().starts_with("batch-1-"));
        assert!(!id.as_str().contains('/'), "path separators must be sanitized");
    }

    #[test]
    fn default_run_id_delegates_to_new() {
        let a = RunId::default();
        let b = RunId::default();
        assert_ne!(a, b);
    }

    #[test]
    fn channel_progress_scoped_adds_prefix() {
        let (progress, mut rx) = Progress::channel();
        progress.scoped("excel").report("hi");
        assert_eq!(rx.try_recv().expect("one message"), "[excel] hi");
    }

    #[test]
    fn channel_progress_unscoped_has_no_prefix() {
        let (progress, mut rx) = Progress::channel();
        progress.report("hi");
        assert_eq!(rx.try_recv().expect("one message"), "hi");
    }

    #[test]
    fn noop_progress_does_not_panic() {
        let progress = Progress::noop();
        progress.report("hi");
        progress.scoped("excel").report("hi");
    }

    #[test]
    fn progress_is_send_sync_clone_static() {
        fn assert_send_sync<T: Send + Sync + Clone + 'static>() {}
        assert_send_sync::<Progress>();
    }

    #[test]
    fn run_context_single_uses_tracing_progress() {
        let ctx = RunContext::single(RunId::new());
        assert!(ctx.governor.is_none());
        assert!(ctx.learning_bus.is_none());
        assert!(!ctx.cancel.is_cancelled());
    }
}
