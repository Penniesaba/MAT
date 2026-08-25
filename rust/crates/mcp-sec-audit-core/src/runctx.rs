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
    ///
    /// The sanitized repo path keeps the id human-readable, but sanitization
    /// alone is not injective (`MCTS/examples` and `MCTS-examples` both
    /// sanitize to `MCTS-examples`). A short stable hash of the *raw* repo
    /// string is appended so two repos in one batch can never share an id (and
    /// therefore never share a [`RunId::temp_dir`]).
    pub fn for_repo(batch_id: &str, repo: &str) -> Self {
        let digest = crate::static_analysis::learning::stable_hash(repo);
        let short = &digest[..8];
        Self(format!("{batch_id}-{}-{short}", sanitize(repo)))
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
    ///
    /// Scoping is single-level: calling `scoped` on an already-scoped reporter
    /// *overwrites* the previous prefix rather than accumulating it
    /// (`scoped("outer").scoped("inner")` reports as `inner` only).
    pub fn scoped(&self, repo: &str) -> Self {
        Self {
            kind: self.kind.clone(),
            prefix: Some(repo.to_string()),
        }
    }
}

/// Every `kind` a scan run passes to [`RunId::temp_dir`]. Kept in one place so
/// [`RunContext::cleanup`] enumerates exactly the directories this crate mints
/// without drifting from the call sites that create them. The path format
/// itself stays in [`RunId::temp_dir`] (the single source of truth).
const TEMP_KINDS: &[&str] = &["codeql", "sarif", "mad", "staging"];

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

    /// Removes every run-scoped temporary directory created for this run's
    /// [`RunId`] (the `codeql`, `sarif`, `mad`, and `staging` kinds).
    ///
    /// Best-effort: a missing directory is not an error, and every kind is
    /// attempted even if one fails. Returns the first real error encountered,
    /// or `Ok(())` when all directories are gone (or never existed).
    pub fn cleanup(&self) -> Result<(), std::io::Error> {
        let mut first_error = None;
        for kind in TEMP_KINDS {
            if let Err(e) = std::fs::remove_dir_all(self.run_id.temp_dir(kind))
                && e.kind() != std::io::ErrorKind::NotFound
                && first_error.is_none()
            {
                first_error = Some(e);
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
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
    fn for_repo_is_deterministic() {
        let a = RunId::for_repo("batch-1", "MCTS/examples");
        let b = RunId::for_repo("batch-1", "MCTS/examples");
        assert_eq!(a, b, "same inputs must produce the same run id");
    }

    #[test]
    fn for_repo_distinguishes_sanitized_collisions() {
        // Each pair sanitizes to the same string, so only the raw-string hash
        // keeps them apart. If any pair collides, two repos in one batch would
        // silently share a temp dir.
        let pairs = [
            ("MCTS/examples", "MCTS-examples"),
            ("a b", "a:b"),
            ("a b", "a-b"),
            ("a:b", "a-b"),
        ];
        for (x, y) in pairs {
            let id_x = RunId::for_repo("batch-1", x);
            let id_y = RunId::for_repo("batch-1", y);
            assert_ne!(id_x, id_y, "{x:?} and {y:?} must not collide");
            assert_ne!(
                id_x.temp_dir("codeql"),
                id_y.temp_dir("codeql"),
                "{x:?} and {y:?} must not share a temp dir"
            );
        }
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
    fn tracing_progress_scoped_attaches_repo_field() {
        use std::sync::{Arc, Mutex};
        use tracing::{Event, Metadata, Subscriber, field, span};

        #[derive(Default)]
        struct Capture {
            fields: Arc<Mutex<Vec<(String, String)>>>,
        }

        impl Subscriber for Capture {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }
            fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
            fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
            fn event(&self, event: &Event<'_>) {
                let mut recorder = Recorder::default();
                event.record(&mut recorder);
                self.fields.lock().unwrap().extend(recorder.fields);
            }
            fn enter(&self, _: &span::Id) {}
            fn exit(&self, _: &span::Id) {}
        }

        #[derive(Default)]
        struct Recorder {
            fields: Vec<(String, String)>,
        }
        impl field::Visit for Recorder {
            fn record_debug(&mut self, f: &field::Field, value: &dyn std::fmt::Debug) {
                self.fields.push((f.name().to_string(), format!("{value:?}")));
            }
            fn record_str(&mut self, f: &field::Field, value: &str) {
                self.fields.push((f.name().to_string(), value.to_string()));
            }
        }

        let capture = Capture::default();
        let captured = capture.fields.clone();
        tracing::subscriber::with_default(capture, || {
            Progress::tracing().scoped("excel").report("hi");
        });

        let fields = captured.lock().unwrap();
        assert!(
            fields.iter().any(|(k, v)| k == "repo" && v.contains("excel")),
            "expected repo=excel field, got {fields:?}"
        );
        assert!(
            fields.iter().any(|(k, v)| k == "message" && v.contains("hi")),
            "expected message=hi field, got {fields:?}"
        );
    }

    #[test]
    fn progress_is_send_sync_clone_static() {
        fn assert_send_sync<T: Send + Sync + Clone + 'static>() {}
        assert_send_sync::<Progress>();
    }

    #[test]
    fn run_context_single_initializes_placeholders_and_cancel() {
        let ctx = RunContext::single(RunId::new());
        assert!(ctx.governor.is_none());
        assert!(ctx.learning_bus.is_none());
        assert!(!ctx.cancel.is_cancelled());
    }

    #[test]
    fn cleanup_removes_run_temp_dirs() {
        let ctx = RunContext::single(RunId::new());
        // Create content in every run-scoped temp dir the pipeline mints. The
        // `sarif` kind is the parent directory `create_dir_all` makes for the
        // SARIF output file, so a marker there exercises that exact path.
        for kind in TEMP_KINDS {
            let dir = ctx.run_id.temp_dir(kind);
            std::fs::create_dir_all(&dir).expect("create temp dir");
            std::fs::write(dir.join("marker.txt"), "x").expect("write marker");
        }
        ctx.cleanup().expect("cleanup should succeed");
        for kind in TEMP_KINDS {
            let dir = ctx.run_id.temp_dir(kind);
            assert!(!dir.exists(), "temp dir for kind {kind:?} should be removed");
        }
        // Idempotent: removing already-gone dirs is not an error.
        ctx.cleanup().expect("second cleanup should be a no-op success");
    }
}
