//! Run state: per-repo progress, bounded log buffers, and snapshot for WS replay.

use std::collections::BTreeMap;

use mcp_sec_audit_core::batch::RepoStatus;
use mcp_sec_audit_core::events::{AnalysisEvent, Stage};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Fixed-capacity ring buffer of log lines per repo.
#[derive(Debug, Clone)]
pub struct RingBuffer<T> {
    items: Vec<T>,
    cap: usize,
}

impl<T> Default for RingBuffer<T> {
    fn default() -> Self {
        Self::new(1)
    }
}

impl<T> RingBuffer<T> {
    pub fn new(cap: usize) -> Self {
        Self { items: Vec::with_capacity(cap), cap: cap.max(1) }
    }
    pub fn push(&mut self, item: T) {
        if self.items.len() == self.cap {
            self.items.remove(0);
        }
        self.items.push(item);
    }
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Live progress of one repo.
///
/// `status` is `None` until the repo finishes, so in-flight repos are
/// distinguishable from genuinely-cancelled ones in `RunSnapshot` (a
/// cancelled repo carries `status: Some(Cancelled)`). `record` sets it only in
/// the `RepoFinished` arm.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RepoProgress {
    pub status: Option<RepoStatus>,
    pub stage: Option<Stage>,
    pub percent: u8,
    pub risk_level: Option<String>,
    pub finding_count: Option<usize>,
    pub error: Option<String>,
}

/// Everything needed to render the page + replay on WS connect.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunSnapshot {
    pub batch_id: Option<String>,
    pub repos: BTreeMap<String, RepoProgress>,
    pub logs: BTreeMap<String, Vec<(String, String)>>, // repo -> (level, line)
}

#[derive(Clone)]
pub struct RunManager {
    tx: broadcast::Sender<AnalysisEvent>,
    cancel: CancellationToken,
    state: std::sync::Arc<std::sync::Mutex<ManagerState>>,
}

struct ManagerState {
    batch_id: Option<String>,
    repos: BTreeMap<String, RepoProgress>,
    logs: BTreeMap<String, RingBuffer<(String, String)>>,
    finished: bool,
}

impl RunManager {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            tx,
            cancel: CancellationToken::new(),
            state: std::sync::Arc::new(std::sync::Mutex::new(ManagerState {
                batch_id: None,
                repos: BTreeMap::new(),
                logs: BTreeMap::new(),
                finished: false,
            })),
        }
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// A receiver that yields future events (for live WS forwarding).
    pub fn subscribe(&self) -> broadcast::Receiver<AnalysisEvent> {
        self.tx.subscribe()
    }

    /// The sender used to broadcast events to subscribers.
    pub fn sender(&self) -> broadcast::Sender<AnalysisEvent> {
        self.tx.clone()
    }

    /// Fold one event into the managed state, then re-broadcast it to
    /// subscribers (the single consumption point: WS clients read the snapshot
    /// on connect, then live events from `subscribe()`).
    pub fn record(&self, event: AnalysisEvent) {
        let mut state = self.state.lock().expect("run state mutex");
        match &event {
            AnalysisEvent::BatchStarted { batch_id, repo_names, .. } => {
                state.batch_id = Some(batch_id.clone());
                for name in repo_names {
                    state.repos.entry(name.clone()).or_default();
                }
            }
            AnalysisEvent::RepoStarted { repo } => {
                state.repos.entry(repo.clone()).or_default();
            }
            AnalysisEvent::StageProgress { repo, stage, percent } => {
                let p = state.repos.entry(repo.clone()).or_default();
                p.stage = Some(stage.clone());
                p.percent = *percent;
            }
            AnalysisEvent::RepoFinished { repo, status, duration_ms: _, risk_level, fused_finding_count } => {
                let p = state.repos.entry(repo.clone()).or_default();
                p.status = Some(*status);
                p.risk_level = risk_level.clone();
                p.finding_count = *fused_finding_count;
            }
            AnalysisEvent::Log { repo, level, line } => {
                let buf = state.logs.entry(repo.clone()).or_insert_with(|| RingBuffer::new(500));
                buf.push((level_to_str(*level).to_string(), line.clone()));
            }
            AnalysisEvent::BatchFinished { .. } => {
                state.finished = true;
            }
        }
        let _ = self.tx.send(event);
    }

    pub fn snapshot(&self) -> RunSnapshot {
        let state = self.state.lock().expect("run state mutex");
        RunSnapshot {
            batch_id: state.batch_id.clone(),
            repos: state.repos.clone(),
            logs: state
                .logs
                .iter()
                .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
                .collect(),
        }
    }
}

impl Default for RunManager {
    fn default() -> Self {
        Self::new()
    }
}

fn level_to_str(level: mcp_sec_audit_core::LogLevel) -> &'static str {
    use mcp_sec_audit_core::LogLevel::*;
    match level {
        Trace => "trace",
        Debug => "debug",
        Info => "info",
        Warn => "warn",
        Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_sec_audit_core::events::{Stage, SetupStep};

    #[test]
    fn ring_buffer_keeps_cap() {
        let mut rb = RingBuffer::new(3);
        rb.push(1);
        rb.push(2);
        rb.push(3);
        rb.push(4);
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.iter().copied().collect::<Vec<_>>(), vec![2, 3, 4]);
    }

    #[test]
    fn record_folds_stage_and_log() {
        let mgr = RunManager::new();
        mgr.record(AnalysisEvent::BatchStarted {
            batch_id: "b1".into(),
            repo_names: vec!["a".into()],
            max_parallel: 1,
        });
        mgr.record(AnalysisEvent::StageProgress {
            repo: "a".into(),
            stage: Stage::Setup(SetupStep::Discover),
            percent: 1,
        });
        mgr.record(AnalysisEvent::Log {
            repo: "a".into(),
            level: mcp_sec_audit_core::LogLevel::Info,
            line: "hi".into(),
        });
        let snap = mgr.snapshot();
        assert_eq!(snap.batch_id.as_deref(), Some("b1"));
        assert_eq!(snap.repos["a"].percent, 1);
        assert_eq!(snap.logs["a"].len(), 1);
    }

    #[test]
    fn repo_status_none_until_finished() {
        let mgr = RunManager::new();
        mgr.record(AnalysisEvent::RepoStarted { repo: "a".into() });
        mgr.record(AnalysisEvent::StageProgress {
            repo: "a".into(),
            stage: Stage::Setup(SetupStep::Discover),
            percent: 1,
        });
        // In-flight: no terminal status yet — distinct from a cancelled repo.
        assert_eq!(mgr.snapshot().repos["a"].status, None);
        mgr.record(AnalysisEvent::RepoFinished {
            repo: "a".into(),
            status: mcp_sec_audit_core::batch::RepoStatus::Ok,
            duration_ms: 42,
            risk_level: Some("low".into()),
            fused_finding_count: Some(0),
        });
        assert_eq!(
            mgr.snapshot().repos["a"].status,
            Some(mcp_sec_audit_core::batch::RepoStatus::Ok)
        );
    }

    #[test]
    fn record_rebroadcasts_to_subscribers() {
        let mgr = RunManager::new();
        let mut rx = mgr.subscribe();
        mgr.record(AnalysisEvent::RepoStarted { repo: "a".into() });
        let ev = rx.try_recv().expect("subscriber should receive the recorded event");
        match ev {
            AnalysisEvent::RepoStarted { repo } => assert_eq!(repo, "a"),
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn clone_shares_state() {
        let mgr = RunManager::new();
        let mgr2 = mgr.clone();
        mgr.record(AnalysisEvent::RepoStarted { repo: "a".into() });
        assert!(mgr2.snapshot().repos.contains_key("a"));
    }
}
