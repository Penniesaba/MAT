//! Structured analysis events for the v6 web UI.
//!
//! [`AnalysisEvent`] is the single stream the web UI consumes: batch/repo
//! lifecycle, hierarchical stage progress, and per-repo log lines. [`EventSink`]
//! is the producer handle threaded through [`crate::runctx::RunContext`]; with
//! no subscriber it is a no-op so the single-repo CLI path is byte-identical.

use tokio::sync::broadcast;

use crate::batch::{BatchSummary, RepoStatus};
use crate::config::LogLevel;

/// A structured event emitted during a scan run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AnalysisEvent {
    BatchStarted {
        batch_id: String,
        repo_names: Vec<String>,
        max_parallel: usize,
    },
    BatchFinished {
        summary: BatchSummary,
    },
    RepoStarted {
        repo: String,
    },
    RepoFinished {
        repo: String,
        status: RepoStatus,
        duration_ms: u64,
        risk_level: Option<String>,
        fused_finding_count: Option<usize>,
        /// Human-readable failure reason, set when `status` is `Failed`.
        error: Option<String>,
    },
    StageProgress {
        repo: String,
        stage: Stage,
        percent: u8,
    },
    Log {
        repo: String,
        level: LogLevel,
        line: String,
    },
}

/// Hierarchical stage tree mirroring `pipeline.rs` (two phases × two lines).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Stage {
    Setup(SetupStep),
    Phase1(Phase1Step),
    Evolution(EvolutionStep),
    Phase2(Phase2Step),
    Validation(ValidationStep),
    Finish(FinishStep),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SetupStep {
    Discover,
    LoadRulebook,
    LoadCatalog,
    BaselineComponents,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Phase1Step {
    Standard(StandardStep),
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Phase2Step {
    Standard(Phase2StandardStep),
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StandardStep {
    Rule,
    Taint,
    Codeql(CodeqlStep),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Phase2StandardStep {
    Taint,
    Codeql(CodeqlStep),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CodeqlStep {
    CreateDb,
    CompileMad,
    Analyze,
    ParseSarif,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EvolutionStep {
    GateG1G2,
    StageG3,
    Diff1,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ValidationStep {
    Diff2,
    Migrate,
    Explain,
    Adjudicate,
    Promote,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FinishStep {
    Fusion,
    Partition,
    Report,
}

/// Cumulative milestone percent for a fully-enabled run. Disabled/skipped
/// stages simply don't emit, so the next emitted stage carries its own higher
/// percent and the bar jumps forward (spec §5.4 weight hand-off).
pub fn stage_percent(stage: &Stage) -> u8 {
    use Stage::*;
    match stage {
        Setup(SetupStep::Discover) => 1,
        Setup(SetupStep::LoadRulebook) => 3,
        Setup(SetupStep::LoadCatalog) => 5,
        Setup(SetupStep::BaselineComponents) => 7,
        Phase1(Phase1Step::Standard(StandardStep::Rule)) => 10,
        Phase1(Phase1Step::Standard(StandardStep::Taint)) => 16,
        Phase1(Phase1Step::Standard(StandardStep::Codeql(CodeqlStep::CreateDb))) => 22,
        Phase1(Phase1Step::Standard(StandardStep::Codeql(CodeqlStep::CompileMad))) => 24,
        Phase1(Phase1Step::Standard(StandardStep::Codeql(CodeqlStep::Analyze))) => 28,
        Phase1(Phase1Step::Standard(StandardStep::Codeql(CodeqlStep::ParseSarif))) => 34,
        Phase1(Phase1Step::Agent) => 40,
        Evolution(EvolutionStep::GateG1G2) => 42,
        Evolution(EvolutionStep::StageG3) => 44,
        Evolution(EvolutionStep::Diff1) => 46,
        Phase2(Phase2Step::Standard(Phase2StandardStep::Taint)) => 52,
        Phase2(Phase2Step::Standard(Phase2StandardStep::Codeql(CodeqlStep::CreateDb))) => 58,
        Phase2(Phase2Step::Standard(Phase2StandardStep::Codeql(CodeqlStep::CompileMad))) => 60,
        Phase2(Phase2Step::Standard(Phase2StandardStep::Codeql(CodeqlStep::Analyze))) => 64,
        Phase2(Phase2Step::Standard(Phase2StandardStep::Codeql(CodeqlStep::ParseSarif))) => 70,
        Phase2(Phase2Step::Agent) => 76,
        Validation(ValidationStep::Diff2) => 82,
        Validation(ValidationStep::Migrate) => 86,
        Validation(ValidationStep::Explain) => 90,
        Validation(ValidationStep::Adjudicate) => 94,
        Validation(ValidationStep::Promote) => 96,
        Finish(FinishStep::Fusion) => 98,
        Finish(FinishStep::Partition) => 99,
        Finish(FinishStep::Report) => 100,
    }
}

/// Cloneable event producer. `None` sender = noop (single-repo CLI path).
#[derive(Clone)]
pub struct EventSink {
    tx: Option<broadcast::Sender<AnalysisEvent>>,
    repo: Option<String>,
}

impl EventSink {
    pub fn noop() -> Self {
        Self { tx: None, repo: None }
    }

    /// Returns a sink plus the receiver subscribers use.
    pub fn broadcast() -> (Self, broadcast::Receiver<AnalysisEvent>) {
        let (tx, rx) = broadcast::channel(256);
        (Self { tx: Some(tx), repo: None }, rx)
    }

    /// Returns a sink that stamps `repo` onto every repo-attributed event.
    pub fn scoped(&self, repo: &str) -> Self {
        Self { tx: self.tx.clone(), repo: Some(repo.to_string()) }
    }

    pub fn emit(&self, event: AnalysisEvent) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(event);
        }
    }

    pub fn stage_progress(&self, stage: Stage, percent: u8) {
        self.emit(AnalysisEvent::StageProgress {
            repo: self.repo.clone().unwrap_or_default(),
            stage,
            percent,
        });
    }

    pub fn log(&self, level: LogLevel, line: impl Into<String>) {
        self.emit(AnalysisEvent::Log {
            repo: self.repo.clone().unwrap_or_default(),
            level,
            line: line.into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_sink_drops_events() {
        let sink = EventSink::noop();
        sink.stage_progress(Stage::Setup(SetupStep::Discover), 1);
        sink.emit(AnalysisEvent::BatchStarted {
            batch_id: "b".into(),
            repo_names: vec![],
            max_parallel: 1,
        });
        // no panic; nothing to assert beyond construction
    }

    #[test]
    fn scoped_sink_stamps_repo_on_stage_and_log() {
        let (sink, mut rx) = EventSink::broadcast();
        let scoped = sink.scoped("excel");
        scoped.stage_progress(Stage::Phase1(Phase1Step::Agent), 40);
        scoped.log(LogLevel::Info, "hello");

        let first = rx.blocking_recv().expect("stage event");
        match first {
            AnalysisEvent::StageProgress { repo, stage, percent } => {
                assert_eq!(repo, "excel");
                assert_eq!(stage, Stage::Phase1(Phase1Step::Agent));
                assert_eq!(percent, 40);
            }
            other => panic!("unexpected event: {other:?}"),
        }
        let second = rx.blocking_recv().expect("log event");
        match second {
            AnalysisEvent::Log { repo, level, line } => {
                assert_eq!(repo, "excel");
                assert_eq!(level, LogLevel::Info);
                assert_eq!(line, "hello");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn stage_percent_is_monotonic_across_boundaries() {
        let ordered = [
            Stage::Setup(SetupStep::Discover),
            Stage::Phase1(Phase1Step::Standard(StandardStep::Rule)),
            Stage::Phase1(Phase1Step::Agent),
            Stage::Phase2(Phase2Step::Standard(Phase2StandardStep::Taint)),
            Stage::Phase2(Phase2Step::Agent),
            Stage::Validation(ValidationStep::Promote),
            Stage::Finish(FinishStep::Report),
        ];
        let mut prev = 0u8;
        for stage in &ordered {
            let p = stage_percent(stage);
            assert!(p >= prev, "percent must not regress: {p} < {prev}");
            prev = p;
        }
        assert_eq!(prev, 100);
    }

    #[test]
    fn event_is_send_sync_clone_static() {
        fn assert_bounds<T: Send + Sync + Clone + 'static>() {}
        assert_bounds::<AnalysisEvent>();
        assert_bounds::<Stage>();
    }
}
