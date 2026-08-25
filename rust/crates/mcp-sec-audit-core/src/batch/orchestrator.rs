//! Batch orchestrator (v5 parallel multi-repository analysis).
//!
//! [`run_batch`] is the integration point for the whole v5 batch subsystem: it
//! runs every repository in a [`BatchConfig`] concurrently, bounded by the
//! `max_parallel` semaphore, with per-class concurrency limited by a shared
//! [`ResourceGovernor`] and cross-repo learning routed through a shared
//! [`LearningBusHandle`]. Each repository writes its own per-repo report files,
//! and the batch writes `batch-summary.md` + `batch-summary.json`.
//!
//! Two distinct concurrency controls must not be conflated (design §6 / §10):
//!
//! * **`max_parallel`** is a single [`Semaphore`] the orchestrator holds for a
//!   repository's *entire* task (one permit per repo, from dispatch until the
//!   scan + report write finish). It bounds how many repositories run at once.
//! * **the governor's class permits** are acquired *inside* the pipeline around
//!   each provider call (CodeQL / agent / CPU), never more than one at a time,
//!   and never across classes — see `static_analysis::pipeline::acquire_permit`.
//!
//! The two interact safely because a repo holds its `max_parallel` permit
//! while, briefly and one-at-a-time, acquiring governor class permits for each
//! provider call; the governor semaphores are independent per class, so no
//! cross-repo ring can form.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::{
    BatchConfig, BatchRepoSummary, BatchSummary, LearningBusHandle, RepoConfig, RepoStatus,
    ResourceGovernor, merge_repo_config, render_batch_summary_json, render_batch_summary_markdown,
    spawn,
};
use crate::config::{ReportConfig, RuntimeConfig};
use crate::reporting::{
    JsonlRenderOptions, MarkdownRenderOptions, ReportFormat, render_json, render_jsonl,
    render_markdown, resolve_output_path,
};
use crate::runctx::{Progress, RunContext, RunId};
use crate::static_analysis::run_static_scan_async;
use crate::StaticAnalysisResult;

/// The finished outcome of one repository, ready to fold into a
/// [`BatchRepoSummary`]. `idx` is the repository's position in the batch config;
/// it travels with the outcome so the orchestrator can re-order results into
/// stable (config) order even though `JoinSet` yields them in completion order,
/// and so a panicked task (whose outcome is lost) still maps back to its repo.
struct RepoOutcome {
    idx: usize,
    name: String,
    path: String,
    status: RepoStatus,
    error: Option<String>,
    duration_ms: u64,
    risk_level: Option<String>,
    fused_finding_count: Option<usize>,
    report_paths: Vec<String>,
}

impl RepoOutcome {
    fn cancelled(idx: usize, repo: &RepoConfig, duration_ms: u64) -> Self {
        Self {
            idx,
            name: repo.name.clone(),
            path: repo.path.clone(),
            status: RepoStatus::Cancelled,
            error: None,
            duration_ms,
            risk_level: None,
            fused_finding_count: None,
            report_paths: Vec::new(),
        }
    }

    fn failed(idx: usize, repo: &RepoConfig, error: impl Into<String>) -> Self {
        Self {
            idx,
            name: repo.name.clone(),
            path: repo.path.clone(),
            status: RepoStatus::Failed,
            error: Some(error.into()),
            duration_ms: 0,
            risk_level: None,
            fused_finding_count: None,
            report_paths: Vec::new(),
        }
    }
}

impl From<RepoOutcome> for BatchRepoSummary {
    fn from(o: RepoOutcome) -> Self {
        Self {
            name: o.name,
            path: o.path,
            status: o.status,
            error: o.error,
            duration_ms: o.duration_ms,
            risk_level: o.risk_level,
            fused_finding_count: o.fused_finding_count,
            report_paths: o.report_paths,
        }
    }
}

/// The batch-wide handles cloned into every repository task.
#[derive(Clone)]
struct Shared {
    governor: ResourceGovernor,
    bus: Option<LearningBusHandle>,
    progress: Progress,
    cancel: CancellationToken,
}

/// Runs a whole batch of repository scans concurrently and writes the per-repo
/// reports plus the `batch-summary.md` / `batch-summary.json` pair.
///
/// `cancel` is the batch-wide cancellation token: with `fail_fast = true` the
/// first repository failure (an `Err` result or a panicked task) calls
/// [`CancellationToken::cancel`], after which repositories that have not yet
/// started are recorded as `Cancelled` instead of beginning new work (the
/// providers already reap child processes on drop/timeout, bounding cleanup).
pub async fn run_batch(cfg: BatchConfig, cancel: CancellationToken) -> Result<BatchSummary> {
    let batch_id = RunId::new();
    let started_at = crate::reporting::current_local_timestamp();

    // Shared learning bus: `Some` only when `[batch].learning_bus` is on. The
    // actor owns `learned_dir` (if any); when off, repos run isolated and read
    // `learned_dir` themselves (reproducible eval baseline).
    let bus = if cfg.batch.learning_bus {
        Some(spawn(
            cfg.runtime.static_.learned_dir.clone().map(PathBuf::from),
        ))
    } else {
        None
    };

    let governor = ResourceGovernor::new(&cfg.batch.limits);
    // Repo-level concurrency: one permit per repo for the whole task. Distinct
    // from the governor's per-class permits (see module doc).
    let max_parallel_limit = cfg.batch.max_parallel.max(1);
    let max_parallel = Arc::new(Semaphore::new(max_parallel_limit));

    // Progress hub (design §5): repos report into one channel, a dedicated task
    // drains it into `tracing` with the `[repo]` prefix already attached by
    // `Progress::scoped`.
    let (progress, mut progress_rx) = Progress::channel();
    let drain = tokio::spawn(async move {
        while let Some(msg) = progress_rx.recv().await {
            tracing::info!(target: "mcp_sec_audit::batch", "{msg}");
        }
    });

    let shared = Shared {
        governor,
        bus: bus.clone(),
        progress: progress.clone(),
        cancel: cancel.clone(),
    };

    // Lazily dispatch repos on the blocking pool, each on its own current-thread
    // runtime. The async pipeline future is `!Send` (it holds a
    // `tracing::EnteredSpan` across `.await` points, and `EnteredSpan` is
    // deliberately `!Send`), so it cannot be driven by a multi-thread runtime's
    // `spawn`/`JoinSet::spawn`. A dedicated current-thread runtime per repo
    // preserves full parallelism: the CPU-bound phases are already offloaded
    // via `spawn_blocking`, and the codeql/agent providers spawn child
    // processes.
    //
    // The repo-level `max_parallel` permit is acquired in this loop, *before*
    // each `spawn_blocking`, and moved into the task (held for its whole run).
    // That bounds the number of concurrently-running blocking tasks — and hence
    // the number of parked blocking threads — to `max_parallel`, not to the
    // repo count. When `cancel` fires (fail_fast), repos that have not yet been
    // dispatched are recorded as `Cancelled` instead of spawning new work.
    let mut outcomes: Vec<Option<RepoOutcome>> =
        (0..cfg.batch.repos.len()).map(|_| None).collect();
    let mut join_error_labels: Vec<&'static str> = Vec::new();
    let mut set = JoinSet::new();
    let mut next = 0usize;
    let mut in_flight = 0usize;
    let mut fail_fast_fired = false;

    loop {
        // Fill available concurrency slots, one `max_parallel` permit at a time.
        while in_flight < max_parallel_limit && next < cfg.batch.repos.len() {
            if cancel.is_cancelled() {
                for (idx, repo) in cfg.batch.repos.iter().enumerate().skip(next) {
                    outcomes[idx] = Some(RepoOutcome::cancelled(idx, repo, 0));
                }
                next = cfg.batch.repos.len();
                break;
            }
            let idx = next;
            let repo = cfg.batch.repos[idx].clone();
            next += 1;

            let slot = max_parallel
                .clone()
                .acquire_owned()
                .await
                .expect("max_parallel semaphore closed");
            in_flight += 1;

            let repo_id = RunId::for_repo(batch_id.as_str(), &repo.name);
            let base = cfg.runtime.clone();
            let shared = shared.clone();
            set.spawn_blocking(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build per-repo current-thread runtime");
                let _slot = slot; // held until the repo task finishes
                rt.block_on(run_repo(idx, repo, base, repo_id, shared))
            });
        }

        if in_flight == 0 {
            break;
        }

        let joined = set
            .join_next()
            .await
            .expect("in_flight > 0 implies a pending repo task");
        in_flight -= 1;

        let (outcome, failed) = match joined {
            Ok(outcome) => {
                let failed = outcome.status == RepoStatus::Failed;
                (Some(outcome), failed)
            }
            Err(e) => {
                // A panicked task loses its return value (no `catch_unwind`,
                // design §10); its slot stays `None` and is synthesized after
                // the loop. A non-panic `JoinError` (an aborted task) is
                // labelled distinctly rather than as a panic.
                join_error_labels.push(if e.is_panic() {
                    "panicked"
                } else {
                    "task join error"
                });
                tracing::warn!(
                    target: "mcp_sec_audit::batch",
                    is_panic = e.is_panic(),
                    error = %e,
                    "repo task aborted"
                );
                (None, true)
            }
        };
        if failed && cfg.batch.fail_fast && !fail_fast_fired {
            fail_fast_fired = true;
            cancel.cancel();
        }
        if let Some(outcome) = outcome {
            let idx = outcome.idx;
            outcomes[idx] = Some(outcome);
        }
    }

    // Close the progress channel and let the drain task flush remaining lines.
    // `shared` still holds a `progress` clone, so drop it before the original
    // `progress` — otherwise the channel never closes and `drain.await` hangs.
    drop(shared);
    drop(progress);
    let _ = drain.await;

    // The learning-bus actor exits when its last handle is dropped; do that
    // after all repos have promoted, then snapshot the final catalog for the
    // cross-repo-learned list.
    let cross_repo_learned = cross_repo_learned_from(&bus).await;
    drop(bus);

    let mut join_errors = join_error_labels.into_iter();
    let repos: Vec<BatchRepoSummary> = outcomes
        .into_iter()
        .enumerate()
        .map(|(idx, o)| match o {
            Some(o) => o.into(),
            None => {
                let error = join_errors.next().unwrap_or("panicked");
                RepoOutcome::failed(idx, &cfg.batch.repos[idx], error).into()
            }
        })
        .collect();

    let mut summary = BatchSummary {
        batch_id: batch_id.as_str().to_string(),
        started_at,
        repos,
        total_fused_findings: 0,
        succeeded: 0,
        failed: 0,
        cancelled: 0,
        learning_bus_enabled: cfg.batch.learning_bus,
        cross_repo_learned,
    };
    for repo in &summary.repos {
        summary.total_fused_findings += repo.fused_finding_count.unwrap_or(0);
        match repo.status {
            RepoStatus::Ok => summary.succeeded += 1,
            RepoStatus::Failed => summary.failed += 1,
            RepoStatus::Cancelled => summary.cancelled += 1,
        }
    }

    // A failed summary write is a reporting I/O problem, not a batch outcome:
    // the batch ran, so `run_batch` must still return `Ok(summary)` and let the
    // repo outcomes (and the caller's exit code) reflect what actually happened.
    if let Err(e) = write_batch_summary(&summary, &cfg.runtime.report) {
        tracing::error!(
            target: "mcp_sec_audit::batch",
            error = %e,
            "failed to write batch summary"
        );
    }

    Ok(summary)
}

/// The per-repository task body: merge the repo's overrides, run the async
/// pipeline, write the per-repo reports, and clean up run-scoped temp dirs.
async fn run_repo(
    idx: usize,
    repo: RepoConfig,
    base: RuntimeConfig,
    repo_id: RunId,
    shared: Shared,
) -> RepoOutcome {
    let Shared {
        governor,
        bus,
        progress,
        cancel,
    } = shared;
    let start = Instant::now();
    let name = repo.name.clone();
    let path = repo.path.clone();
    let progress = progress.scoped(&name);

    // Enter a per-repo span so every log line this repository emits (progress
    // aside, which is already `[repo]`-prefixed by the channel progress) is
    // attributed back to it. The CLI's `ModuleFormat` renders the span's
    // `repo` field as a `[name]` bracket before the module name.
    let span = tracing::info_span!("repo", repo = %name);
    let _enter = span.enter();

    let merged = match merge_repo_config(&base, &repo) {
        Ok(merged) => merged,
        Err(e) => {
            return RepoOutcome {
                idx,
                name,
                path,
                status: RepoStatus::Failed,
                error: Some(format!("merge repo config: {e:#}")),
                duration_ms: start.elapsed().as_millis() as u64,
                risk_level: None,
                fused_finding_count: None,
                report_paths: Vec::new(),
            };
        }
    };

    let run_ctx = RunContext::for_repo(repo_id, progress, cancel, Some(governor), bus);

    let scan = run_static_scan_async(&merged, &[], None, &run_ctx).await;

    let outcome = match scan {
        Ok(result) => {
            let risk_level = result.summary.risk_level.clone();
            let fused = result.summary.fused_finding_count;
            match write_repo_reports(&result, &merged.report, &name) {
                Ok(report_paths) => RepoOutcome {
                    idx,
                    name,
                    path,
                    status: RepoStatus::Ok,
                    error: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                    risk_level: Some(risk_level),
                    fused_finding_count: Some(fused),
                    report_paths,
                },
                Err(e) => RepoOutcome {
                    idx,
                    name,
                    path,
                    status: RepoStatus::Failed,
                    error: Some(format!("write reports: {e:#}")),
                    duration_ms: start.elapsed().as_millis() as u64,
                    risk_level: Some(risk_level),
                    fused_finding_count: Some(fused),
                    report_paths: Vec::new(),
                },
            }
        }
        Err(e) => RepoOutcome {
            idx,
            name,
            path,
            status: RepoStatus::Failed,
            error: Some(format!("{e:#}")),
            duration_ms: start.elapsed().as_millis() as u64,
            risk_level: None,
            fused_finding_count: None,
            report_paths: Vec::new(),
        },
    };

    // Remove per-repo temp dirs (codeql/sarif/mad/staging) keyed by this run id.
    if let Err(e) = run_ctx.cleanup() {
        tracing::warn!(
            target: "mcp_sec_audit::batch",
            repo = %outcome.name,
            error = %e,
            "cleanup of run temp dirs failed"
        );
    }

    outcome
}

/// Writes the per-repo report files, mirroring the CLI's single-repo report
/// loop (`cli/src/main.rs::write_report_files`) but resolving `<repo>` against
/// the repository name (not the result's target label) and returning string
/// paths for the summary.
fn write_repo_reports(
    result: &StaticAnalysisResult,
    report: &ReportConfig,
    repo_name: &str,
) -> Result<Vec<String>> {
    if report.formats.is_empty() {
        tracing::warn!(
            target: "mcp_sec_audit::batch",
            repo = %repo_name,
            "no report formats configured; nothing written"
        );
        return Ok(Vec::new());
    }

    let output = resolve_output_path(&report.output, Some(repo_name));
    let mut written = Vec::new();
    for fmt in &report.formats {
        let Some(format) = ReportFormat::parse(fmt) else {
            bail!("unsupported report format: {fmt}");
        };
        let content = match format {
            ReportFormat::Json => render_json(result)?,
            ReportFormat::Jsonl => render_jsonl(result, &JsonlRenderOptions::from(report))?,
            ReportFormat::Markdown => {
                render_markdown(result, &MarkdownRenderOptions::from(report))
            }
        };
        let path = PathBuf::from(format!("{}.{}", output, format.extension()));
        std::fs::write(&path, content)
            .with_context(|| format!("write report to {}", path.display()))?;
        written.push(path.display().to_string());
    }
    Ok(written)
}

/// Writes `batch-summary.md` + `batch-summary.json` next to the per-repo
/// reports: the report output template with `<repo>` substituted by
/// `batch-summary`.
fn write_batch_summary(summary: &BatchSummary, report: &ReportConfig) -> Result<()> {
    let base = resolve_output_path(&report.output, Some("batch-summary"));
    let markdown_path = PathBuf::from(format!("{base}.md"));
    let json_path = PathBuf::from(format!("{base}.json"));
    std::fs::write(&markdown_path, render_batch_summary_markdown(summary))
        .with_context(|| format!("write batch summary to {}", markdown_path.display()))?;
    std::fs::write(&json_path, render_batch_summary_json(summary)?)
        .with_context(|| format!("write batch summary to {}", json_path.display()))?;
    Ok(())
}

/// Best-effort "cross-repo learned" model names: the learned models
/// (`source == "learned"`) present in the bus's final catalog. Deterministic
/// (sorted, deduplicated) so a CI diff stays stable.
async fn cross_repo_learned_from(bus: &Option<LearningBusHandle>) -> Vec<String> {
    let Some(bus) = bus else {
        return Vec::new();
    };
    let Ok(catalog) = bus.snapshot().await else {
        return Vec::new();
    };
    let mut names = BTreeSet::new();
    for lang in ["python", "javascript", "rust"] {
        for m in catalog.sinks_for_language(lang) {
            if m.source.as_deref() == Some("learned") {
                names.insert(format!("sink:{}:{}", m.language, m.category));
            }
        }
        for m in catalog.sources_for_language(lang) {
            if m.source.as_deref() == Some("learned") {
                names.insert(format!("source:{}:{}", m.language, m.category));
            }
        }
        for m in catalog.sanitizers_for_language(lang) {
            if m.source.as_deref() == Some("learned") {
                names.insert(format!("sanitizer:{}:{}", m.language, m.patterns.join("|")));
            }
        }
    }
    names.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BatchSettings, LimitsConfig};

    /// Creates a tiny python repo with a single `app.py` under a fresh temp dir.
    fn tiny_python_repo(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcp-sec-audit-batch-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).expect("create temp repo");
        std::fs::write(
            dir.join("app.py"),
            "import subprocess\nsubprocess.run(['ls'])\n",
        )
        .expect("write app.py");
        dir
    }

    /// Builds a [`BatchConfig`] over the given `(name, path)` repos with
    /// agent/codeql disabled (pure CPU path) and reports landing in a fresh
    /// writable temp dir.
    fn batch_config_for(repos: &[(&str, &PathBuf)]) -> BatchConfig {
        let out_dir = std::env::temp_dir().join(format!(
            "mcp-sec-audit-batch-out-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        std::fs::create_dir_all(&out_dir).expect("create temp out dir");

        let mut cfg = BatchConfig {
            batch: BatchSettings {
                max_parallel: 2,
                learning_bus: false,
                fail_fast: false,
                limits: LimitsConfig {
                    codeql: 1,
                    agent: 1,
                    cpu: 2,
                },
                repos: Vec::new(),
            },
            runtime: RuntimeConfig::default(),
        };
        // Rule analysis needs a rulebook; the default relative `rules/*` paths
        // don't resolve from a test's CWD, so disable rule and exercise the
        // pure-CPU taint path (which loads only the built-in catalog).
        cfg.runtime.static_.rule.enabled = false;
        cfg.runtime.static_.taint.enabled = true;
        cfg.runtime.static_.agent.enabled = false;
        cfg.runtime.static_.codeql.enabled = false;
        cfg.runtime.report.formats = vec!["json".to_string(), "markdown".to_string()];
        cfg.runtime.report.output = format!("{}/<repo>", out_dir.display());
        for (name, path) in repos {
            cfg.batch.repos.push(RepoConfig {
                name: name.to_string(),
                path: path.display().to_string(),
                overrides: Default::default(),
            });
        }
        cfg
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batch_analyzes_two_repos_and_writes_both_reports() {
        let (dir_a, dir_b) = (tiny_python_repo("a"), tiny_python_repo("b"));
        let cfg = batch_config_for(&[("a", &dir_a), ("b", &dir_b)]);
        let summary = run_batch(cfg, CancellationToken::new()).await.expect("batch");
        assert_eq!(summary.succeeded, 2);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.cancelled, 0);
        for repo in &summary.repos {
            assert!(!repo.report_paths.is_empty());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_failing_repo_does_not_abort_the_batch() {
        let cfg = batch_config_for(&[
            ("ok", &tiny_python_repo("ok")),
            (
                "missing",
                &std::path::Path::new("/nonexistent/repo").to_path_buf(),
            ),
        ]);
        let summary = run_batch(cfg, CancellationToken::new()).await.expect("batch");
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed, 1);
        assert!(summary.repos.iter().any(|r| r.error.is_some()));
    }
}
