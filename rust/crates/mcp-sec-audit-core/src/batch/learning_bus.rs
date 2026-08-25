//! Shared learning bus (v5 parallel multi-repository analysis).
//!
//! A single-writer actor that owns `learned_dir` and the authoritative
//! [`ModelCatalog`] of everything learned so far, plus the accumulated rule
//! capabilities and prompt text. Repositories promote their verified deltas
//! through [`LearningBusHandle::promote`] and read a point-in-time snapshot
//! through [`LearningBusHandle::snapshot`]. Because the "read existing → merge
//! → write back" sequence runs only inside this actor's single task, the
//! lost-update race that v4's per-repo file writes were exposed to disappears.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, oneshot};

use crate::models::{ModelCatalog, SanitizerModel, SinkModel, SourceModel};
use crate::static_analysis::learning::{
    atomic_write, merge_sanitizer_models, merge_sink_models, merge_source_models,
};

/// One message the learning-bus actor can service.
///
/// `Promote` carries a full promotion request plus a oneshot ack; `Snapshot`
/// asks for a clone of the current authoritative catalog; `Shutdown` stops the
/// actor (dropping the handle's channel also does).
pub enum BusMsg {
    Promote {
        req: PromoteRequest,
        ack: oneshot::Sender<Result<()>>,
    },
    Snapshot {
        reply: oneshot::Sender<ModelCatalog>,
    },
    Shutdown,
}

/// A repository's contribution to the shared learned state.
///
/// `sinks` / `sources` / `sanitizers` are the model deltas to merge (each
/// model's `corroboration_count` is summed into any prior evidence); `rules`
/// and `prompt_extra` are accumulated text.
#[derive(Debug, Clone, Default)]
pub struct PromoteRequest {
    pub repo: String,
    pub sinks: Vec<SinkModel>,
    pub sources: Vec<SourceModel>,
    pub sanitizers: Vec<SanitizerModel>,
    pub rules: Vec<String>,
    pub prompt_extra: String,
}

/// A cloneable handle to the learning-bus actor.
#[derive(Clone)]
pub struct LearningBusHandle {
    tx: mpsc::UnboundedSender<BusMsg>,
}

impl LearningBusHandle {
    /// Asks the actor for a clone of its current authoritative catalog.
    pub async fn snapshot(&self) -> Result<ModelCatalog> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(BusMsg::Snapshot { reply })
            .map_err(|_| anyhow::anyhow!("learning bus actor has stopped"))?;
        rx.await.context("learning bus actor dropped before replying")
    }

    /// Sends a promotion and waits until the actor has merged and (if a
    /// `learned_dir` is configured) durably persisted it.
    pub async fn promote(&self, req: PromoteRequest) -> Result<()> {
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(BusMsg::Promote { req, ack })
            .map_err(|_| anyhow::anyhow!("learning bus actor has stopped"))?;
        rx.await.context("learning bus actor dropped before acking")?
    }
}

/// Spawns the learning-bus actor and returns a handle to it.
///
/// When `learned_dir` is `Some(dir)`, the actor loads the existing learned
/// models / rules / prompt from `dir` once at startup and persists every
/// promotion back to `dir` atomically (temp file + rename). When `None`, the
/// actor is purely in-memory (useful for tests and ephemeral batches).
pub fn spawn(learned_dir: Option<PathBuf>) -> LearningBusHandle {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(actor_loop(rx, learned_dir));
    LearningBusHandle { tx }
}

/// The actor's authoritative in-memory state.
struct ActorState {
    learned_dir: Option<PathBuf>,
    catalog: ModelCatalog,
    rules: Vec<String>,
    prompt: String,
}

impl ActorState {
    /// Loads the authoritative state from disk once, at spawn.
    fn load(learned_dir: Option<PathBuf>) -> Self {
        let mut state = Self {
            learned_dir,
            catalog: ModelCatalog::default(),
            rules: Vec::new(),
            prompt: String::new(),
        };
        let Some(dir) = state.learned_dir.clone() else {
            return state;
        };
        if dir.exists() {
            match crate::models::load_models_dir(&dir) {
                Ok(catalog) => state.catalog = catalog,
                Err(e) => tracing::warn!(
                    target: "mcp_sec_audit::batch",
                    dir = %dir.display(),
                    error = %e,
                    "learning bus failed to load learned models; starting empty"
                ),
            }
        }
        let rules_path = dir.join("learned-capabilities.txt");
        if rules_path.exists()
            && let Ok(text) = std::fs::read_to_string(&rules_path)
        {
            state.rules = text
                .lines()
                .filter_map(|l| l.strip_prefix("- ").map(str::to_string))
                .collect();
        }
        let prompt_path = dir.join("learned-prompt.md");
        if prompt_path.exists()
            && let Ok(text) = std::fs::read_to_string(&prompt_path)
        {
            state.prompt = text;
        }
        state
    }

    fn apply_and_persist(&mut self, req: PromoteRequest) -> Result<()> {
        tracing::info!(
            target: "mcp_sec_audit::batch",
            repo = %req.repo,
            sinks = req.sinks.len(),
            sources = req.sources.len(),
            sanitizers = req.sanitizers.len(),
            rules = req.rules.len(),
            "learning bus promote"
        );
        self.merge_models(req.sinks, req.sources, req.sanitizers);
        self.accumulate_rules(&req.rules);
        self.accumulate_prompt(&req.prompt_extra);
        self.persist()
    }

    fn merge_models(
        &mut self,
        sinks: Vec<SinkModel>,
        sources: Vec<SourceModel>,
        sanitizers: Vec<SanitizerModel>,
    ) {
        let existing_sinks = self.all_sinks();
        let existing_sources = self.all_sources();
        let existing_sanitizers = self.all_sanitizers();
        let merged_sinks = if sinks.is_empty() {
            existing_sinks
        } else {
            merge_sink_models(&existing_sinks, &sinks)
        };
        let merged_sources = if sources.is_empty() {
            existing_sources
        } else {
            merge_source_models(&existing_sources, &sources)
        };
        let merged_sanitizers = if sanitizers.is_empty() {
            existing_sanitizers
        } else {
            merge_sanitizer_models(&existing_sanitizers, &sanitizers)
        };
        self.catalog = ModelCatalog::from_models(merged_sinks, merged_sources, merged_sanitizers);
    }

    fn all_sinks(&self) -> Vec<SinkModel> {
        ["python", "javascript", "rust"]
            .iter()
            .flat_map(|lang| self.catalog.sinks_for_language(lang).to_vec())
            .collect()
    }

    fn all_sources(&self) -> Vec<SourceModel> {
        ["python", "javascript", "rust"]
            .iter()
            .flat_map(|lang| self.catalog.sources_for_language(lang).to_vec())
            .collect()
    }

    fn all_sanitizers(&self) -> Vec<SanitizerModel> {
        ["python", "javascript", "rust"]
            .iter()
            .flat_map(|lang| self.catalog.sanitizers_for_language(lang).to_vec())
            .collect()
    }

    fn accumulate_rules(&mut self, capabilities: &[String]) {
        let mut seen: BTreeSet<String> = self.rules.iter().cloned().collect();
        for cap in capabilities {
            if seen.insert(cap.clone()) {
                self.rules.push(cap.clone());
            }
        }
    }

    fn accumulate_prompt(&mut self, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        if !self.prompt.is_empty() && !self.prompt.ends_with('\n') {
            self.prompt.push('\n');
        }
        self.prompt.push_str(text);
    }

    /// Writes the full authoritative state back to `learned_dir`, atomically.
    fn persist(&self) -> Result<()> {
        let Some(dir) = self.learned_dir.as_deref() else {
            return Ok(());
        };
        std::fs::create_dir_all(dir)?;
        crate::static_analysis::learning::write_learned_sinks(dir, &self.all_sinks())?;
        crate::static_analysis::learning::write_learned_sources(dir, &self.all_sources())?;
        crate::static_analysis::learning::write_learned_sanitizers(dir, &self.all_sanitizers())?;
        if !self.rules.is_empty() {
            let text = self
                .rules
                .iter()
                .map(|c| format!("- {c}"))
                .collect::<Vec<_>>()
                .join("\n");
            atomic_write(&dir.join("learned-capabilities.txt"), &text)?;
        }
        if !self.prompt.is_empty() {
            atomic_write(&dir.join("learned-prompt.md"), &self.prompt)?;
        }
        Ok(())
    }
}

async fn actor_loop(mut rx: mpsc::UnboundedReceiver<BusMsg>, learned_dir: Option<PathBuf>) {
    let mut state = ActorState::load(learned_dir);
    while let Some(msg) = rx.recv().await {
        match msg {
            BusMsg::Promote { req, ack } => {
                let result = state.apply_and_persist(req);
                let _ = ack.send(result);
            }
            BusMsg::Snapshot { reply } => {
                let _ = reply.send(state.catalog.clone());
            }
            BusMsg::Shutdown => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Severity};

    fn sink_model(pattern: &str, category: &str) -> SinkModel {
        SinkModel {
            language: "python".into(),
            category: category.into(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            reason: "test".into(),
            patterns: vec![pattern.into()],
            source: Some("learned".into()),
            learned_from: None,
            corroboration_count: 1,
            pollution_count: 0,
            last_seen_run: None,
        }
    }

    fn tempdir_for(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcp-sec-audit-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bus_merges_evidence_across_repos() {
        let dir = tempdir_for("bus-merge");
        let bus = spawn(Some(dir.clone()));
        let sink = sink_model("os.system", "command_injection");

        bus.promote(PromoteRequest {
            repo: "a".into(),
            sinks: vec![sink.clone()],
            ..Default::default()
        })
        .await
        .expect("promote a");
        bus.promote(PromoteRequest {
            repo: "b".into(),
            sinks: vec![sink.clone()],
            ..Default::default()
        })
        .await
        .expect("promote b");

        let snap = bus.snapshot().await.expect("snapshot");
        let found = snap
            .sinks_for_language("python")
            .iter()
            .find(|m| m.patterns.contains(&"os.system".to_string()))
            .expect("model");
        assert!(
            found.corroboration_count >= 2,
            "two independent repos finding the same sink must corroborate"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn snapshot_reflects_only_prior_promotions() {
        let bus = spawn(None);
        let before = bus.snapshot().await.expect("snapshot");
        bus.promote(PromoteRequest {
            repo: "a".into(),
            sinks: vec![sink_model("os.popen", "command_execution")],
            ..Default::default()
        })
        .await
        .expect("promote");
        let after = bus.snapshot().await.expect("snapshot");
        assert!(
            after.sinks_for_language("python").len() > before.sinks_for_language("python").len()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn persisted_promotions_reload_from_disk() {
        let dir = tempdir_for("bus-persist");
        let bus = spawn(Some(dir.clone()));
        bus.promote(PromoteRequest {
            repo: "a".into(),
            sinks: vec![sink_model("os.system", "command_injection")],
            rules: vec!["command_injection".into()],
            prompt_extra: "## recheck command_injection\n".into(),
            ..Default::default()
        })
        .await
        .expect("promote");

        // Drop the first actor and spawn a fresh one against the same dir: it
        // must reload the persisted model / rules / prompt from disk at startup.
        drop(bus);
        let bus2 = spawn(Some(dir.clone()));
        let snap = bus2.snapshot().await.expect("snapshot");
        assert!(
            snap.sinks_for_language("python")
                .iter()
                .any(|m| m.patterns.contains(&"os.system".to_string())),
            "persisted sink must reload from disk"
        );
        let rules = std::fs::read_to_string(dir.join("learned-capabilities.txt"))
            .expect("rules file");
        assert!(rules.contains("- command_injection"));
        let prompt = std::fs::read_to_string(dir.join("learned-prompt.md")).expect("prompt file");
        assert!(prompt.contains("recheck command_injection"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
