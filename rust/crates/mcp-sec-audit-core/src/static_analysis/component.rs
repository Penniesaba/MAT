//! The unified "Component" abstraction: a capability-determining artifact for
//! one analysis tool (CodeQL / taint / rule / agent), with a stable
//! `fingerprint` and the reversible-evolution methods (`evolve` / `promote` /
//! `rollback`) that the two-phase loop drives uniformly.
//!
//! The evolution loop goes through this trait: `evolve` produces the
//! phase-2 component, `promote` persists a verified delta to `learned/`, and
//! `rollback` discards the staging area.

use std::path::Path;

use anyhow::Result;

use crate::models::{ModelCatalog, SanitizerModel, SinkModel, SourceModel};

/// Which tool a Component determines capability for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolKind {
    Codeql,
    Taint,
    Rule,
    Agent,
}

/// A reversible evolution delta: the three taint model classes, plus the
/// rulebook capabilities and the prompt' text for the rule/agent components.
#[derive(Debug, Clone, Default)]
pub(crate) struct ComponentDelta {
    pub(crate) sinks: Vec<SinkModel>,
    pub(crate) sources: Vec<SourceModel>,
    pub(crate) sanitizers: Vec<SanitizerModel>,
    /// New rule capabilities (for `RuleComponent`). Reserved for rule-line
    /// evolution; read by `RuleComponent::evolve` (unit-tested).
    #[allow(dead_code)]
    pub(crate) capabilities: Vec<String>,
    /// Verification-prompt text to append (for `PromptComponent`, prompt').
    /// Reserved for prompt-line evolution; read by `PromptComponent::evolve`.
    #[allow(dead_code)]
    pub(crate) prompt_extra: String,
}

impl ComponentDelta {
    pub(crate) fn model_count(&self) -> usize {
        self.sinks.len() + self.sources.len() + self.sanitizers.len()
    }
}

/// A capability-determining artifact, unified so the evolution loop can treat
/// CodeQL / taint / rule / prompt uniformly.
pub(crate) trait Component {
    fn tool(&self) -> ToolKind;
    /// Stable content identity (canonical, deterministic, debuggable). Used as
    /// the rollback anchor. Not a cryptographic hash.
    fn fingerprint(&self) -> String;

    /// 试探性进化：返回应用 delta 后的新 component（旧 `self` 保留作回滚快照）。
    fn evolve(&self, delta: &ComponentDelta) -> Self;

    /// 固化（真进化）：把验证通过的 delta 持久化为 learned_component。
    fn promote(&self, delta: &ComponentDelta, learned_dir: &Path) -> Result<()>;

    /// 回滚：删除 staging 目录；调用方保留 `self`（evolve 前的快照）作为恢复。
    fn rollback(&self, staging_dir: &Path) -> Result<()>;
}

fn join(items: &[String]) -> String {
    items.join("|")
}

/// CodeQL's component: query files + suite refs + MaD sink entries.
#[derive(Debug, Clone, Default)]
pub(crate) struct CodeqlComponent {
    pub(crate) query_files: Vec<String>, // sorted .ql names
    pub(crate) suite_refs: Vec<String>,  // sorted pack refs
    pub(crate) mad_sinks: Vec<String>,   // sorted "module.function -> kind"
}
impl Component for CodeqlComponent {
    fn tool(&self) -> ToolKind {
        ToolKind::Codeql
    }
    fn fingerprint(&self) -> String {
        let full = format!(
            "qf={}|suites={}|mad={}",
            join(&self.query_files),
            join(&self.suite_refs),
            join(&self.mad_sinks)
        );
        format!(
            "codeql:qf={} suites={} mad={} #{}",
            self.query_files.len(),
            self.suite_refs.len(),
            self.mad_sinks.len(),
            super::learning::stable_hash(&full)
        )
    }
    fn evolve(&self, delta: &ComponentDelta) -> Self {
        let mut out = self.clone();
        for m in &delta.sinks {
            for p in &m.patterns {
                out.mad_sinks
                    .push(format!("{}:{} -> {}", m.language, p, m.category));
            }
        }
        out.mad_sinks.sort();
        out.mad_sinks.dedup();
        out
    }
    fn promote(&self, delta: &ComponentDelta, learned_dir: &Path) -> Result<()> {
        super::learning::write_learned_sinks(learned_dir, &delta.sinks)
    }
    fn rollback(&self, staging_dir: &Path) -> Result<()> {
        super::learning::rollback_staging(staging_dir)
    }
}

/// Taint's component: the three-model catalog (sink + source + sanitizer).
#[derive(Debug, Clone, Default)]
pub(crate) struct TaintComponent {
    pub(crate) catalog: ModelCatalog,
}
impl Component for TaintComponent {
    fn tool(&self) -> ToolKind {
        ToolKind::Taint
    }
    fn fingerprint(&self) -> String {
        super::learning::catalog_fingerprint(&self.catalog)
    }
    fn evolve(&self, delta: &ComponentDelta) -> Self {
        let mut catalog = self.catalog.clone();
        catalog.merge(ModelCatalog::from_models(
            delta.sinks.clone(),
            delta.sources.clone(),
            delta.sanitizers.clone(),
        ));
        Self { catalog }
    }
    fn promote(&self, delta: &ComponentDelta, learned_dir: &Path) -> Result<()> {
        super::learning::write_learned_sinks(learned_dir, &delta.sinks)?;
        super::learning::write_learned_sources(learned_dir, &delta.sources)?;
        super::learning::write_learned_sanitizers(learned_dir, &delta.sanitizers)?;
        Ok(())
    }
    fn rollback(&self, staging_dir: &Path) -> Result<()> {
        super::learning::rollback_staging(staging_dir)
    }
}

/// Rule's component: the rulebook's capabilities.
#[derive(Debug, Clone, Default)]
pub(crate) struct RuleComponent {
    pub(crate) capabilities: Vec<String>, // sorted "name:pattern"
}
impl Component for RuleComponent {
    fn tool(&self) -> ToolKind {
        ToolKind::Rule
    }
    fn fingerprint(&self) -> String {
        format!("rule:{}", join(&self.capabilities))
    }
    fn evolve(&self, delta: &ComponentDelta) -> Self {
        let mut out = self.clone();
        for c in &delta.capabilities {
            if !out.capabilities.contains(c) {
                out.capabilities.push(c.clone());
            }
        }
        out.capabilities.sort();
        out
    }
    fn promote(&self, delta: &ComponentDelta, learned_dir: &Path) -> Result<()> {
        if delta.capabilities.is_empty() {
            return Ok(());
        }
        std::fs::create_dir_all(learned_dir)?;
        let text = delta
            .capabilities
            .iter()
            .map(|c| format!("- {c}"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(learned_dir.join("learned-capabilities.txt"), text)?;
        Ok(())
    }
    fn rollback(&self, staging_dir: &Path) -> Result<()> {
        super::learning::rollback_staging(staging_dir)
    }
}

/// Agent's component: the prompt template text.
#[derive(Debug, Clone, Default)]
pub(crate) struct PromptComponent {
    pub(crate) template: String,
}
impl Component for PromptComponent {
    fn tool(&self) -> ToolKind {
        ToolKind::Agent
    }
    fn fingerprint(&self) -> String {
        format!("prompt:{}", self.template)
    }
    fn evolve(&self, delta: &ComponentDelta) -> Self {
        let mut out = self.clone();
        if !delta.prompt_extra.is_empty() {
            out.template.push_str(&delta.prompt_extra);
        }
        out
    }
    fn promote(&self, delta: &ComponentDelta, learned_dir: &Path) -> Result<()> {
        if delta.prompt_extra.is_empty() {
            return Ok(());
        }
        std::fs::create_dir_all(learned_dir)?;
        std::fs::write(learned_dir.join("learned-prompt.md"), &delta.prompt_extra)?;
        Ok(())
    }
    fn rollback(&self, staging_dir: &Path) -> Result<()> {
        super::learning::rollback_staging(staging_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{SanitizerModel, SinkModel, SourceModel};
    use crate::{Confidence, Severity};

    fn sink(name: &str, category: &str) -> SinkModel {
        SinkModel {
            language: "python".into(),
            category: category.into(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            reason: "t".into(),
            patterns: vec![name.into()],
            source: Some("learned-staged".into()),
            learned_from: None,
            corroboration_count: 0,
            pollution_count: 0,
            last_seen_run: None,
        }
    }

    #[test]
    fn tool_kind_is_correct() {
        assert_eq!(CodeqlComponent::default().tool(), ToolKind::Codeql);
        assert_eq!(TaintComponent::default().tool(), ToolKind::Taint);
        assert_eq!(RuleComponent::default().tool(), ToolKind::Rule);
        assert_eq!(PromptComponent::default().tool(), ToolKind::Agent);
    }

    #[test]
    fn taint_fingerprint_is_deterministic() {
        let a = TaintComponent {
            catalog: crate::models::default_catalog(),
        };
        let b = TaintComponent {
            catalog: crate::models::default_catalog(),
        };
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn taint_evolve_adds_models_and_changes_fingerprint() {
        let base = TaintComponent {
            catalog: crate::models::default_catalog(),
        };
        let delta = ComponentDelta {
            sinks: vec![sink("brand_new.lib.read", "file_read")],
            sources: vec![SourceModel {
                language: "python".into(),
                category: "env_var".into(),
                patterns: vec!["os.custom".into()],
                source: None,
                learned_from: None,
                corroboration_count: 0,
                pollution_count: 0,
                last_seen_run: None,
            }],
            sanitizers: vec![SanitizerModel {
                language: "python".into(),
                patterns: vec!["brand_new.escape".into()],
                neutralizes: vec!["command_execution".into()],
                source: None,
                learned_from: None,
                corroboration_count: 0,
                pollution_count: 0,
                last_seen_run: None,
            }],
            ..Default::default()
        };
        let evolved = base.evolve(&delta);
        assert_ne!(base.fingerprint(), evolved.fingerprint());
        assert_eq!(evolved.catalog.sink_count(), base.catalog.sink_count() + 1);
        assert_eq!(
            evolved.catalog.source_count(),
            base.catalog.source_count() + 1
        );
        assert_eq!(
            evolved.catalog.sanitizer_count(),
            base.catalog.sanitizer_count() + 1
        );
    }

    #[test]
    fn rule_evolve_appends_capabilities() {
        let base = RuleComponent::default();
        let delta = ComponentDelta {
            capabilities: vec!["path_traversal".into()],
            ..Default::default()
        };
        let evolved = base.evolve(&delta);
        assert!(evolved.capabilities.contains(&"path_traversal".to_string()));
        assert_ne!(base.fingerprint(), evolved.fingerprint());
    }

    #[test]
    fn prompt_evolve_appends_extra_text() {
        let base = PromptComponent {
            template: "Role: auditor\n".into(),
        };
        let delta = ComponentDelta {
            prompt_extra: "\n## recheck\n".into(),
            ..Default::default()
        };
        let evolved = base.evolve(&delta);
        assert!(evolved.template.contains("## recheck"));
    }

    #[test]
    fn empty_components_have_stable_fingerprints() {
        assert_eq!(RuleComponent::default().fingerprint(), "rule:");
        assert_eq!(PromptComponent::default().fingerprint(), "prompt:");
    }
}
