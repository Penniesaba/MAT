//! The unified "Component" abstraction: a capability-determining artifact for
//! one analysis tool. Evolve/promote/rollback arrive in a later milestone; this
//! milestone establishes identity (`tool`) and a stable `fingerprint` so a
//! component can be compared across the two phases.
//!
//! Wired into the evolution loop in M2/M3 — until then the types are exercised
//! only by unit tests, hence the module-level allow.
#![allow(dead_code)]

/// Which tool a Component determines capability for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolKind { Codeql, Taint, Rule, Agent }

/// A capability-determining artifact, unified so the evolution loop can treat
/// CodeQL / taint / rule / prompt uniformly.
pub(crate) trait Component {
    fn tool(&self) -> ToolKind;
    /// Stable content identity (canonical, deterministic, debuggable). Used as
    /// the rollback anchor in a later milestone. Not a cryptographic hash.
    fn fingerprint(&self) -> String;
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
    fn tool(&self) -> ToolKind { ToolKind::Codeql }
    fn fingerprint(&self) -> String {
        format!("codeql:qf={}|suites={}|mad={}",
            join(&self.query_files), join(&self.suite_refs), join(&self.mad_sinks))
    }
}

/// Taint's component: the three model classes + package inference rules.
#[derive(Debug, Clone, Default)]
pub(crate) struct TaintComponent {
    pub(crate) sinks: Vec<String>,      // sorted "language:category:pattern"
    pub(crate) sources: Vec<String>,
    pub(crate) sanitizers: Vec<String>,
    pub(crate) package_rules: Vec<String>, // sorted "language:package:category"
}
impl Component for TaintComponent {
    fn tool(&self) -> ToolKind { ToolKind::Taint }
    fn fingerprint(&self) -> String {
        format!("taint:sinks={}|sources={}|sanitizers={}|pkgs={}",
            join(&self.sinks), join(&self.sources), join(&self.sanitizers), join(&self.package_rules))
    }
}

/// Rule's component: the rulebook's capabilities.
#[derive(Debug, Clone, Default)]
pub(crate) struct RuleComponent {
    pub(crate) capabilities: Vec<String>, // sorted "name:pattern"
}
impl Component for RuleComponent {
    fn tool(&self) -> ToolKind { ToolKind::Rule }
    fn fingerprint(&self) -> String {
        format!("rule:{}", join(&self.capabilities))
    }
}

/// Agent's component: the prompt template text.
#[derive(Debug, Clone, Default)]
pub(crate) struct PromptComponent {
    pub(crate) template: String,
}
impl Component for PromptComponent {
    fn tool(&self) -> ToolKind { ToolKind::Agent }
    fn fingerprint(&self) -> String {
        format!("prompt:{}", self.template)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_kind_is_correct() {
        assert_eq!(CodeqlComponent::default().tool(), ToolKind::Codeql);
        assert_eq!(TaintComponent::default().tool(), ToolKind::Taint);
        assert_eq!(RuleComponent::default().tool(), ToolKind::Rule);
        assert_eq!(PromptComponent::default().tool(), ToolKind::Agent);
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = TaintComponent { sinks: vec!["python:file_read:openpyxl.load_workbook".into()], ..Default::default() };
        let b = TaintComponent { sinks: vec!["python:file_read:openpyxl.load_workbook".into()], ..Default::default() };
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_changes_with_content() {
        let a = TaintComponent { sinks: vec!["python:file_read:openpyxl.load_workbook".into()], ..Default::default() };
        let b = TaintComponent { sinks: vec!["python:file_write:openpyxl.save".into()], ..Default::default() };
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn empty_components_have_stable_fingerprints() {
        assert_eq!(RuleComponent::default().fingerprint(), "rule:");
        assert_eq!(PromptComponent::default().fingerprint(), "prompt:");
    }
}
