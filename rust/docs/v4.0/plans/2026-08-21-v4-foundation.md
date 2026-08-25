# v4.0 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the v4.0 foundation — the differential set-partition engine, the b0 representability filter, the `Component` abstraction, and re-enable CodeQL MaD injection (gated on CLI ≥ 2.26.3).

**Architecture:** Reuse the fusion matcher's proximity grouping to partition a scan into the three feedback sets `c / a / b`; classify agent model candidates by whether they can be encoded into a standard-line component (b0 vs b1/b2); introduce a `Component` trait with a deterministic `fingerprint()` so CodeQL/taint/rule/prompt can be evolved uniformly in later milestones; and replace the `MAD_INJECT_ENABLED` const with a runtime CLI-version gate.

**Tech Stack:** Rust (edition 2024, rust-version 1.88), workspace crate `mcp-sec-audit-core`, `tracing` for instrumentation, `anyhow` for errors.

**Spec:** `rust/docs/v4.0/IDEA_EVALUATION_AND_DESIGN.md` (sections 四「Component 抽象」、五「两阶段路程」、七「关键机制」、6.3「CodeQL MaD 必须打开」、八「日志系统优化」).

## Global Constraints

- Rust edition **2024**, `rust-version = "1.88"` (workspace `Cargo.toml`).
- Code lives in `rust/crates/mcp-sec-audit-core/src/static_analysis/`.
- `serde` is pinned to `=1.0.224` (swc_core re-export constraint) — do **not** bump.
- CodeQL CLI **≥ 2.26.3** required for MaD injection; the host currently has **2.26.2** (`/home/xiao/App/codeql/codeql`). All MaD code must be runtime-gated on version and must warn (not crash) under 2.26.2.
- No new external dependencies (std-only for fingerprint/version parsing).
- Follow existing code style: `pub(crate)` for crate-internal items, `tracing` target `mcp_sec_audit::*`, snake_case categories.

---

### Task 1: Differential set-partition (`diff.rs`)

The core of the v4.0 idea: split a scan's four analysis lines into `c` (agreed), `a` (standard-only), `b` (agent-only) by reusing the fusion matcher's grouping.

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/mod.rs:1` (make `matcher` crate-visible)
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/diff.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs` (register `mod diff;`)

**Interfaces:**
- Consumes: `fusion::matcher::{match_results, MatchGroup}` (after making `matcher` `pub(crate)`).
- Produces: `diff::LineDiff { agreed, a_only, b_only }` and `diff::diff_lines(rule_results, taint_results, agent_results, codeql_results, line_proximity) -> LineDiff`.

- [ ] **Step 1: Expose the matcher**

In `rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/mod.rs`, change line 1 from:

```rust
mod matcher;
```

to:

```rust
pub(crate) mod matcher;
```

- [ ] **Step 2: Register the new module**

In `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`, add `mod diff;` after the `mod discovery;` line (keep alphabetical order — insert between `mod codeql;` and `mod discovery;`):

```rust
mod codeql;
mod diff;
mod discovery;
```

- [ ] **Step 3: Write the failing test**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/diff.rs` with only the test module (the types do not exist yet, so it fails to compile):

```rust
//! v4.0 set-partition: split the four analysis lines into the three feedback
//! sets c / a / b by reusing the fusion matcher's proximity grouping.

use crate::model::{AgentAnalysisResult, CodeqlAnalysisResult, RuleAnalysisResult, TaintAnalysisResult};

use super::fusion::matcher::{MatchGroup, match_results};

/// The three-way partition of a scan's findings for differential feedback.
/// - `agreed` = c: standard line(s) AND agent both found it.
/// - `a_only` = a: standard line(s) found it, agent did not.
/// - `b_only` = b: agent found it, standard line(s) did not.
#[derive(Debug, Default)]
pub(crate) struct LineDiff {
    pub(crate) agreed: Vec<MatchGroup>,
    pub(crate) a_only: Vec<MatchGroup>,
    pub(crate) b_only: Vec<MatchGroup>,
}

/// Partition the four lines into c / a / b using the fusion matcher's
/// proximity + category grouping (so "same finding" means what fusion means).
pub(crate) fn diff_lines(
    rule_results: Vec<RuleAnalysisResult>,
    taint_results: Vec<TaintAnalysisResult>,
    agent_results: Vec<AgentAnalysisResult>,
    codeql_results: Vec<CodeqlAnalysisResult>,
    line_proximity: u32,
) -> LineDiff {
    let groups = match_results(
        rule_results,
        taint_results,
        agent_results,
        codeql_results,
        line_proximity,
    );
    let mut diff = LineDiff::default();
    for group in groups {
        let has_standard = !group.rule_results.is_empty()
            || !group.taint_results.is_empty()
            || !group.codeql_results.is_empty();
        let has_agent = !group.agent_results.is_empty();
        match (has_standard, has_agent) {
            (true, true) => diff.agreed.push(group),
            (true, false) => diff.a_only.push(group),
            (false, true) => diff.b_only.push(group),
            (false, false) => {} // unreachable: matcher never emits empty groups
        }
    }
    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Location, Severity};

    fn rule(id: &str, file: &str, line: u32, category: &str) -> RuleAnalysisResult {
        RuleAnalysisResult {
            result_id: id.into(), rule_id: "r".into(), category: category.into(),
            owasp_mcp: None, file: file.into(), line, matched_text: None, evidence: vec![],
            severity: Severity::Medium, confidence: Confidence::High,
            recommendation: None, related_facts_exist: false,
        }
    }
    fn taint(id: &str, sink_id: &str, sink_kind: &str) -> TaintAnalysisResult {
        TaintAnalysisResult {
            result_id: id.into(), source_id: "source:x.py:0".into(),
            source_kind: "mcp_tool_param".into(), entrypoint_id: None,
            sink_id: sink_id.into(), sink_kind: sink_kind.into(),
            call_chain: vec![], dataflow_path: vec![], evidence: vec![],
            taint_confidence: Confidence::Medium, entrypoint_is_mcp: false,
            backward_trace_found_root: false,
        }
    }
    fn agent(id: &str, file: &str, line: u32) -> AgentAnalysisResult {
        AgentAnalysisResult {
            result_id: id.into(), agent_id: "a".into(), prompt_profile: "p".into(),
            model_provider: None, input_scope: vec![],
            candidate_title: "t".into(), affected_locations: vec![format!("{file}:{line}")],
            reasoning_summary: String::new(), evidence_snippets: vec![],
            related_rule_result_ids: vec![], related_taint_result_ids: vec![],
            confidence: Confidence::Medium, verification_status: "uncorroborated".into(),
            limitations: vec![],
        }
    }
    fn codeql(id: &str, file: &str, line: u32) -> CodeqlAnalysisResult {
        CodeqlAnalysisResult {
            result_id: id.into(), rule_id: "py/cmd".into(), rule_name: "cmd".into(),
            category: "command_execution".into(), query_source: "built-in".into(),
            languages: vec!["python".into()], message: "m".into(), severity: Severity::High,
            locations: vec![Location { file: file.into(), line, column: None, message: None }],
            dataflow_path: None, sarif_snippet: None, related_rule_ids: vec![],
            related_taint_ids: vec![], related_agent_ids: vec![],
            verification_status: "uncorroborated".into(), limitations: vec![],
        }
    }

    #[test]
    fn partitions_into_agreed_a_only_b_only() {
        // rule@10 (a-only), agent@40 (b-only), codeql@41 + agent@41 (agreed).
        let rules = vec![rule("r1", "a.py", 10, "command_execution")];
        let taints = vec![];
        let agents = vec![agent("ag1", "a.py", 40), agent("ag2", "a.py", 41)];
        let codeqls = vec![codeql("c1", "a.py", 41)];
        let diff = diff_lines(rules, taints, agents, codeqls, 5);
        assert_eq!(diff.agreed.len(), 1);
        assert_eq!(diff.a_only.len(), 1);
        assert_eq!(diff.b_only.len(), 1);
    }

    #[test]
    fn empty_inputs_partition_empty() {
        let diff = diff_lines(vec![], vec![], vec![], vec![], 5);
        assert!(diff.agreed.is_empty());
        assert!(diff.a_only.is_empty());
        assert!(diff.b_only.is_empty());
    }

    #[test]
    fn taint_and_codeql_count_as_standard_line() {
        // taint sink at a.py:0, agent at a.py:3 — within proximity 5 → agreed.
        let taints = vec![taint("t1", "sink:file_read:a.py:0", "file_read")];
        let agents = vec![agent("ag1", "a.py", 3)];
        let diff = diff_lines(vec![], taints, agents, vec![], 5);
        assert_eq!(diff.agreed.len(), 1);
        assert!(diff.b_only.is_empty());
    }
}
```

- [ ] **Step 4: Run the test to confirm it fails to compile**

Run: `cargo test -p mcp-sec-audit-core diff::tests::partitions_into_agreed_a_only_b_only`
Expected: FAIL (compile error — `diff` module missing).

- [ ] **Step 5: Add the implementation**

The `diff_lines` function and `LineDiff` struct are already written above; the test file in Step 3 contains the full implementation. Ensure it compiles by running the test.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core diff::tests`
Expected: PASS (3 tests).

- [ ] **Step 7: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/diff.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/fusion/mod.rs
git commit -m "feat(v4): add differential set-partition diff_lines (c/a/b)"
```

---

### Task 2: b0 representability filter (`diff.rs`)

Classify each agent model candidate by whether it can be encoded into a standard-line component — `MadSink` (CodeQL MaD), `TaintModel` (source/sanitizer/non-MaD sink), or `SemanticOnly` (b0).

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/diff.rs`

**Interfaces:**
- Consumes: `codeql::models::mad_sink_kind(&str) -> Option<&'static str>`, `infer::name_category(&str) -> Option<&'static str>`, `model::ModelCandidate`.
- Produces: `diff::Representability` and `diff::classify_candidate(&ModelCandidate) -> Representability`.

- [ ] **Step 1: Write the failing test**

Append to `diff.rs` (the `Representability` enum and `classify_candidate` do not exist yet):

```rust
#[cfg(test)]
mod b0_tests {
    use super::*;
    use crate::model::ModelCandidate;

    fn cand(kind: &str, name: &str, category: &str) -> ModelCandidate {
        ModelCandidate {
            kind: kind.into(), name: name.into(), category: category.into(),
            language: "python".into(), argument: Some(0),
            confidence: Confidence::Medium, evidence_snippets: vec![],
        }
    }

    #[test]
    fn sink_with_mad_kind_and_module_is_mad_sink() {
        assert_eq!(
            classify_candidate(&cand("sink", "openpyxl.load_workbook", "file_read")),
            Representability::MadSink
        );
    }

    #[test]
    fn sink_without_mad_kind_but_named_is_taint_model() {
        // "deserialization" has no MaD sink kind, but "load_*" has a name prefix.
        assert_eq!(
            classify_candidate(&cand("sink", "pickle.loads", "deserialization")),
            Representability::TaintModel
        );
    }

    #[test]
    fn source_and_sanitizer_are_taint_models() {
        assert_eq!(classify_candidate(&cand("source", "request.get", "network_request")), Representability::TaintModel);
        assert_eq!(classify_candidate(&cand("sanitizer", "html.escape", "xss")), Representability::TaintModel);
    }

    #[test]
    fn unknown_kind_is_semantic_only() {
        assert_eq!(classify_candidate(&cand("mystery", "foo.bar", "x")), Representability::SemanticOnly);
    }
}
```

- [ ] **Step 2: Run the test to confirm it fails**

Run: `cargo test -p mcp-sec-audit-core diff::b0_tests`
Expected: FAIL (compile error — `Representability`/`classify_candidate` undefined).

- [ ] **Step 3: Write the implementation**

Add the following to the top of `diff.rs` (after the existing `use` statements):

```rust
use crate::model::ModelCandidate;
use super::codeql::models::mad_sink_kind;
use super::infer::name_category;

/// How an agent model candidate can be encoded into a standard-line component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Representability {
    /// Encodable as a CodeQL MaD sinkModel extension (module.function + sink kind).
    MadSink,
    /// Encodable as a taint source/sanitizer model (or a non-MaD sink model).
    TaintModel,
    /// Not encodable as any standard-line component — b0 (semantic-only).
    SemanticOnly,
}

/// Classify a B-only model candidate by its representability (the G2 gate).
pub(crate) fn classify_candidate(c: &ModelCandidate) -> Representability {
    match c.kind.as_str() {
        "sink" => {
            let has_module = c.name.contains('.') || c.name.contains("::");
            if has_module && mad_sink_kind(&c.category).is_some() {
                Representability::MadSink
            } else if name_category(&c.name).is_some() {
                Representability::TaintModel
            } else {
                Representability::SemanticOnly
            }
        }
        "source" | "sanitizer" => Representability::TaintModel,
        _ => Representability::SemanticOnly,
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core diff::`
Expected: PASS (7 tests: 3 from Task 1 + 4 b0 tests).

- [ ] **Step 5: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/diff.rs
git commit -m "feat(v4): add b0 representability filter for model candidates"
```

---

### Task 3: Component abstraction (`component.rs`)

Introduce `ToolKind` and the `Component` trait with a deterministic `fingerprint()`, plus the four concrete components, so CodeQL/taint/rule/prompt can be evolved uniformly later.

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/component.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs` (register `mod component;`)

**Interfaces:**
- Produces: `component::{ToolKind, Component, CodeqlComponent, TaintComponent, RuleComponent, PromptComponent}` with `Component::tool(&self) -> ToolKind` and `Component::fingerprint(&self) -> String`.

- [ ] **Step 1: Register the module**

In `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`, add `mod component;` right after `mod codeql;`:

```rust
mod codeql;
mod component;
mod diff;
```

- [ ] **Step 2: Write the failing test**

Create `rust/crates/mcp-sec-audit-core/src/static_analysis/component.rs` with the trait, the four components, and a test module:

```rust
//! The unified "Component" abstraction: a capability-determining artifact for
//! one analysis tool. Evolve/promote/rollback arrive in a later milestone; this
//! milestone establishes identity (`tool`) and a stable `fingerprint` so a
//! component can be compared across the two phases.

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
```

- [ ] **Step 3: Run the test to confirm it fails to compile**

Run: `cargo test -p mcp-sec-audit-core component::tests`
Expected: FAIL (compile error — `component` module missing).

- [ ] **Step 4: Verify the tests pass**

Run: `cargo test -p mcp-sec-audit-core component::tests`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/component.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs
git commit -m "feat(v4): add Component trait with fingerprint for four tools"
```

---

### Task 4: Re-enable CodeQL MaD injection (runtime version gate)

Replace the `MAD_INJECT_ENABLED = false` const with a runtime check on the CLI version, so MaD is enabled in code and activates once the host runs CLI ≥ 2.26.3.

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/provider.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs`

**Interfaces:**
- Consumes: none new.
- Produces: `CliCodeqlProvider::codeql_version(&self) -> Option<(u32,u32,u32)>`, `provider::parse_codeql_version(&str) -> Option<(u32,u32,u32)>`, `mod.rs::mad_inject_supported(Option<(u32,u32,u32)>) -> bool`.

- [ ] **Step 1: Write the failing test (version parsing + gate)**

In `rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/provider.rs`, append to the existing `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn parses_codeql_version_line() {
        let stdout = "CodeQL command-line toolchain release 2.26.2.\nCopyright (C) ...\n";
        assert_eq!(parse_codeql_version(stdout), Some((2, 26, 2)));
    }

    #[test]
    fn parses_three_component_version_without_trailing_dot() {
        assert_eq!(parse_codeql_version("CodeQL release 2.26.3"), Some((2, 26, 3)));
    }

    #[test]
    fn unparseable_version_returns_none() {
        assert_eq!(parse_codeql_version("not a version line"), None);
    }
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test -p mcp-sec-audit-core codeql::provider::tests::parses_codeql_version_line`
Expected: FAIL (compile error — `parse_codeql_version` undefined).

- [ ] **Step 3: Implement version parsing in provider.rs**

Add to `CliCodeqlProvider` (in `impl CliCodeqlProvider`), and add the free function at module scope:

```rust
    /// Parse the installed CodeQL CLI version from `codeql --version`.
    pub(crate) fn codeql_version(&self) -> Option<(u32, u32, u32)> {
        let output = Command::new(&self.binary)
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
```

And at module scope (above `impl CliCodeqlProvider`):

```rust
/// Parse a `(major, minor, patch)` tuple from the first line of
/// `codeql --version` output (e.g. "CodeQL command-line toolchain release 2.26.2.").
pub(crate) fn parse_codeql_version(stdout: &str) -> Option<(u32, u32, u32)> {
    let line = stdout.lines().next()?;
    let after_release = line.split("release ").nth(1)?;
    let version = after_release.split_whitespace().next()?.trim_end_matches('.');
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}
```

- [ ] **Step 4: Run provider tests**

Run: `cargo test -p mcp-sec-audit-core codeql::provider::tests`
Expected: PASS.

- [ ] **Step 5: Replace the const with a runtime gate in mod.rs**

In `rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs`:

1. Delete the `MAD_INJECT_ENABLED` const (currently lines 22–27) and replace it with:

```rust
/// MaD model-pack injection requires CLI >= 2.26.3 (2.26.2 rejects the 3-column
/// `sinkModel` extension under overlay-eval mode — see SDD ledger RULING 11).
fn mad_inject_supported(version: Option<(u32, u32, u32)>) -> bool {
    matches!(version, Some((major, minor, patch)) if (major, minor, patch) >= (2, 26, 3))
}
```

2. In `run()` (currently `let model_packs: Vec<models::MadPack> = if MAD_INJECT_ENABLED { ... } else { Vec::new() };`), replace with:

```rust
    let cli_version = session.provider.codeql_version();
    let model_packs: Vec<models::MadPack> = if mad_inject_supported(cli_version) {
        match models::write_model_pack_dir(&crate::models::default_catalog(), ctx) {
            Ok(pack) => vec![pack],
            Err(e) => {
                tracing::warn!(
                    target: "mcp_sec_audit::codeql",
                    error = %e,
                    "failed to compile MaD model packs; running without them"
                );
                Vec::new()
            }
        }
    } else {
        tracing::warn!(
            target: "mcp_sec_audit::codeql",
            cli_version = ?cli_version,
            "CodeQL MaD injection disabled: requires CLI >= 2.26.3. Upgrade to enable sink-model evolution."
        );
        Vec::new()
    };
```

- [ ] **Step 6: Add gate unit tests to mod.rs**

Append to `codeql/mod.rs`'s existing `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn mad_gate_accepts_2_26_3_and_newer() {
        assert!(mad_inject_supported(Some((2, 26, 3))));
        assert!(mad_inject_supported(Some((2, 27, 0))));
        assert!(mad_inject_supported(Some((3, 0, 0))));
    }

    #[test]
    fn mad_gate_rejects_2_26_2_and_missing() {
        assert!(!mad_inject_supported(Some((2, 26, 2))));
        assert!(!mad_inject_supported(Some((2, 26, 0))));
        assert!(!mad_inject_supported(None));
    }
```

- [ ] **Step 7: Run codeql tests**

Run: `cargo test -p mcp-sec-audit-core codeql::`
Expected: PASS.

- [ ] **Step 8: Build the crate to catch integration errors**

Run: `cargo build -p mcp-sec-audit-core`
Expected: SUCCESS.

- [ ] **Step 9: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/provider.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs
git commit -m "feat(v4): enable CodeQL MaD injection gated on CLI >= 2.26.3"
```

---

### Task 5: Wire the diff into the pipeline + first logging

Compute the `LineDiff` after fusion and surface the partition (terminal `progress` + structured `tracing`), plus log each component fingerprint at scan start. This makes Tasks 1–3 exercised end-to-end and delivers the first logging improvement.

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`

**Interfaces:**
- Consumes: `diff::diff_lines`, `component::{CodeqlComponent, TaintComponent, RuleComponent, PromptComponent, Component}`.
- Produces: no new public API (internal logging only).

- [ ] **Step 1: Add imports**

In `pipeline.rs`, extend the existing `use super::{...}` line to include `component` and `diff`:

```rust
use super::{agent, codeql, component, diff, fusion, learning, rule, taint, DiscoveredFile, discover_files};
```

- [ ] **Step 2: Log component fingerprints at scan start**

In `run_static_scan_with_progress`, right after the `discover_files` line (`progress(&format!("Discovered {} files", ...))`), insert:

```rust
    let _components = (
        component::CodeqlComponent::default(),
        component::TaintComponent::default(),
        component::RuleComponent::default(),
        component::PromptComponent::default(),
    );
    tracing::debug!(
        target: "mcp_sec_audit::component",
        codeql = %_components.0.fingerprint(),
        taint = %_components.1.fingerprint(),
        rule = %_components.2.fingerprint(),
        agent = %_components.3.fingerprint(),
        "component fingerprints"
    );
```

- [ ] **Step 3: Compute and report the diff after fusion**

In `run_static_scan_with_progress`, immediately after the `fused_findings` block (before `// --- Phase 5: cold persistence ---`), insert:

```rust
    let line_diff = diff::diff_lines(
        rule_results.clone(),
        taint_results.clone(),
        agent_results.clone(),
        codeql_output.results.clone(),
        ctx.config.fusion.line_proximity,
    );
    progress(&format!(
        "Differential: agreed={} standard-only={} agent-only={}",
        line_diff.agreed.len(),
        line_diff.a_only.len(),
        line_diff.b_only.len(),
    ));
    tracing::info!(
        target: "mcp_sec_audit::diff",
        agreed = line_diff.agreed.len(),
        a_only = line_diff.a_only.len(),
        b_only = line_diff.b_only.len(),
        "differential partition"
    );
```

- [ ] **Step 4: Build and run the full core test suite**

Run: `cargo build -p mcp-sec-audit-core && cargo test -p mcp-sec-audit-core`
Expected: PASS (all existing + new tests).

- [ ] **Step 5: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs
git commit -m "feat(v4): compute differential partition and log component fingerprints"
```

---

## Self-Review Notes

- **Spec coverage**: Tasks 1–3 map to spec §四 (Component 抽象) and §五 (两阶段路程的集合差分); Task 2 maps to §七 7.2 G2 (可表达性门控); Task 4 maps to §6.3 (CodeQL MaD 必须打开); Task 5 maps to §八 (日志系统优化 — first slice). The remaining spec (evolve/promote/rollback, prompt', validate.rs, taint source/sanitizer models, full logging) is intentionally deferred to later plans (M2/M3/M4).
- **Placeholders**: none — every step has concrete code and commands.
- **Type consistency**: `LineDiff { agreed, a_only, b_only }`, `Representability::{MadSink, TaintModel, SemanticOnly}`, `ToolKind::{Codeql, Taint, Rule, Agent}`, and `Component::fingerprint() -> String` are used identically across tasks.
- **Known environment gap**: the host CodeQL CLI is 2.26.2, so Task 4's MaD path stays dormant (warns) until the user upgrades to ≥ 2.26.3. Suite-ref un-pinning (`queries.rs`) is deferred to that same upgrade — under 2.26.2 the pins are required.

---

## Execution Handoff

Plan complete and saved to `rust/docs/v4.0/plans/2026-08-21-v4-foundation.md`.
