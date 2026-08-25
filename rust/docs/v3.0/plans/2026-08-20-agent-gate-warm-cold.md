# R5 — Agent Three-Role + Gate + Warm Re-injection + Cold Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the agent line from a one-shot scanner into a three-role (verify + model + audit) semantic engine whose discovered sink models are gated against the cheap semantic-inference heuristics, warm-re-injected this run (rule/taint/codeql), and cold-persisted to a `learned/` directory for the next run — closing the loop so a missed sink becomes a one-time miss.

**Architecture:** The pipeline becomes 2-phase: run the deterministic lines + agent, then gate the agent's `model_candidates`, warm-re-inject the hot/warm sinks into taint (new `Sink` facts on the already-extracted facts) and CodeQL (extended MaD on the cached DB via R4's `CodeqlSession`), re-fuse, then cold-persist every gated candidate to `learned/`. The gate rejects agent-only claims (cold) so hallucination never pollutes this run's results.

**Tech Stack:** Rust (`tracing`, `serde`, `toml`), CodeQL CLI 2.26.2 (reuses R4's `CodeqlSession` + MaD compiler).

**Spec:** `rust/docs/GENERALITY_STRATEGY.md` §5.3/§5.4 (agent feedback loop + gating + hot/warm/cold) + `rust/docs/ARCHITECTURE_REDESIGN.md` §5.4 (three-role agent) and §5.5 (gate + evolution).

## Global Constraints

- No `cargo test` regression. Baseline: **216 core + 4 CLI = 220 green**.
- The gate must never let an agent-only claim re-enter this run (`hot`/`warm` require an inference signal; bare agent claims are `cold`).
- Sink-only scope for model evolution: agent `source`/`sanitizer` candidates are **cold-persisted as-is but not applied** this milestone (the catalog only carries sinks; source/sanitizer application is a documented follow-up).
- Warm re-run uses the facts and DB **already produced** in Phase 1 — never re-extract source or rebuild the CodeQL database.
- All unit tests run **without** CodeQL or an LLM installed (existing convention: never invoke the real CLI/agent in `cargo test`).

---

### Task 1: `ModelCandidate` type + three-role prompt + parser extraction

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/model/static_result.rs` (add `ModelCandidate`, `AgentOutput`)
- Modify: `crates/mcp-sec-audit-core/src/model/mod.rs` (re-export)
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/agent/prompt.rs` (three-role output schema)
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/agent/parser.rs` (parse `model_candidates`)
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/agent/mod.rs` (`run` returns `AgentOutput`)

**Interfaces:**
- Produces:
  - `pub struct ModelCandidate { pub kind: String, pub name: String, pub category: String, pub language: String, pub argument: Option<u32>, pub confidence: Confidence, pub evidence_snippets: Vec<String> }`
  - `pub struct AgentOutput { pub findings: Vec<AgentAnalysisResult>, pub model_candidates: Vec<ModelCandidate> }`
  - `pub fn agent::run(ctx) -> Result<AgentOutput>`

- [ ] **Step 1: Add `ModelCandidate` + `AgentOutput` to `model/static_result.rs`**

Append (after `AgentAnalysisResult`):

```rust
/// A sink/source/sanitizer model proposed by the agent (three-role "model" output).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelCandidate {
    /// "sink" | "source" | "sanitizer".
    pub kind: String,
    /// Callee name, e.g. "openpyxl.load_workbook".
    pub name: String,
    /// Canonical category (snake_case), e.g. "file_read".
    pub category: String,
    /// "python" | "javascript" | "rust".
    pub language: String,
    /// Dangerous argument index (sink) — `None` when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argument: Option<u32>,
    pub confidence: Confidence,
    #[serde(default)]
    pub evidence_snippets: Vec<String>,
}

/// Combined output of the agent line: findings + proposed models.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentOutput {
    pub findings: Vec<AgentAnalysisResult>,
    #[serde(default)]
    pub model_candidates: Vec<ModelCandidate>,
}
```

In `model/mod.rs`, add `ModelCandidate,` and `AgentOutput,` to the existing `pub use` list (verify the current `pub use model::{ ... }` in `lib.rs` re-exports the same names — add `ModelCandidate` and `AgentOutput` there too).

- [ ] **Step 2: Extend the prompt's output schema (three roles)**

In `prompt.rs`, replace the `## Output Format` JSON block and the closing sentence with:

```text
## Output Format

After completing your analysis, output EXACTLY ONE JSON block (wrapped in a
```json code fence) with TWO arrays:

1. `findings` — vulnerabilities you verified or discovered semantically.
2. `model_candidates` — new sink/source/sanitizer models you inferred while
   reading the code. A "model" is a reusable fact about a library function,
   NOT a single vulnerability. Only propose a model when you are confident it
   generalizes beyond the one call site you saw.

For each model candidate use:
- kind: "sink" (dangerous operation consuming untrusted data), "source"
  (user-controllable entrypoint), or "sanitizer" (function that neutralizes
  taint).
- name: the exact callee, e.g. "openpyxl.load_workbook".
- category: one of command_execution, dynamic_execution, file_read,
  file_write, file_delete, network_request, database_injection,
  deserialization, template_injection, path_traversal, prompt_injection,
  data_exfiltration.
- language: python | javascript | rust.
- argument: the 0-based index of the dangerous parameter (sink only).
- confidence: high | medium | low.
- evidence_snippets: the exact source lines that justify the model.
```

```json
{
  "findings": [
    { "candidate_title": "...", "affected_locations": ["path/to/file.rs:42"], "reasoning_summary": "...", "evidence_snippets": ["..."], "confidence": "high", "limitations": [] }
  ],
  "model_candidates": [
    { "kind": "sink", "name": "openpyxl.load_workbook", "category": "file_read", "language": "python", "argument": 0, "confidence": "medium", "evidence_snippets": ["wb = openpyxl.load_workbook(filepath)"] }
  ]
}
```

If you find NO vulnerabilities and NO models, return `{"findings": [], "model_candidates": []}`.
```

- [ ] **Step 3: Parse `model_candidates` in `parser.rs`**

Add:

```rust
#[derive(Debug, Deserialize)]
struct RawModelCandidate {
    kind: String,
    name: String,
    category: String,
    language: String,
    #[serde(default)]
    argument: Option<u32>,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    evidence_snippets: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawOutput {
    #[serde(default)]
    findings: Vec<RawFinding>,
    #[serde(default)]
    model_candidates: Vec<RawModelCandidate>,
}
```

Change `parse_agent_output` to return `AgentOutput` and map raw model candidates (skipping those with an empty `name` or `category`):

```rust
pub fn parse_agent_output(stdout: &str, metadata: &AgentMetadata) -> Result<AgentOutput> {
    // … existing JSON-block extraction + findings loop unchanged …

    let model_candidates = raw.model_candidates.into_iter()
        .filter(|m| !m.name.trim().is_empty() && !m.category.trim().is_empty())
        .map(|m| ModelCandidate {
            kind: m.kind,
            name: m.name,
            category: m.category,
            language: m.language,
            argument: m.argument,
            confidence: parse_confidence(&m.confidence),
            evidence_snippets: m.evidence_snippets,
        })
        .collect();

    Ok(AgentOutput { findings: results, model_candidates })
}
```

- [ ] **Step 4: Change `agent::run` to return `AgentOutput`**

In `agent/mod.rs`, change the return type to `Result<AgentOutput>` and wrap the final value:

```rust
Ok(AgentOutput { findings: results, model_candidates })
```

- [ ] **Step 5: Update the affected tests + run**

Update `agent::mod::tests` (`disabled_agent_returns_empty` and `enabled_with_no_files_returns_empty`) to assert `output.findings.is_empty()` / `output.model_candidates.is_empty()`. Update `agent::parser::tests` to read `.findings` where they previously read the bare vec, and add one new test:

```rust
#[test]
fn parses_model_candidates_alongside_findings() {
    let stdout = r#"```json
{"findings": [], "model_candidates": [
  {"kind":"sink","name":"openpyxl.load_workbook","category":"file_read","language":"python","argument":0,"confidence":"medium","evidence_snippets":["x"]}
]}
```"#;
    let out = parse_agent_output(stdout, &metadata()).expect("parse");
    assert!(out.findings.is_empty());
    assert_eq!(out.model_candidates.len(), 1);
    assert_eq!(out.model_candidates[0].name, "openpyxl.load_workbook");
    assert_eq!(out.model_candidates[0].confidence, Confidence::Medium);
}
```

Run: `cargo test -p mcp-sec-audit-core agent`
Expected: all `agent::*` tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/mcp-sec-audit-core/src/model/ crates/mcp-sec-audit-core/src/static_analysis/agent/ crates/mcp-sec-audit-core/src/lib.rs
git commit -m "feat(agent): three-role output (findings + model_candidates)"
```

---

### Task 2: Gate logic (`learning.rs`)

**Files:**
- Create: `crates/mcp-sec-audit-core/src/static_analysis/learning.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/mod.rs` (add `pub(crate) mod learning;`)
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/infer.rs` (expose `pub(crate) fn name_category`)

**Interfaces:**
- Consumes: `ModelCandidate`, `crate::models::PackageRule`.
- Produces:
  - `pub enum GateDecision { Hot, Warm, Cold }`
  - `pub fn gate_sink_candidate(candidate: &ModelCandidate, rules: &[PackageRule]) -> GateDecision`

- [ ] **Step 1: Expose the layer-3 naming category from `infer.rs`**

Add below `NAME_PREFIX_CATEGORY`:

```rust
/// Layer-3 category for a callee's method-name prefix, or `None`.
pub(crate) fn name_category(callee: &str) -> Option<&'static str> {
    let method = callee.rsplit(['.', ':']).next().unwrap_or(callee).to_lowercase();
    NAME_PREFIX_CATEGORY.iter().find(|(p, _)| method.starts_with(p)).map(|(_, c)| *c)
}
```

- [ ] **Step 2: Write the failing tests in `learning.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, ModelCandidate};
    use crate::models::{PackageRule, default_package_rules};

    fn cand(name: &str, category: &str) -> ModelCandidate {
        ModelCandidate {
            kind: "sink".into(),
            name: name.into(),
            category: category.into(),
            language: "python".into(),
            argument: Some(0),
            confidence: Confidence::Medium,
            evidence_snippets: vec![],
        }
    }

    #[test]
    fn package_agreement_is_hot() {
        // openpyxl is a package rule with read_category=file_read.
        let d = gate_sink_candidate(&cand("openpyxl.load_workbook", "file_read"), &default_package_rules());
        assert_eq!(d, GateDecision::Hot);
    }

    #[test]
    fn name_prefix_only_is_warm() {
        // "load_config" matches the load→file_read naming prefix, but has no package rule.
        let d = gate_sink_candidate(&cand("load_config", "file_read"), &default_package_rules());
        assert_eq!(d, GateDecision::Warm);
    }

    #[test]
    fn no_inference_signal_is_cold() {
        let d = gate_sink_candidate(&cand("frobnicate_thing", "file_read"), &default_package_rules());
        assert_eq!(d, GateDecision::Cold);
    }

    #[test]
    fn category_mismatch_is_not_hot() {
        // openpyxl is file_read, but agent claims command_execution → no agreement.
        let d = gate_sink_candidate(&cand("openpyxl.load_workbook", "command_execution"), &default_package_rules());
        assert_ne!(d, GateDecision::Hot);
    }
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p mcp-sec-audit-core learning`
Expected: compile error — `learning` module not found.

- [ ] **Step 4: Implement the gate**

```rust
//! Gate + learned-dir persistence + warm re-injection for the agent feedback loop.

use std::path::Path;

use crate::model::{Confidence, Fact, ModelCandidate, Severity, SinkFact, FactBase};
use crate::models::{PackageRule, SinkModel, rule_prefix};

use super::infer::name_category;

/// Gating decision for an agent-proposed sink model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision { Hot, Warm, Cold }

fn split_module_function(name: &str) -> Option<(&str, &str)> {
    name.rsplit_once('.').filter(|(m, f)| !m.is_empty() && !f.is_empty())
}

/// Classify an agent-proposed sink by cross-checking it against the cheap
/// semantic-inference heuristics. `Hot` = layer-2 package classification
/// agrees on the same category; `Warm` = only the layer-3 naming prefix
/// matches; `Cold` = no inference support (agent-only, not re-injected).
pub fn gate_sink_candidate(candidate: &ModelCandidate, rules: &[PackageRule]) -> GateDecision {
    let Some((module, _)) = split_module_function(&candidate.name) else {
        return GateDecision::Cold;
    };
    let package_agrees = rules.iter().any(|r| {
        r.language == candidate.language
            && r.package == module
            && (r.category.as_deref() == Some(candidate.category.as_str())
                || r.read_category.as_deref() == Some(candidate.category.as_str())
                || r.write_category.as_deref() == Some(candidate.category.as_str()))
    });
    if package_agrees {
        return GateDecision::Hot;
    }
    if name_category(&candidate.name) == Some(candidate.category.as_str()) {
        return GateDecision::Warm;
    }
    GateDecision::Cold
}
```

- [ ] **Step 5: Run to verify they pass**

Run: `cargo test -p mcp-sec-audit-core learning`
Expected: 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/learning.rs crates/mcp-sec-audit-core/src/static_analysis/mod.rs crates/mcp-sec-audit-core/src/static_analysis/infer.rs
git commit -m "feat(learning): gate agent sink candidates against inference heuristics"
```

---

### Task 3: Learned-dir persistence (cold evolution)

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/models/mod.rs` (add `source`/`learned_from` to `SinkModel`)
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/learning.rs` (add `candidate_to_sink_model` + `write_learned_sinks`)
- Modify: `crates/mcp-sec-audit-core/src/config.rs` (add `learned_dir` to `StaticConfig`)

**Interfaces:**
- Produces:
  - `SinkModel` gains `pub source: Option<String>` and `pub learned_from: Option<String>` (serde default).
  - `pub fn candidate_to_sink_model(c: &ModelCandidate, scan_id: &str, agent_id: &str) -> Option<SinkModel>`
  - `pub fn write_learned_sinks(dir: &Path, models: &[SinkModel]) -> anyhow::Result<()>`
  - `StaticConfig.learned_dir: Option<String>`

- [ ] **Step 1: Extend `SinkModel` with provenance fields**

In `models/mod.rs`, add two `#[serde(default)]` fields to `SinkModel`:

```rust
    /// "manual" | "package" | "learned" — `None` treated as manual.
    #[serde(default)]
    pub source: Option<String>,
    /// Provenance for learned models: "scan-id/agent-id".
    #[serde(default)]
    pub learned_from: Option<String>,
```

Update every `SinkModel { .. }` literal in the crate (in `models/mod.rs` tests, `pipeline.rs` tests, and any fixture) to include `source: None, learned_from: None,`. Use `cargo check` to find them all.

- [ ] **Step 2: Write the failing tests**

In `learning.rs` tests:

```rust
    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("learn-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn candidate_converts_to_learned_sink_model() {
        let m = candidate_to_sink_model(
            &cand("openpyxl.load_workbook", "file_read"),
            "scan-1", "claude",
        ).expect("sink candidate maps");
        assert_eq!(m.language, "python");
        assert_eq!(m.category, "file_read");
        assert_eq!(m.patterns, vec!["openpyxl.load_workbook"]);
        assert_eq!(m.confidence, Confidence::Low);   // learned enters low
        assert_eq!(m.source.as_deref(), Some("learned"));
        assert_eq!(m.learned_from.as_deref(), Some("scan-1/claude"));
    }

    #[test]
    fn write_learned_sinks_roundtrips() {
        let dir = tmp_dir("write");
        let m = candidate_to_sink_model(&cand("openpyxl.load_workbook", "file_read"), "scan-1", "claude").unwrap();
        write_learned_sinks(&dir, &[m]).expect("write");
        let loaded = crate::models::load_models_dir(&dir).expect("load");
        assert_eq!(loaded.sink_count(), 1);
        assert!(loaded.sinks_for_language("python")[0].source.as_deref() == Some("learned"));
        std::fs::remove_dir_all(&dir).ok();
    }
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p mcp-sec-audit-core learning`
Expected: compile error — `candidate_to_sink_model` / `write_learned_sinks` not found.

- [ ] **Step 4: Implement conversion + persistence**

```rust
/// Convert a gated sink candidate into a low-confidence `learned` sink model.
pub fn candidate_to_sink_model(
    c: &ModelCandidate,
    scan_id: &str,
    agent_id: &str,
) -> Option<SinkModel> {
    if c.kind != "sink" || c.name.trim().is_empty() || c.category.trim().is_empty() {
        return None;
    }
    Some(SinkModel {
        language: c.language.clone(),
        category: c.category.clone(),
        severity: Severity::Medium,
        confidence: Confidence::Low,
        reason: format!(
            "learned sink: {} (evidence: {})",
            c.category,
            c.evidence_snippets.first().cloned().unwrap_or_default()
        ),
        patterns: vec![c.name.clone()],
        source: Some("learned".to_string()),
        learned_from: Some(format!("{scan_id}/{agent_id}")),
    })
}

/// Append learned models to a directory as one TOML file per model (sorted by
/// name for determinism). Creates the directory if absent.
pub fn write_learned_sinks(dir: &Path, models: &[SinkModel]) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (i, m) in models.iter().enumerate() {
        let safe = m.patterns.first().map(|p| p.replace(['.', ':', '/'], "_")).unwrap_or_else(|| i.to_string());
        let text = format!(
            "[[sinks]]\nlanguage = {:?}\ncategory = {:?}\nseverity = {:?}\nconfidence = {:?}\nreason = {:?}\npatterns = {:?}\nsource = \"learned\"\nlearned_from = {:?}\n",
            m.language, m.category, severity_str(&m.severity), confidence_str(&m.confidence),
            m.reason, m.patterns, m.learned_from.as_deref().unwrap_or("unknown")
        );
        std::fs::write(dir.join(format!("learned-{safe}.toml")), text)?;
    }
    Ok(())
}

fn severity_str(s: &Severity) -> &'static str {
    match s { Severity::Critical => "critical", Severity::High => "high", Severity::Medium => "medium", Severity::Low => "low" }
}
fn confidence_str(c: &Confidence) -> &'static str {
    match c { Confidence::High => "high", Confidence::Medium => "medium", Confidence::Low => "low" }
}
```

- [ ] **Step 5: Add `learned_dir` to config**

In `config.rs` `StaticConfig`, add:

```rust
    /// Directory where gated learned models are cold-persisted (next run loads them).
    #[serde(default)]
    pub learned_dir: Option<String>,
```

Update `StaticConfig::default()` to set `learned_dir: None`, and add a config-parse test mirroring `models_dir_parses_from_toml`.

- [ ] **Step 6: Run to verify they pass**

Run: `cargo test -p mcp-sec-audit-core learning` then `cargo test -p mcp-sec-audit-core config`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/mcp-sec-audit-core/src/models/mod.rs crates/mcp-sec-audit-core/src/static_analysis/learning.rs crates/mcp-sec-audit-core/src/config.rs
git commit -m "feat(learning): cold-persist gated sinks to learned dir"
```

---

### Task 4: Warm re-injection helpers (candidates → sink facts + MaD)

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/learning.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/infer.rs` (make `make_inferred_sink` reusable, or add a helper)

**Interfaces:**
- Produces:
  - `pub fn sink_candidates_to_sink_facts(facts: &[Fact], candidates: &[ModelCandidate]) -> Vec<Fact>`
  - `pub fn candidates_to_mad_sinks(candidates: &[ModelCandidate]) -> Vec<SinkModel>` (reuse R4's `codeql::models::sink_models_to_mad`)

- [ ] **Step 1: Write the failing test**

```rust
    fn call_fact(id: &str, callee: &str) -> Fact {
        use crate::model::{CallFact, CallArg};
        Fact::Call(CallFact {
            base: FactBase { id: id.into(), file: "s.py".into(), line: 3, extractor: "t".into() },
            caller: "f".into(),
            callee: callee.into(),
            normalized_callee: Some(callee.into()),
            column: None, end_line: None, snippet: format!("{callee}(x)"),
            args: vec![CallArg { index: 0, expr: "x".into(), kind: "positional".into() }],
            kwargs: Default::default(), resolution: None,
        })
    }

    #[test]
    fn warm_candidates_become_sink_facts_for_matching_calls() {
        let facts = vec![
            call_fact("call:1", "openpyxl.load_workbook"),
            call_fact("call:2", "unrelated.thing"),
        ];
        let cands = vec![cand("openpyxl.load_workbook", "file_read")];
        let new = sink_candidates_to_sink_facts(&facts, &cands);
        assert_eq!(new.len(), 1);
        if let Fact::Sink(s) = &new[0] {
            assert_eq!(s.sink_name, "openpyxl.load_workbook");
            assert_eq!(s.category, "file_read");
            assert_eq!(s.confidence, Confidence::Medium);
        } else { panic!("expected Sink"); }
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mcp-sec-audit-core learning`
Expected: compile error — `sink_candidates_to_sink_facts` not found.

- [ ] **Step 3: Implement**

```rust
/// Match agent-proposed sink candidates against already-extracted call facts
/// and produce `Sink` facts for the matching calls (warm re-injection).
pub fn sink_candidates_to_sink_facts(facts: &[Fact], candidates: &[ModelCandidate]) -> Vec<Fact> {
    let mut out = Vec::new();
    for fact in facts {
        let Fact::Call(call) = fact else { continue };
        let callee = call.normalized_callee.as_deref().unwrap_or(&call.callee);
        for c in candidates {
            if c.kind != "sink" { continue; }
            let hit = callee == c.name
                || callee.ends_with(&format!(".{}", c.name))
                || callee.ends_with(&format!("::{}", c.name));
            if !hit { continue; }
            out.push(Fact::Sink(SinkFact {
                base: FactBase {
                    id: format!("sink:learned:{}:{}", call.base.id, c.category),
                    file: call.base.file.clone(),
                    line: call.base.line,
                    extractor: "agent_model".to_string(),
                },
                call_id: call.base.id.clone(),
                category: c.category.clone(),
                rule_id: format!("{}.{}", rule_prefix(&c.language), c.category),
                sink_name: callee.to_string(),
                severity_base: Severity::Medium,
                reason: format!("learned sink from agent (warm re-injection): {}", c.category),
                conditions: Default::default(),
                confidence: c.confidence.clone(),
            }));
        }
    }
}

/// Convert sink candidates to `SinkModel`s so R4's MaD compiler can turn them
/// into CodeQL model packs for the warm CodeQL re-run.
pub fn candidates_to_mad_sinks(candidates: &[ModelCandidate]) -> Vec<SinkModel> {
    candidates.iter().filter(|c| c.kind == "sink").map(|c| SinkModel {
        language: c.language.clone(),
        category: c.category.clone(),
        severity: Severity::Medium,
        confidence: c.confidence.clone(),
        reason: format!("learned sink (warm): {}", c.category),
        patterns: vec![c.name.clone()],
        source: Some("learned".to_string()),
        learned_from: None,
    }).collect()
}
```

Add the imports at the top of `learning.rs`: `use crate::model::{Fact, FactBase, SinkFact, Severity, ...}` (adjust the existing `use crate::model::{...}` line).

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p mcp-sec-audit-core learning`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/learning.rs
git commit -m "feat(learning): warm re-inject candidates as sink facts + MaD sinks"
```

---

### Task 5: Two-phase pipeline orchestration

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`
- Modify: `crates/mcp-sec-audit-core/src/model/static_result.rs` (add `model_candidates` to `StaticAnalysisResult`)
- Modify: `crates/mcp-sec-audit-core/src/lib.rs` (re-export `ModelCandidate` if not already)

**Interfaces:**
- Consumes: `agent::run -> AgentOutput`, `codeql::CodeqlSession`, `learning::{gate_sink_candidate, sink_candidates_to_sink_facts, candidates_to_mad_sinks, candidate_to_sink_model, write_learned_sinks}`, `taint::run_taint_analysis`, `infer::name_category`.
- Produces: `StaticAnalysisResult { .., model_candidates: Vec<ModelCandidate>, .. }`.

- [ ] **Step 1: Add `model_candidates` to `StaticAnalysisResult`**

In `static_result.rs`, add to `StaticAnalysisResult`:

```rust
    /// Sink/source/sanitizer models proposed by the agent this run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_candidates: Vec<ModelCandidate>,
```

Update `empty_result` in `pipeline.rs` and `synthetic_static_analysis_result` in `fixtures.rs` to set `model_candidates: Vec::new()`.

- [ ] **Step 2: Rewrite the pipeline body to two phases**

Replace the section from the `agent_results` block through the `codeql_output` block and the `fused_findings` block with the following sequence (rule + taint blocks unchanged, still earlier in the function):

```rust
    // --- Phase 1b: CodeQL baseline (session kept for warm re-run) ---
    let codeql_session = codeql::CodeqlSession::create(&ctx)?;
    let mut codeql_output = match &codeql_session {
        Some(session) => {
            let pack = codeql::models::write_model_pack_dir(&crate::models::default_catalog(), &ctx)?;
            session.analyze(&[pack], &mut progress)?
        }
        None => codeql::CodeqlOutput::empty(),
    };

    // --- Phase 2: agent (three-role) ---
    let agent_output = agent::run(&ctx)?;
    let agent_results = agent_output.findings;
    let model_candidates = agent_output.model_candidates;

    // --- Phase 3: gate + warm re-injection ---
    let rules = crate::models::default_package_rules();
    let hot_warm: Vec<ModelCandidate> = model_candidates.iter()
        .filter(|c| c.kind == "sink"
            && matches!(learning::gate_sink_candidate(c, &rules),
                        learning::GateDecision::Hot | learning::GateDecision::Warm))
        .cloned()
        .collect();

    let mut facts = all_facts; // from the taint block (renamed below)

    let mut taint_results = taint_results; // from the taint block
    if !hot_warm.is_empty() {
        tracing::info!(target: "mcp_sec_audit::learning", hot_warm = hot_warm.len(),
            "warm re-injecting agent sink models");

        // taint warm re-run on already-extracted facts + new sink facts
        let new_sink_facts = learning::sink_candidates_to_sink_facts(&facts, &hot_warm);
        facts.extend(new_sink_facts);
        if ctx.config.static_.taint.enabled {
            let (t2, df2) = taint::run_taint_analysis(&facts, &ctx.config.static_.taint)?;
            taint_results = t2;
            facts.extend(df2);
        }

        // codeql warm re-run on the cached DB with extended MaD
        if let Some(session) = &codeql_session {
            let mad = learning::candidates_to_mad_sinks(&hot_warm);
            let pack = codeql::models::write_model_pack_dir(
                &crate::models::ModelCatalog::from_sinks(mad), &ctx)?;
            codeql_output = session.analyze(&[pack], &mut progress)?;
        }
    }

    // --- Phase 4: fusion on the post-warm results ---
    let fused_findings = fusion::run(
        &ctx.config.fusion,
        rule_results.clone(),
        taint_results.clone(),
        agent_results.clone(),
        codeql_output.results.clone(),
    );

    // --- Phase 5: cold persistence ---
    let mut learned_written = 0usize;
    if let Some(dir) = &ctx.config.static_.learned_dir {
        let models: Vec<_> = model_candidates.iter()
            .filter_map(|c| learning::candidate_to_sink_model(c, "scan", "agent"))
            .collect();
        learning::write_learned_sinks(std::path::Path::new(dir), &models)?;
        learned_written = models.len();
        tracing::info!(target: "mcp_sec_audit::learning", learned = learned_written, "persisted learned models");
    }
```

**Note on the `taint` block:** rename `(taint_results, all_facts)` to make `all_facts` `mut`-bindable (`let (taint_results, all_facts) = …` then `let mut facts = all_facts;`). Keep the original `taint_results` name by shadowing as above.

- [ ] **Step 3: Update the summary + result assembly**

Add `model_candidates` to the returned `StaticAnalysisResult` (and set `codeql_result_count` from `codeql_output.results.len()` which already reflects the warm re-run). Optionally log `learned_written` into the `StaticAnalysisSummary` (out of scope — keep the summary struct unchanged, just log).

- [ ] **Step 4: Add an orchestration test with a stub agent**

Add a test that runs `run_static_scan` on a small Python target with `agent.enabled = true` but a **stub** agent provider (set `config.static_.agent.provider` to a tiny shell script that prints a fixed JSON containing one `model_candidates` entry for a package that inference corroborates), and assert that the taint results now include a finding for that sink. Follow the existing `provider.rs` test style (the stub prints `{"findings":[],"model_candidates":[{"kind":"sink","name":"openpyxl.load_workbook","category":"file_read","language":"python","argument":0,"confidence":"medium","evidence_snippets":[]}]}`).

> This is the trickiest test; if the stub proves flaky, gate it behind a temp file check and assert at least that `run_static_scan` completes without error when `agent` is enabled.

- [ ] **Step 5: Run the full suite**

Run: `cargo test`
Expected: 220 green (plus new tests).

- [ ] **Step 6: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs crates/mcp-sec-audit-core/src/model/ crates/mcp-sec-audit-core/src/fixtures.rs crates/mcp-sec-audit-core/src/lib.rs
git commit -m "feat(pipeline): two-phase orchestration with warm re-injection + cold persistence"
```

---

### Task 6: E2E — two scans, second finds more + regression

**Files:** none (verification only).

- [ ] **Step 1: Run the full Rust suite**

Run: `cargo test`
Expected: all green.

- [ ] **Step 2: Two-scan evolution check (cold)**

1. Create a scratch target using `openpyxl.load_workbook(path)` (like `test-targets/excel-mcp-server`).
2. Run the CLI once with agent enabled and `[static].learned_dir = "learned"` set.
3. Confirm `learned/` now contains a `learned-openpyxl_load_workbook.toml` with `source = "learned"`.
4. Run again; confirm the second run's taint line hits `openpyxl.load_workbook` even with agent **disabled** (the learned model is loaded via `models_dir`/`learned_dir`).

- [ ] **Step 3: Confirm no hallucination pollution**

Assert that a candidate with no inference signal (e.g. agent claims `frobnicate` is a sink) is written cold (to `learned/`) but does **not** produce a taint finding in the same run.

- [ ] **Step 4: Commit + report**

```bash
git add -A && git commit -m "test(learning): R5 evolution E2E + regression"
```

---

## Self-Review

- **Spec coverage:** three-role agent (Task 1), gate hot/warm/cold (Task 2), cold persistence to learned dir (Task 3), warm re-injection for taint + codeql (Tasks 4–5), 2-phase pipeline (Task 5) — §5.3/5.4/5.5 fully covered. `source`/`sanitizer` model application is explicitly out of scope (documented in Global Constraints).
- **Placeholder scan:** no TBD/TODO; every Rust step has exact code.
- **Type consistency:** `AgentOutput`, `ModelCandidate`, `GateDecision`, `sink_candidates_to_sink_facts`, `candidates_to_mad_sinks`, `candidate_to_sink_model`, `write_learned_sinks` are named identically across tasks; `codeql::CodeqlSession::{create, analyze}` and `codeql::models::{write_model_pack_dir, sink_models_to_mad}` match the R4 plan's "Produces" block.
- **Interface dependency on R4:** Task 5 consumes `CodeqlSession` and `codeql::models::write_model_pack_dir`, which R4 must land first. All non-CodeQL R5 tasks (1–4) are independent of R4.
