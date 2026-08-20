//! Gate for classifying agent-proposed sink candidates against cheap
//! semantic-inference heuristics.

use std::path::Path;

use crate::model::{Confidence, Fact, FactBase, ModelCandidate, Severity, SinkFact};
use crate::models::{rule_prefix, PackageRule, SinkModel};

use super::infer::{language_from_file, name_category};

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
    let package_agrees = split_module_function(&candidate.name).is_some_and(|(module, _)| {
        rules.iter().any(|r| {
            r.language == candidate.language
                && r.package == module
                && (r.category.as_deref() == Some(candidate.category.as_str())
                    || r.read_category.as_deref() == Some(candidate.category.as_str())
                    || r.write_category.as_deref() == Some(candidate.category.as_str()))
        })
    });
    if package_agrees {
        return GateDecision::Hot;
    }
    if name_category(&candidate.name) == Some(candidate.category.as_str()) {
        return GateDecision::Warm;
    }
    GateDecision::Cold
}

/// Match agent-proposed sink candidates against already-extracted call facts
/// and produce `Sink` facts for the matching calls (warm re-injection).
pub fn sink_candidates_to_sink_facts(facts: &[Fact], candidates: &[ModelCandidate]) -> Vec<Fact> {
    let mut out = Vec::new();
    for fact in facts {
        let Fact::Call(call) = fact else { continue };
        let callee = call.normalized_callee.as_deref().unwrap_or(&call.callee);
        for c in candidates {
            if c.kind != "sink" { continue; }
            if language_from_file(&call.base.file) != c.language { continue; }
            // Unqualified method names are too low-specificity to re-inject.
            if !c.name.contains('.') && !c.name.contains("::") { continue; }
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
    out
}

/// Convert sink candidates to `SinkModel`s so R4's MaD compiler can turn them
/// into CodeQL model packs for the warm CodeQL re-run.
// Deferred until CodeQL CLI ≥ 2.26.3 (R4 RULING 11: --model-packs broken under 2.26.2). Not wired by the pipeline.
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, ModelCandidate};
    use crate::models::default_package_rules;

    fn cand(name: &str, category: &str) -> ModelCandidate {
        cand_lang(name, category, "python")
    }

    fn cand_lang(name: &str, category: &str, language: &str) -> ModelCandidate {
        ModelCandidate {
            kind: "sink".into(),
            name: name.into(),
            category: category.into(),
            language: language.into(),
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

    fn call_fact(id: &str, callee: &str) -> Fact {
        use crate::model::{CallArg, CallFact};
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

    #[test]
    fn wrong_language_candidate_is_not_reinjected() {
        // A "rust" candidate must not match a Python (`s.py`) call.
        let facts = vec![call_fact("call:1", "foo.read")];
        let cands = vec![cand_lang("foo.read", "file_read", "rust")];
        let new = sink_candidates_to_sink_facts(&facts, &cands);
        assert!(new.is_empty(), "expected no re-injection across languages");
    }

    #[test]
    fn bare_name_candidate_is_not_reinjected() {
        // A bare, unqualified method name is too low-specificity to re-inject.
        let facts = vec![call_fact("call:1", "threading.Thread.run")];
        let cands = vec![cand("run", "command_execution")];
        let new = sink_candidates_to_sink_facts(&facts, &cands);
        assert!(new.is_empty(), "expected no re-injection for a bare method name");
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
}
