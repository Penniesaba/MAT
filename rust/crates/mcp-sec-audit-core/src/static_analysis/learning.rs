//! Gate for classifying agent-proposed sink candidates against cheap
//! semantic-inference heuristics.

use crate::model::ModelCandidate;
use crate::models::PackageRule;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, ModelCandidate};
    use crate::models::default_package_rules;

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
