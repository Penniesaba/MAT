//! Cross-run evidence accumulation for learned models: corroboration raises
//! confidence (Low→Medium→High), pollution lowers it, and two pollutions (or
//! long inactivity) retire the model.

use crate::models::{SanitizerModel, SinkModel, SourceModel};
use crate::Confidence;

// consumed by Plan 3 evolution wiring
#[allow(dead_code)]
pub enum EvidenceKind { Corroborated, Polluted, Inactive }

// consumed by Plan 3 evolution wiring
#[allow(dead_code)]
fn bump_confidence(c: &Confidence, up: bool) -> Confidence {
    match (c, up) {
        (Confidence::Low, true) => Confidence::Medium,
        (Confidence::Medium, true) => Confidence::High,
        (Confidence::High, true) => Confidence::High,
        (Confidence::High, false) => Confidence::Medium,
        (Confidence::Medium, false) => Confidence::Low,
        (Confidence::Low, false) => Confidence::Low,
    }
}

// consumed by Plan 3 evolution wiring
#[allow(dead_code)]
pub fn apply_evidence(model: &mut SinkModel, kind: EvidenceKind) -> bool {
    match kind {
        EvidenceKind::Corroborated => {
            model.corroboration_count += 1;
            model.confidence = bump_confidence(&model.confidence, true);
            false
        }
        EvidenceKind::Polluted => {
            model.pollution_count += 1;
            model.confidence = bump_confidence(&model.confidence, false);
            model.pollution_count >= 2
        }
        EvidenceKind::Inactive => true, // long-unseen → retire (caller decides threshold)
    }
}

// consumed by Plan 3 evolution wiring
#[allow(dead_code)]
pub fn apply_evidence_source(model: &mut SourceModel, kind: EvidenceKind) -> bool {
    match kind {
        EvidenceKind::Corroborated => { model.corroboration_count += 1; false }
        EvidenceKind::Polluted => { model.pollution_count += 1; model.pollution_count >= 2 }
        EvidenceKind::Inactive => true,
    }
}

// consumed by Plan 3 evolution wiring
#[allow(dead_code)]
pub fn apply_evidence_sanitizer(model: &mut SanitizerModel, kind: EvidenceKind) -> bool {
    match kind {
        EvidenceKind::Corroborated => { model.corroboration_count += 1; false }
        EvidenceKind::Polluted => { model.pollution_count += 1; model.pollution_count >= 2 }
        EvidenceKind::Inactive => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{SinkModel, SourceModel, SanitizerModel};
    use crate::{Confidence, Severity};

    #[test]
    fn corroboration_upgrades_confidence_and_pollution_retires() {
        let mut m = SinkModel {
            language: "python".into(), category: "file_read".into(),
            severity: Severity::Medium, confidence: Confidence::Low,
            reason: "t".into(), patterns: vec!["x.read".into()],
            source: None, learned_from: None,
            corroboration_count: 0, pollution_count: 0, last_seen_run: None,
        };
        // 第一次 corroboration → medium, count=1
        assert!(!apply_evidence(&mut m, EvidenceKind::Corroborated));
        assert_eq!(m.corroboration_count, 1);
        assert_eq!(m.confidence, Confidence::Medium);
        // 第二次 corroboration → high, count=2
        assert!(!apply_evidence(&mut m, EvidenceKind::Corroborated));
        assert_eq!(m.corroboration_count, 2);
        assert_eq!(m.confidence, Confidence::High);
        // 一次污染 → 降级
        assert!(!apply_evidence(&mut m, EvidenceKind::Polluted));
        assert_eq!(m.pollution_count, 1);
        assert_eq!(m.confidence, Confidence::Medium);
        // 二次污染 → retire
        assert!(apply_evidence(&mut m, EvidenceKind::Polluted));
    }

    #[test]
    fn source_evidence_counts_and_retires_after_two_pollutions() {
        let mut m = SourceModel {
            language: "python".into(), category: "env_var".into(),
            patterns: vec!["os.environ".into()],
            source: Some("learned".into()), learned_from: Some("scan-1/agent".into()),
            corroboration_count: 0, pollution_count: 0, last_seen_run: Some("20260823".into()),
        };
        assert!(!apply_evidence_source(&mut m, EvidenceKind::Corroborated));
        assert_eq!(m.corroboration_count, 1);
        assert!(!apply_evidence_source(&mut m, EvidenceKind::Polluted));
        assert_eq!(m.pollution_count, 1);
        assert!(apply_evidence_source(&mut m, EvidenceKind::Polluted));
    }

    #[test]
    fn sanitizer_evidence_counts_and_retires_after_two_pollutions() {
        let mut m = SanitizerModel {
            language: "python".into(), patterns: vec!["shlex.quote".into()],
            neutralizes: vec!["command_execution".into()],
            source: Some("learned".into()), learned_from: Some("scan-1/agent".into()),
            corroboration_count: 0, pollution_count: 0, last_seen_run: None,
        };
        assert!(!apply_evidence_sanitizer(&mut m, EvidenceKind::Corroborated));
        assert_eq!(m.corroboration_count, 1);
        assert!(!apply_evidence_sanitizer(&mut m, EvidenceKind::Polluted));
        assert_eq!(m.pollution_count, 1);
        assert!(apply_evidence_sanitizer(&mut m, EvidenceKind::Polluted));
    }

    #[test]
    fn inactive_retires_all_three_model_kinds() {
        let mut sink = SinkModel {
            language: "python".into(), category: "file_read".into(),
            severity: Severity::Medium, confidence: Confidence::High,
            reason: "t".into(), patterns: vec!["x.read".into()],
            source: None, learned_from: None,
            corroboration_count: 0, pollution_count: 0, last_seen_run: None,
        };
        assert!(apply_evidence(&mut sink, EvidenceKind::Inactive));

        let mut src = SourceModel {
            language: "python".into(), category: "env_var".into(),
            patterns: vec!["os.environ".into()],
            source: None, learned_from: None,
            corroboration_count: 0, pollution_count: 0, last_seen_run: None,
        };
        assert!(apply_evidence_source(&mut src, EvidenceKind::Inactive));

        let mut san = SanitizerModel {
            language: "python".into(), patterns: vec!["shlex.quote".into()],
            neutralizes: vec!["command_execution".into()],
            source: None, learned_from: None,
            corroboration_count: 0, pollution_count: 0, last_seen_run: None,
        };
        assert!(apply_evidence_sanitizer(&mut san, EvidenceKind::Inactive));
    }

    #[test]
    fn corroboration_never_downgrades_and_pollution_never_upgrades_at_bounds() {
        let mut m = SinkModel {
            language: "python".into(), category: "file_read".into(),
            severity: Severity::Medium, confidence: Confidence::High,
            reason: "t".into(), patterns: vec!["x.read".into()],
            source: None, learned_from: None,
            corroboration_count: 0, pollution_count: 0, last_seen_run: None,
        };
        // 已是 High，再 corroboration 仍为 High（不降级）
        assert!(!apply_evidence(&mut m, EvidenceKind::Corroborated));
        assert_eq!(m.confidence, Confidence::High);
        // 已是 Low，pollution 仍为 Low（不升级）
        m.confidence = Confidence::Low;
        m.pollution_count = 0;
        assert!(!apply_evidence(&mut m, EvidenceKind::Polluted));
        assert_eq!(m.confidence, Confidence::Low);
    }
}
