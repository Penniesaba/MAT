use crate::model::{CallFact, Confidence, Severity};
use crate::models::SinkModel;

#[derive(Debug, Clone)]
pub(crate) struct SinkClassification {
    pub category: String,
    pub severity: Severity,
    pub reason: String,
    pub confidence: Confidence,
}

pub(crate) fn canonical_sink_name(callee: &str) -> String {
    if let Some(prefix) = callee.strip_suffix(".write_text") {
        if prefix == "Path" || prefix.ends_with(".Path") || prefix.ends_with("(...)") {
            return "Path.write_text".to_string();
        }
    }
    if let Some(prefix) = callee.strip_suffix(".write_bytes") {
        if prefix == "Path" || prefix.ends_with(".Path") || prefix.ends_with("(...)") {
            return "Path.write_bytes".to_string();
        }
    }
    callee.to_string()
}

pub(crate) fn classify_sink(
    callee: &str,
    call: &CallFact,
    sinks: &[SinkModel],
) -> Option<SinkClassification> {
    // Mode-sensitive: `open()` builtin, `Path.open`, and other `.open` methods.
    // Classify by file mode so read and write are split into distinct categories.
    if is_open_callee(callee) {
        return if open_call_writes(call) {
            Some(SinkClassification {
                category: "file_write".to_string(),
                severity: Severity::Medium,
                reason: "Python open call uses a write-capable file mode".to_string(),
                confidence: Confidence::High,
            })
        } else {
            Some(SinkClassification {
                category: "file_read".to_string(),
                severity: Severity::Medium,
                reason: "Python open call reads a file path that may be attacker-controlled (path traversal)"
                    .to_string(),
                confidence: Confidence::High,
            })
        };
    }

    for model in sinks {
        if matches_sink(callee, &model.patterns) {
            return Some(SinkClassification {
                category: model.category.clone(),
                severity: model.severity.clone(),
                reason: model.reason.clone(),
                confidence: model.confidence.clone(),
            });
        }
    }

    None
}

fn matches_sink(callee: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        callee == pattern
            || callee.ends_with(&format!(".{pattern}"))
            || callee.starts_with(&format!("{pattern}."))
    })
}

fn is_open_callee(callee: &str) -> bool {
    callee == "open" || callee == "builtins.open" || callee.ends_with(".open")
}

fn open_call_writes(call: &CallFact) -> bool {
    if let Some(mode) = call.kwargs.get("mode") {
        return file_mode_writes(&mode.expr);
    }
    call.args
        .get(1)
        .map(|arg| file_mode_writes(&arg.expr))
        .unwrap_or(false)
}

fn file_mode_writes(mode: &str) -> bool {
    let trimmed = mode.trim_matches(|ch| ch == '\'' || ch == '"');
    trimmed.contains('w') || trimmed.contains('a') || trimmed.contains('x') || trimmed.contains('+')
}
