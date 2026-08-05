use crate::model::{CallFact, Confidence, Severity};

#[derive(Debug, Clone)]
pub(crate) struct SinkClassification {
    pub category: &'static str,
    pub severity: Severity,
    pub reason: &'static str,
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

pub(crate) fn classify_sink(callee: &str, call: &CallFact) -> Option<SinkClassification> {
    match callee {
        "subprocess.run" | "subprocess.Popen" | "os.system" | "os.popen" => {
            Some(SinkClassification {
                category: "command_execution",
                severity: Severity::High,
                reason: "Python command execution call can execute attacker-controlled commands",
                confidence: Confidence::High,
            })
        }
        "Path.write_text" | "Path.write_bytes" => Some(SinkClassification {
            category: "file_write",
            severity: Severity::Medium,
            reason: "Python file write call can modify filesystem contents",
            confidence: Confidence::High,
        }),
        "open" if open_call_writes(call) => Some(SinkClassification {
            category: "file_write",
            severity: Severity::Medium,
            reason: "Python open call uses a write-capable file mode",
            confidence: Confidence::High,
        }),
        "eval" | "exec" => Some(SinkClassification {
            category: "dynamic_execution",
            severity: Severity::Critical,
            reason: "Python dynamic execution call can execute attacker-controlled code",
            confidence: Confidence::High,
        }),
        "requests.get"
        | "requests.post"
        | "requests.request"
        | "httpx.get"
        | "httpx.post"
        | "httpx.request"
        | "urllib.request.urlopen" => Some(SinkClassification {
            category: "network_request",
            severity: Severity::Medium,
            reason: "Python network request call can reach attacker-controlled URLs",
            confidence: Confidence::Medium,
        }),
        "importlib.import_module" | "__import__" => Some(SinkClassification {
            category: "dynamic_import",
            severity: Severity::Medium,
            reason: "Python dynamic import call can load attacker-controlled modules",
            confidence: Confidence::Medium,
        }),
        _ => None,
    }
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
