use std::collections::BTreeMap;

use crate::model::{Confidence, Fact, FactBase, Severity, SinkFact};

struct SinkRule {
    patterns: &'static [&'static str],
    category: &'static str,
    rule_id: &'static str,
    severity: Severity,
    reason: &'static str,
}

static SINK_RULES: &[SinkRule] = &[
    SinkRule {
        patterns: &["child_process.exec", "child_process.execSync", "child_process.spawn",
                     "child_process.spawnSync", "child_process.execFile", "child_process.fork"],
        category: "command_execution",
        rule_id: "js.command_execution",
        severity: Severity::High,
        reason: "Executes external commands via child_process",
    },
    SinkRule {
        patterns: &["eval", "new Function", "Function"],
        category: "dynamic_execution",
        rule_id: "js.dynamic_execution",
        severity: Severity::Critical,
        reason: "Dynamic code execution can run attacker-controlled code",
    },
    SinkRule {
        patterns: &["fs.readFile", "fs.readFileSync", "fs.createReadStream",
                     "fs.promises.readFile"],
        category: "file_read",
        rule_id: "js.file_read",
        severity: Severity::Medium,
        reason: "File read access can leak sensitive data",
    },
    SinkRule {
        patterns: &["fs.writeFile", "fs.writeFileSync", "fs.createWriteStream",
                     "fs.promises.writeFile"],
        category: "file_write",
        rule_id: "js.file_write",
        severity: Severity::Medium,
        reason: "File write can modify filesystem contents",
    },
    SinkRule {
        patterns: &["http.request", "https.request", "fetch", "net.connect", "axios"],
        category: "network_request",
        rule_id: "js.network_request",
        severity: Severity::Medium,
        reason: "Network request can reach attacker-controlled URLs (SSRF)",
    },
    SinkRule {
        patterns: &["process.env"],
        category: "credential_leak",
        rule_id: "js.credential_leak",
        severity: Severity::High,
        reason: "Access to environment variables can leak credentials",
    },
    SinkRule {
        patterns: &["connection.query", "connection.execute", "db.run", "Model.find",
                     "mysql.createConnection", "mysql.createPool", "mysql.query",
                     "mongoose.Model", "mongoose.Query.prototype.exec"],
        category: "database_injection",
        rule_id: "js.database_injection",
        severity: Severity::Critical,
        reason: "Database query may be vulnerable to injection",
    },
    SinkRule {
        patterns: &["vm.runInNewContext", "vm.Script", "new WebAssembly.Module"],
        category: "deserialization_rce",
        rule_id: "js.deserialization_rce",
        severity: Severity::Critical,
        reason: "Deserialization/vm execution can run attacker-controlled code",
    },
];

pub(crate) fn check_sink(
    normalized_callee: &str,
    call_id: &str,
    line: u32,
    file: &str,
    extractor_name: &str,
    facts: &mut Vec<Fact>,
) {
    for rule in SINK_RULES {
        if matches_sink(normalized_callee, rule.patterns) {
            facts.push(Fact::Sink(SinkFact {
                base: FactBase {
                    id: format!("sink:{}:{}:{}", rule.category, file, line),
                    file: file.to_string(),
                    line,
                    extractor: extractor_name.to_string(),
                },
                call_id: call_id.to_string(),
                category: rule.category.to_string(),
                rule_id: rule.rule_id.to_string(),
                sink_name: normalized_callee.to_string(),
                severity_base: rule.severity.clone(),
                reason: rule.reason.to_string(),
                conditions: BTreeMap::new(),
                confidence: Confidence::High,
            }));
            return;
        }
    }
}

fn matches_sink(callee: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| {
        callee == *pattern
            || callee.ends_with(&format!(".{pattern}"))
            || callee.starts_with(&format!("{pattern}."))
    })
}
