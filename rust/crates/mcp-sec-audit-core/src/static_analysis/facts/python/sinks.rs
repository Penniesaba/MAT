use crate::model::{CallFact, Confidence, Severity};

#[derive(Debug, Clone)]
pub(crate) struct SinkClassification {
    pub category: &'static str,
    pub severity: Severity,
    pub reason: &'static str,
    pub confidence: Confidence,
}

/// A table-driven sink rule. `patterns` are matched against the (normalized)
/// callee name using exact, `.suffix`, and `prefix.` matching.
struct SinkRule {
    patterns: &'static [&'static str],
    category: &'static str,
    severity: Severity,
    reason: &'static str,
    confidence: Confidence,
}

/// Non-mode-sensitive sinks. The `open` builtin and `Path.open` method are
/// mode-sensitive (read vs write) and handled separately in `classify_sink`.
static SINK_RULES: &[SinkRule] = &[
    SinkRule {
        patterns: &[
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "os.system",
            "os.popen",
            "os.execl",
            "os.execle",
            "os.execlp",
            "os.execv",
            "os.execve",
            "os.execvp",
            "os.execvpe",
            "os.spawnl",
            "os.spawnlp",
            "os.spawnv",
            "os.spawnvp",
            "os.spawnve",
            "os.spawnvpe",
        ],
        category: "command_execution",
        severity: Severity::High,
        reason: "Python command execution call can execute attacker-controlled commands",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &["eval", "exec", "compile"],
        category: "dynamic_execution",
        severity: Severity::Critical,
        reason: "Python dynamic execution call can execute attacker-controlled code",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &[
            "importlib.import_module",
            "__import__",
            "importlib.util.spec_from_file_location",
            "importlib.machinery.SourceFileLoader",
        ],
        category: "dynamic_import",
        severity: Severity::Medium,
        reason: "Python dynamic import call can load attacker-controlled modules",
        confidence: Confidence::Medium,
    },
    SinkRule {
        patterns: &["Path.read_text", "Path.read_bytes", "read_text", "read_bytes"],
        category: "file_read",
        severity: Severity::Medium,
        reason: "Python file read call can leak sensitive data from attacker-controlled paths",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &["Path.write_text", "Path.write_bytes", "write_text", "write_bytes"],
        category: "file_write",
        severity: Severity::Medium,
        reason: "Python file write call can modify filesystem contents",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &[
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "requests.patch",
            "requests.head",
            "requests.request",
            "httpx.get",
            "httpx.post",
            "httpx.put",
            "httpx.delete",
            "httpx.request",
            "urllib.request.urlopen",
            "urllib.request.urlretrieve",
            "urllib.request.Request",
            "aiohttp.ClientSession.get",
            "aiohttp.ClientSession.post",
            "aiohttp.ClientSession.request",
            "socket.create_connection",
        ],
        category: "network_request",
        severity: Severity::Medium,
        reason: "Python network request call can reach attacker-controlled URLs (SSRF)",
        confidence: Confidence::Medium,
    },
    SinkRule {
        patterns: &[
            "pickle.load",
            "pickle.loads",
            "cPickle.load",
            "cPickle.loads",
            "yaml.load",
            "yaml.unsafe_load",
            "marshal.loads",
            "dill.load",
            "dill.loads",
        ],
        category: "deserialization",
        severity: Severity::Critical,
        reason: "Deserializing untrusted input can cause arbitrary code execution",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &[
            "execute",
            "executemany",
            "executescript",
            "sqlite3",
            "pymysql",
            "psycopg2",
            "MySQLdb",
            "sqlalchemy.text",
            "sqlalchemy.execute",
        ],
        category: "database_injection",
        severity: Severity::Critical,
        reason: "Database query may be vulnerable to SQL injection",
        confidence: Confidence::Medium,
    },
    SinkRule {
        patterns: &[
            "render_template_string",
            "jinja2.Template",
            "jinja2.Environment.from_string",
            "Template.render",
            "Template.from_string",
        ],
        category: "template_injection",
        severity: Severity::Critical,
        reason: "Template rendering can execute attacker-controlled code (SSTI)",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &[
            "lxml.etree.parse",
            "lxml.etree.fromstring",
            "lxml.etree.XML",
            "xml.etree.ElementTree.parse",
            "xml.etree.ElementTree.fromstring",
            "ElementTree.parse",
            "ElementTree.fromstring",
            "xml.sax.parse",
        ],
        category: "xml_parsing",
        severity: Severity::Medium,
        reason: "XML parsing can be vulnerable to XXE or billion-laughs attacks",
        confidence: Confidence::Medium,
    },
    SinkRule {
        patterns: &[
            "lxml.etree.XPath",
            "ElementTree.Element.find",
            "Element.findall",
            "Element.xpath",
        ],
        category: "xpath_injection",
        severity: Severity::Medium,
        reason: "XPath query built from untrusted input can be vulnerable to injection",
        confidence: Confidence::Medium,
    },
    SinkRule {
        patterns: &[
            "os.remove",
            "os.unlink",
            "os.rmdir",
            "shutil.rmtree",
            "Path.unlink",
            "Path.rmdir",
        ],
        category: "file_delete",
        severity: Severity::Medium,
        reason: "File deletion can remove attacker-controlled paths",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &["os.environ", "os.getenv", "os.putenv"],
        category: "env_access",
        severity: Severity::High,
        reason: "Environment variable access can leak credentials",
        confidence: Confidence::High,
    },
];

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
    // Mode-sensitive: `open()` builtin, `Path.open`, and other `.open` methods.
    // Classify by file mode so read and write are split into distinct categories.
    if is_open_callee(callee) {
        return if open_call_writes(call) {
            Some(SinkClassification {
                category: "file_write",
                severity: Severity::Medium,
                reason: "Python open call uses a write-capable file mode",
                confidence: Confidence::High,
            })
        } else {
            Some(SinkClassification {
                category: "file_read",
                severity: Severity::Medium,
                reason: "Python open call reads a file path that may be attacker-controlled (path traversal)",
                confidence: Confidence::High,
            })
        };
    }

    for rule in SINK_RULES {
        if matches_sink(callee, rule.patterns) {
            return Some(SinkClassification {
                category: rule.category,
                severity: rule.severity.clone(),
                reason: rule.reason,
                confidence: rule.confidence.clone(),
            });
        }
    }

    None
}

fn matches_sink(callee: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| {
        callee == *pattern
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
