use crate::model::{Confidence, Severity};

// ---------------------------------------------------------------------------
// Sink classification for Rust APIs
// ---------------------------------------------------------------------------

pub(crate) struct SinkRule {
    pub patterns: &'static [&'static str],
    pub category: &'static str,
    pub rule_id: &'static str,
    pub severity: Severity,
    pub reason: &'static str,
    pub confidence: Confidence,
}

pub(crate) static SINK_RULES: &[SinkRule] = &[
    SinkRule {
        patterns: &[
            "std::process::Command",
            "Command::new",
            "Command::output",
            "Command::spawn",
            "std::process::Command::new",
        ],
        category: "command_execution",
        rule_id: "rust.command_execution",
        severity: Severity::High,
        reason: "Executes external commands via std::process::Command",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &[
            "std::fs::read",
            "std::fs::read_to_string",
            "std::fs::File::open",
            "File::open",
        ],
        category: "file_read",
        rule_id: "rust.file_read",
        severity: Severity::Medium,
        reason: "File read access can leak sensitive data",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &[
            "std::fs::write",
            "std::fs::File::create",
            "File::create",
            "std::io::Write::write",
            "std::io::Write::write_all",
        ],
        category: "file_write",
        rule_id: "rust.file_write",
        severity: Severity::Medium,
        reason: "File write can modify filesystem contents",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &[
            "std::net::TcpStream::connect",
            "TcpStream::connect",
            "std::os::unix::net::UnixStream::connect",
            "reqwest::get",
            "reqwest::blocking::get",
            "reqwest::Client::new",
            "hyper::client",
            "ureq::get",
        ],
        category: "network_request",
        rule_id: "rust.network_request",
        severity: Severity::Medium,
        reason: "Network request can reach attacker-controlled URLs (SSRF)",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &[
            "std::env::var",
            "std::env::var_os",
            "std::env::vars",
            "std::env::vars_os",
        ],
        category: "credential_leak",
        rule_id: "rust.credential_leak",
        severity: Severity::High,
        reason: "Access to environment variables can leak credentials",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &[
            "serde_json::from_str",
            "serde_json::from_slice",
            "serde_json::from_reader",
            "serde_yaml::from_str",
        ],
        category: "deserialization",
        rule_id: "rust.deserialization",
        severity: Severity::Medium,
        reason: "Deserialization of untrusted input can cause type-confusion or RCE",
        confidence: Confidence::High,
    },
    SinkRule {
        patterns: &["libloading::Library::new", "dlopen", "libc::dlopen"],
        category: "dynamic_loading",
        rule_id: "rust.dynamic_loading",
        severity: Severity::High,
        reason: "Dynamic library loading can execute attacker-controlled code",
        confidence: Confidence::High,
    },
];

pub(crate) fn matches_sink(callee: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| {
        callee == *pattern
            || callee.ends_with(&format!("::{pattern}"))
            || callee.starts_with(&format!("{pattern}::"))
            || callee.starts_with(&format!("{pattern}<"))
    })
}
