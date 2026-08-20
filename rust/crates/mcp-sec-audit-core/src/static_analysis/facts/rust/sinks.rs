//! Sink matching for Rust APIs. Sink models are loaded from the model catalog
//! (`models/sinks/rust.yaml`); this module only owns the Rust-specific `::`
//! separator matching.

pub(crate) fn matches_sink(callee: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        callee == pattern
            || callee.ends_with(&format!("::{pattern}"))
            || callee.starts_with(&format!("{pattern}::"))
            || callee.starts_with(&format!("{pattern}<"))
            // Flattened method chains render `receiver.method(...)` as
            // `std::fs::write(...).map_err`, so the sink's base callee is
            // followed by `(` rather than `::`.
            || callee.starts_with(&format!("{pattern}("))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::default_catalog;
    use crate::Severity;

    fn category_for(callee: &str) -> Option<String> {
        default_catalog()
            .sinks_for_language("rust")
            .iter()
            .find(|m| matches_sink(callee, &m.patterns))
            .map(|m| m.category.clone())
    }

    #[test]
    fn classifies_extended_rust_sinks() {
        assert_eq!(category_for("std::process::Command::new").as_deref(), Some("command_execution"));
        assert_eq!(category_for("std::fs::File::open").as_deref(), Some("file_read"));
        assert_eq!(category_for("std::fs::remove_file").as_deref(), Some("file_delete"));
        assert_eq!(category_for("std::env::var").as_deref(), Some("env_access"));
        assert_eq!(category_for("reqwest::get").as_deref(), Some("network_request"));
        assert_eq!(category_for("rusqlite::Connection::execute").as_deref(), Some("database_injection"));
        assert_eq!(category_for("sqlx::query").as_deref(), Some("database_injection"));
        assert_eq!(category_for("tera::Tera::render").as_deref(), Some("template_injection"));
        assert_eq!(category_for("serde_json::from_str").as_deref(), Some("deserialization"));
        assert_eq!(category_for("libloading::Library::new").as_deref(), Some("dynamic_loading"));
    }

    #[test]
    fn deserialization_reasons_split_by_library() {
        let rust = default_catalog().sinks_for_language("rust").to_vec();
        let serde = rust
            .iter()
            .find(|m| matches_sink("serde_json::from_str", &m.patterns))
            .expect("serde_json::from_str sink");
        assert_eq!(serde.severity, Severity::Medium);
        assert!(serde.reason.contains("memory-safe"), "reason was: {}", serde.reason);

        let bincode = rust
            .iter()
            .find(|m| matches_sink("bincode::deserialize", &m.patterns))
            .expect("bincode::deserialize sink");
        assert_eq!(bincode.severity, Severity::High);
        assert!(bincode.reason.contains("RCE"), "reason was: {}", bincode.reason);
    }
}
