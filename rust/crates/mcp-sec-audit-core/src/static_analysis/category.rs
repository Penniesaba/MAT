//! Canonical vulnerability-category vocabulary shared across the rule, taint,
//! and CodeQL analysis lines.
//!
//! Each line reports categories in its own vocabulary (rulebook names, sink
//! `category` fields, CodeQL `rule_id` maps). Fusion compares categories by
//! exact string, so a `command_exec` rule finding and a `command_execution`
//! taint finding would never corroborate. [`normalize_category`] collapses
//! that drift to one shared vocabulary before any comparison or vote.

/// The canonical category set (snake_case), the union of all line vocabularies.
pub(crate) const CANONICAL_CATEGORIES: &[&str] = &[
    "command_execution",
    "dynamic_execution",
    "database_injection",
    "file_read",
    "file_write",
    "file_delete",
    "network_request",
    "deserialization",
    "template_injection",
    "path_traversal",
    "prompt_injection",
    "data_exfiltration",
    "tool_poisoning",
    "unsafe_block",
    "env_access",
    "xml_parsing",
    "xpath_injection",
];

/// Resolve a normalized category to its canonical form if it is a known
/// synonym of one. Returns `None` for already-canonical or unknown categories
/// so free-form names are preserved rather than collapsed.
fn alias_map(normalized: &str) -> Option<&'static str> {
    Some(match normalized {
        "command_exec" | "cmd_inj" | "cmd_injection" | "command_injection" | "shell_exec"
        | "shell_injection" => "command_execution",
        "code_injection" | "dynamic_import" | "dynamic_loading" | "eval" => "dynamic_execution",
        "sql_injection" | "sqli" => "database_injection",
        "ssrf" => "network_request",
        "path_injection" => "path_traversal",
        "deserialization_rce" => "deserialization",
        _ => return None,
    })
}

/// Normalize a raw category to the shared vocabulary: trim, lowercase, fold
/// `-`/spaces to `_`, then resolve known synonyms. Unknown categories are
/// returned as-is (normalized) so identical free-form names still match.
pub(crate) fn normalize_category(raw: &str) -> String {
    let normalized: String = raw.trim().to_lowercase().replace(['-', ' '], "_");
    alias_map(&normalized)
        .map(str::to_string)
        .unwrap_or(normalized)
}

/// Whether `raw` normalizes to a member of [`CANONICAL_CATEGORIES`].
pub(crate) fn is_known_category(raw: &str) -> bool {
    let normalized = normalize_category(raw);
    CANONICAL_CATEGORIES.contains(&normalized.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_maps_aliases_to_canonical() {
        assert_eq!(normalize_category("command_exec"), "command_execution");
        assert_eq!(normalize_category("cmd_inj"), "command_execution");
        assert_eq!(normalize_category("command-injection"), "command_execution");
        assert_eq!(normalize_category("sql_injection"), "database_injection");
        assert_eq!(normalize_category("ssrf"), "network_request");
        assert_eq!(normalize_category("path_injection"), "path_traversal");
        assert_eq!(normalize_category("deserialization_rce"), "deserialization");
        assert_eq!(normalize_category("code_injection"), "dynamic_execution");
        assert_eq!(normalize_category("dynamic_import"), "dynamic_execution");
    }

    #[test]
    fn normalize_preserves_unknown_and_canonical() {
        assert_eq!(normalize_category("command_execution"), "command_execution");
        assert_eq!(normalize_category("file_read"), "file_read");
        // Unknown free-form names survive (not collapsed to "uncategorized").
        assert_eq!(normalize_category("MyCustom Rule"), "mycustom_rule");
    }

    #[test]
    fn known_category_detection() {
        assert!(is_known_category("command_exec")); // alias of canonical
        assert!(is_known_category("file_write"));
        assert!(!is_known_category("bogus_category"));
    }
}
