//! Compile the shared sink model catalog into CodeQL MaD (Models as Data)
//! `sinkModel` extensions so standard queries reach third-party wrappers.

use crate::models::SinkModel;

/// One MaD sink entry in the 3-tuple format `[module, path, kind]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MadSinkEntry {
    pub module: String,
    pub path: String,
    pub kind: String,
}

/// Map a canonical category to a CodeQL MaD sink kind, or `None` when no
/// standard query consumes that category via `sinkModel`.
pub fn mad_sink_kind(category: &str) -> Option<&'static str> {
    match category {
        "command_execution" => Some("command-injection"),
        "dynamic_execution" => Some("code-injection"),
        "database_injection" => Some("sql-injection"),
        "network_request" => Some("request-forgery"),
        "file_read" | "file_write" | "file_delete" | "path_traversal" => Some("path-injection"),
        "template_injection" => Some("template injection"),
        "prompt_injection" => Some("prompt-injection"),
        _ => None,
    }
}

/// Split a callee pattern into `(module, function)` for MaD. Patterns that are
/// not a plain `module.function` (single segment like `eval`, or `new X`) are
/// skipped because they have no module prefix to hang the model on.
fn split_module_function(pattern: &str) -> Option<(&str, &str)> {
    if let Some((module, function)) = pattern.rsplit_once('.') {
        if module.is_empty() || function.is_empty() || function.contains(' ') {
            return None;
        }
        Some((module, function))
    } else {
        None
    }
}

/// Compile a list of sink models into MaD entries, skipping models with no
/// standard sink kind or with an un-splittable pattern.
pub fn sink_models_to_mad(models: &[SinkModel]) -> Vec<MadSinkEntry> {
    let mut out = Vec::new();
    for model in models {
        let Some(kind) = mad_sink_kind(&model.category) else {
            continue;
        };
        for pattern in &model.patterns {
            if let Some((module, function)) = split_module_function(pattern) {
                out.push(MadSinkEntry {
                    module: module.to_string(),
                    path: format!("Member[{function}].Argument[0]"),
                    kind: kind.to_string(),
                });
            }
        }
    }
    out
}

/// Render a full MaD model-pack extension file for one language.
pub fn render_mad_pack(models: &[SinkModel], language: &str) -> String {
    let pack = match language {
        "javascript" | "typescript" => "codeql/javascript-all",
        _ => "codeql/python-all",
    };
    let mut body = String::from("extensions:\n  - addsTo:\n");
    body.push_str(&format!("      pack: {pack}\n"));
    body.push_str("      extensible: sinkModel\n    data:\n");
    for entry in sink_models_to_mad(models) {
        body.push_str(&format!(
            "      - [\"{}\", \"{}\", \"{}\"]\n",
            entry.module, entry.path, entry.kind
        ));
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SinkModel;
    use crate::{Confidence, Severity};

    fn model(category: &str, patterns: &[&str]) -> SinkModel {
        SinkModel {
            language: "python".into(),
            category: category.into(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            reason: "t".into(),
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn maps_categories_to_mad_kinds() {
        assert_eq!(mad_sink_kind("command_execution"), Some("command-injection"));
        assert_eq!(mad_sink_kind("dynamic_execution"), Some("code-injection"));
        assert_eq!(mad_sink_kind("database_injection"), Some("sql-injection"));
        assert_eq!(mad_sink_kind("network_request"), Some("request-forgery"));
        assert_eq!(mad_sink_kind("file_read"), Some("path-injection"));
        assert_eq!(mad_sink_kind("template_injection"), Some("template injection"));
        assert_eq!(mad_sink_kind("deserialization"), None);
        assert_eq!(mad_sink_kind("env_access"), None);
    }

    #[test]
    fn module_function_pattern_becomes_mad_entry() {
        let models = vec![model("file_read", &["openpyxl.load_workbook"])];
        let entries = sink_models_to_mad(&models);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].module, "openpyxl");
        assert_eq!(entries[0].path, "Member[load_workbook].Argument[0]");
        assert_eq!(entries[0].kind, "path-injection");
    }

    #[test]
    fn single_segment_patterns_are_skipped() {
        // eval/exec are builtins with no module prefix — not MaD-representable.
        let models = vec![model("dynamic_execution", &["eval", "exec"])];
        assert!(sink_models_to_mad(&models).is_empty());
    }

    #[test]
    fn render_mad_pack_emits_sink_model_extension() {
        let models = vec![model("command_execution", &["os.system"])];
        let yaml = render_mad_pack(&models, "python");
        assert!(yaml.contains("extensible: sinkModel"));
        assert!(yaml.contains("codeql/python-all"));
        assert!(yaml.contains("- [\"os\", \"Member[system].Argument[0]\", \"command-injection\"]"));
    }
}
