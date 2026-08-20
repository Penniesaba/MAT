//! Compile the shared sink model catalog into CodeQL MaD (Models as Data)
//! `sinkModel` extensions so standard queries reach third-party wrappers.

use std::path::PathBuf;

use anyhow::Result;

use crate::models::{ModelCatalog, SinkModel};
use crate::static_analysis::pipeline::StaticScanContext;

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

/// A compiled MaD model pack: a directory (passed via `--additional-packs`)
/// containing one library extension pack referenced by `name` (passed via
/// `--model-packs`).
pub(crate) struct MadPack {
    pub name: String,
    pub search_path: PathBuf,
}

/// Compile the catalog's Python and JavaScript sink models into a CodeQL MaD
/// model pack under a temp dir: the `.model.yml` files plus a `qlpack.yml`
/// that declares the extension targets. Languages with no models are skipped
/// (no empty `.model.yml` is written); `rust` is intentionally not a MaD
/// target today.
pub(crate) fn write_model_pack_dir(
    catalog: &ModelCatalog,
    _ctx: &StaticScanContext,
) -> Result<MadPack> {
    let dir = std::env::temp_dir().join(format!("mcp-sec-audit-mad-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    for language in ["python", "javascript"] {
        let models = catalog.sinks_for_language(language);
        if models.is_empty() {
            continue;
        }
        let yaml = render_mad_pack(models, language);
        let path = dir.join(format!("{language}.model.yml"));
        std::fs::write(&path, yaml)?;
    }
    // The pack must be a dependency-free library extension pack (CodeQL rejects
    // extension packs that declare `dependencies`). Target versions are pinned.
    let qlpack = r#"name: mcp-sec-audit-mad
version: 0.0.1
library: true
extensionTargets:
  codeql/python-all: "7.2.2"
  codeql/javascript-all: "2.8.2"
dataExtensions:
  - "*.model.yml"
"#;
    std::fs::write(dir.join("qlpack.yml"), qlpack)?;
    Ok(MadPack {
        name: "mcp-sec-audit-mad".into(),
        search_path: dir,
    })
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
            source: None,
            learned_from: None,
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

    #[test]
    fn write_model_pack_dir_writes_python_and_javascript_packs() {
        let catalog = crate::models::default_catalog();
        let ctx = StaticScanContext {
            config: crate::RuntimeConfig::default(),
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        let pack = write_model_pack_dir(&catalog, &ctx).expect("write model pack dir");
        assert_eq!(pack.name, "mcp-sec-audit-mad");
        let dir = pack.search_path;
        for language in ["python", "javascript"] {
            let path = dir.join(format!("{language}.model.yml"));
            let yaml = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {language}.model.yml: {e}"));
            assert!(
                yaml.contains("extensible: sinkModel"),
                "{language}.model.yml missing sinkModel"
            );
        }
        // Only python + javascript are MaD targets; rust must not be emitted.
        assert!(!dir.join("rust.model.yml").exists());
        // The model pack must be a dependency-free library extension pack that
        // declares its extension targets and data extensions.
        let qlpack = std::fs::read_to_string(dir.join("qlpack.yml")).expect("read qlpack.yml");
        assert!(qlpack.contains("library: true"), "qlpack.yml missing library: true");
        assert!(qlpack.contains("extensionTargets:"), "qlpack.yml missing extensionTargets");
        assert!(
            qlpack.contains("codeql/python-all: \"7.2.2\""),
            "qlpack.yml missing python-all target"
        );
        assert!(
            qlpack.contains("codeql/javascript-all: \"2.8.2\""),
            "qlpack.yml missing javascript-all target"
        );
        assert!(qlpack.contains("dataExtensions:"), "qlpack.yml missing dataExtensions");
        assert!(
            !qlpack.contains("dependencies:"),
            "qlpack.yml must not declare dependencies"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
