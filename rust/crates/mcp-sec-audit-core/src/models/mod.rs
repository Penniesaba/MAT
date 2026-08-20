use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{Confidence, Severity};

/// A single sink model in the shared, language-agnostic schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SinkModel {
    /// Language key: "python" | "javascript" | "rust" (javascript covers TS).
    pub language: String,
    /// Canonical category (snake_case), e.g. "command_execution".
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub reason: String,
    /// Callee patterns matched with the language's separator rules.
    pub patterns: Vec<String>,
    /// "manual" | "package" | "learned" — `None` treated as manual.
    #[serde(default)]
    pub source: Option<String>,
    /// Provenance for learned models: "scan-id/agent-id".
    #[serde(default)]
    pub learned_from: Option<String>,
}

impl SinkModel {
    /// Derived rule_id: `{prefix}.{category}` ("python"/"rust"/"js").
    pub fn rule_id(&self) -> String {
        format!("{}.{}", rule_prefix(&self.language), self.category)
    }
}

pub(crate) fn rule_prefix(language: &str) -> &'static str {
    match language {
        "python" => "python",
        "rust" => "rust",
        _ => "js", // javascript + typescript
    }
}

/// A package → dangerous-category classification rule for semantic inference.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PackageRule {
    pub language: String,
    pub package: String,
    /// Whole package is this category (e.g. subprocess → command_execution).
    #[serde(default)]
    pub category: Option<String>,
    /// Read methods (load*/read*/open*) are this category (file I/O split).
    #[serde(default)]
    pub read_category: Option<String>,
    /// Write methods (save*/write*/dump*/to_*) are this category (file I/O split).
    #[serde(default)]
    pub write_category: Option<String>,
}

/// All sink models, grouped by language key.
#[derive(Debug, Clone, Default)]
pub struct ModelCatalog {
    sinks: BTreeMap<String, Vec<SinkModel>>,
}

impl ModelCatalog {
    /// Build a catalog by grouping a flat model list by `language`.
    pub fn from_sinks(models: Vec<SinkModel>) -> Self {
        let mut sinks: BTreeMap<String, Vec<SinkModel>> = BTreeMap::new();
        for model in models {
            sinks.entry(model.language.clone()).or_default().push(model);
        }
        Self { sinks }
    }

    /// Models for a language key ("python" | "javascript" | "rust"), or `[]`.
    pub fn sinks_for_language(&self, language: &str) -> &[SinkModel] {
        self.sinks
            .get(language)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Append another catalog's models (user/learned models are tried after
    /// the built-in models, preserving first-match-wins for built-ins).
    pub fn merge(&mut self, other: ModelCatalog) {
        for (lang, models) in other.sinks {
            self.sinks.entry(lang).or_default().extend(models);
        }
    }

    /// Total number of sink models across all languages.
    pub fn sink_count(&self) -> usize {
        self.sinks.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.values().all(Vec::is_empty)
    }
}

/// Parse a TOML document of sink models (a `[[sinks]]` array of tables).
pub fn parse_sinks(toml_str: &str) -> Result<Vec<SinkModel>> {
    #[derive(Deserialize)]
    struct SinkFile {
        sinks: Vec<SinkModel>,
    }
    let file: SinkFile = toml::from_str(toml_str).context("parse sink models TOML")?;
    Ok(file.sinks)
}

/// Parse a TOML document of package classification rules (a `[[packages]]` array).
pub fn parse_package_rules(toml_str: &str) -> Result<Vec<PackageRule>> {
    #[derive(Deserialize)]
    struct PackageFile {
        packages: Vec<PackageRule>,
    }
    let file: PackageFile =
        toml::from_str(toml_str).context("parse package inference rules TOML")?;
    Ok(file.packages)
}

/// Built-in package classification rules, compiled from
/// `models/package_inference.toml` at build time.
pub fn default_package_rules() -> Vec<PackageRule> {
    parse_package_rules(include_str!("../../models/package_inference.toml"))
        .expect("package inference rules")
}

/// The default catalog, compiled from `models/sinks/*.toml` at build time.
pub fn default_catalog() -> ModelCatalog {
    let mut models = Vec::new();
    models.extend(
        parse_sinks(include_str!("../../models/sinks/python.toml")).expect("python sink models"),
    );
    models.extend(
        parse_sinks(include_str!("../../models/sinks/javascript.toml"))
            .expect("javascript sink models"),
    );
    models.extend(
        parse_sinks(include_str!("../../models/sinks/rust.toml")).expect("rust sink models"),
    );
    ModelCatalog::from_sinks(models)
}

/// Load + merge all `*.toml` files in a directory (used by `models_dir` / `learned/`).
pub fn load_models_dir(dir: &Path) -> Result<ModelCatalog> {
    let mut models = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("read models dir {}", dir.display()))?
        .collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read model file {}", path.display()))?;
        models.extend(parse_sinks(&text)?);
    }
    Ok(ModelCatalog::from_sinks(models))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sinks_reads_a_model_list() {
        let toml_str = r#"
[[sinks]]
language = "python"
category = "command_execution"
severity = "high"
confidence = "high"
reason = "Runs commands"
patterns = ["subprocess.run", "os.system"]
"#;
        let models = parse_sinks(toml_str).expect("parse models");
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].language, "python");
        assert_eq!(models[0].severity, Severity::High);
        assert_eq!(models[0].confidence, Confidence::High);
        assert_eq!(models[0].patterns, vec!["subprocess.run", "os.system"]);
        assert_eq!(models[0].rule_id(), "python.command_execution");
    }

    #[test]
    fn rule_id_prefix_is_js_for_javascript() {
        let model = SinkModel {
            language: "javascript".into(),
            category: "command_execution".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            reason: "x".into(),
            patterns: vec![],
            source: None,
            learned_from: None,
        };
        assert_eq!(model.rule_id(), "js.command_execution");
    }

    #[test]
    fn catalog_groups_and_merges_by_language() {
        let a = parse_sinks(
            "[[sinks]]\nlanguage = \"python\"\ncategory = \"command_execution\"\nseverity = \"high\"\nconfidence = \"high\"\nreason = \"x\"\npatterns = [\"subprocess.run\"]\n",
        )
        .unwrap();
        let b = parse_sinks(
            "[[sinks]]\nlanguage = \"rust\"\ncategory = \"file_read\"\nseverity = \"medium\"\nconfidence = \"high\"\nreason = \"y\"\npatterns = [\"std::fs::read\"]\n",
        )
        .unwrap();
        let mut cat = ModelCatalog::from_sinks(a);
        cat.merge(ModelCatalog::from_sinks(b));
        assert_eq!(cat.sink_count(), 2);
        assert_eq!(cat.sinks_for_language("python").len(), 1);
        assert_eq!(cat.sinks_for_language("rust").len(), 1);
        assert!(cat.sinks_for_language("javascript").is_empty());
    }

    #[test]
    fn default_catalog_matches_legacy_sink_counts() {
        let cat = default_catalog();
        // Legacy counts: python 13, rust 11, javascript 10.
        assert_eq!(cat.sinks_for_language("python").len(), 13);
        assert_eq!(cat.sinks_for_language("rust").len(), 11);
        assert_eq!(cat.sinks_for_language("javascript").len(), 10);
        assert_eq!(cat.sink_count(), 34);
        // Spot-check a few derived rule_ids.
        assert!(cat
            .sinks_for_language("rust")
            .iter()
            .any(|m| m.category == "dynamic_loading" && m.rule_id() == "rust.dynamic_loading"));
        assert!(cat
            .sinks_for_language("javascript")
            .iter()
            .any(|m| m.category == "deserialization_rce" && m.rule_id() == "js.deserialization_rce"));
    }

    #[test]
    fn parse_package_rules_reads_category_and_readwrite_split() {
        let rules = parse_package_rules(
            r#"
[[packages]]
language = "python"
package = "openpyxl"
read_category = "file_read"
write_category = "file_write"

[[packages]]
language = "python"
package = "subprocess"
category = "command_execution"
"#,
        )
        .expect("parse rules");

        assert_eq!(rules.len(), 2);
        let openpyxl = &rules[0];
        assert_eq!(openpyxl.language, "python");
        assert_eq!(openpyxl.package, "openpyxl");
        assert_eq!(openpyxl.read_category.as_deref(), Some("file_read"));
        assert_eq!(openpyxl.write_category.as_deref(), Some("file_write"));
        assert_eq!(openpyxl.category, None);

        let subprocess = &rules[1];
        assert_eq!(subprocess.category.as_deref(), Some("command_execution"));
        assert_eq!(subprocess.read_category, None);
        assert_eq!(subprocess.write_category, None);
    }

    #[test]
    fn default_package_rules_include_openpyxl() {
        let rules = default_package_rules();
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.package == "openpyxl"
            && r.read_category.as_deref() == Some("file_read")
            && r.write_category.as_deref() == Some("file_write")));
        assert!(rules.iter().any(|r| r.package == "sh" && r.category.as_deref() == Some("command_execution")));
    }
}
