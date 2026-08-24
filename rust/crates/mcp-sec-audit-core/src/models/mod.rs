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
    /// Times this learned model was corroborated by the differential signal (b1/a1).
    #[serde(default)]
    pub corroboration_count: u32,
    /// Times this learned model was implicated in a b2 pollution event.
    #[serde(default)]
    pub pollution_count: u32,
    /// Run identifier (e.g. "20260824") of the last scan that observed this model.
    #[serde(default)]
    pub last_seen_run: Option<String>,
}

impl SinkModel {
    /// Derived rule_id: `{prefix}.{category}` ("python"/"rust"/"js").
    pub fn rule_id(&self) -> String {
        format!("{}.{}", rule_prefix(&self.language), self.category)
    }
}

/// A single source model: an external-input entrypoint that produces taint.
/// Complements the structurally-detected MCP tool parameters (which need no
/// model) by covering library/env/CLI inputs (`os.environ`, `sys.argv`,
/// `requests.get`, …) that the structural extractor cannot see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceModel {
    /// Language key: "python" | "javascript" | "rust".
    pub language: String,
    /// Input category: "env_var" | "cli_arg" | "network_request" | "http_request" …
    pub category: String,
    /// Callee/access patterns matched with the language's separator rules.
    pub patterns: Vec<String>,
    /// "manual" | "learned" — `None` treated as manual.
    #[serde(default)]
    pub source: Option<String>,
    /// Provenance for learned models: "scan-id/agent-id".
    #[serde(default)]
    pub learned_from: Option<String>,
    /// Times this learned model was corroborated by the differential signal (b1/a1).
    #[serde(default)]
    pub corroboration_count: u32,
    /// Times this learned model was implicated in a b2 pollution event.
    #[serde(default)]
    pub pollution_count: u32,
    /// Run identifier (e.g. "20260824") of the last scan that observed this model.
    #[serde(default)]
    pub last_seen_run: Option<String>,
}

/// A single sanitizer model: a function that neutralizes taint for one or more
/// sink categories (`shlex.quote` → command_execution). A tainted value flowing
/// through such a function no longer reaches sinks of the neutralized
/// categories — this is the "补 sanitizer = 补精度" lever that suppresses A-line
/// false positives (a2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizerModel {
    /// Language key: "python" | "javascript" | "rust".
    pub language: String,
    /// Callee patterns matched with the language's separator rules.
    pub patterns: Vec<String>,
    /// Sink categories this sanitizer neutralizes (e.g. ["command_execution"]).
    /// A `"*"` entry neutralizes every category.
    pub neutralizes: Vec<String>,
    /// "manual" | "learned" — `None` treated as manual.
    #[serde(default)]
    pub source: Option<String>,
    /// Provenance for learned models: "scan-id/agent-id".
    #[serde(default)]
    pub learned_from: Option<String>,
    /// Times this learned model was corroborated by the differential signal (b1/a1).
    #[serde(default)]
    pub corroboration_count: u32,
    /// Times this learned model was implicated in a b2 pollution event.
    #[serde(default)]
    pub pollution_count: u32,
    /// Run identifier (e.g. "20260824") of the last scan that observed this model.
    #[serde(default)]
    pub last_seen_run: Option<String>,
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

/// All models (sink + source + sanitizer), grouped by language key.
#[derive(Debug, Clone, Default)]
pub struct ModelCatalog {
    sinks: BTreeMap<String, Vec<SinkModel>>,
    sources: BTreeMap<String, Vec<SourceModel>>,
    sanitizers: BTreeMap<String, Vec<SanitizerModel>>,
}

impl ModelCatalog {
    /// Build a catalog by grouping a flat sink-model list by `language`.
    pub fn from_sinks(models: Vec<SinkModel>) -> Self {
        let mut sinks: BTreeMap<String, Vec<SinkModel>> = BTreeMap::new();
        for model in models {
            sinks.entry(model.language.clone()).or_default().push(model);
        }
        Self {
            sinks,
            sources: BTreeMap::new(),
            sanitizers: BTreeMap::new(),
        }
    }

    /// Build a catalog by grouping a flat source-model list by `language`.
    pub fn from_sources(models: Vec<SourceModel>) -> Self {
        let mut sources: BTreeMap<String, Vec<SourceModel>> = BTreeMap::new();
        for model in models {
            sources
                .entry(model.language.clone())
                .or_default()
                .push(model);
        }
        Self {
            sinks: BTreeMap::new(),
            sources,
            sanitizers: BTreeMap::new(),
        }
    }

    /// Build a catalog by grouping a flat sanitizer-model list by `language`.
    pub fn from_sanitizers(models: Vec<SanitizerModel>) -> Self {
        let mut sanitizers: BTreeMap<String, Vec<SanitizerModel>> = BTreeMap::new();
        for model in models {
            sanitizers
                .entry(model.language.clone())
                .or_default()
                .push(model);
        }
        Self {
            sinks: BTreeMap::new(),
            sources: BTreeMap::new(),
            sanitizers,
        }
    }

    /// Build a catalog from all three model classes in one call.
    pub fn from_models(
        sinks: Vec<SinkModel>,
        sources: Vec<SourceModel>,
        sanitizers: Vec<SanitizerModel>,
    ) -> Self {
        let mut catalog = Self::from_sinks(sinks);
        catalog.merge(Self::from_sources(sources));
        catalog.merge(Self::from_sanitizers(sanitizers));
        catalog
    }

    /// Sink models for a language key ("python" | "javascript" | "rust"), or `[]`.
    pub fn sinks_for_language(&self, language: &str) -> &[SinkModel] {
        self.sinks
            .get(language)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Source models for a language key, or `[]`.
    pub fn sources_for_language(&self, language: &str) -> &[SourceModel] {
        self.sources
            .get(language)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Sanitizer models for a language key, or `[]`.
    pub fn sanitizers_for_language(&self, language: &str) -> &[SanitizerModel] {
        self.sanitizers
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
        for (lang, models) in other.sources {
            self.sources.entry(lang).or_default().extend(models);
        }
        for (lang, models) in other.sanitizers {
            self.sanitizers.entry(lang).or_default().extend(models);
        }
    }

    /// Total number of sink models across all languages.
    pub fn sink_count(&self) -> usize {
        self.sinks.values().map(|v| v.len()).sum()
    }

    /// Total number of source models across all languages.
    pub fn source_count(&self) -> usize {
        self.sources.values().map(|v| v.len()).sum()
    }

    /// Total number of sanitizer models across all languages.
    pub fn sanitizer_count(&self) -> usize {
        self.sanitizers.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.values().all(Vec::is_empty)
            && self.sources.values().all(Vec::is_empty)
            && self.sanitizers.values().all(Vec::is_empty)
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

/// Parse a TOML document of source models (a `[[sources]]` array of tables).
pub fn parse_sources(toml_str: &str) -> Result<Vec<SourceModel>> {
    #[derive(Deserialize)]
    struct SourceFile {
        #[serde(default)]
        sources: Vec<SourceModel>,
    }
    let file: SourceFile = toml::from_str(toml_str).context("parse source models TOML")?;
    Ok(file.sources)
}

/// Parse a TOML document of sanitizer models (a `[[sanitizers]]` array of tables).
pub fn parse_sanitizers(toml_str: &str) -> Result<Vec<SanitizerModel>> {
    #[derive(Deserialize)]
    struct SanitizerFile {
        #[serde(default)]
        sanitizers: Vec<SanitizerModel>,
    }
    let file: SanitizerFile = toml::from_str(toml_str).context("parse sanitizer models TOML")?;
    Ok(file.sanitizers)
}

/// Parse a TOML document that may carry any subset of `[[sinks]]`, `[[sources]]`,
/// and `[[sanitizers]]` arrays (used for `models_dir` / `learned/` files, which
/// can be sink-only, source-only, or mixed). Returns three flat lists.
pub fn parse_model_file(
    toml_str: &str,
) -> Result<(Vec<SinkModel>, Vec<SourceModel>, Vec<SanitizerModel>)> {
    #[derive(Deserialize, Default)]
    struct ModelFile {
        #[serde(default)]
        sinks: Vec<SinkModel>,
        #[serde(default)]
        sources: Vec<SourceModel>,
        #[serde(default)]
        sanitizers: Vec<SanitizerModel>,
    }
    let file: ModelFile = toml::from_str(toml_str).context("parse model file TOML")?;
    Ok((file.sinks, file.sources, file.sanitizers))
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

/// The default catalog, compiled from `models/{sinks,sources,sanitizers}/*.toml`
/// at build time.
pub fn default_catalog() -> ModelCatalog {
    let mut sinks = Vec::new();
    sinks.extend(
        parse_sinks(include_str!("../../models/sinks/python.toml")).expect("python sink models"),
    );
    sinks.extend(
        parse_sinks(include_str!("../../models/sinks/javascript.toml"))
            .expect("javascript sink models"),
    );
    sinks.extend(
        parse_sinks(include_str!("../../models/sinks/rust.toml")).expect("rust sink models"),
    );

    let mut sources = Vec::new();
    sources.extend(
        parse_sources(include_str!("../../models/sources/python.toml"))
            .expect("python source models"),
    );
    sources.extend(
        parse_sources(include_str!("../../models/sources/javascript.toml"))
            .expect("javascript source models"),
    );
    sources.extend(
        parse_sources(include_str!("../../models/sources/rust.toml")).expect("rust source models"),
    );

    let mut sanitizers = Vec::new();
    sanitizers.extend(
        parse_sanitizers(include_str!("../../models/sanitizers/python.toml"))
            .expect("python sanitizer models"),
    );
    sanitizers.extend(
        parse_sanitizers(include_str!("../../models/sanitizers/javascript.toml"))
            .expect("javascript sanitizer models"),
    );
    sanitizers.extend(
        parse_sanitizers(include_str!("../../models/sanitizers/rust.toml"))
            .expect("rust sanitizer models"),
    );

    ModelCatalog::from_models(sinks, sources, sanitizers)
}

/// Load + merge all `*.toml` files in a directory (used by `models_dir` / `learned/`).
/// Each file may carry sinks, sources, and/or sanitizers.
pub fn load_models_dir(dir: &Path) -> Result<ModelCatalog> {
    let mut catalog = ModelCatalog::default();
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
        let (sinks, sources, sanitizers) = parse_model_file(&text)?;
        catalog.merge(ModelCatalog::from_models(sinks, sources, sanitizers));
    }
    Ok(catalog)
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
    fn parse_sources_reads_a_model_list() {
        let toml_str = r#"
[[sources]]
language = "python"
category = "env_var"
patterns = ["os.environ", "os.getenv"]
source = "manual"
"#;
        let models = parse_sources(toml_str).expect("parse sources");
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].language, "python");
        assert_eq!(models[0].category, "env_var");
        assert_eq!(models[0].patterns, vec!["os.environ", "os.getenv"]);
        assert_eq!(models[0].source.as_deref(), Some("manual"));
    }

    #[test]
    fn parse_sanitizers_reads_a_model_list() {
        let toml_str = r#"
[[sanitizers]]
language = "python"
patterns = ["shlex.quote"]
neutralizes = ["command_execution"]
"#;
        let models = parse_sanitizers(toml_str).expect("parse sanitizers");
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].patterns, vec!["shlex.quote"]);
        assert_eq!(models[0].neutralizes, vec!["command_execution"]);
    }

    #[test]
    fn parse_model_file_accepts_mixed_and_single_kinds() {
        let sink_only = "[[sinks]]\nlanguage = \"python\"\ncategory = \"file_read\"\nseverity = \"medium\"\nconfidence = \"low\"\nreason = \"r\"\npatterns = [\"openpyxl.load_workbook\"]\n";
        let (s, so, sa) = parse_model_file(sink_only).expect("sink-only file");
        assert_eq!(s.len(), 1);
        assert!(so.is_empty());
        assert!(sa.is_empty());

        let mixed = r#"
[[sinks]]
language = "python"
category = "file_read"
severity = "medium"
confidence = "low"
reason = "r"
patterns = ["openpyxl.load_workbook"]

[[sources]]
language = "python"
category = "env_var"
patterns = ["os.environ"]

[[sanitizers]]
language = "python"
patterns = ["shlex.quote"]
neutralizes = ["command_execution"]
"#;
        let (s, so, sa) = parse_model_file(mixed).expect("mixed file");
        assert_eq!(s.len(), 1);
        assert_eq!(so.len(), 1);
        assert_eq!(sa.len(), 1);
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
            corroboration_count: 0,
            pollution_count: 0,
            last_seen_run: None,
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
    fn catalog_holds_all_three_model_classes() {
        let cat = default_catalog();
        assert!(cat.sink_count() >= 34);
        assert!(cat.source_count() > 0, "built-in source models should load");
        assert!(
            cat.sanitizer_count() > 0,
            "built-in sanitizer models should load"
        );
        assert!(cat.sources_for_language("python").len() > 0);
        assert!(cat.sanitizers_for_language("python").len() > 0);
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
        assert!(
            cat.sinks_for_language("rust")
                .iter()
                .any(|m| m.category == "dynamic_loading" && m.rule_id() == "rust.dynamic_loading")
        );
        assert!(
            cat.sinks_for_language("javascript")
                .iter()
                .any(|m| m.category == "deserialization_rce"
                    && m.rule_id() == "js.deserialization_rce")
        );
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
        assert!(
            rules
                .iter()
                .any(|r| r.package == "sh" && r.category.as_deref() == Some("command_execution"))
        );
    }

    #[test]
    fn learned_model_lifecycle_fields_roundtrip_toml() {
        // 旧格式（无生命周期字段）仍能加载 → 向后兼容
        let old = r#"
[[sinks]]
language = "python"
category = "file_read"
severity = "medium"
confidence = "low"
reason = "legacy"
patterns = ["openpyxl.load_workbook"]
source = "learned"
"#;
        let dir = std::env::temp_dir().join(format!("lifecycle-old-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("old.toml"), old).unwrap();
        let cat = super::load_models_dir(&dir).expect("old TOML must still load");
        let s = &cat.sinks_for_language("python")[0];
        assert_eq!(s.corroboration_count, 0);
        assert_eq!(s.pollution_count, 0);
        assert_eq!(s.last_seen_run, None);
        std::fs::remove_dir_all(&dir).ok();

        // 新格式字段被反序列化
        let new = r#"
[[sinks]]
language = "python"
category = "file_read"
severity = "medium"
confidence = "high"
reason = "learned"
patterns = ["openpyxl.load_workbook"]
source = "learned"
corroboration_count = 2
pollution_count = 1
last_seen_run = "20260824"
"#;
        let dir2 = std::env::temp_dir().join(format!("lifecycle-new-{}", std::process::id()));
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(dir2.join("new.toml"), new).unwrap();
        let cat2 = super::load_models_dir(&dir2).expect("new TOML loads");
        let s2 = &cat2.sinks_for_language("python")[0];
        assert_eq!(s2.corroboration_count, 2);
        assert_eq!(s2.pollution_count, 1);
        assert_eq!(s2.last_seen_run.as_deref(), Some("20260824"));
        std::fs::remove_dir_all(&dir2).ok();
    }
}
