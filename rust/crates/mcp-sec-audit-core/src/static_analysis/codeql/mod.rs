pub(crate) mod models;
mod parser;
mod provider;
mod queries;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};

use crate::config::StaticCodeqlConfig;
use crate::model::CodeqlOutput;
use crate::Progress;

use super::pipeline::StaticScanContext;
use models::MadPack;
use provider::{CliCodeqlProvider, DatabaseInfo};
use queries::{QueryPack, resolve_query_pack};

/// Hardcoded constants (not user-configurable).
/// Languages CodeQL supports — Rust is supported as of CodeQL 2.26.x.
const SUPPORTED_LANGUAGES: &[&str] = &["python", "javascript", "typescript", "rust"];

/// MaD model-pack injection requires CLI >= 2.26.3 (2.26.2 rejects the 3-column
/// `sinkModel` extension under overlay-eval mode — see SDD ledger RULING 11).
fn mad_inject_supported(version: Option<(u32, u32, u32)>) -> bool {
    matches!(version, Some((major, minor, patch)) if (major, minor, patch) >= (2, 26, 3))
}

/// Map a CodeQL database language to its MaD model-pack language key.
/// `typescript` shares the `javascript` pack; `rust` has no MaD pack today.
fn mad_language_for_db_language(db_language: &str) -> Option<&'static str> {
    match db_language {
        "python" => Some("python"),
        "javascript" | "typescript" => Some("javascript"),
        _ => None,
    }
}

/// A prepared CodeQL scan: provider, config, and per-language databases and
/// query packs. `create` builds databases (reusing any cached DB); `analyze`
/// runs analysis and parses SARIF.
pub(crate) struct CodeqlSession {
    provider: CliCodeqlProvider,
    config: StaticCodeqlConfig,
    databases: BTreeMap<String, DatabaseInfo>,
    query_packs: BTreeMap<String, QueryPack>,
    diagnostics: Vec<String>,
}

impl CodeqlSession {
    /// Create a session (build databases + resolve query packs) if there is
    /// CodeQL work to do; `Ok(None)` when disabled or no supported language.
    pub(crate) fn create(ctx: &StaticScanContext) -> Result<Option<Self>> {
        let codeql_config = &ctx.config.static_.codeql;

        if !codeql_config.enabled {
            return Ok(None);
        }

        // Filter discovered files to CodeQL-supported languages only.
        // Must happen BEFORE the CLI check so unit tests can run without CodeQL installed.
        let supported_files: Vec<_> = ctx
            .discovered_files
            .iter()
            .filter(|df| {
                let lang = df.language.config_keys()[0];
                SUPPORTED_LANGUAGES.contains(&lang)
            })
            .collect();

        if supported_files.is_empty() {
            // The "CodeQL skipped" progress + diagnostic is emitted by `run`
            // (which owns the progress callback and builds the output).
            return Ok(None);
        }

        // Hard-error if CodeQL CLI is not installed (only checked when we have work to do).
        let provider = CliCodeqlProvider::new(codeql_config.binary.clone(), ctx.run_id.clone());
        if !provider.check_available() {
            bail!(
                "CodeQL CLI ('{}') not found. Set [static.codeql].binary or add it to PATH. \
                 Install it from: https://github.com/github/codeql-cli-binaries/releases",
                codeql_config.binary
            );
        }

        // Group files by language to create one database per language.
        let mut languages = BTreeSet::new();
        for df in &supported_files {
            let lang = df.language.config_keys()[0].to_string();
            languages.insert(lang);
        }

        // Determine source root from the configured scan targets (a directory target
        // is used as-is; a file target contributes its parent directory).
        let target_root = ctx
            .config
            .scan
            .targets
            .first()
            .map(|t| {
                let p = std::path::Path::new(t);
                if p.is_dir() {
                    p.display().to_string()
                } else {
                    p.parent()
                        .map(|d| d.display().to_string())
                        .unwrap_or_else(|| ".".to_string())
                }
            })
            .unwrap_or_else(|| ".".to_string());

        let mut databases = BTreeMap::new();
        let mut query_packs = BTreeMap::new();
        let mut diagnostics = Vec::new();

        for language in &languages {
            // Resolve the query pack for this database's language (built-in or custom).
            let query_pack =
                resolve_query_pack(codeql_config.query_pack_path.as_deref(), language)?;
            tracing::info!(
                target: "mcp_sec_audit::codeql",
                language = %language,
                query_files = query_pack.query_files.len(),
                suite_refs = ?query_pack.suite_refs,
                "query pack resolved"
            );

            // Create database for this language.
            tracing::debug!(
                target: "mcp_sec_audit::codeql",
                language = %language,
                "creating CodeQL database"
            );
            let db = match provider.create_database_blocking(std::path::Path::new(&target_root), language) {
                Ok(db) => db,
                Err(e) => {
                    diagnostics.push(format!(
                        "CodeQL database create failed for {}: {}",
                        language, e
                    ));
                    continue;
                }
            };

            databases.insert(language.clone(), db);
            query_packs.insert(language.clone(), query_pack);
        }

        Ok(Some(Self {
            provider,
            config: codeql_config.clone(),
            databases,
            query_packs,
            diagnostics,
        }))
    }

    /// Run per-language analysis against the prepared databases, parse SARIF,
    /// and collect results/diagnostics/raw SARIF into a `CodeqlOutput`.
    pub(crate) fn analyze(
        &self,
        model_packs: &[MadPack],
        progress: &Progress,
    ) -> Result<CodeqlOutput> {
        let mut all_results = Vec::new();
        let mut all_diagnostics = self.diagnostics.clone();
        let mut raw_sarif_parts = Vec::new();

        for (language, db) in &self.databases {
            let query_pack = &self.query_packs[language];

            // Inject only the MaD pack matching this database's language.
            // Injecting the javascript pack while analyzing a python DB (or
            // vice-versa) loads the wrong language's `sinkModel` tuples and
            // aborts analysis with `Expected 4, but was 3`.
            let language_packs: Vec<&MadPack> = model_packs
                .iter()
                .filter(|mp| Some(mp.language.as_str()) == mad_language_for_db_language(language))
                .collect();

            // Run analysis against the database.
            tracing::debug!(
                target: "mcp_sec_audit::codeql",
                language = %language,
                "running CodeQL analysis"
            );
            progress.report(format!("CodeQL: analyzing {} database...", language));
            match self.provider.run_analysis_blocking(
                db,
                query_pack,
                self.config.timeout_seconds,
                &self.config.extra_args,
                &language_packs,
            ) {
                Ok(sarif) => {
                    let metadata = parser::CodeqlMetadata {
                        query_source: self
                            .config
                            .query_pack_path
                            .clone()
                            .unwrap_or_else(|| "built-in".to_string()),
                        languages: vec![language.clone()],
                    };

                    match parser::parse_sarif(&sarif, &metadata) {
                        Ok(results) => {
                            tracing::info!(
                                target: "mcp_sec_audit::codeql",
                                language = %language,
                                findings = results.len(),
                                "CodeQL analysis produced results"
                            );
                            all_results.extend(results);
                            raw_sarif_parts.push(sarif);
                        }
                        Err(e) => {
                            all_diagnostics
                                .push(format!("SARIF parse failed for {}: {}", language, e));
                        }
                    }
                }
                Err(e) => {
                    all_diagnostics.push(format!("CodeQL analyze failed for {}: {}", language, e));
                }
            }
        }

        let raw_sarif = if raw_sarif_parts.is_empty() {
            None
        } else {
            Some(raw_sarif_parts.join("\n"))
        };

        Ok(CodeqlOutput {
            results: all_results,
            raw_sarif,
            diagnostics: all_diagnostics,
        })
    }
}

/// CodeQL line entry point.
///
/// Builds a session (databases + query packs), compiles the shared sink model
/// catalog into a MaD model pack, runs analysis, and parses SARIF into
/// structured results.
pub fn run(
    ctx: &StaticScanContext,
    catalog: &crate::models::ModelCatalog,
    progress: &Progress,
) -> Result<CodeqlOutput> {
    let Some(session) = CodeqlSession::create(ctx)? else {
        // `create` returned `None`: either CodeQL is disabled, or no supported
        // language files were found. Reproduce the skip behavior here (where
        // the progress callback and output are available).
        if !ctx.config.static_.codeql.enabled {
            return Ok(CodeqlOutput::empty());
        }

        tracing::warn!(
            target: "mcp_sec_audit::codeql",
            "CodeQL skipped: no CodeQL-supported language in target"
        );
        progress.report("CodeQL skipped: no CodeQL-supported language in target");
        let mut output = CodeqlOutput::empty();
        let total = ctx.discovered_files.len();
        output.diagnostics.push(format!(
            "No CodeQL-supported language files among {} discovered files — CodeQL line skipped.",
            total
        ));
        return Ok(output);
    };

    // Compile the shared sink model catalog into a CodeQL MaD model pack and
    // feed it to every `analyze`. Injection is const-gated (RULING 11): disabled
    // under CLI 2.26.2 because `--model-packs` rejects the 3-column `sinkModel`
    // extension when the lock-file mcp-* query packs are evaluated in
    // overlay-eval mode. MaD compilation is non-fatal: on error fall back to
    // built-in queries and warn, so the CodeQL line still runs.
    let cli_version = session.provider.codeql_version();
    let model_packs: Vec<models::MadPack> = if mad_inject_supported(cli_version) {
        match models::write_model_pack_dir(catalog, ctx) {
            Ok(packs) => {
                for pack in &packs {
                    tracing::info!(
                        target: "mcp_sec_audit::codeql",
                        pack = %pack.name,
                        language = %pack.language,
                        "compiled MaD model pack"
                    );
                }
                packs
            }
            Err(e) => {
                tracing::warn!(
                    target: "mcp_sec_audit::codeql",
                    error = %e,
                    "failed to compile MaD model packs; running without them"
                );
                Vec::new()
            }
        }
    } else {
        tracing::warn!(
            target: "mcp_sec_audit::codeql",
            cli_version = ?cli_version,
            "CodeQL MaD injection disabled: requires CLI >= 2.26.3. Upgrade to enable sink-model evolution."
        );
        Vec::new()
    };

    session.analyze(&model_packs, progress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeConfig, StaticScanContext};

    #[test]
    fn disabled_codeql_returns_empty() {
        let ctx = StaticScanContext {
            run_id: crate::RunId::new(),
            config: RuntimeConfig::default(), // codeql disabled by default
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        let output = run(
            &ctx,
            &crate::models::default_catalog(),
            &crate::Progress::noop(),
        )
        .expect("run disabled codeql");
        assert!(output.results.is_empty());
        assert!(output.raw_sarif.is_none());
        assert!(output.diagnostics.is_empty());
    }

    #[test]
    fn enabled_with_no_files_returns_empty_with_diagnostic() {
        let mut config = RuntimeConfig::default();
        config.static_.codeql.enabled = true;
        let ctx = StaticScanContext {
            run_id: crate::RunId::new(),
            config,
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        // Safe even without CodeQL CLI: no files → returns before CLI check.
        let output = run(
            &ctx,
            &crate::models::default_catalog(),
            &crate::Progress::noop(),
        )
        .expect("run codeql with no files");
        assert!(output.results.is_empty());
        assert!(!output.diagnostics.is_empty());
        assert!(output.diagnostics[0].contains("No CodeQL-supported language"));
    }

    #[test]
    fn unsupported_language_emits_skip_progress() {
        use crate::static_analysis::discovery::{DiscoveredFile, ScanLanguage};
        let mut config = RuntimeConfig::default();
        config.static_.codeql.enabled = true;
        let ctx = StaticScanContext {
            run_id: crate::RunId::new(),
            config,
            rulebook_paths: Vec::new(),
            discovered_files: vec![DiscoveredFile {
                path: "data.json".into(),
                language: ScanLanguage::Json,
            }],
        };
        let (progress, mut rx) = crate::Progress::channel();
        let output = run(&ctx, &crate::models::default_catalog(), &progress).expect("run");
        let messages: Vec<String> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(output.results.is_empty());
        assert!(messages.iter().any(|m| m.contains("CodeQL skipped")));
    }

    #[test]
    fn missing_codeql_binary_returns_err_not_panic() {
        use crate::static_analysis::discovery::{DiscoveredFile, ScanLanguage};
        let mut config = RuntimeConfig::default();
        config.static_.codeql.enabled = true;
        config.static_.codeql.binary = "/nonexistent/definitely-not-codeql".to_string();
        // A supported-language file is required to reach the CLI availability
        // check: empty/unsupported discovered files return Ok(None) before it.
        let ctx = StaticScanContext {
            run_id: crate::RunId::new(),
            config,
            rulebook_paths: Vec::new(),
            discovered_files: vec![DiscoveredFile {
                path: "main.py".into(),
                language: ScanLanguage::Python,
            }],
        };
        let result = CodeqlSession::create(&ctx);
        // `err()` (rather than `unwrap_err()`) because `CodeqlSession` is not
        // `Debug`; the intent is "recoverable Err, not a panic".
        let err = result.err().expect("missing CLI must be a recoverable Err, not a panic");
        assert!(
            err.to_string().contains("codeql"),
            "error should mention the CodeQL CLI"
        );
    }

    #[test]
    fn mad_gate_accepts_2_26_3_and_newer() {
        assert!(mad_inject_supported(Some((2, 26, 3))));
        assert!(mad_inject_supported(Some((2, 27, 0))));
        assert!(mad_inject_supported(Some((3, 0, 0))));
    }

    #[test]
    fn mad_gate_rejects_2_26_2_and_missing() {
        assert!(!mad_inject_supported(Some((2, 26, 2))));
        assert!(!mad_inject_supported(Some((2, 26, 0))));
        assert!(!mad_inject_supported(None));
    }

    /// Regression gate for the P0 cross-language MaD pollution bug: compiling the
    /// full catalog (python + javascript) and analyzing a single-language DB must
    /// not load the other language's `.model.yml` (which previously aborted with
    /// `sinkModel Expected 4, but was 3`). Requires a real CodeQL CLI, so it is
    /// `#[ignore]`d by default; run manually with:
    ///   cargo test -p mcp-sec-audit-core --lib codeql -- --ignored
    #[test]
    #[ignore = "requires CodeQL CLI >= 2.26.3 on PATH"]
    fn mad_pack_isolation_end_to_end_no_cross_language_error() {
        use super::models::MadPack;
        use super::provider::CliCodeqlProvider;
        use super::queries::QueryPack;

        let provider = CliCodeqlProvider::new("codeql".to_string(), crate::RunId::new());
        if !provider.check_available() {
            eprintln!("skipping: codeql CLI not on PATH");
            return;
        }
        if !mad_inject_supported(provider.codeql_version()) {
            eprintln!("skipping: codeql CLI < 2.26.3 (MaD disabled)");
            return;
        }

        // Minimal python DB with a command sink reachable from an env var.
        let src = std::env::temp_dir().join("mcp-sec-audit-mad-e2e-src");
        std::fs::create_dir_all(&src).expect("create src dir");
        std::fs::write(
            src.join("main.py"),
            "import os\np = os.environ.get('X')\nos.system(p)\n",
        )
        .expect("write main.py");
        let db = provider
            .create_database_blocking(&src, "python")
            .expect("create python DB");

        // Compile the FULL catalog (python + javascript sinks) into per-language
        // packs, then analyze the python DB with ONLY the python pack.
        let ctx = StaticScanContext {
            run_id: crate::RunId::new(),
            config: RuntimeConfig::default(),
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        let packs = super::models::write_model_pack_dir(&crate::models::default_catalog(), &ctx)
            .expect("write model pack dir");
        let python_pack: Vec<&MadPack> = packs.iter().filter(|p| p.language == "python").collect();
        assert_eq!(python_pack.len(), 1, "expected exactly one python pack");

        let query_pack = QueryPack {
            query_files: Vec::new(),
            suite_refs: vec!["codeql/python-queries".to_string()],
        };
        match provider.run_analysis_blocking(&db, &query_pack, 600, &[], &python_pack) {
            Ok(_sarif) => {}
            Err(e) => panic!("MaD cross-language pollution (or analyze failure): {e}"),
        }

        let _ = std::fs::remove_dir_all(&src);
    }
}
