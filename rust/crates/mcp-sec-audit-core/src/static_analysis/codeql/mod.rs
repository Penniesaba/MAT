mod models;
mod parser;
mod provider;
mod queries;

use std::collections::BTreeSet;

use anyhow::Result;

use crate::model::CodeqlOutput;

use super::pipeline::StaticScanContext;
use provider::{CliCodeqlProvider, CodeqlProvider};
use queries::resolve_query_pack;

/// Hardcoded constants (not user-configurable).
/// Languages CodeQL supports — Rust is supported as of CodeQL 2.26.x.
const SUPPORTED_LANGUAGES: &[&str] = &["python", "javascript", "typescript", "rust"];

/// CodeQL line entry point.
///
/// Filters to Python/JS/TS targets, creates CodeQL databases per language,
/// runs analysis with built-in or custom queries, and parses SARIF output
/// into structured results.
pub fn run(ctx: &StaticScanContext, mut progress: impl FnMut(&str)) -> Result<CodeqlOutput> {
    let codeql_config = &ctx.config.static_.codeql;

    if !codeql_config.enabled {
        return Ok(CodeqlOutput::empty());
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
        tracing::warn!(
            target: "mcp_sec_audit::codeql",
            "CodeQL skipped: no CodeQL-supported language in target"
        );
        progress("CodeQL skipped: no CodeQL-supported language in target");
        let mut output = CodeqlOutput::empty();
        let total = ctx.discovered_files.len();
        output.diagnostics.push(format!(
            "No CodeQL-supported language files among {} discovered files — CodeQL line skipped.",
            total
        ));
        return Ok(output);
    }

    // Hard-error if CodeQL CLI is not installed (only checked when we have work to do).
    let provider = CliCodeqlProvider::new(&codeql_config.binary);
    if !provider.check_available() {
        panic!(
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

    let mut all_results = Vec::new();
    let mut all_diagnostics = Vec::new();
    let mut raw_sarif_parts = Vec::new();

    for language in &languages {
        // Resolve the query pack for this database's language (built-in or custom).
        let query_pack = resolve_query_pack(codeql_config.query_pack_path.as_deref(), language)?;

        // Create database for this language.
        tracing::debug!(
            target: "mcp_sec_audit::codeql",
            language = %language,
            "creating CodeQL database"
        );
        let db = match provider.create_database(
            std::path::Path::new(&target_root),
            language,
        ) {
            Ok(db) => db,
            Err(e) => {
                all_diagnostics.push(format!(
                    "CodeQL database create failed for {}: {}",
                    language, e
                ));
                continue;
            }
        };

        // Run analysis against the database.
        tracing::debug!(
            target: "mcp_sec_audit::codeql",
            language = %language,
            "running CodeQL analysis"
        );
        match provider.run_analysis(
            &db,
            &query_pack,
            codeql_config.timeout_seconds,
            &codeql_config.extra_args,
        ) {
            Ok(sarif) => {
                let metadata = parser::CodeqlMetadata {
                    query_source: codeql_config
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
                        all_diagnostics.push(format!(
                            "SARIF parse failed for {}: {}",
                            language, e
                        ));
                    }
                }
            }
            Err(e) => {
                all_diagnostics.push(format!(
                    "CodeQL analyze failed for {}: {}",
                    language, e
                ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeConfig, StaticScanContext};

    #[test]
    fn disabled_codeql_returns_empty() {
        let ctx = StaticScanContext {
            config: RuntimeConfig::default(), // codeql disabled by default
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        let output = run(&ctx, |_| {}).expect("run disabled codeql");
        assert!(output.results.is_empty());
        assert!(output.raw_sarif.is_none());
        assert!(output.diagnostics.is_empty());
    }

    #[test]
    fn enabled_with_no_files_returns_empty_with_diagnostic() {
        let mut config = RuntimeConfig::default();
        config.static_.codeql.enabled = true;
        let ctx = StaticScanContext {
            config,
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        // Safe even without CodeQL CLI: no files → returns before CLI check.
        let output = run(&ctx, |_| {}).expect("run codeql with no files");
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
            config,
            rulebook_paths: Vec::new(),
            discovered_files: vec![DiscoveredFile {
                path: "data.json".into(),
                language: ScanLanguage::Json,
            }],
        };
        let mut messages: Vec<String> = Vec::new();
        let output = run(&ctx, |m| messages.push(m.to_string())).expect("run");
        assert!(output.results.is_empty());
        assert!(messages.iter().any(|m| m.contains("CodeQL skipped")));
    }
}
