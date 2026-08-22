use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// Represents a resolved query pack ready for CodeQL analysis.
#[derive(Debug, Clone)]
pub struct QueryPack {
    /// Paths to .ql files or .qlref references (language-native for this DB).
    pub query_files: Vec<PathBuf>,
    /// Standard query pack references for this language (e.g. "codeql/rust-queries").
    pub suite_refs: Vec<String>,
}

impl QueryPack {
    /// Build the built-in query pack for one database language.
    pub fn for_language(language: &str) -> Result<Self> {
        let dir = builtin_mcp_query_dir_for(language)?;
        let mut query_files = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("ql") {
                query_files.push(path);
            }
        }
        Ok(Self {
            query_files,
            suite_refs: standard_suite_refs_for(language),
        })
    }

    /// Load a user-specified query pack directory (applies to every language).
    pub fn from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!("CodeQL query pack path does not exist: {}", path.display());
        }
        let mut query_files = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("ql") {
                query_files.push(p);
            }
        }
        Ok(Self {
            query_files,
            suite_refs: Vec::new(),
        })
    }
}

/// Standard security suite reference for a database language.
///
/// Unversioned refs resolve to the latest compatible pack under CLI >= 2.26.3.
fn standard_suite_refs_for(language: &str) -> Vec<String> {
    match language {
        "python" => vec!["codeql/python-queries".to_string()],
        "javascript" | "typescript" => vec!["codeql/javascript-queries".to_string()],
        "rust" => vec!["codeql/rust-queries".to_string()],
        _ => Vec::new(),
    }
}

/// Resolve the active query pack: user override or built-in per-language default.
pub fn resolve_query_pack(custom_path: Option<&str>, language: &str) -> Result<QueryPack> {
    match custom_path {
        Some(p) => QueryPack::from_path(Path::new(p)),
        None => QueryPack::for_language(language),
    }
}

/// Directory containing built-in MCP CodeQL queries for one language.
fn builtin_mcp_query_dir_for(language: &str) -> Result<PathBuf> {
    let lang_dir = match language {
        "python" => "mcp-python",
        "javascript" | "typescript" => "mcp-js",
        "rust" => "mcp-rust",
        _ => bail!("no built-in MCP query pack for language '{}'", language),
    };
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("static_analysis")
        .join("codeql")
        .join("queries")
        .join(lang_dir);
    if !dir.exists() {
        bail!(
            "Built-in CodeQL query directory not found: {}. \
             Ensure the crate is built from the correct directory.",
            dir.display()
        );
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_pack_has_mcp_queries_and_python_suite() {
        let pack = QueryPack::for_language("python").expect("python pack");
        assert!(pack.query_files.iter().any(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |n| n.contains("ToolParameterToSink"))
        }));
        assert_eq!(pack.suite_refs, vec!["codeql/python-queries"]);
    }

    #[test]
    fn rust_pack_has_rust_suite() {
        let pack = QueryPack::for_language("rust").expect("rust pack");
        assert_eq!(pack.suite_refs, vec!["codeql/rust-queries"]);
    }

    #[test]
    fn unknown_language_errors() {
        let err = QueryPack::for_language("cobol").expect_err("unknown language should fail");
        assert!(err.to_string().contains("no built-in MCP query pack"));
    }

    #[test]
    fn resolve_custom_path_overrides_default() {
        let tmp = std::env::temp_dir().join("codeql-test-queries");
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        std::fs::write(tmp.join("test.ql"), "// test query").expect("write test file");
        let pack =
            resolve_query_pack(Some(tmp.to_str().unwrap()), "python").expect("resolve custom pack");
        assert!(!pack.query_files.is_empty());
        assert!(pack.suite_refs.is_empty());
        std::fs::remove_dir_all(&tmp).expect("cleanup");
    }

    #[test]
    fn missing_custom_path_returns_error() {
        let err = resolve_query_pack(Some("/nonexistent/path/xyz"), "python")
            .expect_err("nonexistent path should fail");
        assert!(err.to_string().contains("does not exist"));
    }
}
