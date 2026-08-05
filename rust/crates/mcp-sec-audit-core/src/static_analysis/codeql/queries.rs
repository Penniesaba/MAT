use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// Represents a resolved query pack ready for CodeQL analysis.
#[derive(Debug, Clone)]
pub struct QueryPack {
    /// Paths to .ql files or .qlref references.
    pub query_files: Vec<PathBuf>,
    /// Additional CodeQL query pack references (e.g. "codeql/python-queries").
    pub suite_refs: Vec<String>,
}

impl QueryPack {
    /// Build the default query pack: built-in MCP queries + standard security suites.
    pub fn default() -> Result<Self> {
        let mcp_dir = builtin_mcp_query_dir()?;
        let mut query_files = Vec::new();
        for entry in std::fs::read_dir(&mcp_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("ql") {
                query_files.push(path);
            }
        }
        Ok(Self {
            query_files,
            suite_refs: vec![
                "codeql/python-queries".to_string(),
                "codeql/javascript-queries".to_string(),
            ],
        })
    }

    /// Load a user-specified query pack directory.
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

/// Resolve the active query pack: user override or built-in default.
pub fn resolve_query_pack(custom_path: Option<&str>) -> Result<QueryPack> {
    match custom_path {
        Some(p) => QueryPack::from_path(Path::new(p)),
        None => QueryPack::default(),
    }
}

/// Directory containing built-in MCP CodeQL queries.
fn builtin_mcp_query_dir() -> Result<PathBuf> {
    // Relative to the crate source at build/run time
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("static_analysis")
        .join("codeql")
        .join("queries")
        .join("mcp");
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
    fn default_query_pack_includes_mcp_queries() {
        let pack = QueryPack::default().expect("default query pack");
        assert!(
            !pack.query_files.is_empty(),
            "Expected at least one built-in .ql file"
        );
        assert!(pack.query_files.iter().any(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |n| n.contains("ToolParameterToSink"))
        }));
        assert_eq!(
            pack.suite_refs,
            vec!["codeql/python-queries", "codeql/javascript-queries"]
        );
    }

    #[test]
    fn resolve_custom_path_overrides_default() {
        let tmp = std::env::temp_dir().join("codeql-test-queries");
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        std::fs::write(tmp.join("test.ql"), "// test query").expect("write test file");

        let pack = resolve_query_pack(Some(tmp.to_str().unwrap()))
            .expect("resolve custom pack");
        assert!(!pack.query_files.is_empty());
        assert!(pack.suite_refs.is_empty());

        std::fs::remove_dir_all(&tmp).expect("cleanup");
    }

    #[test]
    fn missing_custom_path_returns_error() {
        let err = resolve_query_pack(Some("/nonexistent/path/xyz"))
            .expect_err("nonexistent path should fail");
        assert!(err.to_string().contains("does not exist"));
    }
}
