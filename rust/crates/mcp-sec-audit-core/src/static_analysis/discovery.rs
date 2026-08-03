use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::ScanConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLanguage {
    Python,
    JavaScript,
    TypeScript,
    Rust,
    Json,
}

impl ScanLanguage {
    pub fn config_keys(self) -> &'static [&'static str] {
        match self {
            Self::Python => &["python"],
            Self::JavaScript => &["javascript", "js"],
            Self::TypeScript => &["typescript", "ts"],
            Self::Rust => &["rust"],
            Self::Json => &["json", "metadata"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredFile {
    pub path: PathBuf,
    pub language: ScanLanguage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverySummary {
    pub scanned_targets: Vec<String>,
    pub discovered_files: Vec<DiscoveredFile>,
    pub skipped_paths: usize,
}

pub fn detect_language(path: &Path) -> Option<ScanLanguage> {
    let extension = path.extension()?.to_string_lossy().to_lowercase();
    match extension.as_str() {
        "py" => Some(ScanLanguage::Python),
        "js" | "mjs" | "cjs" => Some(ScanLanguage::JavaScript),
        "ts" | "mts" | "cts" | "tsx" => Some(ScanLanguage::TypeScript),
        "rs" => Some(ScanLanguage::Rust),
        "json" => Some(ScanLanguage::Json),
        _ => None,
    }
}

pub fn discover_files(targets: &[PathBuf], scan: &ScanConfig) -> Result<DiscoverySummary> {
    let enabled = enabled_languages(scan);
    let mut discovered = BTreeSet::new();
    let mut skipped_paths = 0usize;

    for target in targets {
        if !target.exists() {
            bail!("scan target does not exist: {}", target.display());
        }

        if target.is_file() {
            if let Some(file) = discover_file(target, &enabled, scan) {
                discovered.insert((file.path.clone(), file.language));
            } else {
                skipped_paths += 1;
            }
            continue;
        }

        if target.is_dir() {
            walk_directory(target, scan, &enabled, &mut discovered, &mut skipped_paths)
                .with_context(|| format!("discover files under {}", target.display()))?;
            continue;
        }

        skipped_paths += 1;
    }

    let discovered_files = discovered
        .into_iter()
        .map(|(path, language)| DiscoveredFile { path, language })
        .collect();

    Ok(DiscoverySummary {
        scanned_targets: targets
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        discovered_files,
        skipped_paths,
    })
}

pub fn is_excluded(path: &Path, excludes: &[String]) -> bool {
    if excludes.is_empty() {
        return false;
    }

    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        excludes.iter().any(|exclude| value == exclude.as_str())
    })
}

fn walk_directory(
    directory: &Path,
    scan: &ScanConfig,
    enabled: &BTreeSet<ScanLanguage>,
    discovered: &mut BTreeSet<(PathBuf, ScanLanguage)>,
    skipped_paths: &mut usize,
) -> Result<()> {
    if is_excluded(directory, &scan.exclude) {
        *skipped_paths += 1;
        return Ok(());
    }

    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("read directory {}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if is_excluded(&path, &scan.exclude) {
            *skipped_paths += 1;
            continue;
        }
        if path.is_dir() {
            walk_directory(&path, scan, enabled, discovered, skipped_paths)?;
        } else if path.is_file() {
            if let Some(file) = discover_file(&path, enabled, scan) {
                discovered.insert((file.path, file.language));
            } else {
                *skipped_paths += 1;
            }
        } else {
            *skipped_paths += 1;
        }
    }

    Ok(())
}

fn discover_file(
    path: &Path,
    enabled: &BTreeSet<ScanLanguage>,
    scan: &ScanConfig,
) -> Option<DiscoveredFile> {
    if is_excluded(path, &scan.exclude) {
        return None;
    }
    let language = detect_language(path)?;
    if !enabled.contains(&language) {
        return None;
    }
    Some(DiscoveredFile {
        path: path.to_path_buf(),
        language,
    })
}

fn enabled_languages(scan: &ScanConfig) -> BTreeSet<ScanLanguage> {
    let configured = scan
        .languages
        .iter()
        .map(|language| language.to_lowercase())
        .collect::<BTreeSet<_>>();

    [
        ScanLanguage::Python,
        ScanLanguage::JavaScript,
        ScanLanguage::TypeScript,
        ScanLanguage::Rust,
        ScanLanguage::Json,
    ]
    .into_iter()
    .filter(|language| {
        language
            .config_keys()
            .iter()
            .any(|key| configured.contains(*key))
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    #[test]
    fn detects_supported_languages_by_extension() {
        assert_eq!(
            detect_language(Path::new("server.py")),
            Some(ScanLanguage::Python)
        );
        assert_eq!(
            detect_language(Path::new("server.js")),
            Some(ScanLanguage::JavaScript)
        );
        assert_eq!(
            detect_language(Path::new("server.tsx")),
            Some(ScanLanguage::TypeScript)
        );
        assert_eq!(
            detect_language(Path::new("main.rs")),
            Some(ScanLanguage::Rust)
        );
        assert_eq!(
            detect_language(Path::new("tool.json")),
            Some(ScanLanguage::Json)
        );
        assert_eq!(detect_language(Path::new("README.md")), None);
    }

    #[test]
    fn excludes_path_segments() {
        assert!(is_excluded(
            Path::new("src/node_modules/pkg/index.js"),
            &["node_modules".to_string()]
        ));
        assert!(!is_excluded(
            Path::new("src/node_modules_like/index.js"),
            &["node_modules".to_string()]
        ));
    }

    #[test]
    fn discovers_files_with_language_filter_and_excludes() {
        let root = temp_dir("discover_files");
        fs::create_dir_all(root.join("src")).expect("create src");
        fs::create_dir_all(root.join("target")).expect("create target");
        fs::write(root.join("src/server.py"), "print('ok')").expect("write py");
        fs::write(root.join("src/app.ts"), "export {};").expect("write ts");
        fs::write(root.join("src/meta.json"), "{}").expect("write json");
        fs::write(root.join("target/ignored.rs"), "fn main() {}").expect("write ignored");

        let mut scan = ScanConfig::default();
        scan.languages = vec!["python".to_string(), "typescript".to_string()];
        let summary = discover_files(&[root.clone()], &scan).expect("discover files");

        let paths = summary
            .discovered_files
            .iter()
            .map(|file| file.path.strip_prefix(&root).unwrap().display().to_string())
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["src/app.ts", "src/server.py"]);
        assert!(summary.skipped_paths >= 2);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn includes_json_only_when_enabled() {
        let root = temp_dir("discover_json");
        fs::write(root.join("meta.json"), "{}").expect("write json");

        let scan = ScanConfig::default();
        assert!(
            discover_files(&[root.clone()], &scan)
                .unwrap()
                .discovered_files
                .is_empty()
        );

        let mut scan = ScanConfig::default();
        scan.languages.push("metadata".to_string());
        let summary = discover_files(&[root.clone()], &scan).expect("discover json");
        assert_eq!(summary.discovered_files.len(), 1);
        assert_eq!(summary.discovered_files[0].language, ScanLanguage::Json);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn missing_target_errors() {
        let err = discover_files(
            &[PathBuf::from("/definitely/missing/mcp-sec-audit")],
            &ScanConfig::default(),
        )
        .expect_err("missing target should fail");
        assert!(err.to_string().contains("scan target does not exist"));
    }

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mcp-sec-audit-{name}-{suffix}"));
        fs::create_dir_all(&root).expect("create temp dir");
        root
    }
}
