use std::fs;

use anyhow::{Context, Result, bail};

use crate::{Fact, ScanLanguage, static_analysis::pipeline::StaticScanContext};

use super::extract_python_facts;

pub fn extract_static_facts(ctx: &StaticScanContext) -> Result<Vec<Fact>> {
    let mut facts = Vec::new();
    let mut diagnostics = Vec::new();

    for file in &ctx.discovered_files {
        if file.language != ScanLanguage::Python {
            continue;
        }

        let source = fs::read_to_string(&file.path).with_context(|| {
            format!(
                "read Python source for fact extraction: {}",
                file.path.display()
            )
        })?;
        let root = file.path.parent().unwrap_or_else(|| file.path.as_path());
        let result = extract_python_facts(root, &file.path, &source);
        facts.extend(result.facts);
        diagnostics.extend(result.diagnostics);
    }

    if !diagnostics.is_empty() {
        let summary = diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "{}:{} {}: {}",
                    diagnostic.file, diagnostic.line, diagnostic.kind, diagnostic.message
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        bail!("Python fact extraction produced diagnostics: {summary}");
    }

    Ok(facts)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{RuntimeConfig, static_analysis::DiscoveredFile};

    #[test]
    fn extract_static_facts_reads_python_discovered_files() {
        let root = temp_dir("facts-pipeline");
        let file = root.join("server.py");
        fs::write(
            &file,
            r#"
import subprocess as sp

@mcp.tool()
def run_command(command: str):
    runner = sp.run
    return runner(command, shell=True)
"#,
        )
        .expect("write Python file");

        let ctx = StaticScanContext {
            config: RuntimeConfig::default(),
            rulebook_paths: Vec::new(),
            discovered_files: vec![DiscoveredFile {
                path: file,
                language: ScanLanguage::Python,
            }],
        };

        let facts = extract_static_facts(&ctx).expect("extract facts");
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Import(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Function(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Entrypoint(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Source(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Call(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Assign(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Sink(_))));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn extract_static_facts_reports_python_diagnostics() {
        let root = temp_dir("facts-diagnostic");
        let file = root.join("broken.py");
        fs::write(&file, "def broken(:\n    pass\n").expect("write Python file");

        let ctx = StaticScanContext {
            config: RuntimeConfig::default(),
            rulebook_paths: Vec::new(),
            discovered_files: vec![DiscoveredFile {
                path: file,
                language: ScanLanguage::Python,
            }],
        };

        let err = extract_static_facts(&ctx).expect_err("diagnostics should fail extraction");
        assert!(
            err.to_string()
                .contains("Python fact extraction produced diagnostics")
        );
        assert!(err.to_string().contains("syntax_error"));

        fs::remove_dir_all(root).expect("cleanup");
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
