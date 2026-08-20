use std::fs;

use anyhow::{Context, Result, bail};

use crate::models::{default_catalog, load_models_dir};
use crate::{Fact, ScanLanguage, static_analysis::pipeline::StaticScanContext};

use super::{extract_js_ts_facts, extract_python_facts, extract_rust_facts, ExtractionDiagnostic};

pub fn extract_static_facts(ctx: &StaticScanContext) -> Result<Vec<Fact>> {
    let mut facts = Vec::new();
    let mut diagnostics = Vec::new();

    let mut catalog = default_catalog();
    if let Some(dir) = &ctx.config.static_.models_dir {
        let extra = load_models_dir(std::path::Path::new(dir))?;
        tracing::info!(
            target: "mcp_sec_audit::taint",
            models_dir = %dir,
            loaded = extra.sink_count(),
            "loaded extra sink models"
        );
        catalog.merge(extra);
    }
    tracing::info!(
        target: "mcp_sec_audit::taint",
        sinks = catalog.sink_count(),
        "sink model catalog ready"
    );

    for file in &ctx.discovered_files {
        match file.language {
            ScanLanguage::Python => {
                let source = fs::read_to_string(&file.path).with_context(|| {
                    format!(
                        "read Python source for fact extraction: {}",
                        file.path.display()
                    )
                })?;
                let root = file.path.parent().unwrap_or_else(|| file.path.as_path());
                let result = extract_python_facts(
                    root,
                    &file.path,
                    &source,
                    catalog.sinks_for_language("python"),
                );
                facts.extend(result.facts);
                diagnostics.extend(result.diagnostics);
            }
            ScanLanguage::JavaScript | ScanLanguage::TypeScript => {
                let source = fs::read_to_string(&file.path).with_context(|| {
                    format!(
                        "read JS/TS source for fact extraction: {}",
                        file.path.display()
                    )
                })?;
                let root = file.path.parent().unwrap_or_else(|| file.path.as_path());
                let result = extract_js_ts_facts(
                    root,
                    &file.path,
                    &source,
                    catalog.sinks_for_language("javascript"),
                );
                if result.has_fatal() {
                    bail!("JS/TS fact extraction produced fatal errors");
                }
                facts.extend(result.facts);
                diagnostics.extend(
                    result.diagnostics.into_iter().map(ExtractionDiagnostic::from),
                );
            }
            ScanLanguage::Rust => {
                let source = fs::read_to_string(&file.path).with_context(|| {
                    format!(
                        "read Rust source for fact extraction: {}",
                        file.path.display()
                    )
                })?;
                let root = file.path.parent().unwrap_or_else(|| file.path.as_path());
                let result = extract_rust_facts(
                    root,
                    &file.path,
                    &source,
                    catalog.sinks_for_language("rust"),
                );
                facts.extend(result.facts);
                diagnostics.extend(result.diagnostics);
            }
            _ => continue,
        }
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
        bail!("fact extraction produced diagnostics: {summary}");
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
                .contains("fact extraction produced diagnostics")
        );
        assert!(err.to_string().contains("syntax_error"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn extract_static_facts_reads_rust_discovered_files() {
        let root = temp_dir("facts-pipeline-rust");
        let file = root.join("server.rs");
        fs::write(
            &file,
            r#"
use std::process::Command;

#[tool]
async fn run_command(command: String) -> Result<String, String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
"#,
        )
        .expect("write Rust file");

        let ctx = StaticScanContext {
            config: RuntimeConfig::default(),
            rulebook_paths: Vec::new(),
            discovered_files: vec![DiscoveredFile {
                path: file,
                language: ScanLanguage::Rust,
            }],
        };

        let facts = extract_static_facts(&ctx).expect("extract facts");
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Import(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Function(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Entrypoint(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Source(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Call(_))));
        assert!(facts.iter().any(|fact| matches!(fact, Fact::Sink(_))));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn custom_sink_model_is_picked_up_from_models_slice() {
        let model = crate::models::SinkModel {
            language: "python".into(),
            category: "command_execution".into(),
            severity: crate::Severity::High,
            confidence: crate::Confidence::High,
            reason: "custom".into(),
            patterns: vec!["totally.custom.sink".into()],
        };
        let source = "import os\ntotally.custom.sink('x')\n";
        let result = extract_python_facts(
            std::path::Path::new("/repo"),
            std::path::Path::new("/repo/a.py"),
            source,
            std::slice::from_ref(&model),
        );
        assert!(result
            .facts
            .iter()
            .any(|f| matches!(f, Fact::Sink(s) if s.sink_name == "totally.custom.sink")));
    }

    #[test]
    fn models_dir_loads_and_merges_custom_sinks() {
        let root = temp_dir("models-dir");
        let models_dir = root.join("models");
        fs::create_dir_all(&models_dir).expect("create models dir");
        fs::write(
            models_dir.join("custom.yaml"),
            "- language: python\n  category: command_execution\n  severity: high\n  confidence: high\n  reason: custom\n  patterns: [totally.custom.sink]\n",
        )
        .expect("write custom model");
        let file = root.join("a.py");
        fs::write(&file, "totally.custom.sink('x')\n").expect("write source");

        let mut config = RuntimeConfig::default();
        config.static_.models_dir = Some(models_dir.display().to_string());
        let ctx = StaticScanContext {
            config,
            rulebook_paths: Vec::new(),
            discovered_files: vec![DiscoveredFile {
                path: file.clone(),
                language: ScanLanguage::Python,
            }],
        };
        let facts = extract_static_facts(&ctx).expect("extract facts");
        assert!(facts
            .iter()
            .any(|f| matches!(f, Fact::Sink(s) if s.sink_name == "totally.custom.sink")));

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
