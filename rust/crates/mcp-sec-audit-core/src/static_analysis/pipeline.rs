use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use crate::{
    ConfigSnapshot, RuleBook, RuntimeConfig, StaticAnalysisResult, StaticAnalysisSummary,
    load_rulebook,
};

use super::{DiscoveredFile, discover_files, extract_static_facts, lines};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticScanContext {
    pub config: RuntimeConfig,
    pub rulebook_paths: Vec<String>,
    pub discovered_files: Vec<DiscoveredFile>,
}

pub fn run_static_scan(
    config: &RuntimeConfig,
    rulebook_paths: &[PathBuf],
    target_overrides: Option<&[PathBuf]>,
) -> Result<StaticAnalysisResult> {
    let mut effective_config = config.clone();
    if let Some(targets) = target_overrides {
        effective_config.scan.targets = targets
            .iter()
            .map(|target| target.display().to_string())
            .collect();
    }

    let targets = effective_config
        .scan
        .targets
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();

    if !effective_config.static_.enabled {
        return Ok(empty_result(
            effective_config,
            rulebook_paths_to_strings(rulebook_paths),
            target_label(&targets),
        ));
    }

    let discovery = discover_files(&targets, &effective_config.scan)?;
    let effective_rulebook_paths = if rulebook_paths.is_empty() {
        effective_config
            .static_
            .rule
            .rule_paths
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>()
    } else {
        rulebook_paths.to_vec()
    };

    let loaded_rulebook = if effective_config.static_.rule.enabled {
        Some(load_merged_rulebook(&effective_rulebook_paths)?)
    } else {
        None
    };

    let ctx = StaticScanContext {
        config: effective_config.clone(),
        rulebook_paths: rulebook_paths_to_strings(&effective_rulebook_paths),
        discovered_files: discovery.discovered_files,
    };

    let facts = extract_static_facts(&ctx)?;
    let rule_results = lines::run_rule_line(&ctx, loaded_rulebook.as_ref())?;
    let taint_results = lines::run_taint_line(&ctx)?;
    let agent_results = lines::run_agent_line(&ctx)?;

    let summary = StaticAnalysisSummary {
        target: target_label(&targets),
        fact_count: facts.len(),
        rule_result_count: rule_results.len(),
        taint_result_count: taint_results.len(),
        agent_result_count: agent_results.len(),
        fused_finding_count: 0,
        highest_severity: None,
        risk_level: "none".to_string(),
    };

    Ok(StaticAnalysisResult {
        facts,
        rule_results,
        taint_results,
        agent_results,
        fused_findings: Vec::new(),
        summary,
        config_snapshot: ConfigSnapshot {
            runtime: effective_config,
            rulebook_paths: ctx.rulebook_paths,
        },
    })
}

pub fn load_merged_rulebook(paths: &[PathBuf]) -> Result<RuleBook> {
    let files = expand_rulebook_paths(paths)?;
    let mut capabilities = BTreeMap::new();

    for path in files {
        let rulebook = load_rulebook(&path)?;
        for (name, rule) in rulebook.capabilities {
            if capabilities.insert(name.clone(), rule).is_some() {
                bail!("duplicate capability '{name}' while loading rulebooks");
            }
        }
    }

    Ok(RuleBook { capabilities })
}

fn expand_rulebook_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in paths {
        if !path.exists() {
            bail!("rulebook path does not exist: {}", path.display());
        }
        if path.is_file() {
            if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
                files.push(path.clone());
            }
            continue;
        }
        if path.is_dir() {
            collect_toml_files(path, &mut files)
                .with_context(|| format!("expand rulebook directory {}", path.display()))?;
            continue;
        }
        bail!(
            "rulebook path is neither file nor directory: {}",
            path.display()
        );
    }
    files.sort();
    Ok(files)
}

fn collect_toml_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("read rulebook directory {}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_toml_files(&path, files)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
            files.push(path);
        }
    }

    Ok(())
}

fn empty_result(
    runtime: RuntimeConfig,
    rulebook_paths: Vec<String>,
    target: String,
) -> StaticAnalysisResult {
    StaticAnalysisResult {
        facts: Vec::new(),
        rule_results: Vec::new(),
        taint_results: Vec::new(),
        agent_results: Vec::new(),
        fused_findings: Vec::new(),
        summary: StaticAnalysisSummary {
            target,
            fact_count: 0,
            rule_result_count: 0,
            taint_result_count: 0,
            agent_result_count: 0,
            fused_finding_count: 0,
            highest_severity: None,
            risk_level: "none".to_string(),
        },
        config_snapshot: ConfigSnapshot {
            runtime,
            rulebook_paths,
        },
    }
}

fn target_label(targets: &[PathBuf]) -> String {
    if targets.is_empty() {
        return "<none>".to_string();
    }
    targets
        .iter()
        .map(|target| target.display().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn rulebook_paths_to_strings(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::Fact;

    #[test]
    fn disabled_static_scan_returns_empty_result() {
        let root = temp_dir("disabled");
        fs::write(root.join("server.py"), "print('ok')").expect("write file");
        let mut config = RuntimeConfig::default();
        config.static_.enabled = false;

        let result = run_static_scan(&config, &[], Some(&[root.clone()])).expect("run scan");
        assert_eq!(result.summary.risk_level, "none");
        assert!(result.rule_results.is_empty());
        assert!(result.config_snapshot.runtime.static_.enabled == false);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn enabled_static_scan_runs_rule_line() {
        let root = temp_dir("enabled");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(root.join("server.py"), "subprocess.run('id')").expect("write file");

        let result = run_static_scan(
            &RuntimeConfig::default(),
            &[rules.clone()],
            Some(&[root.clone()]),
        )
        .expect("run scan");
        assert_eq!(result.summary.rule_result_count, 1);
        assert_eq!(result.rule_results[0].rule_id, "command_exec");
        assert_eq!(result.summary.taint_result_count, 0);
        assert_eq!(result.summary.agent_result_count, 0);
        assert!(!result.facts.is_empty());
        assert_eq!(result.summary.fact_count, result.facts.len());
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Call(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Sink(_)))
        );
        assert_eq!(
            result.config_snapshot.rulebook_paths,
            vec![rules.display().to_string()]
        );

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn enabled_static_scan_includes_python_facts_and_fact_count() {
        let root = temp_dir("scan-facts");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(
            root.join("server.py"),
            r#"
import subprocess as sp

@mcp.tool()
def run_command(command: str):
    runner = sp.run
    command_text = command.strip()
    return runner(command_text, shell=True)
"#,
        )
        .expect("write file");

        let result = run_static_scan(&RuntimeConfig::default(), &[rules], Some(&[root.clone()]))
            .expect("run scan");

        assert!(!result.facts.is_empty());
        assert_eq!(result.summary.fact_count, result.facts.len());
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Import(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Function(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Entrypoint(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Source(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Call(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Assign(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Sink(_)))
        );
        assert_eq!(result.summary.taint_result_count, 0);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rulebook_directory_expands_toml_files() {
        let root = temp_dir("rule-dir");
        let rules_dir = root.join("rules");
        fs::create_dir_all(&rules_dir).expect("create rules dir");
        write_rulebook(&rules_dir, "a.toml", "command_exec");
        write_rulebook(&rules_dir, "b.toml", "file_read");

        let rulebook = load_merged_rulebook(&[rules_dir]).expect("load merged rulebook");
        assert_eq!(rulebook.len(), 2);
        assert!(rulebook.capabilities.contains_key("command_exec"));
        assert!(rulebook.capabilities.contains_key("file_read"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn duplicate_rulebook_capabilities_fail() {
        let root = temp_dir("duplicate-rules");
        let rules_dir = root.join("rules");
        fs::create_dir_all(&rules_dir).expect("create rules dir");
        write_rulebook(&rules_dir, "a.toml", "command_exec");
        write_rulebook(&rules_dir, "b.toml", "command_exec");

        let err = load_merged_rulebook(&[rules_dir]).expect_err("duplicate should fail");
        assert!(err.to_string().contains("duplicate capability"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    fn write_rulebook(root: &Path, name: &str, capability: &str) -> PathBuf {
        let path = root.join(name);
        fs::write(
            &path,
            format!(
                r#"
                [[capabilities]]
                name = "{capability}"
                  [[capabilities.indicators]]
                  languages = ["python"]
                  patterns = ["subprocess."]
                "#
            ),
        )
        .expect("write rulebook");
        path
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
