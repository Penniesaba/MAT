mod parser;
mod prompt;
pub mod provider;

use anyhow::Result;

use crate::model::AgentAnalysisResult;

use super::pipeline::StaticScanContext;
use prompt::FileSummary;
use provider::{AgentProvider, AgentRunConfig, CliAgentProvider};

/// Hardcoded constants (not user-configurable).
const PROMPT_PROFILE: &str = "mcp_security_audit";
const MAX_FILES: usize = 80;

/// Resolve `path` to an absolute path. Prefers `canonicalize` (resolves `..`
/// and symlinks, and requires the path to exist); falls back to joining the
/// current directory so the result is still absolute even if the path was
/// deleted between discovery and here.
fn absolute_path(path: &std::path::Path) -> std::path::PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    path.canonicalize().unwrap_or_else(|_| {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    })
}

/// Agent line entry point.
///
/// Prepares file context, renders the prompt template, invokes the
/// configured CLI agent provider, and parses structured results from
/// the agent's output.
pub fn run(ctx: &StaticScanContext) -> Result<Vec<AgentAnalysisResult>> {
    let agent_config = &ctx.config.static_.agent;

    if !agent_config.enabled {
        return Ok(Vec::new());
    }

    // Build file summaries (capped at MAX_FILES)
    let file_summaries: Vec<FileSummary> = ctx
        .discovered_files
        .iter()
        .take(MAX_FILES)
        .map(|df| {
            let line_count = std::fs::read_to_string(&df.path)
                .map(|s| s.lines().count())
                .unwrap_or(0);
            FileSummary {
                // Canonicalize to an absolute path: the agent subprocess runs
                // with a different cwd (target_root), so the relative paths
                // produced by discovery would not resolve there.
                path: absolute_path(&df.path).display().to_string(),
                language: df.language.config_keys()[0].to_string(),
                line_count,
            }
        })
        .collect();

    if file_summaries.is_empty() {
        return Ok(Vec::new());
    }

    // Determine target root from the first file's parent (canonicalized so the
    // agent subprocess runs in a valid absolute directory).
    let target_root = ctx
        .discovered_files
        .first()
        .and_then(|df| df.path.parent())
        .map(|p| absolute_path(p).display().to_string())
        .unwrap_or_else(|| ".".to_string());

    // Render the prompt
    let prompt = prompt::render(
        agent_config.prompt_template_path.as_deref(),
        &file_summaries,
        &target_root,
    )?;

    // Build input scope for metadata
    let input_scope: Vec<String> = file_summaries
        .iter()
        .map(|fs| fs.path.clone())
        .collect();

    // Invoke the agent provider
    let provider = CliAgentProvider;
    let run_config = AgentRunConfig {
        working_dir: target_root,
        prompt,
        provider_binary: agent_config.provider.clone(),
        max_turns: agent_config.max_turns,
        timeout_seconds: agent_config.timeout_seconds,
        extra_args: agent_config.extra_args.clone(),
    };

    let output = provider.run(&run_config)?;

    // Parse results
    let metadata = parser::AgentMetadata {
        agent_id: agent_config.provider.clone(),
        prompt_profile: PROMPT_PROFILE.to_string(),
        input_scope,
    };

    let mut results = parser::parse_agent_output(&output.stdout, &metadata)?;

    // Annotate timeout limitation
    if output.timed_out {
        for r in &mut results {
            r.limitations.push(format!(
                "agent analysis timed out after {}s",
                agent_config.timeout_seconds
            ));
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeConfig;

    #[test]
    fn disabled_agent_returns_empty() {
        let ctx = StaticScanContext {
            config: RuntimeConfig::default(), // agent disabled by default
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        let results = run(&ctx).expect("run disabled agent");
        assert!(results.is_empty());
    }

    #[test]
    fn enabled_with_no_files_returns_empty() {
        let mut config = RuntimeConfig::default();
        config.static_.agent.enabled = true;
        let ctx = StaticScanContext {
            config,
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };
        let results = run(&ctx).expect("run agent with no files");
        assert!(results.is_empty());
    }
}
