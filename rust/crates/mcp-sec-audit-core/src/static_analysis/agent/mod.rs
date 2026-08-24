mod adjudicate;
mod parser;
mod prompt;
pub mod provider;

use anyhow::Result;

use crate::model::AgentOutput;

use super::pipeline::StaticScanContext;
use prompt::FileSummary;
use provider::{AgentProvider, AgentRunConfig, CliAgentProvider};

// 两阶段编排（M3 Task 4）在 pipeline 里渲染 prompt' 并调用 run_with_prompt；
// 故把 prompt 的验证提示词原语 re-export 到 agent 模块面。
pub(crate) use prompt::{PromptFinding, render_explanation_prompt, render_verification_prompt};

// Self-consistent adjudication (Task 3/4): the runner consumes this rendered
// prompt as its input contract, so re-export at the agent module surface.
pub(crate) use adjudicate::{AdjudicationVerdict, parse_verdicts, render_adjudication_prompt, run_adjudication};

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

/// Agent line entry point (阶段 1).
///
/// Prepares file context, renders the prompt template, invokes the
/// configured CLI agent provider, and parses structured results from
/// the agent's output.
pub fn run(ctx: &StaticScanContext) -> Result<AgentOutput> {
    run_with_prompt(ctx, None)
}

/// 跑 agent，可选地在渲染好的基础 prompt 之后追加一段验证提示词（阶段 2 的 prompt'）。
pub(crate) fn run_with_prompt(
    ctx: &StaticScanContext,
    prompt_extra: Option<&str>,
) -> Result<AgentOutput> {
    let agent_config = &ctx.config.static_.agent;

    if !agent_config.enabled {
        return Ok(AgentOutput {
            findings: Vec::new(),
            model_candidates: Vec::new(),
        });
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
        return Ok(AgentOutput {
            findings: Vec::new(),
            model_candidates: Vec::new(),
        });
    }

    // Determine target root from the first file's parent (canonicalized so the
    // agent subprocess runs in a valid absolute directory).
    let target_root = ctx
        .discovered_files
        .first()
        .and_then(|df| df.path.parent())
        .map(|p| absolute_path(p).display().to_string())
        .unwrap_or_else(|| ".".to_string());

    // Render the prompt (base template + optional verification extra)
    let mut prompt = prompt::render(
        agent_config.prompt_template_path.as_deref(),
        &file_summaries,
        &target_root,
    )?;
    if let Some(extra) = prompt_extra {
        prompt.push_str(extra);
    }

    tracing::info!(
        target: "mcp_sec_audit::agent",
        prompt_bytes = prompt.len(),
        files = file_summaries.len(),
        "agent prompt rendered"
    );

    // Build input scope for metadata
    let input_scope: Vec<String> = file_summaries.iter().map(|fs| fs.path.clone()).collect();

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

    let mut agent_output = parser::parse_agent_output(&output.stdout, &metadata)?;

    // Annotate timeout limitation
    if output.timed_out {
        for r in &mut agent_output.findings {
            r.limitations.push(format!(
                "agent analysis timed out after {}s",
                agent_config.timeout_seconds
            ));
        }
    }

    tracing::info!(
        target: "mcp_sec_audit::agent",
        findings = agent_output.findings.len(),
        model_candidates = agent_output.model_candidates.len(),
        "agent analysis parsed"
    );

    Ok(agent_output)
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
        let output = run(&ctx).expect("run disabled agent");
        assert!(output.findings.is_empty());
        assert!(output.model_candidates.is_empty());
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
        let output = run(&ctx).expect("run agent with no files");
        assert!(output.findings.is_empty());
        assert!(output.model_candidates.is_empty());
    }
}
