pub(crate) mod matcher;
mod merger;
mod scorer;

use crate::config::FusionConfig;
use crate::model::{
    AgentAnalysisResult, CodeqlAnalysisResult, FusedFinding, RuleAnalysisResult,
    TaintAnalysisResult,
};

/// Run the fusion pipeline across all four analysis lines.
///
/// 1. [matcher::match_results] groups rule, taint, agent, and codeql results by
///    file/line proximity and category.
/// 2. [scorer::score_groups] filters and scores each group.
/// 3. [merger::merge_groups] builds the final [`FusedFinding`]s.
///
/// When `config.enabled` is `false`, returns an empty `Vec`.
pub(crate) fn run(
    config: &FusionConfig,
    rule_results: Vec<RuleAnalysisResult>,
    taint_results: Vec<TaintAnalysisResult>,
    agent_results: Vec<AgentAnalysisResult>,
    codeql_results: Vec<CodeqlAnalysisResult>,
) -> Vec<FusedFinding> {
    if !config.enabled {
        return Vec::new();
    }

    // Four-line fusion
    let match_groups = matcher::match_results(
        rule_results,
        taint_results,
        agent_results,
        codeql_results,
        config.line_proximity,
    );
    tracing::info!(
        target: "mcp_sec_audit::fusion",
        groups = match_groups.len(),
        "fusion match groups formed"
    );

    let scored_groups = scorer::score_groups(match_groups, config);
    tracing::info!(
        target: "mcp_sec_audit::fusion",
        surviving = scored_groups.len(),
        "fusion score pass complete"
    );

    merger::merge_groups(scored_groups)
}
