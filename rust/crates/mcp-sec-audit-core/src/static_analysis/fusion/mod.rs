mod matcher;
mod scorer;
mod merger;
mod codeql_passthrough;

use crate::config::FusionConfig;
use crate::model::{AgentAnalysisResult, CodeqlAnalysisResult, FusedFinding, RuleAnalysisResult, TaintAnalysisResult};

/// Run the fusion pipeline across all four analysis lines.
///
/// 1. [matcher::match_results] groups rule, taint, and agent results by file/line proximity and category.
/// 2. [scorer::score_groups] filters and scores each group.
/// 3. [merger::merge_groups] builds the final [`FusedFinding`]s.
/// 4. [codeql_passthrough::passthrough_codeql] appends CodeQL results as standalone fused findings.
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

    // Three-line fusion
    let match_groups = matcher::match_results(
        rule_results,
        taint_results,
        agent_results,
        config.line_proximity,
    );

    let scored_groups = scorer::score_groups(match_groups, config);

    let mut fused = merger::merge_groups(scored_groups);

    // CodeQL passthrough (always appended, not interleaved)
    let codeql_fused = codeql_passthrough::passthrough_codeql(codeql_results);
    fused.extend(codeql_fused);

    fused
}
