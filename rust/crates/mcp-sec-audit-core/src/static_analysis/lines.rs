use anyhow::{Result, bail};

use crate::{
    AgentAnalysisResult, RuleAnalysisResult, RuleBook, TaintAnalysisResult,
    static_analysis::{pipeline::StaticScanContext, rule},
};

pub fn run_rule_line(
    ctx: &StaticScanContext,
    rulebook: Option<&RuleBook>,
) -> Result<Vec<RuleAnalysisResult>> {
    if !ctx.config.static_.rule.enabled {
        return Ok(Vec::new());
    }

    let Some(rulebook) = rulebook else {
        bail!("rule analysis line is enabled but no rulebook was loaded");
    };

    if rulebook.is_empty() {
        bail!("rule analysis line is enabled but rulebook is empty");
    }

    rule::analyze_rule_line(ctx, rulebook)
}

pub fn run_taint_line(ctx: &StaticScanContext) -> Result<Vec<TaintAnalysisResult>> {
    if !ctx.config.static_.taint.enabled {
        return Ok(Vec::new());
    }

    bail!(
        "taint analysis line is enabled but not implemented until Phase 10/11; disable [static.taint].enabled or continue the refactor roadmap"
    )
}

pub fn run_agent_line(ctx: &StaticScanContext) -> Result<Vec<AgentAnalysisResult>> {
    if !ctx.config.static_.agent.enabled {
        return Ok(Vec::new());
    }

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeConfig, static_analysis::DiscoveredFile};

    #[test]
    fn disabled_rule_line_returns_empty_without_rulebook() {
        let mut config = RuntimeConfig::default();
        config.static_.rule.enabled = false;
        let ctx = StaticScanContext {
            config,
            rulebook_paths: Vec::new(),
            discovered_files: Vec::<DiscoveredFile>::new(),
        };

        let results = run_rule_line(&ctx, None).expect("run rule line");
        assert!(results.is_empty());
    }

    #[test]
    fn enabled_rule_line_requires_rulebook() {
        let ctx = StaticScanContext {
            config: RuntimeConfig::default(),
            rulebook_paths: Vec::new(),
            discovered_files: Vec::<DiscoveredFile>::new(),
        };

        let err = run_rule_line(&ctx, None).expect_err("missing rulebook should fail");
        assert!(err.to_string().contains("no rulebook was loaded"));
    }

    #[test]
    fn disabled_taint_line_returns_empty() {
        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = false;
        let ctx = StaticScanContext {
            config,
            rulebook_paths: Vec::new(),
            discovered_files: Vec::<DiscoveredFile>::new(),
        };

        let results = run_taint_line(&ctx).expect("run disabled taint line");
        assert!(results.is_empty());
    }

    #[test]
    fn enabled_taint_line_reports_unimplemented_error() {
        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = true;
        let ctx = StaticScanContext {
            config,
            rulebook_paths: Vec::new(),
            discovered_files: Vec::<DiscoveredFile>::new(),
        };

        let err = run_taint_line(&ctx).expect_err("enabled taint line should fail");
        assert!(
            err.to_string()
                .contains("taint analysis line is enabled but not implemented")
        );
        assert!(err.to_string().contains("disable [static.taint].enabled"));
    }
}
