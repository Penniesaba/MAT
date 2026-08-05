use anyhow::Result;

use crate::{
    AgentAnalysisResult, Fact, RuleAnalysisResult, RuleBook, TaintAnalysisResult,
    static_analysis::{pipeline::StaticScanContext, rule},
};

pub fn run_rule_line(
    ctx: &StaticScanContext,
    rulebook: Option<&RuleBook>,
) -> Result<Vec<RuleAnalysisResult>> {
    rule::run(ctx, rulebook)
}

pub fn run_taint_line(
    ctx: &StaticScanContext,
    facts: &[Fact],
) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)> {
    if !ctx.config.static_.taint.enabled {
        return Ok((Vec::new(), Vec::new()));
    }

    super::taint::run_taint_analysis(facts, &ctx.config.static_.taint)
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

        let (results, dataflows) =
            run_taint_line(&ctx, &[]).expect("run disabled taint line");
        assert!(results.is_empty());
        assert!(dataflows.is_empty());
    }

    #[test]
    fn enabled_taint_line_runs_analysis() {
        use crate::model::{
            CallArg, CallFact, Confidence, EntryPointEvidence, EntryPointFact, EntryPointKind,
            FactBase, FunctionFact, ParamInfo, Severity, SinkFact, SourceFact,
        };

        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = true;

        let facts = vec![
            Fact::Function(FunctionFact {
                base: FactBase { id: "python:s.py:h".into(), file: "s.py".into(), line: 1, extractor: "t".into() },
                language: "python".into(), name: "h".into(), qualified_name: "h".into(),
                end_line: 5, params: vec![ParamInfo { name: "cmd".into(), annotation: None, default: None }],
                decorators: vec!["@mcp.tool()".into()], docstring: None, return_type: None, enclosing_class: None,
            }),
            Fact::Entrypoint(EntryPointFact {
                base: FactBase { id: "entry:s.py:h".into(), file: "s.py".into(), line: 1, extractor: "t".into() },
                kind: EntryPointKind::McpTool, name: "h".into(),
                function_id: "python:s.py:h".into(),
                evidence: Some(EntryPointEvidence { kind: "decorator".into(), text: "@mcp.tool()".into() }),
                params: vec!["cmd".into()], confidence: Confidence::High,
            }),
            Fact::Source(SourceFact {
                base: FactBase { id: "source:s.py:h:cmd".into(), file: "s.py".into(), line: 1, extractor: "t".into() },
                kind: "mcp_tool_parameter".into(), function_id: "python:s.py:h".into(),
                name: "cmd".into(), confidence: Confidence::High,
            }),
            Fact::Call(CallFact {
                base: FactBase { id: "call:s.py:3:0".into(), file: "s.py".into(), line: 3, extractor: "t".into() },
                caller: "python:s.py:h".into(), callee: "os.system".into(),
                normalized_callee: Some("os.system".into()),
                column: Some(0), end_line: Some(3), snippet: "os.system(cmd)".into(),
                args: vec![CallArg { index: 0, expr: "cmd".into(), kind: "positional".into() }],
                kwargs: std::collections::BTreeMap::new(), resolution: None,
            }),
            Fact::Sink(SinkFact {
                base: FactBase { id: "sink:cmd:s.py:3".into(), file: "s.py".into(), line: 3, extractor: "t".into() },
                call_id: "call:s.py:3:0".into(), category: "command_execution".into(),
                rule_id: "python.command_execution".into(), sink_name: "os.system".into(),
                severity_base: Severity::Critical, reason: "dangerous".into(),
                conditions: std::collections::BTreeMap::new(), confidence: Confidence::High,
            }),
        ];

        let ctx = StaticScanContext {
            config,
            rulebook_paths: Vec::new(),
            discovered_files: Vec::new(),
        };

        let (results, dataflows) = run_taint_line(&ctx, &facts).expect("run taint line");
        assert!(!results.is_empty(), "expected taint results");
        assert!(!dataflows.is_empty(), "expected dataflow facts");
    }
}
