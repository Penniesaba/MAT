pub mod graph;
pub mod builder;
pub mod propagation;
pub mod result;

use anyhow::Result;
use crate::config::StaticTaintConfig;
use crate::model::{Fact, TaintAnalysisResult};

use super::facts::extract_static_facts;
use super::pipeline::StaticScanContext;

/// Taint line entry point. Extracts facts from source files,
/// builds program graph, runs BFS propagation, returns results + all facts.
pub fn run(ctx: &StaticScanContext) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)> {
    if !ctx.config.static_.taint.enabled {
        return Ok((Vec::new(), Vec::new()));
    }

    let facts = extract_static_facts(ctx)?;
    let (results, dataflow_facts) =
        run_taint_analysis(&facts, &ctx.config.static_.taint)?;

    let mut all_facts = facts;
    all_facts.extend(dataflow_facts);

    Ok((results, all_facts))
}

/// Run the full taint analysis pipeline:
/// 1. Build unified graph from all facts
/// 2. Run forward and/or backward propagation per config
/// 3. Generate TaintAnalysisResult + DataFlowFact
pub fn run_taint_analysis(
    facts: &[Fact],
    config: &StaticTaintConfig,
) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)> {
    if !config.enabled {
        return Ok((Vec::new(), Vec::new()));
    }

    // Build the unified program graph
    let graph = builder::build_graph(facts);

    // Run propagation
    let paths = propagation::propagate_both(&graph, config);

    // Generate results
    let taint_results = result::build_taint_results(&paths, &graph);
    let dataflow_facts = result::build_dataflow_facts(&paths);

    Ok((taint_results, dataflow_facts))
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AssignFact, CallArg, CallFact, Confidence, EntryPointEvidence, EntryPointFact,
        EntryPointKind, Fact, FactBase, FunctionFact, ParamInfo, Severity, SinkFact, SourceFact,
    };

    fn default_config() -> StaticTaintConfig {
        StaticTaintConfig {
            enabled: true,
            forward: true,
            backward: true,
            max_depth: 8,
            entrypoint_required: true,
        }
    }

    /// Build a minimal but realistic fact set for a Python MCP server:
    ///   @mcp.tool()
    ///   def run_cmd(cmd: str):
    ///       os.system(cmd)
    fn python_direct_facts() -> Vec<Fact> {
        let file = "server.py".to_string();
        let func_id = "python:server.py:run_cmd".to_string();
        let call_id = "call:server.py:3:0".to_string();
        let sink_id = "sink:command_execution:server.py:3".to_string();
        let source_id = "source:server.py:run_cmd:cmd".to_string();
        let entry_id = "entry:server.py:run_cmd".to_string();

        vec![
            Fact::Function(FunctionFact {
                base: FactBase { id: func_id.clone(), file: file.clone(), line: 1, extractor: "test".into() },
                language: "python".into(), name: "run_cmd".into(),
                qualified_name: "run_cmd".into(), end_line: 5,
                params: vec![ParamInfo { name: "cmd".into(), annotation: Some("str".into()), default: None }],
                decorators: vec!["@mcp.tool()".into()], docstring: None,
                return_type: None, enclosing_class: None,
            }),
            Fact::Entrypoint(EntryPointFact {
                base: FactBase { id: entry_id, file: file.clone(), line: 1, extractor: "test".into() },
                kind: EntryPointKind::McpTool, name: "run_cmd".into(),
                function_id: func_id.clone(),
                evidence: Some(EntryPointEvidence { kind: "decorator".into(), text: "@mcp.tool()".into() }),
                params: vec!["cmd".into()], confidence: Confidence::High,
            }),
            Fact::Source(SourceFact {
                base: FactBase { id: source_id.clone(), file: file.clone(), line: 1, extractor: "test".into() },
                kind: "mcp_tool_parameter".into(), function_id: func_id.clone(),
                name: "cmd".into(), confidence: Confidence::High,
            }),
            Fact::Call(CallFact {
                base: FactBase { id: call_id.clone(), file: file.clone(), line: 3, extractor: "test".into() },
                caller: func_id, callee: "os.system".into(),
                normalized_callee: Some("os.system".into()),
                column: Some(0), end_line: Some(3),
                snippet: "os.system(cmd)".into(),
                args: vec![CallArg { index: 0, expr: "cmd".into(), kind: "positional".into() }],
                kwargs: std::collections::BTreeMap::new(), resolution: None,
            }),
            Fact::Sink(SinkFact {
                base: FactBase { id: sink_id.clone(), file: file.clone(), line: 3, extractor: "test".into() },
                call_id: call_id.clone(), category: "command_execution".into(),
                rule_id: "python.command_execution".into(), sink_name: "os.system".into(),
                severity_base: Severity::Critical, reason: "dangerous".into(),
                conditions: std::collections::BTreeMap::new(), confidence: Confidence::High,
            }),
        ]
    }

    #[test]
    fn direct_source_to_sink_python() {
        let facts = python_direct_facts();
        let config = default_config();
        let (results, dataflows) = run_taint_analysis(&facts, &config).expect("taint analysis");

        assert!(!results.is_empty(), "Expected taint results for direct source->sink");
        let r = &results[0];
        assert!(r.source_id.contains("cmd"));
        assert!(r.sink_id.contains("command_execution"));
        assert!(r.entrypoint_is_mcp);
        // os.system is an unresolved external call, so confidence is Medium
        assert_eq!(r.taint_confidence, Confidence::Medium);
        assert!(!dataflows.is_empty());
    }

    #[test]
    fn one_hop_call_chain() {
        // handler(cmd) -> helper(cmd) -> os.system(cmd)
        let file = "s.py".to_string();
        let func_id = "python:s.py:handler".to_string();
        let helper_id = "python:s.py:helper".to_string();
        let call1_id = "call:s.py:4:0".to_string();
        let call2_id = "call:s.py:8:0".to_string();
        let sink_id = "sink:command_execution:s.py:8".to_string();

        let facts = vec![
            Fact::Function(FunctionFact {
                base: FactBase { id: func_id.clone(), file: file.clone(), line: 1, extractor: "t".into() },
                language: "python".into(), name: "handler".into(),
                qualified_name: "handler".into(), end_line: 6,
                params: vec![ParamInfo { name: "cmd".into(), annotation: None, default: None }],
                decorators: vec!["@mcp.tool()".into()], docstring: None, return_type: None, enclosing_class: None,
            }),
            Fact::Function(FunctionFact {
                base: FactBase { id: helper_id.clone(), file: file.clone(), line: 7, extractor: "t".into() },
                language: "python".into(), name: "helper".into(),
                qualified_name: "helper".into(), end_line: 10,
                params: vec![ParamInfo { name: "command".into(), annotation: None, default: None }],
                decorators: vec![], docstring: None, return_type: None, enclosing_class: None,
            }),
            Fact::Entrypoint(EntryPointFact {
                base: FactBase { id: "entry:s.py:handler".into(), file: file.clone(), line: 1, extractor: "t".into() },
                kind: EntryPointKind::McpTool, name: "handler".into(),
                function_id: func_id.clone(),
                evidence: Some(EntryPointEvidence { kind: "decorator".into(), text: "@mcp.tool()".into() }),
                params: vec!["cmd".into()], confidence: Confidence::High,
            }),
            Fact::Source(SourceFact {
                base: FactBase { id: "source:s.py:handler:cmd".into(), file: file.clone(), line: 1, extractor: "t".into() },
                kind: "mcp_tool_parameter".into(), function_id: func_id.clone(),
                name: "cmd".into(), confidence: Confidence::High,
            }),
            // handler -> helper(cmd)
            Fact::Call(CallFact {
                base: FactBase { id: call1_id.clone(), file: file.clone(), line: 4, extractor: "t".into() },
                caller: func_id.clone(), callee: "helper".into(),
                normalized_callee: Some("helper".into()),
                column: Some(0), end_line: Some(4), snippet: "helper(cmd)".into(),
                args: vec![CallArg { index: 0, expr: "cmd".into(), kind: "positional".into() }],
                kwargs: std::collections::BTreeMap::new(), resolution: None,
            }),
            // helper -> os.system(command)
            Fact::Call(CallFact {
                base: FactBase { id: call2_id.clone(), file: file.clone(), line: 8, extractor: "t".into() },
                caller: helper_id.clone(), callee: "os.system".into(),
                normalized_callee: Some("os.system".into()),
                column: Some(0), end_line: Some(8), snippet: "os.system(command)".into(),
                args: vec![CallArg { index: 0, expr: "command".into(), kind: "positional".into() }],
                kwargs: std::collections::BTreeMap::new(), resolution: None,
            }),
            Fact::Sink(SinkFact {
                base: FactBase { id: sink_id.clone(), file: file.clone(), line: 8, extractor: "t".into() },
                call_id: call2_id, category: "command_execution".into(),
                rule_id: "python.command_execution".into(), sink_name: "os.system".into(),
                severity_base: Severity::Critical, reason: "dangerous".into(),
                conditions: std::collections::BTreeMap::new(), confidence: Confidence::High,
            }),
        ];

        let config = default_config();
        let (results, _) = run_taint_analysis(&facts, &config).expect("taint analysis");
        assert!(!results.is_empty(), "Expected taint results for one-hop chain");
    }

    #[test]
    fn disabled_config_returns_empty() {
        let mut config = default_config();
        config.enabled = false;
        let (results, dataflows) = run_taint_analysis(&[], &config).expect("disabled taint");
        assert!(results.is_empty());
        assert!(dataflows.is_empty());
    }

    #[test]
    fn empty_facts_returns_empty() {
        let config = default_config();
        let (results, dataflows) = run_taint_analysis(&[], &config).expect("empty facts");
        assert!(results.is_empty());
        assert!(dataflows.is_empty());
    }

    #[test]
    fn assignment_alias_tracks_variable_to_sink() {
        let file = "s.py".to_string();
        let func_id = "python:s.py:handler".to_string();
        let call_id = "call:s.py:5:0".to_string();
        let sink_id = "sink:command_execution:s.py:5".to_string();

        let facts = vec![
            Fact::Function(FunctionFact {
                base: FactBase { id: func_id.clone(), file: file.clone(), line: 1, extractor: "t".into() },
                language: "python".into(), name: "handler".into(),
                qualified_name: "handler".into(), end_line: 6,
                params: vec![ParamInfo { name: "cmd".into(), annotation: None, default: None }],
                decorators: vec!["@mcp.tool()".into()], docstring: None, return_type: None, enclosing_class: None,
            }),
            Fact::Entrypoint(EntryPointFact {
                base: FactBase { id: "entry:s.py:handler".into(), file: file.clone(), line: 1, extractor: "t".into() },
                kind: EntryPointKind::McpTool, name: "handler".into(),
                function_id: func_id.clone(),
                evidence: Some(EntryPointEvidence { kind: "decorator".into(), text: "@mcp.tool()".into() }),
                params: vec!["cmd".into()], confidence: Confidence::High,
            }),
            Fact::Source(SourceFact {
                base: FactBase { id: "source:s.py:handler:cmd".into(), file: file.clone(), line: 1, extractor: "t".into() },
                kind: "mcp_tool_parameter".into(), function_id: func_id.clone(),
                name: "cmd".into(), confidence: Confidence::High,
            }),
            Fact::Assign(AssignFact {
                base: FactBase { id: "assign:s.py:4:command".into(), file: file.clone(), line: 4, extractor: "t".into() },
                function_id: func_id.clone(), target: "command".into(),
                value: "cmd".into(), snippet: "command = cmd".into(),
            }),
            Fact::Call(CallFact {
                base: FactBase { id: call_id.clone(), file: file.clone(), line: 5, extractor: "t".into() },
                caller: func_id.clone(), callee: "os.system".into(),
                normalized_callee: Some("os.system".into()),
                column: Some(0), end_line: Some(5), snippet: "os.system(command)".into(),
                args: vec![CallArg { index: 0, expr: "command".into(), kind: "positional".into() }],
                kwargs: std::collections::BTreeMap::new(), resolution: None,
            }),
            Fact::Sink(SinkFact {
                base: FactBase { id: sink_id.clone(), file: file.clone(), line: 5, extractor: "t".into() },
                call_id, category: "command_execution".into(),
                rule_id: "python.command_execution".into(), sink_name: "os.system".into(),
                severity_base: Severity::Critical, reason: "dangerous".into(),
                conditions: std::collections::BTreeMap::new(), confidence: Confidence::High,
            }),
        ];

        let config = default_config();
        let (results, _) = run_taint_analysis(&facts, &config).expect("taint analysis");
        assert!(!results.is_empty(), "Expected taint results for assignment alias");
    }

    #[test]
    fn js_direct_source_to_sink() {
        // server.tool("run", async (params) => { exec(params.command); });
        let file = "server.js".to_string();
        let func_id = "javascript:server.js:run_handler".to_string();
        let call_id = "call:server.js:3:0".to_string();
        let sink_id = "sink:command_execution:server.js:3".to_string();

        let facts = vec![
            Fact::Function(FunctionFact {
                base: FactBase { id: func_id.clone(), file: file.clone(), line: 1, extractor: "test".into() },
                language: "javascript".into(), name: "run_handler".into(),
                qualified_name: "run_handler".into(), end_line: 5,
                params: vec![ParamInfo { name: "params".into(), annotation: None, default: None }],
                decorators: vec![], docstring: None, return_type: None, enclosing_class: None,
            }),
            Fact::Entrypoint(EntryPointFact {
                base: FactBase { id: "entry:server.js:run".into(), file: file.clone(), line: 1, extractor: "test".into() },
                kind: EntryPointKind::McpTool, name: "run".into(),
                function_id: func_id.clone(),
                evidence: Some(EntryPointEvidence { kind: "sdk_call".into(), text: "server.tool".into() }),
                params: vec!["params".into()], confidence: Confidence::High,
            }),
            Fact::Source(SourceFact {
                base: FactBase { id: "source:server.js:run_handler:params".into(), file: file.clone(), line: 1, extractor: "test".into() },
                kind: "mcp_tool_parameter".into(), function_id: func_id.clone(),
                name: "params".into(), confidence: Confidence::High,
            }),
            Fact::Call(CallFact {
                base: FactBase { id: call_id.clone(), file: file.clone(), line: 3, extractor: "test".into() },
                caller: func_id.clone(), callee: "exec".into(),
                normalized_callee: Some("exec".into()),
                column: Some(0), end_line: Some(3), snippet: "exec(params.command)".into(),
                args: vec![CallArg { index: 0, expr: "params.command".into(), kind: "positional".into() }],
                kwargs: std::collections::BTreeMap::new(), resolution: None,
            }),
            Fact::Sink(SinkFact {
                base: FactBase { id: sink_id.clone(), file: file.clone(), line: 3, extractor: "test".into() },
                call_id, category: "command_execution".into(),
                rule_id: "javascript.command_execution".into(), sink_name: "exec".into(),
                severity_base: Severity::Critical, reason: "dangerous".into(),
                conditions: std::collections::BTreeMap::new(), confidence: Confidence::High,
            }),
        ];

        let config = default_config();
        let (results, _) = run_taint_analysis(&facts, &config).expect("taint analysis");
        assert!(!results.is_empty(), "Expected taint results for JS source→sink");
    }

    #[test]
    fn rust_direct_source_to_sink() {
        // #[tool] async fn my_tool(params: Value) { Command::new("sh").arg(params).output(); }
        let file = "src/main.rs".to_string();
        let func_id = "rust:src/main.rs:my_tool".to_string();
        let call_id = "call:src/main.rs:3:0".to_string();
        let sink_id = "sink:command_execution:src/main.rs:3".to_string();

        let facts = vec![
            Fact::Function(FunctionFact {
                base: FactBase { id: func_id.clone(), file: file.clone(), line: 1, extractor: "test".into() },
                language: "rust".into(), name: "my_tool".into(),
                qualified_name: "my_tool".into(), end_line: 5,
                params: vec![ParamInfo { name: "params".into(), annotation: Some("Value".into()), default: None }],
                decorators: vec!["#[tool]".into()], docstring: None, return_type: None, enclosing_class: None,
            }),
            Fact::Entrypoint(EntryPointFact {
                base: FactBase { id: "entry:src/main.rs:my_tool".into(), file: file.clone(), line: 1, extractor: "test".into() },
                kind: EntryPointKind::McpTool, name: "my_tool".into(),
                function_id: func_id.clone(),
                evidence: Some(EntryPointEvidence { kind: "attribute_macro".into(), text: "#[tool]".into() }),
                params: vec!["params".into()], confidence: Confidence::High,
            }),
            Fact::Source(SourceFact {
                base: FactBase { id: "source:src/main.rs:my_tool:params".into(), file: file.clone(), line: 1, extractor: "test".into() },
                kind: "mcp_tool_parameter".into(), function_id: func_id.clone(),
                name: "params".into(), confidence: Confidence::High,
            }),
            Fact::Call(CallFact {
                base: FactBase { id: call_id.clone(), file: file.clone(), line: 3, extractor: "test".into() },
                caller: func_id.clone(), callee: "Command::new".into(),
                normalized_callee: Some("std::process::Command::new".into()),
                column: Some(0), end_line: Some(3), snippet: "Command::new(\"sh\")".into(),
                args: vec![CallArg { index: 0, expr: "\"sh\"".into(), kind: "positional".into() }],
                kwargs: std::collections::BTreeMap::new(), resolution: None,
            }),
            Fact::Sink(SinkFact {
                base: FactBase { id: sink_id.clone(), file: file.clone(), line: 3, extractor: "test".into() },
                call_id, category: "command_execution".into(),
                rule_id: "rust.command_execution".into(), sink_name: "std::process::Command::new".into(),
                severity_base: Severity::Critical, reason: "dangerous".into(),
                conditions: std::collections::BTreeMap::new(), confidence: Confidence::High,
            }),
        ];

        let config = default_config();
        let (results, _) = run_taint_analysis(&facts, &config).expect("taint analysis");
        assert!(!results.is_empty(), "Expected taint results for Rust source→sink");
    }

    #[test]
    fn run_disabled_taint_returns_empty() {
        use crate::RuntimeConfig;
        use crate::static_analysis::DiscoveredFile;

        let ctx = StaticScanContext {
            config: RuntimeConfig::default(),  // taint disabled by default
            rulebook_paths: Vec::new(),
            discovered_files: Vec::<DiscoveredFile>::new(),
        };

        let (results, facts) = run(&ctx).expect("run disabled taint");
        assert!(results.is_empty());
        assert!(facts.is_empty());
    }

    #[test]
    fn read_log_path_traversal_produces_file_read_taint() {
        use crate::static_analysis::facts::extract_python_facts;
        use std::path::Path;

        let source = r#"
from pathlib import Path

@mcp.tool()
def read_log(filename: str):
    safe_path = filename.strip()
    log_dir = Path("/var/log")
    full_path = log_dir / safe_path
    content = open(full_path, "r").read()
    return content
"#;

        let extracted =
            extract_python_facts(Path::new("/repo"), Path::new("/repo/server.py"), source);
        assert!(extracted.diagnostics.is_empty());

        let config = default_config();
        let (results, _) = run_taint_analysis(&extracted.facts, &config).expect("taint analysis");

        let sink_ids = results
            .iter()
            .map(|r| r.sink_id.as_str())
            .collect::<Vec<_>>();
        assert!(
            sink_ids.iter().any(|id| id.contains("file_read")),
            "expected a file_read taint result for read_log; got {sink_ids:?}"
        );
    }
}
