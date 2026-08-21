use super::graph::{Graph, Node};
use super::propagation::PropagationPath;
use crate::model::{DataFlowFact, Fact, FactBase, TaintAnalysisResult};

/// Whether a path is neutralized: its sink category is covered by a sanitizer
/// on the path, or a `"*"` wildcard sanitizer neutralizes every category.
fn path_is_sanitized(path: &PropagationPath, graph: &Graph) -> bool {
    if path.neutralized.iter().any(|c| c == "*") {
        return true;
    }
    let Some(Node::Sink { category, .. }) = graph.get_node(&path.sink_id) else {
        return false;
    };
    path.neutralized.iter().any(|c| c == category)
}

/// Convert propagation paths into TaintAnalysisResult values.
pub fn build_taint_results(paths: &[PropagationPath], graph: &Graph) -> Vec<TaintAnalysisResult> {
    paths
        .iter()
        .filter(|path| !path_is_sanitized(path, graph))
        .map(|path| {
            let source_kind = graph
                .get_node(&path.source_id)
                .map(|n| match n {
                    Node::Source { kind, .. } => kind.clone(),
                    _ => "unknown".to_string(),
                })
                .unwrap_or_else(|| "unknown".to_string());

            let sink_kind = graph
                .get_node(&path.sink_id)
                .map(|n| match n {
                    Node::Sink { category, .. } => category.clone(),
                    _ => "unknown".to_string(),
                })
                .unwrap_or_else(|| "unknown".to_string());

            let entrypoint_is_mcp = path
                .entrypoint_id
                .as_ref()
                .and_then(|ep_id| {
                    // EntryPointFacts are not directly in the graph — check via
                    // entrypoint_to_function mapping and infer from source kind.
                    // If the source's function is linked to an entrypoint, it's MCP.
                    graph.entrypoint_to_function.get(ep_id).map(|_| true)
                })
                .unwrap_or(false);

            let call_chain: Vec<String> = path
                .steps
                .iter()
                .filter(|s| {
                    s.kind == crate::model::PathStepKind::CallArg
                        || s.kind == crate::model::PathStepKind::Return
                })
                .filter_map(|s| s.function.clone())
                .collect();

            let dataflow_path: Vec<String> = path
                .steps
                .iter()
                .filter_map(|s| s.snippet.clone().or_else(|| s.name.clone()))
                .filter(|s| !s.is_empty())
                .collect();

            let evidence: Vec<String> = path
                .steps
                .iter()
                .filter(|s| s.snippet.is_some() || s.name.is_some())
                .map(|s| {
                    let loc = format!("{}:{}", s.call_id.as_deref().unwrap_or("?"), s.line);
                    let detail = s
                        .snippet
                        .clone()
                        .unwrap_or_else(|| s.name.clone().unwrap_or_else(|| "?".to_string()));
                    format!("{loc} — {detail}")
                })
                .collect();

            TaintAnalysisResult {
                result_id: format!("taint:{}:{}", path.source_id, path.sink_id),
                source_id: path.source_id.clone(),
                source_kind,
                entrypoint_id: path.entrypoint_id.clone(),
                sink_id: path.sink_id.clone(),
                sink_kind,
                call_chain,
                dataflow_path,
                evidence,
                taint_confidence: path.confidence.clone(),
                entrypoint_is_mcp,
                backward_trace_found_root: path.entrypoint_id.is_some(),
            }
        })
        .collect()
}

/// Derive the source file path from a `sink:<category>:<rel_path>:<line>` id.
///
/// The id is produced by `facts::ids::make_sink_id`, e.g.
/// `sink:command_execution:main.rs:33` -> `main.rs`. Paths that themselves
/// contain `:` (rare, but possible on some filesystems) are preserved because
/// only the leading `sink:`/category and the trailing line are stripped.
fn file_from_sink_id(sink_id: &str) -> String {
    let parts: Vec<&str> = sink_id.split(':').collect();
    if parts.len() >= 4 {
        parts[2..parts.len() - 1].join(":")
    } else {
        String::new()
    }
}

/// Convert propagation paths into DataFlowFact values for persistence.
pub fn build_dataflow_facts(paths: &[PropagationPath]) -> Vec<Fact> {
    paths
        .iter()
        .map(|path| {
            let file = file_from_sink_id(&path.sink_id);
            let line = path.steps.first().map(|s| s.line).unwrap_or(0);
            Fact::Dataflow(DataFlowFact {
                base: FactBase {
                    id: format!("dataflow:{}:{}", path.source_id, path.sink_id),
                    file,
                    line,
                    extractor: "rust_taint_phase10_11".to_string(),
                },
                source_id: path.source_id.clone(),
                sink_id: path.sink_id.clone(),
                path: path.steps.clone(),
                confidence: path.confidence.clone(),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, PathStep, PathStepKind};

    fn make_test_graph() -> Graph {
        let mut g = Graph::new();
        let func_id = "python:s.py:handler".to_string();
        g.add_node(
            func_id.clone(),
            Node::Function {
                id: func_id.clone(),
                name: "handler".into(),
                qualified_name: "handler".into(),
                file: "s.py".into(),
                params: vec!["cmd".into()],
                language: "python".into(),
                line: 1,
            },
        );
        g.source_to_function
            .insert("source:s.py:handler:cmd".into(), func_id.clone());
        g.entrypoint_to_function
            .insert("entry:s.py:handler".into(), func_id);
        g
    }

    #[test]
    fn builds_taint_results_from_paths() {
        let g = make_test_graph();
        let paths = vec![PropagationPath {
            source_id: "source:s.py:handler:cmd".into(),
            sink_id: "sink:cmd:s.py:3".into(),
            entrypoint_id: Some("entry:s.py:handler".into()),
            steps: vec![PathStep {
                kind: PathStepKind::Param,
                line: 3,
                name: Some("cmd".into()),
                function: Some("python:s.py:handler".into()),
                from_: None,
                to: None,
                snippet: Some("os.system(cmd)".into()),
                call_id: Some("call:s.py:3:0".into()),
                arg_index: Some(0),
            }],
            confidence: Confidence::High,
            has_external_call: true,
            neutralized: vec![],
        }];

        let results = build_taint_results(&paths, &g);
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.source_id, "source:s.py:handler:cmd");
        assert_eq!(r.sink_id, "sink:cmd:s.py:3");
        assert!(r.entrypoint_is_mcp);
        assert!(r.backward_trace_found_root);
        assert_eq!(r.taint_confidence, Confidence::High);
        assert!(!r.evidence.is_empty());
    }

    #[test]
    fn builds_dataflow_facts_from_paths() {
        let paths = vec![PropagationPath {
            source_id: "source:s.py:handler:cmd".into(),
            sink_id: "sink:cmd:s.py:3".into(),
            entrypoint_id: Some("entry:s.py:handler".into()),
            steps: vec![PathStep {
                kind: PathStepKind::Param,
                line: 3,
                name: Some("cmd".into()),
                function: None,
                from_: None,
                to: None,
                snippet: Some("os.system(cmd)".into()),
                call_id: None,
                arg_index: None,
            }],
            confidence: Confidence::Medium,
            has_external_call: true,
            neutralized: vec![],
        }];

        let facts = build_dataflow_facts(&paths);
        assert_eq!(facts.len(), 1);
        if let Fact::Dataflow(df) = &facts[0] {
            assert!(df.base.id.starts_with("dataflow:"));
            assert_eq!(df.base.file, "s.py");
            assert_eq!(df.source_id, "source:s.py:handler:cmd");
            assert_eq!(df.sink_id, "sink:cmd:s.py:3");
            assert_eq!(df.confidence, Confidence::Medium);
        } else {
            panic!("Expected Dataflow fact");
        }
    }

    #[test]
    fn taint_results_dataflow_path_falls_back_to_name() {
        let g = make_test_graph();
        let paths = vec![PropagationPath {
            source_id: "source:s.py:handler:cmd".into(),
            sink_id: "sink:cmd:s.py:3".into(),
            entrypoint_id: Some("entry:s.py:handler".into()),
            steps: vec![PathStep {
                kind: PathStepKind::Param,
                line: 3,
                name: Some("cmd".into()),
                function: Some("python:s.py:handler".into()),
                from_: None,
                to: None,
                snippet: None,
                call_id: Some("call:s.py:3:0".into()),
                arg_index: Some(0),
            }],
            confidence: Confidence::High,
            has_external_call: true,
            neutralized: vec![],
        }];

        let results = build_taint_results(&paths, &g);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dataflow_path, vec!["cmd".to_string()]);
    }

    #[test]
    fn empty_paths_produce_empty_results() {
        let g = Graph::new();
        assert!(build_taint_results(&[], &g).is_empty());
        assert!(build_dataflow_facts(&[]).is_empty());
    }
}
