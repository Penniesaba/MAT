use std::collections::{HashSet, VecDeque};

use crate::config::StaticTaintConfig;
use crate::model::{Confidence, PathStep, PathStepKind};
use super::graph::{Edge, Graph, Node};

/// A discovered path from source to sink (or reverse).
#[derive(Debug, Clone)]
pub struct PropagationPath {
    pub source_id: String,
    pub sink_id: String,
    pub entrypoint_id: Option<String>,
    pub steps: Vec<PathStep>,
    pub confidence: Confidence,
    /// Whether the path traverses an external call; informational, not yet consumed.
    #[allow(dead_code)]
    pub has_external_call: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Backward,
}

/// Internal queue item for BFS.
struct BfsItem {
    node_id: String,
    start_id: String,
    steps: Vec<PathStep>,
    visited: HashSet<String>,
    depth: u32,
    has_external_call: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run forward propagation: from Source nodes → Sink nodes.
pub fn propagate_forward(
    graph: &Graph,
    config: &StaticTaintConfig,
) -> Vec<PropagationPath> {
    let start_ids = find_source_start_nodes(graph, config.entrypoint_required);
    propagate(graph, config, Direction::Forward, &start_ids)
}

/// Run backward propagation: from Sink nodes → Source nodes.
pub fn propagate_backward(
    graph: &Graph,
    config: &StaticTaintConfig,
) -> Vec<PropagationPath> {
    let start_ids = find_sink_start_nodes(graph);
    propagate(graph, config, Direction::Backward, &start_ids)
}

/// Run both forward and backward, merge/return all paths.
pub fn propagate_both(
    graph: &Graph,
    config: &StaticTaintConfig,
) -> Vec<PropagationPath> {
    let mut paths = Vec::new();
    if config.forward {
        paths.extend(propagate_forward(graph, config));
    }
    if config.backward {
        paths.extend(propagate_backward(graph, config));
    }
    deduplicate_paths(paths)
}

// ---------------------------------------------------------------------------
// Core BFS
// ---------------------------------------------------------------------------

fn propagate(
    graph: &Graph,
    config: &StaticTaintConfig,
    direction: Direction,
    start_ids: &[String],
) -> Vec<PropagationPath> {
    let mut results: Vec<PropagationPath> = Vec::new();
    let mut queue: VecDeque<BfsItem> = VecDeque::new();

    for id in start_ids {
        let mut visited = HashSet::new();
        visited.insert(id.clone());
        queue.push_back(BfsItem {
            node_id: id.clone(),
            start_id: id.clone(),
            steps: Vec::new(),
            visited,
            depth: 0,
            has_external_call: false,
        });
    }

    while let Some(item) = queue.pop_front() {
        if item.depth >= config.max_depth {
            continue;
        }

        let _current_node = match graph.get_node(&item.node_id) {
            Some(n) => n,
            None => continue,
        };

        let edges: Vec<&Edge> = match direction {
            Direction::Forward => graph.outgoing_edges(&item.node_id).iter().collect(),
            Direction::Backward => graph.incoming_edges(&item.node_id).iter().collect(),
        };

        for edge in edges {
            let next_id = match direction {
                Direction::Forward => edge.to_id(),
                Direction::Backward => edge.from_id(),
            };

            if item.visited.contains(next_id) {
                continue; // cycle prevention
            }

            let next_node = match graph.get_node(next_id) {
                Some(n) => n,
                None => continue,
            };

            let step = edge_to_path_step(edge, graph, direction);
            let mut new_steps = item.steps.clone();
            if let Some(s) = step {
                new_steps.push(s);
            }

            let mut new_visited = item.visited.clone();
            new_visited.insert(next_id.to_string());

            let next_has_external = item.has_external_call
                || matches!(edge, Edge::CallToFunction { .. } if matches!(next_node, Node::Call { is_external: true, .. }));

            // Check termination conditions
            let reached_target = match direction {
                Direction::Forward => matches!(next_node, Node::Sink { .. }),
                Direction::Backward => matches!(next_node, Node::Source { .. }),
            };

            if reached_target {
                let (source_id, sink_id) = match direction {
                    Direction::Forward => (item.start_id.clone(), next_id.to_string()),
                    Direction::Backward => (next_id.to_string(), item.start_id.clone()),
                };

                let entrypoint_id = resolve_entrypoint_id(graph, &source_id);

                let confidence = compute_path_confidence(&new_steps, next_has_external);

                results.push(PropagationPath {
                    source_id,
                    sink_id,
                    entrypoint_id,
                    steps: new_steps.clone(),
                    confidence,
                    has_external_call: next_has_external,
                });
            }

            // For forward, also stop at external Call with sink
            let external_call_sink = match direction {
                Direction::Forward => {
                    matches!(next_node, Node::Call { is_external: true, .. })
                        && graph.outgoing_edges(next_id).iter().any(|e| matches!(e, Edge::CallToSink { .. }))
                }
                Direction::Backward => false,
            };

            if external_call_sink {
                // Find the sink attached to this external call
                for e in graph.outgoing_edges(next_id) {
                    if let Edge::CallToSink { sink_id, .. } = e {
                        let source_id = item.start_id.clone();
                        let entrypoint_id = resolve_entrypoint_id(graph, &source_id);
                        results.push(PropagationPath {
                            source_id,
                            sink_id: sink_id.clone(),
                            entrypoint_id,
                            steps: new_steps.clone(),
                            confidence: compute_path_confidence(&new_steps, true),
                            has_external_call: true,
                        });
                    }
                }
                continue; // Don't recurse into external calls
            }

            // Continue BFS (if not at terminal)
            if item.depth + 1 < config.max_depth {
                queue.push_back(BfsItem {
                    node_id: next_id.to_string(),
                    start_id: item.start_id.clone(),
                    steps: new_steps,
                    visited: new_visited,
                    depth: item.depth + 1,
                    has_external_call: next_has_external,
                });
            }
        }
    }

    deduplicate_paths(results)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find Source nodes to start forward propagation from.
fn find_source_start_nodes(graph: &Graph, entrypoint_required: bool) -> Vec<String> {
    let mut ids: Vec<String> = graph
        .nodes
        .iter()
        .filter_map(|(id, node)| {
            if let Node::Source { function_id, .. } = node {
                if entrypoint_required {
                    // Only sources belonging to entrypoint functions
                    let is_ep = graph
                        .entrypoint_to_function
                        .values()
                        .any(|ep_func_id| ep_func_id == function_id);
                    if is_ep {
                        Some(id.clone())
                    } else {
                        None
                    }
                } else {
                    Some(id.clone())
                }
            } else {
                None
            }
        })
        .collect();
    ids.sort();
    ids
}

/// Find Sink nodes to start backward propagation from.
fn find_sink_start_nodes(graph: &Graph) -> Vec<String> {
    let mut ids: Vec<String> = graph
        .nodes
        .iter()
        .filter_map(|(id, node)| {
            if matches!(node, Node::Sink { .. }) {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect();
    ids.sort();
    ids
}

/// Convert an edge to a PathStep for the output.
fn edge_to_path_step(edge: &Edge, graph: &Graph, _direction: Direction) -> Option<PathStep> {
    match edge {
        Edge::SourceToArg { source_id, call_id, arg_index } => {
            let source_name = graph.get_node(source_id)
                .and_then(|n| if let Node::Source { name, .. } = n { Some(name.clone()) } else { None });
            let call_node = graph.get_node(call_id);
            let line = call_node.map(|n| match n {
                Node::Call { line, .. } => *line,
                _ => 0,
            }).unwrap_or(0);
            let snippet = call_node.map(|n| match n {
                Node::Call { callee, .. } => format!("{callee}(...)"),
                _ => String::new(),
            });
            let caller_func = call_node.and_then(|n| match n {
                Node::Call { caller_function_id, .. } => Some(caller_function_id.clone()),
                _ => None,
            });
            Some(PathStep {
                kind: PathStepKind::Param,
                line,
                name: source_name,
                function: caller_func,
                from_: None,
                to: None,
                snippet,
                call_id: Some(call_id.clone()),
                arg_index: Some(*arg_index),
            })
        }
        Edge::VarToArg { var_id, call_id, arg_index } => {
            let var_name = graph.get_node(var_id)
                .and_then(|n| if let Node::Variable { name, .. } = n { Some(name.clone()) } else { None });
            let call_node = graph.get_node(call_id);
            let line = call_node.and_then(|n| match n { Node::Call { line, .. } => Some(*line), _ => None }).unwrap_or(0);
            Some(PathStep {
                kind: PathStepKind::CallArg,
                line,
                name: var_name,
                function: None,
                from_: Some(var_id.clone()),
                to: Some(call_id.clone()),
                snippet: None,
                call_id: Some(call_id.clone()),
                arg_index: Some(*arg_index),
            })
        }
        Edge::ValToVar { from_var_id, to_var_id } => {
            let from_name = graph.get_node(from_var_id)
                .and_then(|n| if let Node::Variable { name, .. } = n { Some(name.clone()) } else { None });
            let to_name = graph.get_node(to_var_id)
                .and_then(|n| if let Node::Variable { name, .. } = n { Some(name.clone()) } else { None });
            let func = graph.get_node(to_var_id)
                .and_then(|n| if let Node::Variable { function_id, .. } = n { Some(function_id.clone()) } else { None });
            let line = 0; // Variables don't have line info directly
            let snippet = from_name.as_ref().zip(to_name.as_ref())
                .map(|(f, t)| format!("{t} = {f}"));
            Some(PathStep {
                kind: PathStepKind::Assign,
                line,
                name: to_name,
                function: func,
                from_: Some(from_var_id.clone()),
                to: Some(to_var_id.clone()),
                snippet,
                call_id: None,
                arg_index: None,
            })
        }
        Edge::SourceToVar { source_id, var_id } => {
            let source_name = graph.get_node(source_id)
                .and_then(|n| if let Node::Source { name, .. } = n { Some(name.clone()) } else { None });
            let to_name = graph.get_node(var_id)
                .and_then(|n| if let Node::Variable { name, .. } = n { Some(name.clone()) } else { None });
            let func = graph.get_node(var_id)
                .and_then(|n| if let Node::Variable { function_id, .. } = n { Some(function_id.clone()) } else { None });
            let snippet = source_name.as_ref().zip(to_name.as_ref())
                .map(|(s, t)| format!("{t} = {s}"));
            Some(PathStep {
                kind: PathStepKind::Assign,
                line: 0,
                name: to_name,
                function: func,
                from_: Some(source_id.clone()),
                to: Some(var_id.clone()),
                snippet,
                call_id: None,
                arg_index: None,
            })
        }
        Edge::ReturnToVar { call_id, var_id } => {
            let var_name = graph.get_node(var_id)
                .and_then(|n| if let Node::Variable { name, .. } = n { Some(name.clone()) } else { None });
            let call_node = graph.get_node(call_id);
            let line = call_node.and_then(|n| match n { Node::Call { line, .. } => Some(*line), _ => None }).unwrap_or(0);
            Some(PathStep {
                kind: PathStepKind::Return,
                line,
                name: var_name,
                function: None,
                from_: Some(call_id.clone()),
                to: Some(var_id.clone()),
                snippet: None,
                call_id: Some(call_id.clone()),
                arg_index: None,
            })
        }
        Edge::CallToFunction { call_id, callee_function_id, .. } => {
            let caller_func = graph.get_node(call_id)
                .and_then(|n| match n { Node::Call { caller_function_id, .. } => Some(caller_function_id.clone()), _ => None });
            let callee_name = graph.functions.get(callee_function_id).map(|m| m.name.clone());
            let line = graph.get_node(call_id)
                .and_then(|n| match n { Node::Call { line, .. } => Some(*line), _ => None }).unwrap_or(0);
            Some(PathStep {
                kind: PathStepKind::CallArg,
                line,
                name: callee_name,
                function: caller_func,
                from_: Some(call_id.clone()),
                to: Some(callee_function_id.clone()),
                snippet: None,
                call_id: Some(call_id.clone()),
                arg_index: None,
            })
        }
        _ => None, // SourceInFunction, CallInFunction, etc. are structural — no visible step
    }
}

/// Determine the entrypoint_id for a source by following Source → Function → Entrypoint.
fn resolve_entrypoint_id(graph: &Graph, source_id: &str) -> Option<String> {
    let func_id = graph.source_to_function.get(source_id)?;
    for (ep_id, ep_func_id) in &graph.entrypoint_to_function {
        if ep_func_id == func_id {
            return Some(ep_id.clone());
        }
    }
    None
}

/// Compute confidence for a path based on external calls and variable aliasing.
fn compute_path_confidence(steps: &[PathStep], has_external_call: bool) -> Confidence {
    let has_var_alias = steps.iter().any(|s| s.kind == PathStepKind::Assign);
    if has_external_call && has_var_alias {
        Confidence::Low
    } else if has_external_call || has_var_alias {
        Confidence::Medium
    } else {
        Confidence::High
    }
}

/// Deduplicate paths: same (source_id, sink_id) with same function chain → keep shortest.
/// Different function chains → keep all.
fn deduplicate_paths(paths: Vec<PropagationPath>) -> Vec<PropagationPath> {
    let mut result: Vec<PropagationPath> = Vec::new();
    for path in paths {
        let key = (&path.source_id, &path.sink_id);
        if let Some(existing) = result.iter_mut().find(|p| &p.source_id == key.0 && &p.sink_id == key.1) {
            if path.steps.len() < existing.steps.len() {
                *existing = path;
            }
        } else {
            result.push(path);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::graph::FunctionMeta;
    use crate::config::StaticTaintConfig;

    fn default_config() -> StaticTaintConfig {
        StaticTaintConfig {
            enabled: true,
            forward: true,
            backward: true,
            max_depth: 8,
            entrypoint_required: true,
        }
    }

    fn make_minimal_graph() -> Graph {
        let mut g = Graph::new();

        // Function "handler" with param "cmd"
        let func_id = "python:s.py:handler".to_string();
        g.add_node(func_id.clone(), Node::Function {
            id: func_id.clone(),
            name: "handler".into(),
            qualified_name: "handler".into(),
            file: "s.py".into(),
            params: vec!["cmd".into()],
            language: "python".into(),
            line: 1,
        });
        g.functions.insert(func_id.clone(), FunctionMeta {
            name: "handler".into(),
            qualified_name: "handler".into(),
            file: "s.py".into(),
            language: "python".into(),
            params: vec!["cmd".into()],
            line: 1,
        });

        // Entrypoint
        let ep_id = "entry:s.py:handler".to_string();
        g.entrypoint_to_function.insert(ep_id, func_id.clone());

        // Source "cmd"
        let src_id = "source:s.py:handler:cmd".to_string();
        g.add_node(src_id.clone(), Node::Source {
            id: src_id.clone(),
            name: "cmd".into(),
            kind: "mcp_tool_parameter".into(),
            function_id: func_id.clone(),
            confidence: Confidence::High,
        });
        g.source_to_function.insert(src_id.clone(), func_id.clone());
        g.add_edge(Edge::SourceInFunction {
            source_id: src_id.clone(),
            function_id: func_id.clone(),
        });

        // Call "os.system(cmd)"
        let call_id = "call:s.py:3:0".to_string();
        g.add_node(call_id.clone(), Node::Call {
            id: call_id.clone(),
            callee: "os.system".into(),
            normalized_callee: "os.system".into(),
            caller_function_id: func_id.clone(),
            is_external: true,
            line: 3,
            file: "s.py".into(),
        });
        g.add_edge(Edge::CallInFunction {
            call_id: call_id.clone(),
            function_id: func_id.clone(),
        });
        g.add_edge(Edge::SourceToArg {
            source_id: src_id.clone(),
            call_id: call_id.clone(),
            arg_index: 0,
        });

        // Sink
        let sink_id = "sink:cmd:s.py:3".to_string();
        g.add_node(sink_id.clone(), Node::Sink {
            id: sink_id.clone(),
            category: "command_execution".into(),
            call_id: call_id.clone(),
            severity_base: crate::model::Severity::High,
        });
        g.add_edge(Edge::CallToSink {
            call_id: call_id.clone(),
            sink_id,
        });

        g
    }

    #[test]
    fn forward_propagation_finds_direct_source_to_sink() {
        let g = make_minimal_graph();
        let mut config = default_config();
        config.backward = false;
        let paths = propagate_forward(&g, &config);
        assert!(!paths.is_empty(), "Expected at least one path");
        let path = paths.iter().find(|p| p.source_id.contains("cmd")).expect("path for cmd source");
        assert!(path.sink_id.contains("cmd"), "sink_id should contain 'cmd'");
        assert!(!path.steps.is_empty());
    }

    #[test]
    fn backward_propagation_finds_sink_to_source() {
        let g = make_minimal_graph();
        let mut config = default_config();
        config.forward = false;
        let paths = propagate_backward(&g, &config);
        assert!(!paths.is_empty());
        let path = paths.iter().find(|p| p.sink_id.contains("cmd")).expect("path for sink");
        assert!(path.source_id.contains("cmd"), "should find cmd source");
    }

    #[test]
    fn empty_graph_returns_no_paths() {
        let g = Graph::new();
        let config = default_config();
        assert!(propagate_forward(&g, &config).is_empty());
        assert!(propagate_backward(&g, &config).is_empty());
    }

    #[test]
    fn max_depth_limits_propagation() {
        let g = make_minimal_graph();
        let mut config = default_config();
        config.max_depth = 0;
        let paths = propagate_forward(&g, &config);
        assert!(paths.is_empty(), "max_depth=0 should find no paths");
    }

    #[test]
    fn entrypoint_required_filters_non_entrypoint_sources() {
        let mut g = Graph::new();
        let func_id = "python:s.py:plain".to_string();
        let src_id = "source:s.py:plain:x".to_string();
        g.add_node(src_id.clone(), Node::Source {
            id: src_id.clone(),
            name: "x".into(),
            kind: "unknown".into(),
            function_id: func_id.clone(),
            confidence: Confidence::Low,
        });
        g.source_to_function.insert(src_id, func_id);

        let mut config = default_config();
        config.entrypoint_required = true;
        assert!(propagate_forward(&g, &config).is_empty());

        // With entrypoint_required=false, source should be a start node
        let start_ids: Vec<String> = g.nodes.iter()
            .filter_map(|(id, n)| if matches!(n, Node::Source { .. }) { Some(id.clone()) } else { None })
            .collect();
        assert!(!start_ids.is_empty());
    }
}
