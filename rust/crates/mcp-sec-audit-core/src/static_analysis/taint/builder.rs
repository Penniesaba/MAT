use std::collections::HashMap;
use crate::model::Fact;
use super::graph::{Edge, FunctionMeta, Graph, Node};

/// Special separator used in variable IDs to avoid ambiguity with colons/paths.
const VAR_SEP: char = '\x00';

/// Build a unified cross-file program graph from all extracted facts.
pub fn build_graph(facts: &[Fact]) -> Graph {
    let mut g = Graph::new();

    // Pre-scan: collect FunctionFacts to build callee lookup table.
    // qualified_name → [(function_id, file, language, params)]
    let mut func_lookup: HashMap<String, Vec<(String, String, String, Vec<String>)>> =
        HashMap::new();

    // -----------------------------------------------------------------------
    // Step 1: Register all Function nodes
    // -----------------------------------------------------------------------
    for fact in facts {
        if let Fact::Function(f) = fact {
            let func_id = f.base.id.clone();
            let meta = FunctionMeta {
                name: f.name.clone(),
                qualified_name: f.qualified_name.clone(),
                file: f.base.file.clone(),
                language: f.language.clone(),
                params: f.params.iter().map(|p| p.name.clone()).collect(),
                line: f.base.line,
            };
            g.functions.insert(func_id.clone(), meta);
            g.add_node(func_id.clone(), Node::Function {
                id: func_id.clone(),
                name: f.name.clone(),
                qualified_name: f.qualified_name.clone(),
                file: f.base.file.clone(),
                params: f.params.iter().map(|p| p.name.clone()).collect(),
                language: f.language.clone(),
                line: f.base.line,
            });

            func_lookup
                .entry(f.qualified_name.clone())
                .or_default()
                .push((
                    func_id,
                    f.base.file.clone(),
                    f.language.clone(),
                    f.params.iter().map(|p| p.name.clone()).collect(),
                ));
        }
    }

    // -----------------------------------------------------------------------
    // Step 2: Register Entrypoint → Function mappings
    // -----------------------------------------------------------------------
    for fact in facts {
        if let Fact::Entrypoint(ep) = fact {
            g.entrypoint_to_function
                .insert(ep.base.id.clone(), ep.function_id.clone());
        }
    }

    // -----------------------------------------------------------------------
    // Step 3: Register Source nodes
    // -----------------------------------------------------------------------
    for fact in facts {
        if let Fact::Source(s) = fact {
            let source_id = s.base.id.clone();
            g.source_to_function
                .insert(source_id.clone(), s.function_id.clone());
            g.add_node(source_id.clone(), Node::Source {
                id: source_id.clone(),
                name: s.name.clone(),
                kind: s.kind.clone(),
                function_id: s.function_id.clone(),
                confidence: s.confidence.clone(),
            });

            // SourceInFunction edge
            g.add_edge(Edge::SourceInFunction {
                source_id: source_id.clone(),
                function_id: s.function_id.clone(),
            });
        }
    }

    // -----------------------------------------------------------------------
    // Step 4: Register Call nodes and resolve callees
    // -----------------------------------------------------------------------
    for fact in facts {
        if let Fact::Call(c) = fact {
            let call_id = c.base.id.clone();
            let normalized = c.normalized_callee.clone().unwrap_or_else(|| c.callee.clone());
            let caller_file = c.base.file.clone();

            // Resolve callee
            let (resolved_func_id, is_external, confidence) =
                resolve_callee(&normalized, &caller_file, &func_lookup);

            g.add_node(call_id.clone(), Node::Call {
                id: call_id.clone(),
                callee: c.callee.clone(),
                normalized_callee: normalized.clone(),
                caller_function_id: c.caller.clone(),
                is_external,
                line: c.base.line,
                file: c.base.file.clone(),
            });

            // CallInFunction edge
            if !c.caller.is_empty() {
                g.add_edge(Edge::CallInFunction {
                    call_id: call_id.clone(),
                    function_id: c.caller.clone(),
                });
            }

            // CallToFunction edge (if resolved)
            if let Some(func_id) = resolved_func_id {
                g.add_edge(Edge::CallToFunction {
                    call_id: call_id.clone(),
                    callee_function_id: func_id.clone(),
                    confidence,
                });

                // ArgToParam edges: map call args to callee params
                let num_params = g.functions.get(&func_id).map(|m| m.params.len()).unwrap_or(0);
                let param_names: Vec<String> = g
                    .functions
                    .get(&func_id)
                    .map(|m| m.params.clone())
                    .unwrap_or_default();
                for arg in &c.args {
                    if (arg.index as usize) < num_params {
                        g.add_edge(Edge::ArgToParam {
                            call_id: call_id.clone(),
                            arg_index: arg.index,
                            param_name: param_names[arg.index as usize].clone(),
                            callee_function_id: func_id.clone(),
                        });
                    }
                }
            }

            // VarToArg edges: link variables used as call arguments
            for arg in &c.args {
                let var_id = make_var_id(&c.caller, &arg.expr);
                if g.nodes.contains_key(&var_id) {
                    g.add_edge(Edge::VarToArg {
                        var_id,
                        call_id: call_id.clone(),
                        arg_index: arg.index,
                    });
                }
                // SourceToArg: check if arg matches a source name in current function
                // Collect source info first to avoid borrow conflicts
                let source_matches: Vec<(String, String)> = g
                    .source_to_function
                    .iter()
                    .filter(|(_, fid)| *fid == &c.caller)
                    .filter_map(|(sid, _)| {
                        match g.nodes.get(sid) {
                            Some(Node::Source { name, .. }) => Some((sid.clone(), name.clone())),
                            _ => None,
                        }
                    })
                    .collect();
                for (source_id, name) in source_matches {
                    if name == arg.expr {
                        g.add_edge(Edge::SourceToArg {
                            source_id,
                            call_id: call_id.clone(),
                            arg_index: arg.index,
                        });
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 5: Register Sink nodes
    // -----------------------------------------------------------------------
    for fact in facts {
        if let Fact::Sink(s) = fact {
            let sink_id = s.base.id.clone();
            g.add_node(sink_id.clone(), Node::Sink {
                id: sink_id.clone(),
                category: s.category.clone(),
                call_id: s.call_id.clone(),
                severity_base: s.severity_base.clone(),
            });

            // CallToSink edge
            g.add_edge(Edge::CallToSink {
                call_id: s.call_id.clone(),
                sink_id,
            });
        }
    }

    // -----------------------------------------------------------------------
    // Step 6: Register Variables and assignment propagation
    // -----------------------------------------------------------------------
    for fact in facts {
        if let Fact::Assign(a) = fact {
            let target_id = make_var_id(&a.function_id, &a.target);
            let target_node = Node::Variable {
                id: target_id.clone(),
                name: a.target.clone(),
                function_id: a.function_id.clone(),
            };
            g.add_node(target_id.clone(), target_node);

            // ValToVar: if value is a simple variable name, link it
            let trimmed = a.value.trim();
            if is_simple_var(trimmed) {
                let from_id = make_var_id(&a.function_id, trimmed);
                g.add_edge(Edge::ValToVar {
                    from_var_id: from_id,
                    to_var_id: target_id.clone(),
                });
            }

            // ReturnToVar: if value looks like a function call result
            if trimmed.contains('(') && trimmed.contains(')') {
                // Extract the callee from "foo(x, y)" pattern
                if let Some(paren_idx) = trimmed.find('(') {
                    let callee_name = trimmed[..paren_idx].trim().to_string();
                    // Find the most recent CallFact in the same function/line that matches
                    // We link all matching calls in the same function
                    for call_fact in facts.iter().filter_map(|f| {
                        if let Fact::Call(c) = f {
                            if c.caller == a.function_id && c.base.line <= a.base.line {
                                let call_callee = &c.callee;
                                let call_normalized = c.normalized_callee.as_deref().unwrap_or(call_callee);
                                if call_callee == &callee_name || call_normalized == callee_name {
                                    return Some(c);
                                }
                            }
                            None
                        } else {
                            None
                        }
                    }) {
                        g.add_edge(Edge::ReturnToVar {
                            call_id: call_fact.base.id.clone(),
                            var_id: target_id.clone(),
                        });
                    }
                }
            }
        }
    }

    g
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Build a variable node ID: `{function_id}{SEP}{var_name}`
fn make_var_id(function_id: &str, var_name: &str) -> String {
    format!("{function_id}{VAR_SEP}{var_name}")
}

/// A simple variable name is an identifier with no operators, parens, dots.
fn is_simple_var(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

/// Resolve a callee name to a function_id using the lookup table.
///
/// Strategy:
/// 1. Exact match on qualified_name → High confidence
/// 2. Multiple matches: prefer same-file → Medium confidence
/// 3. Single match (any file) → Medium confidence
/// 4. Last-segment match (mod.func or Mod::func) → Medium confidence
/// 5. No match → external (None, is_external=true)
fn resolve_callee(
    normalized_callee: &str,
    caller_file: &str,
    lookup: &HashMap<String, Vec<(String, String, String, Vec<String>)>>,
) -> (Option<String>, bool, crate::model::Confidence) {
    if let Some(candidates) = lookup.get(normalized_callee) {
        if candidates.len() == 1 {
            let (func_id, _, _, _) = &candidates[0];
            return (
                Some(func_id.clone()),
                false,
                crate::model::Confidence::High,
            );
        }
        // Multiple matches — prefer same file
        if let Some((func_id, _, _, _)) = candidates.iter().find(|(_, file, _, _)| file == caller_file) {
            return (
                Some(func_id.clone()),
                false,
                crate::model::Confidence::Medium,
            );
        }
        // Fallback: first match from any file
        let (func_id, _, _, _) = &candidates[0];
        return (
            Some(func_id.clone()),
            false,
            crate::model::Confidence::Low,
        );
    }

    // Try matching just the last segment.
    // Python/JS use "." (e.g. "mod.func"), Rust uses "::" (e.g. "Mod::func").
    let last_seg = normalized_callee
        .rsplit("::")
        .next()
        .and_then(|rust_seg| {
            // Check if the Rust-style last segment matches
            if lookup.contains_key(rust_seg) {
                Some(rust_seg.to_string())
            } else {
                None
            }
        })
        .or_else(|| {
            normalized_callee
                .rsplit('.')
                .next()
                .filter(|seg| lookup.contains_key(*seg))
                .map(|s| s.to_string())
        });

    if let Some(seg) = last_seg {
        if let Some(candidates) = lookup.get(&seg) {
            if candidates.len() == 1 {
                let (func_id, _, _, _) = &candidates[0];
                return (
                    Some(func_id.clone()),
                    false,
                    crate::model::Confidence::Medium,
                );
            }
            // Prefer same-file if multiple
            if let Some((func_id, _, _, _)) = candidates.iter().find(|(_, file, _, _)| file == caller_file) {
                return (
                    Some(func_id.clone()),
                    false,
                    crate::model::Confidence::Low,
                );
            }
        }
    }

    // No match → external
    (None, true, crate::model::Confidence::Low)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CallArg, CallFact, Fact, FactBase, FunctionFact, ParamInfo, SinkFact,
        Confidence, Severity,
    };

    fn make_function(id: &str, name: &str, qualified_name: &str, file: &str, params: Vec<&str>) -> Fact {
        Fact::Function(FunctionFact {
            base: FactBase {
                id: id.into(),
                file: file.into(),
                line: 1,
                extractor: "test".into(),
            },
            language: "python".into(),
            name: name.into(),
            qualified_name: qualified_name.into(),
            end_line: 5,
            params: params
                .into_iter()
                .map(|p| ParamInfo {
                    name: p.into(),
                    annotation: None,
                    default: None,
                })
                .collect(),
            decorators: vec![],
            docstring: None,
            return_type: None,
            enclosing_class: None,
        })
    }

    fn make_call(id: &str, caller: &str, callee: &str, normalized: &str, file: &str, line: u32, args: Vec<(u32, &str)>) -> Fact {
        Fact::Call(CallFact {
            base: FactBase {
                id: id.into(),
                file: file.into(),
                line,
                extractor: "test".into(),
            },
            caller: caller.into(),
            callee: callee.into(),
            normalized_callee: Some(normalized.into()),
            column: Some(0),
            end_line: Some(line),
            snippet: String::new(),
            args: args
                .into_iter()
                .map(|(i, e)| CallArg {
                    index: i,
                    expr: e.into(),
                    kind: "positional".into(),
                })
                .collect(),
            kwargs: std::collections::BTreeMap::new(),
            resolution: None,
        })
    }

    fn make_sink(id: &str, call_id: &str, category: &str, file: &str, line: u32) -> Fact {
        Fact::Sink(SinkFact {
            base: FactBase {
                id: id.into(),
                file: file.into(),
                line,
                extractor: "test".into(),
            },
            call_id: call_id.into(),
            category: category.into(),
            rule_id: format!("python.{category}"),
            sink_name: "test_sink".into(),
            severity_base: Severity::High,
            reason: "test".into(),
            conditions: std::collections::BTreeMap::new(),
            confidence: Confidence::High,
        })
    }

    #[test]
    fn builds_function_nodes() {
        let facts = vec![
            make_function("python:a.py:foo", "foo", "foo", "a.py", vec!["x"]),
            make_function("python:b.py:bar", "bar", "bar", "b.py", vec!["y"]),
        ];
        let g = build_graph(&facts);
        assert_eq!(g.functions.len(), 2);
        assert!(g.nodes.contains_key("python:a.py:foo"));
        assert!(g.nodes.contains_key("python:b.py:bar"));
    }

    #[test]
    fn resolves_call_to_function_in_same_file() {
        let facts = vec![
            make_function("python:s.py:main", "main", "main", "s.py", vec![]),
            make_function("python:s.py:helper", "helper", "helper", "s.py", vec!["arg"]),
            make_call(
                "call:s.py:3:0", "python:s.py:main", "helper", "helper", "s.py", 3,
                vec![(0, "x")],
            ),
        ];
        let g = build_graph(&facts);
        // Check CallToFunction edge exists
        let edges = g.outgoing_edges("call:s.py:3:0");
        let ctf = edges.iter().find(|e| matches!(e, Edge::CallToFunction { .. }));
        assert!(ctf.is_some());
        if let Some(Edge::CallToFunction { callee_function_id, confidence, .. }) = ctf {
            assert_eq!(callee_function_id, "python:s.py:helper");
            assert_eq!(*confidence, Confidence::High);
        }
    }

    #[test]
    fn unresolvable_callee_marked_external() {
        let facts = vec![
            make_function("python:s.py:main", "main", "main", "s.py", vec![]),
            make_call(
                "call:s.py:5:0", "python:s.py:main", "os.system", "os.system", "s.py", 5,
                vec![(0, "cmd")],
            ),
        ];
        let g = build_graph(&facts);
        if let Some(Node::Call { is_external, .. }) = g.nodes.get("call:s.py:5:0") {
            assert!(is_external);
        } else {
            panic!("call node not found");
        }
    }

    #[test]
    fn builds_sink_nodes_with_edges() {
        let facts = vec![
            make_function("python:s.py:main", "main", "main", "s.py", vec![]),
            make_call("call:s.py:10:0", "python:s.py:main", "os.system", "os.system", "s.py", 10, vec![(0, "x")]),
            make_sink("sink:cmd:s.py:10", "call:s.py:10:0", "command_execution", "s.py", 10),
        ];
        let g = build_graph(&facts);
        assert!(g.nodes.contains_key("sink:cmd:s.py:10"));
        let edges = g.outgoing_edges("call:s.py:10:0");
        assert!(edges.iter().any(|e| matches!(e, Edge::CallToSink { .. })));
    }

    #[test]
    fn builds_variable_nodes_from_assign_facts() {
        let facts = vec![
            make_function("python:s.py:main", "main", "main", "s.py", vec!["cmd"]),
            Fact::Assign(crate::model::AssignFact {
                base: FactBase {
                    id: "assign:s.py:3:runner".into(),
                    file: "s.py".into(),
                    line: 3,
                    extractor: "test".into(),
                },
                function_id: "python:s.py:main".into(),
                target: "runner".into(),
                value: "sp.run".into(),
                snippet: "runner = sp.run".into(),
            }),
        ];
        let g = build_graph(&facts);
        let var_id = make_var_id("python:s.py:main", "runner");
        assert!(g.nodes.contains_key(&var_id));
    }

    #[test]
    fn val_to_var_edge_for_simple_assignment() {
        let facts = vec![
            make_function("python:s.py:main", "main", "main", "s.py", vec!["cmd"]),
            Fact::Assign(crate::model::AssignFact {
                base: FactBase {
                    id: "assign:s.py:4:command".into(),
                    file: "s.py".into(),
                    line: 4,
                    extractor: "test".into(),
                },
                function_id: "python:s.py:main".into(),
                target: "command".into(),
                value: "cmd".into(),
                snippet: "command = cmd".into(),
            }),
        ];
        let g = build_graph(&facts);
        let to_id = make_var_id("python:s.py:main", "command");
        let from_id = make_var_id("python:s.py:main", "cmd");
        let edges = g.incoming_edges(&to_id);
        assert!(edges.iter().any(|e| matches!(e, Edge::ValToVar { from_var_id, .. } if from_var_id == &from_id)));
    }
}
