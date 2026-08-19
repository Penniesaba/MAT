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
    // Register Variable nodes (from Assign facts) before Call nodes so that
    // the VarToArg edges built in Step 4 can link to variables defined
    // anywhere in the file (removes line-order dependence).
    // -----------------------------------------------------------------------
    for fact in facts {
        if let Fact::Assign(a) = fact {
            let target_id = make_var_id(&a.function_id, &a.target);
            g.add_node(
                target_id.clone(),
                Node::Variable {
                    id: target_id,
                    name: a.target.clone(),
                    function_id: a.function_id.clone(),
                },
            );
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

            // CallInFunction edge (call → function)
            if !c.caller.is_empty() {
                g.add_edge(Edge::CallInFunction {
                    call_id: call_id.clone(),
                    function_id: c.caller.clone(),
                });
                // FunctionCall reverse edge (function → call) for forward traversal
                g.add_edge(Edge::FunctionCall {
                    function_id: c.caller.clone(),
                    call_id: call_id.clone(),
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
                let var_id = make_var_id(&c.caller, strip_ref_prefix(&arg.expr));
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
                    let stripped = strip_ref_prefix(&arg.expr);
                    if name == stripped
                        || stripped.starts_with(&format!("{name}."))
                        || stripped.starts_with(&format!("{name}["))
                    {
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
    // Step 6: Assignment propagation — link each assignment's right-hand side
    // back to the variables and sources it references.
    // -----------------------------------------------------------------------
    for fact in facts {
        if let Fact::Assign(a) = fact {
            let target_id = make_var_id(&a.function_id, &a.target);
            let trimmed = a.value.trim();

            // Link every identifier referenced on the right-hand side to the
            // target, so compound expressions (`x / y`, `x.strip()`, `x[y]`)
            // carry taint instead of leaving the variable orphaned.
            for ident in extract_identifiers(trimmed) {
                let var_id = make_var_id(&a.function_id, &ident);
                if g.nodes.contains_key(&var_id) {
                    g.add_edge(Edge::ValToVar {
                        from_var_id: var_id,
                        to_var_id: target_id.clone(),
                    });
                } else if let Some(source_id) = source_id_for_name(&g, &a.function_id, &ident) {
                    g.add_edge(Edge::SourceToVar {
                        source_id,
                        var_id: target_id.clone(),
                    });
                }
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

/// Strip a leading `&` / `&mut` / `*` reference/deref prefix from an argument
/// expression so source/variable name matching works on `&command`, `&mut x`,
/// etc. (Rust call args are recorded with their reference operators).
fn strip_ref_prefix(expr: &str) -> &str {
    let mut s = expr.trim_start();
    while s.starts_with('&') || s.starts_with('*') {
        s = s[1..].trim_start();
    }
    if let Some(rest) = s.strip_prefix("mut ") {
        s = rest;
    }
    s
}

/// Extract identifier tokens from an assignment's right-hand side expression.
/// String-literal contents are skipped so `x = "name"` does not falsely taint a
/// variable named `name`; operators and method names (`.strip`, `(...)`) are
/// naturally ignored because they do not name in-scope variables or sources.
fn extract_identifiers(expr: &str) -> Vec<String> {
    let bytes = expr.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    let n = bytes.len();

    while i < n {
        let b = bytes[i];

        // Skip quoted string literals (single, double, and triple-quoted).
        if b == b'"' || b == b'\'' {
            i += 1;
            if i + 1 < n && bytes[i] == b && bytes[i + 1] == b {
                i += 2; // triple-quote opening
                while i < n {
                    if bytes[i] == b && i + 2 < n && bytes[i + 1] == b && bytes[i + 2] == b {
                        i += 3;
                        break;
                    }
                    i += 1;
                }
            } else {
                while i < n {
                    if bytes[i] == b'\\' {
                        i += 2;
                    } else if bytes[i] == b {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            }
            continue;
        }

        // Start of an identifier token.
        if b == b'_' || b.is_ascii_alphabetic() {
            let start = i;
            i += 1;
            while i < n && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            let token = &expr[start..i];
            if !is_python_keyword(token) {
                out.push(token.to_string());
            }
        } else {
            i += 1;
        }
    }

    // De-duplicate while preserving first-seen order.
    let mut seen = std::collections::HashSet::new();
    out.retain(|t| seen.insert(t.clone()));
    out
}

fn is_python_keyword(token: &str) -> bool {
    matches!(
        token,
        "True" | "False" | "None" | "and" | "or" | "not" | "if" | "else" | "elif" | "for"
            | "while" | "in" | "is" | "lambda" | "def" | "return" | "import" | "from" | "as"
            | "with" | "try" | "except" | "finally" | "raise" | "class" | "global" | "nonlocal"
            | "pass" | "break" | "continue" | "yield" | "del" | "assert" | "async" | "await"
    )
}

/// Find the id of a Source node in `function_id` whose name is `name`.
fn source_id_for_name(g: &Graph, function_id: &str, name: &str) -> Option<String> {
    g.source_to_function
        .iter()
        .filter(|(_, fid)| *fid == function_id)
        .filter_map(|(source_id, _)| match g.nodes.get(source_id) {
            Some(Node::Source { name: source_name, .. }) if source_name == name => {
                Some(source_id.clone())
            }
            _ => None,
        })
        .next()
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
        let func_id = "python:s.py:main";
        let facts = vec![
            make_function(func_id, "main", "main", "s.py", vec![]),
            make_assign("assign:s.py:3:cmd", func_id, "cmd", "\"x\"", 3),
            make_assign("assign:s.py:4:command", func_id, "command", "cmd", 4),
        ];
        let g = build_graph(&facts);
        let to_id = make_var_id(func_id, "command");
        let from_id = make_var_id(func_id, "cmd");
        let edges = g.incoming_edges(&to_id);
        assert!(edges.iter().any(|e| matches!(e, Edge::ValToVar { from_var_id, .. } if from_var_id == &from_id)));
    }

    fn make_assign(id: &str, func_id: &str, target: &str, value: &str, line: u32) -> Fact {
        Fact::Assign(crate::model::AssignFact {
            base: FactBase {
                id: id.into(),
                file: "s.py".into(),
                line,
                extractor: "test".into(),
            },
            function_id: func_id.into(),
            target: target.into(),
            value: value.into(),
            snippet: format!("{target} = {value}"),
        })
    }

    #[test]
    fn extracts_identifiers_from_compound_assignment() {
        let func_id = "python:s.py:f".to_string();
        let facts = vec![
            make_function("python:s.py:f", "f", "f", "s.py", vec![]),
            make_assign("assign:s.py:1:a", &func_id, "a", "\"x\"", 1),
            make_assign("assign:s.py:2:b", &func_id, "b", "\"y\"", 2),
            make_assign("assign:s.py:3:c", &func_id, "c", "(a Div b)", 3),
        ];
        let g = build_graph(&facts);

        let mut froms: Vec<String> = g
            .incoming_edges(&make_var_id(&func_id, "c"))
            .iter()
            .filter_map(|e| match e {
                Edge::ValToVar { from_var_id, .. } => Some(from_var_id.clone()),
                _ => None,
            })
            .collect();
        froms.sort();

        let mut expected = vec![make_var_id(&func_id, "a"), make_var_id(&func_id, "b")];
        expected.sort();
        assert_eq!(froms, expected);
    }

    #[test]
    fn links_source_to_var_on_simple_assignment() {
        let func_id = "python:s.py:handler".to_string();
        let source_id = "source:s.py:handler:cmd".to_string();
        let facts = vec![
            make_function("python:s.py:handler", "handler", "handler", "s.py", vec!["cmd"]),
            Fact::Source(crate::model::SourceFact {
                base: FactBase {
                    id: source_id.clone(),
                    file: "s.py".into(),
                    line: 1,
                    extractor: "test".into(),
                },
                kind: "mcp_tool_parameter".into(),
                function_id: func_id.clone(),
                name: "cmd".into(),
                confidence: Confidence::High,
            }),
            make_assign("assign:s.py:2:command", &func_id, "command", "cmd", 2),
        ];
        let g = build_graph(&facts);

        let command_id = make_var_id(&func_id, "command");
        let linked = g.incoming_edges(&command_id).iter().any(|e| {
            matches!(e, Edge::SourceToVar { source_id: sid, .. } if sid.as_str() == source_id.as_str())
        });
        assert!(linked, "expected SourceToVar from source `cmd` to variable `command`");
    }

    #[test]
    fn reference_prefixed_arg_matches_source() {
        let func_id = "rust:main.rs:exec_shell".to_string();
        let source_id = "source:main.rs:exec_shell:command".to_string();
        let facts = vec![
            make_function(&func_id, "exec_shell", "exec_shell", "main.rs", vec!["command"]),
            Fact::Source(crate::model::SourceFact {
                base: FactBase { id: source_id.clone(), file: "main.rs".into(), line: 24, extractor: "test".into() },
                kind: "mcp_tool_parameter".into(), function_id: func_id.clone(),
                name: "command".into(), confidence: Confidence::High,
            }),
            make_call("call:main.rs:32:0", &func_id, "build_shell_command", "helpers::build_shell_command", "main.rs", 32, vec![(0, "&command")]),
        ];
        let g = build_graph(&facts);
        let edges = g.outgoing_edges(&source_id);
        assert!(edges.iter().any(|e| matches!(e, Edge::SourceToArg { call_id, .. } if call_id == "call:main.rs:32:0")),
            "expected SourceToArg from `command` to the `&command` call");
    }
}
