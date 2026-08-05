# Phase 10/11 Unified Taint Analysis — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a unified cross-file taint analysis module that constructs a program graph from facts (Python/JS/TS/Rust) and runs BFS-based forward/backward propagation to trace source-to-sink paths, producing `TaintAnalysisResult` and `DataFlowFact` values.

**Architecture:** Five-file module `static_analysis/taint/` — graph data structures, graph builder from facts, parametrized BFS propagation, result generation to `TaintAnalysisResult` + `DataFlowFact`. Integrated via `lines.rs` replacing the current bail-with-error stub, with `pipeline.rs` updated to pass facts and collect results.

**Tech Stack:** Rust, existing fact model types (`TaintAnalysisResult`, `DataFlowFact`, `PathStep`, `PathStepKind`, `Confidence`), no new dependencies.

## Global Constraints

- No empty implementations or placeholder stubs — every function must be fully implemented
- All taint analysis logic must work identically for Python, JS/TS, and Rust facts
- Default taint config: `enabled: false, forward: true, backward: true, max_depth: 8, entrypoint_required: true`
- Output must serialize correctly to JSON (existing `TaintAnalysisResult` and `DataFlowFact` serialization)
- Existing tests that reference `run_taint_line` must be updated (not broken)
- Cross-file callee resolution must handle external libraries gracefully (no crash, mark as external)
- BFS must handle cycles via visited set — no infinite loops

---

### Task 1: Graph data structures (`graph.rs`)

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/graph.rs`

**Interfaces:**
- Produces: `Node` enum, `Edge` enum, `FunctionMeta` struct, `Graph` struct — all public to the taint module

- [ ] **Step 1: Write `graph.rs` with Node, Edge, FunctionMeta, Graph**

```rust
use std::collections::HashMap;
use crate::model::{Confidence, Severity};

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Function {
        id: String,
        name: String,
        qualified_name: String,
        file: String,
        params: Vec<String>,
        language: String,
        line: u32,
    },
    Source {
        id: String,
        name: String,
        kind: String,
        function_id: String,
        confidence: Confidence,
    },
    Sink {
        id: String,
        category: String,
        call_id: String,
        severity_base: Severity,
    },
    Call {
        id: String,
        callee: String,
        normalized_callee: String,
        caller_function_id: String,
        is_external: bool,
        line: u32,
        file: String,
    },
    Variable {
        id: String,
        name: String,
        function_id: String,
    },
}

impl Node {
    pub fn id(&self) -> &str {
        match self {
            Node::Function { id, .. } => id,
            Node::Source { id, .. } => id,
            Node::Sink { id, .. } => id,
            Node::Call { id, .. } => id,
            Node::Variable { id, .. } => id,
        }
    }

    pub fn node_type_name(&self) -> &'static str {
        match self {
            Node::Function { .. } => "function",
            Node::Source { .. } => "source",
            Node::Sink { .. } => "sink",
            Node::Call { .. } => "call",
            Node::Variable { .. } => "variable",
        }
    }
}

// ---------------------------------------------------------------------------
// Edge
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Edge {
    SourceInFunction {
        source_id: String,
        function_id: String,
    },
    CallInFunction {
        call_id: String,
        function_id: String,
    },
    CallToFunction {
        call_id: String,
        callee_function_id: String,
        confidence: Confidence,
    },
    ArgToParam {
        call_id: String,
        arg_index: u32,
        param_name: String,
        callee_function_id: String,
    },
    VarToArg {
        var_id: String,
        call_id: String,
        arg_index: u32,
    },
    ValToVar {
        from_var_id: String,
        to_var_id: String,
    },
    CallToSink {
        call_id: String,
        sink_id: String,
    },
    ReturnToVar {
        call_id: String,
        var_id: String,
    },
    SourceToArg {
        source_id: String,
        call_id: String,
        arg_index: u32,
    },
}

impl Edge {
    pub fn edge_type_name(&self) -> &'static str {
        match self {
            Edge::SourceInFunction { .. } => "source_in_function",
            Edge::CallInFunction { .. } => "call_in_function",
            Edge::CallToFunction { .. } => "call_to_function",
            Edge::ArgToParam { .. } => "arg_to_param",
            Edge::VarToArg { .. } => "var_to_arg",
            Edge::ValToVar { .. } => "val_to_var",
            Edge::CallToSink { .. } => "call_to_sink",
            Edge::ReturnToVar { .. } => "return_to_var",
            Edge::SourceToArg { .. } => "source_to_arg",
        }
    }

    pub fn from_id(&self) -> &str {
        match self {
            Edge::SourceInFunction { source_id, .. } => source_id,
            Edge::CallInFunction { call_id, .. } => call_id,
            Edge::CallToFunction { call_id, .. } => call_id,
            Edge::ArgToParam { call_id, .. } => call_id,
            Edge::VarToArg { var_id, .. } => var_id,
            Edge::ValToVar { from_var_id, .. } => from_var_id,
            Edge::CallToSink { call_id, .. } => call_id,
            Edge::ReturnToVar { call_id, .. } => call_id,
            Edge::SourceToArg { source_id, .. } => source_id,
        }
    }

    pub fn to_id(&self) -> &str {
        match self {
            Edge::SourceInFunction { function_id, .. } => function_id,
            Edge::CallInFunction { function_id, .. } => function_id,
            Edge::CallToFunction { callee_function_id, .. } => callee_function_id,
            Edge::ArgToParam { param_name, callee_function_id, .. } => callee_function_id,
            Edge::VarToArg { call_id, .. } => call_id,
            Edge::ValToVar { to_var_id, .. } => to_var_id,
            Edge::CallToSink { sink_id, .. } => sink_id,
            Edge::ReturnToVar { var_id, .. } => var_id,
            Edge::SourceToArg { call_id, .. } => call_id,
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionMeta
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FunctionMeta {
    pub name: String,
    pub qualified_name: String,
    pub file: String,
    pub language: String,
    pub params: Vec<String>,
    pub line: u32,
}

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Graph {
    pub nodes: HashMap<String, Node>,
    pub outgoing: HashMap<String, Vec<Edge>>,
    pub incoming: HashMap<String, Vec<Edge>>,
    pub functions: HashMap<String, FunctionMeta>,
    pub source_to_function: HashMap<String, String>,
    pub entrypoint_to_function: HashMap<String, String>,
}

impl Graph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            functions: HashMap::new(),
            source_to_function: HashMap::new(),
            entrypoint_to_function: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, id: String, node: Node) {
        self.nodes.insert(id, node);
    }

    pub fn add_edge(&mut self, edge: Edge) {
        let from = edge.from_id().to_string();
        let to = edge.to_id().to_string();
        self.outgoing.entry(from.clone()).or_default().push(edge.clone());
        self.incoming.entry(to).or_default().push(edge);
    }

    pub fn get_node(&self, id: &str) -> Option<&Node> {
        self.nodes.get(id)
    }

    pub fn outgoing_edges(&self, node_id: &str) -> &[Edge] {
        self.outgoing.get(node_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn incoming_edges(&self, node_id: &str) -> &[Edge] {
        self.incoming.get(node_id).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

impl Default for Graph {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 2: Write unit tests for Node and Edge ID methods**

At the bottom of `graph.rs`, add:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Severity};

    #[test]
    fn node_id_returns_correct_field() {
        let func = Node::Function {
            id: "python:server.py:run_cmd".into(),
            name: "run_cmd".into(),
            qualified_name: "run_cmd".into(),
            file: "server.py".into(),
            params: vec!["cmd".into()],
            language: "python".into(),
            line: 5,
        };
        assert_eq!(func.id(), "python:server.py:run_cmd");
        assert_eq!(func.node_type_name(), "function");
    }

    #[test]
    fn edge_from_to_ids_are_correct() {
        let edge = Edge::CallToFunction {
            call_id: "call:server.py:8:4".into(),
            callee_function_id: "python:server.py:helper".into(),
            confidence: Confidence::High,
        };
        assert_eq!(edge.from_id(), "call:server.py:8:4");
        assert_eq!(edge.to_id(), "python:server.py:helper");
        assert_eq!(edge.edge_type_name(), "call_to_function");
    }

    #[test]
    fn graph_add_node_and_edge() {
        let mut g = Graph::new();
        let func_id = "python:server.py:main".into();
        g.add_node(func_id.clone(), Node::Function {
            id: func_id.clone(),
            name: "main".into(),
            qualified_name: "main".into(),
            file: "server.py".into(),
            params: vec![],
            language: "python".into(),
            line: 1,
        });

        let call_id = "call:server.py:5:0".into();
        g.add_node(call_id.clone(), Node::Call {
            id: call_id.clone(),
            callee: "helper".into(),
            normalized_callee: "helper".into(),
            caller_function_id: func_id.clone(),
            is_external: false,
            line: 5,
            file: "server.py".into(),
        });

        let edge = Edge::CallInFunction {
            call_id: call_id.clone(),
            function_id: func_id.clone(),
        };
        g.add_edge(edge);

        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.outgoing_edges(&call_id).len(), 1);
        assert_eq!(g.incoming_edges(&func_id).len(), 1);
    }

    #[test]
    fn graph_default_is_empty() {
        let g = Graph::default();
        assert!(g.nodes.is_empty());
        assert!(g.outgoing.is_empty());
        assert!(g.incoming.is_empty());
    }
}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core -- taint::graph`
Expected: All 4 tests pass

- [ ] **Step 4: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/taint/
git commit -m "feat(phase10-11): add taint graph data structures

- Node enum: Function, Source, Sink, Call, Variable
- Edge enum: 9 edge types covering all fact relationships
- Graph struct with bidirectional edge indexing

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 2: Graph builder (`builder.rs`)

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/builder.rs`

**Interfaces:**
- Consumes: `Vec<Fact>` (from `pipeline.rs`), `Graph`, `Node`, `Edge`, `FunctionMeta` (from `graph.rs`)
- Produces: `pub fn build_graph(facts: &[Fact]) -> Graph`

- [ ] **Step 1: Write `builder.rs` with full graph construction logic**

```rust
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
                if let Some(meta) = g.functions.get(&func_id) {
                    for arg in &c.args {
                        if (arg.index as usize) < meta.params.len() {
                            g.add_edge(Edge::ArgToParam {
                                call_id: call_id.clone(),
                                arg_index: arg.index,
                                param_name: meta.params[arg.index as usize].clone(),
                                callee_function_id: func_id.clone(),
                            });
                        }
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
                for (source_id, func_id) in &g.source_to_function {
                    if func_id == &c.caller {
                        if let Some(Node::Source { name, .. }) = g.nodes.get(source_id) {
                            if name == &arg.expr {
                                g.add_edge(Edge::SourceToArg {
                                    source_id: source_id.clone(),
                                    call_id: call_id.clone(),
                                    arg_index: arg.index,
                                });
                            }
                        }
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
        CallArg, CallFact, Fact, FactBase, FunctionFact, ParamInfo, SinkFact, SourceFact,
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
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core -- taint::builder`
Expected: All 6 tests pass

- [ ] **Step 3: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/taint/builder.rs
git commit -m "feat(phase10-11): add graph builder from facts

- 6-step construction: functions → sources → calls → sinks → variables
- Cross-file callee resolution with qualified_name matching
- External function handling (no crash)
- ArgToParam, VarToArg, ValToVar, SourceToArg, ReturnToVar edges

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 3: BFS propagation (`propagation.rs`)

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/propagation.rs`

**Interfaces:**
- Consumes: `Graph`, `StaticTaintConfig` (from config), `Node`, `Edge` (from graph.rs)
- Produces: `PropagationPath` struct, `pub fn propagate_forward(...)`, `pub fn propagate_backward(...)`

- [ ] **Step 1: Write `propagation.rs`**

```rust
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

        let current_node = match graph.get_node(&item.node_id) {
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
                    Direction::Forward => (item.node_id.clone(), next_id.to_string()),
                    Direction::Backward => (next_id.to_string(), item.node_id.clone()),
                };

                let entrypoint_id = resolve_entrypoint_id(graph, &source_id);

                let confidence = compute_path_confidence(&new_steps, next_has_external);

                results.push(PropagationPath {
                    source_id,
                    sink_id,
                    entrypoint_id,
                    steps: new_steps,
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
                        let source_id = item.node_id.clone();
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
fn edge_to_path_step(edge: &Edge, graph: &Graph, direction: Direction) -> Option<PathStep> {
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
            Some(PathStep {
                kind: PathStepKind::Assign,
                line,
                name: to_name,
                function: func,
                from_: Some(from_var_id.clone()),
                to: Some(to_var_id.clone()),
                snippet: from_name.zip(to_name).map(|(f, t)| format!("{t} = {f}")),
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

        config.entrypoint_required = false;
        // Still empty because no sink to reach, but source should be a start node
        let start_ids: Vec<String> = g.nodes.iter()
            .filter_map(|(id, n)| if matches!(n, Node::Source { .. }) { Some(id.clone()) } else { None })
            .collect();
        assert!(!start_ids.is_empty());
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core -- taint::propagation`
Expected: All 5 tests pass

- [ ] **Step 3: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/taint/propagation.rs
git commit -m "feat(phase10-11): add BFS-based taint propagation

- Forward propagation: Source → Sink via BFS with depth limit
- Backward propagation: Sink → Source via reverse edges
- Cycle prevention with visited set per BFS path
- Confidence computation from external calls and variable aliasing
- Path deduplication keeping shortest path per (source, sink) pair

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: Result generation (`result.rs`)

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/result.rs`

**Interfaces:**
- Consumes: `PropagationPath` (from propagation.rs), `Graph` (from graph.rs)
- Produces: `pub fn build_taint_results(...) -> Vec<TaintAnalysisResult>`, `pub fn build_dataflow_facts(...) -> Vec<Fact>`

- [ ] **Step 1: Write `result.rs`**

```rust
use crate::model::{
    DataFlowFact, EntryPointKind, Fact, FactBase, TaintAnalysisResult,
};
use super::graph::{Graph, Node};
use super::propagation::PropagationPath;

/// Convert propagation paths into TaintAnalysisResult values.
pub fn build_taint_results(
    paths: &[PropagationPath],
    graph: &Graph,
) -> Vec<TaintAnalysisResult> {
    paths
        .iter()
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
                .filter(|s| s.kind == crate::model::PathStepKind::CallArg || s.kind == crate::model::PathStepKind::Return)
                .filter_map(|s| s.function.clone())
                .collect();

            let dataflow_path: Vec<String> = path
                .steps
                .iter()
                .filter_map(|s| s.snippet.clone())
                .collect();

            let evidence: Vec<String> = path
                .steps
                .iter()
                .filter(|s| s.snippet.is_some() || s.name.is_some())
                .map(|s| {
                    let loc = format!("{}:{}", 
                        s.call_id.as_deref().unwrap_or("?"), 
                        s.line);
                    let detail = s.snippet.clone().unwrap_or_else(|| {
                        s.name.clone().unwrap_or_else(|| "?".to_string())
                    });
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

/// Convert propagation paths into DataFlowFact values for persistence.
pub fn build_dataflow_facts(
    paths: &[PropagationPath],
) -> Vec<Fact> {
    paths
        .iter()
        .map(|path| {
            let file = "".to_string(); // Derive from source/sink context
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
    use crate::model::{Confidence, PathStep, PathStepKind, Severity};

    fn make_test_graph() -> Graph {
        let mut g = Graph::new();
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
        g.source_to_function.insert("source:s.py:handler:cmd".into(), func_id.clone());
        g.entrypoint_to_function.insert("entry:s.py:handler".into(), func_id);
        g
    }

    #[test]
    fn builds_taint_results_from_paths() {
        let g = make_test_graph();
        let paths = vec![PropagationPath {
            source_id: "source:s.py:handler:cmd".into(),
            sink_id: "sink:cmd:s.py:3".into(),
            entrypoint_id: Some("entry:s.py:handler".into()),
            steps: vec![
                PathStep {
                    kind: PathStepKind::Param,
                    line: 3,
                    name: Some("cmd".into()),
                    function: Some("python:s.py:handler".into()),
                    from_: None,
                    to: None,
                    snippet: Some("os.system(cmd)".into()),
                    call_id: Some("call:s.py:3:0".into()),
                    arg_index: Some(0),
                },
            ],
            confidence: Confidence::High,
            has_external_call: true,
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
        }];

        let facts = build_dataflow_facts(&paths);
        assert_eq!(facts.len(), 1);
        if let Fact::Dataflow(df) = &facts[0] {
            assert!(df.base.id.starts_with("dataflow:"));
            assert_eq!(df.source_id, "source:s.py:handler:cmd");
            assert_eq!(df.sink_id, "sink:cmd:s.py:3");
            assert_eq!(df.confidence, Confidence::Medium);
        } else {
            panic!("Expected Dataflow fact");
        }
    }

    #[test]
    fn empty_paths_produce_empty_results() {
        let g = Graph::new();
        assert!(build_taint_results(&[], &g).is_empty());
        assert!(build_dataflow_facts(&[]).is_empty());
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core -- taint::result`
Expected: All 3 tests pass

- [ ] **Step 3: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/taint/result.rs
git commit -m "feat(phase10-11): add result generation from taint paths

- PropagationPath → TaintAnalysisResult mapping
- PropagationPath → DataFlowFact mapping
- Entrypoint MCP status and backward trace detection
- Evidence extraction from path steps

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5: Module public API (`mod.rs`)

**Files:**
- Create: `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/mod.rs`

**Interfaces:**
- Consumes: All sub-modules (graph, builder, propagation, result), `StaticTaintConfig`, `Fact`
- Produces: `pub fn run_taint_analysis(&[Fact], &StaticTaintConfig) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)>`

- [ ] **Step 1: Write `mod.rs`**

```rust
pub mod builder;
pub mod graph;
pub mod propagation;
pub mod result;

use anyhow::Result;
use crate::config::StaticTaintConfig;
use crate::model::{Fact, TaintAnalysisResult};

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
        AssignFact, CallArg, CallFact, Confidence, EntryPointFact, EntryPointKind,
        Fact, FactBase, FunctionFact, ParamInfo, Severity, SinkFact, SourceFact,
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
                evidence: Some(crate::model::EntryPointEvidence { kind: "decorator".into(), text: "@mcp.tool()".into() }),
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

        assert!(!results.is_empty(), "Expected taint results for direct source→sink");
        let r = &results[0];
        assert!(r.source_id.contains("cmd"));
        assert!(r.sink_id.contains("command_execution"));
        assert!(r.entrypoint_is_mcp);
        assert_eq!(r.taint_confidence, Confidence::High);
        assert!(!dataflows.is_empty());
    }

    #[test]
    fn one_hop_call_chain() {
        // handler(cmd) → helper(cmd) → os.system(cmd)
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
                evidence: Some(crate::model::EntryPointEvidence { kind: "decorator".into(), text: "@mcp.tool()".into() }),
                params: vec!["cmd".into()], confidence: Confidence::High,
            }),
            Fact::Source(SourceFact {
                base: FactBase { id: "source:s.py:handler:cmd".into(), file: file.clone(), line: 1, extractor: "t".into() },
                kind: "mcp_tool_parameter".into(), function_id: func_id.clone(),
                name: "cmd".into(), confidence: Confidence::High,
            }),
            // handler → helper(cmd)
            Fact::Call(CallFact {
                base: FactBase { id: call1_id.clone(), file: file.clone(), line: 4, extractor: "t".into() },
                caller: func_id.clone(), callee: "helper".into(),
                normalized_callee: Some("helper".into()),
                column: Some(0), end_line: Some(4), snippet: "helper(cmd)".into(),
                args: vec![CallArg { index: 0, expr: "cmd".into(), kind: "positional".into() }],
                kwargs: std::collections::BTreeMap::new(), resolution: None,
            }),
            // helper → os.system(command)
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
                evidence: Some(crate::model::EntryPointEvidence { kind: "decorator".into(), text: "@mcp.tool()".into() }),
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
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core -- taint::tests`
Expected: All 5 integration tests pass

- [ ] **Step 3: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/taint/mod.rs
git commit -m "feat(phase10-11): add taint module public API and integration tests

- run_taint_analysis() orchestrates: build → propagate → generate results
- Integration tests: direct source→sink, one-hop chain, disabled, empty,
  assignment alias

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 6: Pipeline integration

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs`
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`

**Interfaces:**
- Consumes: `run_taint_analysis` from taint module
- Produces: Updated `run_taint_line()` signature, updated `run_static_scan()` to pass facts

- [ ] **Step 1: Add taint module to `mod.rs`**

In `rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`, add the module declaration. The file currently has:

```rust
pub mod facts;

mod discovery;
mod lines;
mod pipeline;
mod rule;
...
```

Add `mod taint;` after `mod rule;`:

```rust
pub mod facts;

mod discovery;
mod lines;
mod pipeline;
mod rule;
mod taint;
```

- [ ] **Step 2: Rewrite `run_taint_line` in `lines.rs`**

Replace the current `run_taint_line` function. The current code:

```rust
pub fn run_taint_line(ctx: &StaticScanContext) -> Result<Vec<TaintAnalysisResult>> {
    if !ctx.config.static_.taint.enabled {
        return Ok(Vec::new());
    }

    bail!(
        "taint analysis line is enabled but not implemented until Phase 10/11; disable [static.taint].enabled or continue the refactor roadmap"
    )
}
```

Replace with:

```rust
use super::taint;
use crate::Fact;

pub fn run_taint_line(
    ctx: &StaticScanContext,
    facts: &[Fact],
) -> Result<(Vec<TaintAnalysisResult>, Vec<Fact>)> {
    if !ctx.config.static_.taint.enabled {
        return Ok((Vec::new(), Vec::new()));
    }

    taint::run_taint_analysis(facts, &ctx.config.static_.taint)
}
```

And update the test `enabled_taint_line_reports_unimplemented_error` → it should now verify the taint module works when enabled (with sample facts):

```rust
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
```

- [ ] **Step 3: Update `pipeline.rs` to pass facts**

In `run_static_scan()`, change the taint line call from:

```rust
let taint_results = lines::run_taint_line(&ctx)?;
```

To:

```rust
let (taint_results, dataflow_facts) = lines::run_taint_line(&ctx, &facts)?;
```

And add after the taint_results assignment:

```rust
let mut all_facts = facts;
all_facts.extend(dataflow_facts);
```

Then update `summary.fact_count` to use `all_facts.len()` and the `StaticAnalysisResult` to use `all_facts` instead of `facts`.

Full updated section of `run_static_scan()`:

```rust
let facts = extract_static_facts(&ctx)?;
let rule_results = lines::run_rule_line(&ctx, loaded_rulebook.as_ref())?;
let (taint_results, dataflow_facts) = lines::run_taint_line(&ctx, &facts)?;
let agent_results = lines::run_agent_line(&ctx)?;

let mut all_facts = facts;
all_facts.extend(dataflow_facts);

let summary = StaticAnalysisSummary {
    target: target_label(&targets),
    fact_count: all_facts.len(),
    rule_result_count: rule_results.len(),
    taint_result_count: taint_results.len(),
    agent_result_count: agent_results.len(),
    fused_finding_count: 0,
    highest_severity: None,
    risk_level: "none".to_string(),
};

Ok(StaticAnalysisResult {
    facts: all_facts,
    rule_results,
    taint_results,
    agent_results,
    fused_findings: Vec::new(),
    summary,
    config_snapshot: ConfigSnapshot {
        runtime: effective_config,
        rulebook_paths: ctx.rulebook_paths,
    },
})
```

- [ ] **Step 4: Run all existing tests**

Run: `cargo test -p mcp-sec-audit-core`
Expected: All tests pass (including `lines::tests` and `pipeline::tests`)

- [ ] **Step 5: Run the full CLI build**

Run: `cargo build -p mcp-sec-audit-cli`
Expected: Build succeeds

- [ ] **Step 6: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs
git add rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs
git add rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs
git commit -m "feat(phase10-11): integrate taint module into static analysis pipeline

- Replace run_taint_line() bail stub with real taint::run_taint_analysis()
- Pass extracted facts to taint line, collect DataFlowFact results
- Update fact_count in summary to include dataflow facts
- Update existing test to verify taint module produces results

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 7: JS/TS and Rust integration tests

**Files:**
- Modify: `rust/crates/mcp-sec-audit-core/src/static_analysis/taint/mod.rs` — add JS and Rust test fixtures

- [ ] **Step 1: Add JS/TS integration test**

In `taint/mod.rs` tests module, add:

```rust
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
            evidence: Some(crate::model::EntryPointEvidence { kind: "sdk_call".into(), text: "server.tool".into() }),
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
```

- [ ] **Step 2: Add Rust integration test**

```rust
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
            evidence: Some(crate::model::EntryPointEvidence { kind: "attribute_macro".into(), text: "#[tool]".into() }),
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
```

- [ ] **Step 3: Run all tests**

Run: `cargo test -p mcp-sec-audit-core`
Expected: All tests pass, including JS and Rust integration tests

- [ ] **Step 4: Commit**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/taint/mod.rs
git commit -m "test(phase10-11): add JS and Rust integration tests for taint analysis

- JS: server.tool() → exec(params.command) direct path
- Rust: #[tool] → Command::new() direct path

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 8: Update REFACTOR_PLAN.md status

**Files:**
- Modify: `rust/docs/REFACTOR_PLAN.md`

- [ ] **Step 1: Update Phase 10 and 11 status rows**

Change:

```
| Phase 10：调用关系分析  | 未开始 | ... |
| Phase 11：轻量数据流分析 | 未开始 | ... |
```

To:

```
| Phase 10：调用关系分析  | 完成 | ... |
| Phase 11：轻量数据流分析 | 完成 | ... |
```

And add a brief completion note after the Phase 9 note:

```
Phase 10 和 Phase 11 已作为统一污点分析模块（`static_analysis/taint/`）一起交付。模块包含：统一跨文件程序图构造（graph + builder）、前向/后向 BFS 污点传播（propagation），以及 TaintAnalysisResult 和 DataFlowFact 结果生成（result）。支持 Python、JavaScript/TypeScript、Rust 三种语言的跨文件调用链追踪和参数到 sink 的数据流分析。taint line 已集成到 static scan pipeline，默认配置保持 disabled；启用 config `[static.taint].enabled = true` 时正常产出污点分析结果。
```

- [ ] **Step 2: Commit**

```bash
git add rust/docs/REFACTOR_PLAN.md
git commit -m "docs: mark Phase 10 and 11 as complete

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 9: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test -p mcp-sec-audit-core`
Expected: All tests pass (existing + new taint module tests)

- [ ] **Step 2: Run CLI build**

Run: `cargo build -p mcp-sec-audit-cli`
Expected: Build succeeds

- [ ] **Step 3: Run with taint enabled on a test target**

Run: `cargo run -p mcp-sec-audit-cli -- static --target targets/test-python-mcp --config rust/config.test.toml 2>&1 | head -60`
Expected: No errors; output includes `taint_result_count` > 0 in summary

- [ ] **Step 4: Verify JSON serialization works**

Using a test fixture that enables taint:

Run: `cargo run -p mcp-sec-audit-cli -- static --target targets/test-python-mcp --format json 2>&1 | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'taint_results' in d; print(f'Taint results: {len(d[\"taint_results\"])}')" 2>&1 || echo "json check: $?"`
Expected: Prints "Taint results: N" where N > 0
