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
    /// Returns the node's unique id; used by tests and future graph consumers.
    #[allow(dead_code)]
    pub fn id(&self) -> &str {
        match self {
            Node::Function { id, .. } => id,
            Node::Source { id, .. } => id,
            Node::Sink { id, .. } => id,
            Node::Call { id, .. } => id,
            Node::Variable { id, .. } => id,
        }
    }

    #[allow(dead_code)]
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
    /// Reverse of CallInFunction: function → call (for forward traversal).
    FunctionCall {
        function_id: String,
        call_id: String,
    },
}

impl Edge {
    #[allow(dead_code)]
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
            Edge::FunctionCall { .. } => "function_call",
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
            Edge::FunctionCall { function_id, .. } => function_id,
        }
    }

    pub fn to_id(&self) -> &str {
        match self {
            Edge::SourceInFunction { function_id, .. } => function_id,
            Edge::CallInFunction { function_id, .. } => function_id,
            Edge::CallToFunction { callee_function_id, .. } => callee_function_id,
            Edge::ArgToParam { callee_function_id, .. } => callee_function_id,
            Edge::VarToArg { call_id, .. } => call_id,
            Edge::ValToVar { to_var_id, .. } => to_var_id,
            Edge::CallToSink { sink_id, .. } => sink_id,
            Edge::ReturnToVar { var_id, .. } => var_id,
            Edge::SourceToArg { call_id, .. } => call_id,
            Edge::FunctionCall { call_id, .. } => call_id,
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionMeta
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FunctionMeta {
    pub name: String,
    /// Reserved context fields; not yet consumed by propagation.
    #[allow(dead_code)]
    pub qualified_name: String,
    #[allow(dead_code)]
    pub file: String,
    #[allow(dead_code)]
    pub language: String,
    pub params: Vec<String>,
    #[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Confidence;

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
        let func_id: String = "python:server.py:main".into();
        g.add_node(func_id.clone(), Node::Function {
            id: func_id.clone(),
            name: "main".into(),
            qualified_name: "main".into(),
            file: "server.py".into(),
            params: vec![],
            language: "python".into(),
            line: 1,
        });

        let call_id: String = "call:server.py:5:0".into();
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
