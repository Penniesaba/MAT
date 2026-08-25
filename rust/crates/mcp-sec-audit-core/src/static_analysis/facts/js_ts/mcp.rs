use std::collections::BTreeMap;

use swc_core::ecma::ast::{ArrowExpr, Pat};

use crate::model::{
    Confidence, EntryPointEvidence, EntryPointFact, EntryPointKind, Fact, FactBase, SourceFact,
};

const MCP_PATTERNS: &[&str] = &[
    "server.tool",
    "server.resource",
    "server.prompt",
    "mcp.tool",
    "mcp.resource",
    "mcp.prompt",
];

pub(crate) fn is_mcp_registration(callee: &str) -> bool {
    MCP_PATTERNS
        .iter()
        .any(|pattern| callee == *pattern || callee.ends_with(&format!(".{pattern}")))
}

pub(crate) fn entrypoint_kind_from_callee(callee: &str) -> EntryPointKind {
    let method = callee.rsplit('.').next().unwrap_or(callee);
    match method {
        "resource" => EntryPointKind::McpResource,
        "prompt" => EntryPointKind::McpPrompt,
        _ => EntryPointKind::McpTool,
    }
}

/// Process an inline arrow function MCP handler.
/// Creates FunctionFact, EntryPointFact, and SourceFacts for destructured params.
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_inline_arrow_handler(
    facts: &mut Vec<Fact>,
    handler_func_id: String,
    tool_name: String,
    callee_str: &str,
    file: &str,
    line: u32,
    extractor_name: &str,
    arrow: &ArrowExpr,
    source: &str,
) {
    let _ = source;
    // Extract source params (including destructured)
    let source_facts =
        extract_source_params_from_arrow(arrow, &handler_func_id, file, line, extractor_name);

    let param_names: Vec<String> = source_facts
        .iter()
        .map(|sf| match sf {
            Fact::Source(s) => s.name.clone(),
            _ => String::new(),
        })
        .filter(|name| !name.is_empty() && !name.starts_with("..."))
        .collect();

    for sf in source_facts {
        facts.push(sf);
    }

    let ep_kind = entrypoint_kind_from_callee(callee_str);
    facts.push(Fact::Entrypoint(EntryPointFact {
        base: FactBase {
            id: format!("entry:{file}:{tool_name}"),
            file: file.to_string(),
            line,
            extractor: extractor_name.to_string(),
        },
        kind: ep_kind,
        name: tool_name,
        function_id: handler_func_id,
        evidence: Some(EntryPointEvidence {
            kind: "call_registration".to_string(),
            text: callee_str.to_string(),
        }),
        params: param_names,
        confidence: Confidence::High,
    }));
}

/// Process a named (identifier-referenced) MCP handler for deferred backfill.
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_named_handler(
    named_handlers: &mut BTreeMap<String, String>,
    handler_name: &str,
    tool_name: &str,
    callee_str: &str,
    file: &str,
    line: u32,
    extractor_name: &str,
    facts: &mut Vec<Fact>,
) {
    let ep_kind = entrypoint_kind_from_callee(callee_str);
    let ep_id = format!("entry:{file}:{tool_name}");

    facts.push(Fact::Entrypoint(EntryPointFact {
        base: FactBase {
            id: ep_id.clone(),
            file: file.to_string(),
            line,
            extractor: extractor_name.to_string(),
        },
        kind: ep_kind,
        name: tool_name.to_string(),
        function_id: format!("javascript:{file}:{handler_name}"),
        evidence: Some(EntryPointEvidence {
            kind: "call_registration".to_string(),
            text: callee_str.to_string(),
        }),
        params: Vec::new(), // backfilled later
        confidence: Confidence::High,
    }));

    named_handlers.insert(handler_name.to_string(), ep_id);
}

/// Extract SourceFact from arrow function parameters (with destructuring expansion).
fn extract_source_params_from_arrow(
    arrow: &ArrowExpr,
    function_id: &str,
    file: &str,
    line: u32,
    extractor_name: &str,
) -> Vec<Fact> {
    arrow
        .params
        .iter()
        .flat_map(|pat| extract_source_from_pat(pat, function_id, file, line, extractor_name))
        .collect()
}

fn extract_source_from_pat(
    pat: &Pat,
    function_id: &str,
    file: &str,
    line: u32,
    extractor_name: &str,
) -> Vec<Fact> {
    match pat {
        Pat::Ident(id) => vec![Fact::Source(SourceFact {
            base: FactBase {
                id: format!("source:{file}:{function_id}:{}", id.sym),
                file: file.to_string(),
                line,
                extractor: extractor_name.to_string(),
            },
            kind: "mcp_tool_parameter".to_string(),
            function_id: function_id.to_string(),
            name: id.sym.to_string(),
            call_id: None,
            confidence: Confidence::High,
        })],
        Pat::Object(obj) => obj
            .props
            .iter()
            .flat_map(|prop| match prop {
                swc_core::ecma::ast::ObjectPatProp::KeyValue(kv) => {
                    extract_source_from_pat(&kv.value, function_id, file, line, extractor_name)
                }
                swc_core::ecma::ast::ObjectPatProp::Assign(assign) => {
                    vec![Fact::Source(SourceFact {
                        base: FactBase {
                            id: format!("source:{file}:{function_id}:{}", assign.key.sym),
                            file: file.to_string(),
                            line,
                            extractor: extractor_name.to_string(),
                        },
                        kind: "mcp_tool_parameter".to_string(),
                        function_id: function_id.to_string(),
                        name: assign.key.sym.to_string(),
                        call_id: None,
                        confidence: Confidence::High,
                    })]
                }
                swc_core::ecma::ast::ObjectPatProp::Rest(rest) => {
                    extract_source_from_pat(&rest.arg, function_id, file, line, extractor_name)
                }
            })
            .collect(),
        Pat::Array(arr) => arr
            .elems
            .iter()
            .filter_map(|elem| elem.as_ref())
            .flat_map(|pat| extract_source_from_pat(pat, function_id, file, line, extractor_name))
            .collect(),
        Pat::Rest(rest) => {
            extract_source_from_pat(&rest.arg, function_id, file, line, extractor_name)
        }
        _ => Vec::new(),
    }
}
