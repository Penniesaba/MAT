use swc_core::ecma::ast::{Function, Pat};

use crate::model::{FactBase, FunctionFact, ParamInfo};

/// Extract parameter info from SWC Function node (shared by all function forms).
pub(crate) fn params_from_fn(f: &Function, source: &str) -> Vec<ParamInfo> {
    f.params
        .iter()
        .map(|param| match &param.pat {
            Pat::Ident(id) => ParamInfo {
                name: id.sym.to_string(),
                annotation: id.type_ann.as_ref().and_then(|ta| ts_type_ann_to_string(ta, source)),
                default: None,
            },
            Pat::Rest(rest) => match rest.arg.as_ref() {
                Pat::Ident(id) => ParamInfo {
                    name: format!("...{}", id.sym),
                    annotation: None,
                    default: None,
                },
                _ => ParamInfo {
                    name: "...".to_string(),
                    annotation: None,
                    default: None,
                },
            },
            _ => ParamInfo {
                name: format!("<pat:{:?}>", param.pat),
                annotation: None,
                default: None,
            },
        })
        .collect()
}

fn ts_type_ann_to_string(type_ann: &swc_core::ecma::ast::TsTypeAnn, source: &str) -> Option<String> {
    // Extract TS type annotation from SWC's TsTypeAnn node by slicing source text at span.
    let span = type_ann.span;
    let lo = span.lo.0 as usize;
    let hi = span.hi.0 as usize;
    source.get(lo..hi).map(|s| s.trim().to_string())
}

/// Build qualified function name from scope + class context.
pub(crate) fn build_qualified_name(
    scope: &[String],
    class_stack: &[String],
    name: &str,
) -> String {
    // Scope is reserved for nested-function qualification; Phase 8 prefixes the
    // enclosing class when present, falling back to the bare function name.
    let _ = scope;
    let mut parts: Vec<&str> = Vec::new();
    if let Some(class_name) = class_stack.last() {
        parts.push(class_name.as_str());
    }
    parts.push(name);
    parts.join(".")
}

/// Create FunctionFact for a function declaration.
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_function_fact(
    id: String,
    file: String,
    line: u32,
    extractor: String,
    language: String,
    name: String,
    qualified_name: String,
    end_line: u32,
    params: Vec<ParamInfo>,
    enclosing_class: Option<String>,
) -> FunctionFact {
    FunctionFact {
        base: FactBase { id, file, line, extractor },
        language,
        name,
        qualified_name,
        end_line,
        params,
        decorators: Vec::new(),
        docstring: None,
        return_type: None,
        enclosing_class,
    }
}
