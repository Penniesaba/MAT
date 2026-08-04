use std::collections::BTreeMap;

use swc_core::ecma::ast::{CallExpr, Callee, Expr, MemberProp};

use crate::model::CallArg;

/// Get string representation of a callee expression (including nested members).
pub(crate) fn callee_to_string(callee: &Callee) -> String {
    match callee {
        Callee::Expr(expr) => expr_to_string(expr),
        _ => "<unknown>".to_string(),
    }
}

fn expr_to_string(expr: &Expr) -> String {
    match expr {
        Expr::Ident(id) => id.sym.to_string(),
        Expr::Member(member) => {
            let obj = expr_to_string(&member.obj);
            let prop = match &member.prop {
                MemberProp::Ident(id) => id.sym.to_string(),
                MemberProp::Computed(comp) => expr_to_string(&comp.expr),
                _ => "<?>".to_string(),
            };
            format!("{obj}.{prop}")
        }
        Expr::Call(call) => {
            let callee = callee_to_string(&call.callee);
            format!("{callee}(...)")
        }
        Expr::Lit(lit) => match lit {
            swc_core::ecma::ast::Lit::Str(s) => s.value.to_string(),
            swc_core::ecma::ast::Lit::Num(n) => n.value.to_string(),
            swc_core::ecma::ast::Lit::Bool(b) => b.value.to_string(),
            _ => "<lit>".to_string(),
        },
        _ => format!("<{expr:?}>"),
    }
}

/// Resolve callee through import and require aliases.
/// Returns (normalized_callee, resolved_alias).
pub(crate) fn resolve_callee(
    callee_str: &str,
    import_aliases: &BTreeMap<String, String>,
    require_aliases: &BTreeMap<String, String>,
) -> (String, Option<String>) {
    // Check direct alias match
    if let Some(resolved) = import_aliases.get(callee_str) {
        return (resolved.clone(), Some(callee_str.to_string()));
    }
    if let Some(resolved) = require_aliases.get(callee_str) {
        return (resolved.clone(), Some(callee_str.to_string()));
    }

    // Check member expression alias (e.g., "sp.run" where "sp" -> "child_process")
    if let Some((head, tail)) = callee_str.split_once('.') {
        if let Some(resolved) = import_aliases.get(head) {
            return (format!("{resolved}.{tail}"), Some(head.to_string()));
        }
        if let Some(resolved) = require_aliases.get(head) {
            return (format!("{resolved}.{tail}"), Some(head.to_string()));
        }
    }

    (callee_str.to_string(), None)
}

/// Extract positional arguments from a call expression.
pub(crate) fn extract_call_args(call: &CallExpr) -> Vec<CallArg> {
    call.args
        .iter()
        .enumerate()
        .map(|(i, arg)| {
            let expr_str = match arg.expr.as_ref() {
                Expr::Ident(id) => id.sym.to_string(),
                Expr::Lit(lit) => match lit {
                    swc_core::ecma::ast::Lit::Str(s) => s.value.to_string(),
                    swc_core::ecma::ast::Lit::Num(n) => n.value.to_string(),
                    swc_core::ecma::ast::Lit::Bool(b) => b.value.to_string(),
                    _ => "<lit>".to_string(),
                },
                Expr::Member(m) => expr_to_string(&Expr::Member(m.clone())),
                _ => "<expr>".to_string(),
            };
            CallArg {
                index: i as u32,
                expr: expr_str,
                kind: "positional".to_string(),
            }
        })
        .collect()
}
