use syn::{punctuated::Punctuated, Expr, Token};

use crate::model::CallArg;

use super::display::expr_to_string;

pub(crate) fn extract_call_args(args: &Punctuated<Expr, Token![,]>) -> Vec<CallArg> {
    args.iter()
        .enumerate()
        .map(|(i, expr)| CallArg {
            index: i as u32,
            expr: expr_to_string(expr),
            kind: "positional".to_string(),
        })
        .collect()
}

/// Collect the arguments of a flattened method chain, e.g.
/// `Command::new("sh").arg("-c").arg(&shell_cmd).output().map_err(..)`.
///
/// `expr_to_string` renders a method call's args as `(...)`, so the args of
/// intermediate chain links are otherwise lost when the chain is collapsed to
/// a single CallFact. Walking the receiver recovers `"sh"`, `"-c"`,
/// `&shell_cmd` so taint can still match them.
pub(crate) fn extract_method_chain_args(node: &syn::ExprMethodCall) -> Vec<CallArg> {
    let mut args = Vec::new();
    collect_receiver_args(&node.receiver, &mut args);
    args.extend(extract_call_args(&node.args));
    args
}

fn collect_receiver_args(expr: &Expr, out: &mut Vec<CallArg>) {
    match expr {
        Expr::MethodCall(m) => {
            collect_receiver_args(&m.receiver, out);
            out.extend(extract_call_args(&m.args));
        }
        Expr::Call(c) => {
            out.extend(extract_call_args(&c.args));
        }
        Expr::Try(t) => collect_receiver_args(&t.expr, out),
        Expr::Reference(r) => collect_receiver_args(&r.expr, out),
        _ => {}
    }
}
