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
