use rustpython_parser::ast;

pub(crate) fn expr_to_string(expr: &ast::Expr) -> String {
    match expr {
        ast::Expr::Name(name) => name.id.to_string(),
        ast::Expr::Attribute(attr) => format!("{}.{}", expr_to_string(&attr.value), attr.attr),
        ast::Expr::Call(call) => {
            let func = expr_to_string(&call.func);
            if call.args.is_empty() && call.keywords.is_empty() {
                format!("{func}()")
            } else {
                format!("{func}(...)")
            }
        }
        ast::Expr::Constant(constant) => format_constant(&constant.value),
        ast::Expr::Subscript(subscript) => {
            format!(
                "{}[{}]",
                expr_to_string(&subscript.value),
                expr_to_string(&subscript.slice)
            )
        }
        ast::Expr::Tuple(tuple) => tuple
            .elts
            .iter()
            .map(expr_to_string)
            .collect::<Vec<_>>()
            .join(", "),
        ast::Expr::List(list) => format!(
            "[{}]",
            list.elts
                .iter()
                .map(expr_to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ast::Expr::UnaryOp(unary) => format!("{:?}{}", unary.op, expr_to_string(&unary.operand)),
        _ => format!("{expr:?}"),
    }
}

fn format_constant(value: &ast::Constant) -> String {
    match value {
        ast::Constant::Str(item) => item.clone(),
        ast::Constant::Int(item) => item.to_string(),
        ast::Constant::Bool(item) => {
            if *item {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        ast::Constant::None => "None".to_string(),
        ast::Constant::Bytes(item) => format!("{item:?}"),
        ast::Constant::Tuple(items) => items
            .iter()
            .map(format_constant)
            .collect::<Vec<_>>()
            .join(", "),
        ast::Constant::Float(item) => item.to_string(),
        ast::Constant::Complex { real, imag } => format!("{real}+{imag}j"),
        ast::Constant::Ellipsis => "...".to_string(),
    }
}

pub(crate) fn looks_like_callable_reference(value: &str) -> bool {
    value.contains('.')
        || value
            .chars()
            .all(|item| item == '_' || item.is_ascii_alphanumeric())
}
