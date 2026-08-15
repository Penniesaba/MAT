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
        ast::Expr::BinOp(bin_op) => format!(
            "({} {:?} {})",
            expr_to_string(&bin_op.left),
            bin_op.op,
            expr_to_string(&bin_op.right)
        ),
        ast::Expr::BoolOp(bool_op) => bool_op
            .values
            .iter()
            .map(expr_to_string)
            .collect::<Vec<_>>()
            .join(" or "),
        ast::Expr::Compare(compare) => {
            let mut out = expr_to_string(&compare.left);
            for (op, comp) in compare.ops.iter().zip(&compare.comparators) {
                out.push_str(&format!(" {:?} {}", op, expr_to_string(comp)));
            }
            out
        }
        ast::Expr::IfExp(if_exp) => format!(
            "({} if {} else {})",
            expr_to_string(&if_exp.body),
            expr_to_string(&if_exp.test),
            expr_to_string(&if_exp.orelse)
        ),
        ast::Expr::Dict(dict) => {
            let items = dict
                .keys
                .iter()
                .zip(&dict.values)
                .map(|(key, value)| match key {
                    Some(key) => format!("{}: {}", expr_to_string(key), expr_to_string(value)),
                    None => format!("**{}", expr_to_string(value)),
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{items}}}")
        }
        ast::Expr::Set(set) => format!(
            "{{{}}}",
            set.elts
                .iter()
                .map(expr_to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
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
