use rustpython_parser::ast;

use crate::model::ParamInfo;

pub(crate) fn params_from_arguments(args: &ast::Arguments) -> Vec<ParamInfo> {
    let mut params = Vec::new();
    for arg in &args.posonlyargs {
        params.push(param_from_arg(&arg.def, arg.default.as_deref()));
    }
    for arg in &args.args {
        params.push(param_from_arg(&arg.def, arg.default.as_deref()));
    }
    if let Some(vararg) = &args.vararg {
        let mut param = param_from_arg(vararg, None);
        param.name = format!("*{}", param.name);
        params.push(param);
    }
    for arg in &args.kwonlyargs {
        params.push(param_from_arg(&arg.def, arg.default.as_deref()));
    }
    if let Some(kwarg) = &args.kwarg {
        let mut param = param_from_arg(kwarg, None);
        param.name = format!("**{}", param.name);
        params.push(param);
    }
    params
}

fn param_from_arg(arg: &ast::Arg, default: Option<&ast::Expr>) -> ParamInfo {
    ParamInfo {
        name: arg.arg.to_string(),
        annotation: arg.annotation.as_deref().map(super::calls::expr_to_string),
        default: default.map(super::calls::expr_to_string),
    }
}

pub(crate) fn docstring_from_body(body: &[ast::Stmt]) -> Option<String> {
    let first = body.first()?;
    match first {
        ast::Stmt::Expr(expr_stmt) => match expr_stmt.value.as_ref() {
            ast::Expr::Constant(constant) => match &constant.value {
                ast::Constant::Str(item) => Some(item.clone()),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}
