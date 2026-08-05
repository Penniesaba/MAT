use syn::*;

use crate::model::ParamInfo;

// ---------------------------------------------------------------------------
// Expression → string conversion
// ---------------------------------------------------------------------------

pub(crate) fn expr_to_string(expr: &Expr) -> String {
    match expr {
        Expr::Path(path) => syn_path_to_string(&path.path),
        Expr::Call(call) => {
            let func = expr_to_string(&call.func);
            if call.args.is_empty() {
                format!("{func}()")
            } else {
                format!("{func}(...)")
            }
        }
        Expr::MethodCall(method_call) => {
            let receiver = expr_to_string(&method_call.receiver);
            let method = method_call.method.to_string();
            format!("{receiver}.{method}(...)")
        }
        Expr::Lit(lit) => lit_to_string(&lit.lit),
        Expr::Macro(mac) => {
            let name = mac
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            format!("{name}!(...)")
        }
        Expr::Field(field) => {
            let base = expr_to_string(&field.base);
            let member = member_to_string(&field.member);
            format!("{base}.{member}")
        }
        Expr::Reference(reference) => {
            let inner = expr_to_string(&reference.expr);
            if reference.mutability.is_some() {
                format!("&mut {inner}")
            } else {
                format!("&{inner}")
            }
        }
        Expr::Closure(_) => "<closure>".to_string(),
        Expr::Block(_) => "<block>".to_string(),
        Expr::If(_) => "<if-expr>".to_string(),
        Expr::Match(_) => "<match>".to_string(),
        Expr::Loop(_) => "<loop>".to_string(),
        Expr::Struct(strct) => {
            let name = syn_path_to_string(&strct.path);
            format!("{name} {{ ... }}")
        }
        _ => format!("<{expr:?}>"),
    }
}

pub(crate) fn syn_path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|seg| {
            let ident = seg.ident.to_string();
            match &seg.arguments {
                PathArguments::AngleBracketed(args) => {
                    let types: Vec<String> = args
                        .args
                        .iter()
                        .map(|ga| match ga {
                            GenericArgument::Type(ty) => type_to_string(ty),
                            _ => "<_>".to_string(),
                        })
                        .collect();
                    format!("{ident}<{}>", types.join(", "))
                }
                _ => ident,
            }
        })
        .collect::<Vec<_>>()
        .join("::")
}

pub(crate) fn lit_to_string(lit: &Lit) -> String {
    match lit {
        Lit::Str(s) => format!("\"{}\"", s.value()),
        Lit::Char(c) => format!("'{}'", c.value()),
        Lit::Int(i) => i.base10_digits().to_string(),
        Lit::Float(f) => f.base10_digits().to_string(),
        Lit::Bool(b) => b.value.to_string(),
        Lit::ByteStr(_) => "<byte-str>".to_string(),
        Lit::Byte(_) => "<byte>".to_string(),
        Lit::Verbatim(_) => "<verbatim>".to_string(),
        _ => "<lit>".to_string(),
    }
}

pub(crate) fn member_to_string(member: &Member) -> String {
    match member {
        Member::Named(ident) => ident.to_string(),
        Member::Unnamed(index) => index.index.to_string(),
    }
}

pub(crate) fn type_to_string(ty: &Type) -> String {
    match ty {
        Type::Path(type_path) => syn_path_to_string(&type_path.path),
        Type::Reference(reference) => {
            let inner = type_to_string(&reference.elem);
            if reference.mutability.is_some() {
                format!("&mut {inner}")
            } else {
                format!("&{inner}")
            }
        }
        Type::Tuple(tuple) => {
            let elems: Vec<String> = tuple.elems.iter().map(type_to_string).collect();
            format!("({})", elems.join(", "))
        }
        Type::ImplTrait(trait_ty) => {
            let bounds: Vec<String> = trait_ty
                .bounds
                .iter()
                .map(type_param_bound_to_string)
                .collect();
            format!("impl {}", bounds.join(" + "))
        }
        _ => format!("<{ty:?}>"),
    }
}

pub(crate) fn type_param_bound_to_string(bound: &TypeParamBound) -> String {
    match bound {
        TypeParamBound::Trait(trait_bound) => syn_path_to_string(&trait_bound.path),
        TypeParamBound::Lifetime(lt) => lt.ident.to_string(),
        _ => "<bound>".to_string(),
    }
}

pub(crate) fn return_type_to_string(output: &ReturnType) -> Option<String> {
    match output {
        ReturnType::Type(_, ty) => Some(type_to_string(ty)),
        ReturnType::Default => None,
    }
}

pub(crate) fn use_tree_summary(tree: &UseTree) -> String {
    match tree {
        UseTree::Path(path) => format!("{}::{}", path.ident, use_tree_summary(&path.tree)),
        UseTree::Name(name) => name.ident.to_string(),
        UseTree::Rename(rename) => format!("{} as {}", rename.ident, rename.rename),
        UseTree::Glob(_) => "*".to_string(),
        UseTree::Group(_) => "{...}".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Attribute handling
// ---------------------------------------------------------------------------

pub(crate) fn attrs_to_strings(attrs: &[Attribute]) -> Vec<String> {
    attrs.iter().map(attr_to_string).collect()
}

fn attr_to_string(attr: &Attribute) -> String {
    let path = syn_path_to_string(attr.path());
    if path.starts_with("doc") {
        return path;
    }
    let tokens = format!("{:?}", attr.meta);
    if tokens.is_empty() || tokens == "Meta::Path(Path { leading_colon: None, segments: [] })" {
        format!("#[{path}]")
    } else {
        format!("#[{path}(...)]")
    }
}

pub(crate) fn doc_from_attrs(attrs: &[Attribute]) -> Option<String> {
    let doc_lines: Vec<String> = attrs
        .iter()
        .filter_map(|attr| {
            if attr.path().is_ident("doc") {
                match &attr.meta {
                    Meta::NameValue(nv) => {
                        let s = expr_to_string(&nv.value);
                        let trimmed = s.trim_matches('"').trim().to_string();
                        Some(trimmed)
                    }
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect();

    if doc_lines.is_empty() {
        None
    } else {
        Some(doc_lines.join("\n"))
    }
}

// ---------------------------------------------------------------------------
// Parameter extraction
// ---------------------------------------------------------------------------

pub(crate) fn params_from_signature(sig: &Signature) -> Vec<ParamInfo> {
    sig.inputs
        .iter()
        .map(|input| match input {
            FnArg::Typed(pat_type) => {
                let name = pat_to_string(&pat_type.pat);
                let annotation = Some(type_to_string(&pat_type.ty));
                ParamInfo {
                    name,
                    annotation,
                    default: None,
                }
            }
            FnArg::Receiver(receiver) => {
                let mut name = "self".to_string();
                if receiver.reference.is_some() {
                    name = if receiver.mutability.is_some() {
                        "&mut self".to_string()
                    } else {
                        "&self".to_string()
                    };
                }
                ParamInfo {
                    name,
                    annotation: None,
                    default: None,
                }
            }
        })
        .collect()
}

pub(crate) fn pat_to_string(pat: &Pat) -> String {
    match pat {
        Pat::Ident(ident) => ident.ident.to_string(),
        Pat::Type(pat_type) => pat_to_string(&pat_type.pat),
        Pat::Reference(reference) => {
            let inner = pat_to_string(&reference.pat);
            if reference.mutability.is_some() {
                format!("&mut {inner}")
            } else {
                format!("&{inner}")
            }
        }
        Pat::Tuple(tuple) => {
            let elems: Vec<String> = tuple.elems.iter().map(pat_to_string).collect();
            format!("({})", elems.join(", "))
        }
        Pat::Struct(strct) => {
            let fields: Vec<String> = strct
                .fields
                .iter()
                .map(|f| member_to_string(&f.member))
                .collect();
            format!("{{ {} }}", fields.join(", "))
        }
        _ => "<pat>".to_string(),
    }
}
