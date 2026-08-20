pub(crate) mod calls;
pub(crate) mod display;
pub(crate) mod mcp;
pub(crate) mod sinks;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use syn::{
    spanned::Spanned,
    visit::Visit,
    *,
};

use crate::model::{
    AssignFact, CallFact, Confidence, EntryPointEvidence, EntryPointFact,
    Fact, FactBase, FunctionFact, ImportFact, ImportKind, Severity, SinkFact, SourceFact,
};
use crate::models::SinkModel;

use super::{
    ExtractionDiagnostic, display_path, fact_sort_key, line_col_for_offset,
    make_assign_id, make_call_id, make_entrypoint_id,
    make_function_id, make_import_id, make_sink_id, make_source_id,
};

const EXTRACTOR_NAME: &str = "rust_syn_phase9";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct RustExtractionResult {
    pub facts: Vec<Fact>,
    pub diagnostics: Vec<ExtractionDiagnostic>,
}

impl RustExtractionResult {
    pub fn empty() -> Self {
        Self {
            facts: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Extractor state
// ---------------------------------------------------------------------------

struct RustFactExtractor<'a> {
    root: PathBuf,
    file: PathBuf,
    #[allow(dead_code)]
    source: &'a str,
    sinks: &'a [SinkModel],
    facts: Vec<Fact>,
    diagnostics: Vec<ExtractionDiagnostic>,

    /// Maps alias name → full path (e.g. "Command" → "std::process::Command")
    use_aliases: BTreeMap<String, String>,

    /// Tracks the current function scope for qualified names
    scope: Vec<String>,

    /// Tracks the current impl/struct context (e.g. "MyServer")
    impl_stack: Vec<String>,

    /// (line, column) pairs of already-emitted call/sink spans, used to collapse
    /// a method chain (whose every level shares the chain root's span start) to
    /// a single CallFact + SinkFact.
    seen_calls: BTreeSet<(u32, u32)>,
}

impl<'a> RustFactExtractor<'a> {
    fn new(root: &Path, file: &Path, source: &'a str, sinks: &'a [SinkModel]) -> Self {
        Self {
            root: root.to_path_buf(),
            file: file.to_path_buf(),
            source,
            sinks,
            facts: Vec::new(),
            diagnostics: Vec::new(),
            use_aliases: BTreeMap::new(),
            scope: Vec::new(),
            impl_stack: Vec::new(),
            seen_calls: BTreeSet::new(),
        }
    }

    fn line_of(&self, node: &impl Spanned) -> u32 {
        // Uses proc_macro2 span-locations feature for real line numbers.
        node.span().start().line as u32
    }

    fn column_of(&self, node: &impl Spanned) -> u32 {
        // Accurate 0-based column from the byte offset of the span start.
        let (_line, column) =
            line_col_for_offset(self.source, node.span().byte_range().start as u32);
        column
    }

    fn rel_path(&self) -> String {
        display_path(&self.file)
    }

    fn caller_function_id(&self) -> Option<String> {
        if self.scope.is_empty() {
            None
        } else {
            Some(make_function_id(
                "rust",
                &self.root,
                &self.file,
                &self.scope.join("."),
            ))
        }
    }

    /// Resolve a callee path through use aliases.
    fn resolve_callee(&self, callee: &str) -> (String, Option<String>) {
        if let Some(resolved) = self.use_aliases.get(callee) {
            return (resolved.clone(), Some(callee.to_string()));
        }
        if let Some((head, tail)) = callee.split_once("::")
            && let Some(resolved) = self.use_aliases.get(head)
        {
            return (format!("{resolved}::{tail}"), Some(head.to_string()));
        }
        (callee.to_string(), None)
    }

    /// Emit a SinkFact if the callee matches known dangerous APIs.
    fn check_sink(&mut self, normalized_callee: &str, call_id: &str, line: u32) {
        for model in self.sinks {
            if sinks::matches_sink(normalized_callee, &model.patterns) {
                let file = self.rel_path();
                self.facts.push(Fact::Sink(SinkFact {
                    base: FactBase {
                        id: make_sink_id(&model.category, &self.root, &self.file, line),
                        file: file.clone(),
                        line,
                        extractor: EXTRACTOR_NAME.to_string(),
                    },
                    call_id: call_id.to_string(),
                    category: model.category.clone(),
                    rule_id: model.rule_id(),
                    sink_name: normalized_callee.to_string(),
                    severity_base: model.severity.clone(),
                    reason: model.reason.clone(),
                    conditions: BTreeMap::new(),
                    confidence: model.confidence.clone(),
                }));
                return;
            }
        }
    }

    fn build_qualified_name(impl_stack: &[String], name: &str) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if let Some(impl_name) = impl_stack.last() {
            parts.push(impl_name.as_str());
        }
        parts.push(name);
        parts.join(".")
    }

    /// Recursively extract `use` tree into ImportFacts and populate use_aliases.
    fn extract_use_tree(
        &mut self,
        tree: &UseTree,
        file: &str,
        line: u32,
        prefix: &mut String,
    ) {
        match tree {
            UseTree::Path(path) => {
                let seg = path.ident.to_string();
                let old_len = prefix.len();
                if !prefix.is_empty() {
                    prefix.push_str("::");
                }
                prefix.push_str(&seg);
                self.extract_use_tree(&path.tree, file, line, prefix);
                prefix.truncate(old_len);
            }
            UseTree::Name(name) => {
                let full_path = if prefix.is_empty() {
                    name.ident.to_string()
                } else {
                    format!("{}::{}", prefix, name.ident)
                };
                let simple_name = name.ident.to_string();
                self.use_aliases
                    .insert(simple_name.clone(), full_path.clone());

                self.facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: make_import_id(&self.root, &self.file, line, &full_path),
                        file: file.to_string(),
                        line,
                        extractor: EXTRACTOR_NAME.to_string(),
                    },
                    language: "rust".to_string(),
                    module: full_path,
                    imported_name: None,
                    alias: Some(simple_name),
                    kind: ImportKind::Use,
                }));
            }
            UseTree::Rename(rename) => {
                let full_path = if prefix.is_empty() {
                    rename.ident.to_string()
                } else {
                    format!("{}::{}", prefix, rename.ident)
                };
                let alias = rename.rename.to_string();
                self.use_aliases.insert(alias.clone(), full_path.clone());

                self.facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: make_import_id(&self.root, &self.file, line, &full_path),
                        file: file.to_string(),
                        line,
                        extractor: EXTRACTOR_NAME.to_string(),
                    },
                    language: "rust".to_string(),
                    module: full_path,
                    imported_name: None,
                    alias: Some(alias),
                    kind: ImportKind::UseAs,
                }));
            }
            UseTree::Glob(_) => {
                let pattern = if prefix.is_empty() {
                    "*".to_string()
                } else {
                    format!("{prefix}::*")
                };

                self.facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: make_import_id(&self.root, &self.file, line, &pattern),
                        file: file.to_string(),
                        line,
                        extractor: EXTRACTOR_NAME.to_string(),
                    },
                    language: "rust".to_string(),
                    module: pattern,
                    imported_name: Some("*".to_string()),
                    alias: None,
                    kind: ImportKind::UseGlob,
                }));
            }
            UseTree::Group(group) => {
                let group_path = if prefix.is_empty() {
                    String::new()
                } else {
                    format!("{prefix}::")
                };

                for item in &group.items {
                    let item_str = display::use_tree_summary(item);
                    self.facts.push(Fact::Import(ImportFact {
                        base: FactBase {
                            id: make_import_id(
                                &self.root,
                                &self.file,
                                line,
                                &format!("{group_path}{item_str}"),
                            ),
                            file: file.to_string(),
                            line,
                            extractor: EXTRACTOR_NAME.to_string(),
                        },
                        language: "rust".to_string(),
                        module: format!("{group_path}{item_str}"),
                        imported_name: None,
                        alias: None,
                        kind: ImportKind::UseGroup,
                    }));

                    let old_len = prefix.len();
                    self.extract_use_tree(item, file, line, prefix);
                    prefix.truncate(old_len);
                }
            }
        }
    }

    /// Emit FunctionFact + MCP Entrypoint/Source facts for a function-like node.
    fn emit_function_fact(
        &mut self,
        name: &str,
        sig: &Signature,
        attrs: &[Attribute],
        line: u32,
        end_line: u32,
    ) -> String {
        let qual_name = Self::build_qualified_name(&self.impl_stack, name);
        let file = self.rel_path();
        let func_id = make_function_id("rust", &self.root, &self.file, &qual_name);
        let params = display::params_from_signature(sig);
        let decorators = display::attrs_to_strings(attrs);
        let docstring = display::doc_from_attrs(attrs);
        let return_type = display::return_type_to_string(&sig.output);
        let enclosing_class = self.impl_stack.last().cloned();

        self.facts.push(Fact::Function(FunctionFact {
            base: FactBase {
                id: func_id.clone(),
                file: file.clone(),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            language: "rust".to_string(),
            name: name.to_string(),
            qualified_name: qual_name.clone(),
            end_line,
            params: params.clone(),
            decorators: decorators.clone(),
            docstring,
            return_type,
            enclosing_class,
        }));

        // Check for MCP attribute macros (#[tool], #[resource], #[prompt])
        if let Some((kind, evidence_text)) = decorators
            .iter()
            .find_map(|attr| mcp::classify_mcp_attr(attr).map(|k| (k, attr.clone())))
        {
            let entry_id = make_entrypoint_id(&self.root, &self.file, &qual_name);
            let param_names: Vec<String> = params
                .iter()
                .map(|p| p.name.clone())
                .filter(|n| n != "self" && n != "&self" && n != "&mut self")
                .collect();

            self.facts.push(Fact::Entrypoint(EntryPointFact {
                base: FactBase {
                    id: entry_id,
                    file: file.clone(),
                    line,
                    extractor: EXTRACTOR_NAME.to_string(),
                },
                kind,
                name: name.to_string(),
                function_id: func_id.clone(),
                evidence: Some(EntryPointEvidence {
                    kind: "attribute_macro".to_string(),
                    text: evidence_text,
                }),
                params: param_names.clone(),
                confidence: Confidence::High,
            }));

            for param_name in param_names {
                self.facts.push(Fact::Source(SourceFact {
                    base: FactBase {
                        id: make_source_id(&self.root, &self.file, &qual_name, &param_name),
                        file: file.clone(),
                        line,
                        extractor: EXTRACTOR_NAME.to_string(),
                    },
                    kind: "mcp_tool_parameter".to_string(),
                    function_id: func_id.clone(),
                    name: param_name,
                    confidence: Confidence::High,
                }));
            }
        }

        func_id
    }

    /// Emit EntrypointFact for SDK call pattern, and SourceFacts for inline closure params.
    fn emit_sdk_entrypoint(
        &mut self,
        callee: &str,
        tool_name: &str,
        line: u32,
        caller_func_id: &str,
        closure_sig: Option<&Signature>,
    ) {
        let file = self.rel_path();
        let kind = mcp::entrypoint_kind_from_callee(callee);
        let entry_id = make_entrypoint_id(
            &self.root,
            &self.file,
            &format!("{callee}.{tool_name}"),
        );

        let mut param_names: Vec<String> = Vec::new();

        // Generate SourceFacts if we have inline closure params
        if let Some(sig) = closure_sig {
            let params = display::params_from_signature(sig);
            param_names = params
                .iter()
                .map(|p| p.name.clone())
                .filter(|n| n != "self" && n != "&self" && n != "&mut self")
                .collect();

            for param_name in &param_names {
                self.facts.push(Fact::Source(SourceFact {
                    base: FactBase {
                        id: make_source_id(
                            &self.root,
                            &self.file,
                            &format!("{callee}.{tool_name}"),
                            param_name,
                        ),
                        file: file.clone(),
                        line,
                        extractor: EXTRACTOR_NAME.to_string(),
                    },
                    kind: "mcp_tool_parameter".to_string(),
                    function_id: caller_func_id.to_string(),
                    name: param_name.clone(),
                    confidence: Confidence::Medium,
                }));
            }
        }

        self.facts.push(Fact::Entrypoint(EntryPointFact {
            base: FactBase {
                id: entry_id,
                file: file.clone(),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            kind,
            name: tool_name.to_string(),
            function_id: caller_func_id.to_string(),
            evidence: Some(EntryPointEvidence {
                kind: "sdk_call".to_string(),
                text: callee.to_string(),
            }),
            params: param_names,
            confidence: Confidence::Medium,
        }));
    }
}

// ---------------------------------------------------------------------------
// syn Visit trait implementation
// ---------------------------------------------------------------------------

/// Inspect an `unsafe { .. }` block for operations that actually exercise
/// memory-unsafe semantics (raw pointer deref, transmute, uninitialized memory).
/// Returns false when the block is a benign wrapper with no dangerous op.
fn unsafe_block_is_dangerous(block: &syn::Block) -> bool {
    struct Detector {
        dangerous: bool,
    }
    impl<'ast> syn::visit::Visit<'ast> for Detector {
        fn visit_expr_unary(&mut self, e: &'ast syn::ExprUnary) {
            if matches!(e.op, syn::UnOp::Deref(_)) {
                self.dangerous = true;
            }
            syn::visit::visit_expr_unary(self, e);
        }
        fn visit_expr_call(&mut self, e: &'ast syn::ExprCall) {
            if is_dangerous_callee(&display::expr_to_string(&e.func)) {
                self.dangerous = true;
            }
            syn::visit::visit_expr_call(self, e);
        }
        fn visit_expr_method_call(&mut self, e: &'ast syn::ExprMethodCall) {
            if is_dangerous_callee(&e.method.to_string()) {
                self.dangerous = true;
            }
            syn::visit::visit_expr_method_call(self, e);
        }
    }
    let mut detector = Detector { dangerous: false };
    syn::visit::visit_block(&mut detector, block);
    detector.dangerous
}

fn is_dangerous_callee(callee: &str) -> bool {
    [
        "transmute",
        "MaybeUninit",
        "uninitialized",
        "assume_init",
        "zeroed",
        "uninit",
        "get_unchecked",
        "from_raw_parts",
        "from_raw_parts_mut",
    ]
    .iter()
    .any(|pattern| callee.contains(pattern))
}

impl<'ast> Visit<'ast> for RustFactExtractor<'ast> {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        let line = self.line_of(node);
        let file = self.rel_path();
        self.extract_use_tree(&node.tree, &file, line, &mut String::new());
        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let name = node.sig.ident.to_string();
        let line = self.line_of(node);
        let end_line = 1; // FIXME: end span not reliable
        self.scope.push(
            Self::build_qualified_name(&self.impl_stack, &name)
        );
        self.emit_function_fact(&name, &node.sig, &node.attrs, line, end_line);
        syn::visit::visit_item_fn(self, node);
        self.scope.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let type_name = display::type_to_string(&node.self_ty);
        self.impl_stack.push(type_name);
        syn::visit::visit_item_impl(self, node);
        self.impl_stack.pop();
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        let _name = node.ident.to_string();
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let name = node.sig.ident.to_string();
        let line = self.line_of(node);
        let end_line = 1; // FIXME: end span not reliable
        self.scope.push(
            Self::build_qualified_name(&self.impl_stack, &name)
        );
        self.emit_function_fact(&name, &node.sig, &node.attrs, line, end_line);
        syn::visit::visit_impl_item_fn(self, node);
        self.scope.pop();
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let line = self.line_of(node);
        let column = self.column_of(node);
        let file = self.rel_path();
        let callee = display::expr_to_string(&node.func);
        let caller = self.caller_function_id().unwrap_or_default();

        // MCP registration detection runs for every call, even dedup'd levels of
        // a method chain, so chained registrations are not lost.
        if mcp::is_mcp_registration(&callee) {
            if let Some(first_arg) = node.args.first() {
                let tool_name = display::expr_to_string(first_arg).trim_matches('"').to_string();
                if !tool_name.is_empty() {
                    // Check if second argument is a closure for inline SourceFact extraction
                    let closure_sig = node.args.iter().nth(1).and_then(|arg| {
                        if let Expr::Closure(closure) = arg {
                            // Build a synthetic Signature from closure inputs
                            let inputs: Vec<String> = closure
                                .inputs
                                .iter()
                                .map(|pat| display::pat_to_string(pat))
                                .collect();
                            if inputs.is_empty() {
                                None
                            } else {
                                // Create a minimal synthetic signature for param extraction
                                Some(Signature {
                                    constness: None,
                                    asyncness: None,
                                    unsafety: None,
                                    abi: None,
                                    fn_token: Token![fn](proc_macro2::Span::call_site()),
                                    ident: proc_macro2::Ident::new("handler", proc_macro2::Span::call_site()),
                                    generics: Generics::default(),
                                    paren_token: syn::token::Paren::default(),
                                    inputs: closure
                                        .inputs
                                        .iter()
                                        .map(|pat| {
                                            FnArg::Typed(PatType {
                                                attrs: Vec::new(),
                                                pat: Box::new(pat.clone()),
                                                colon_token: Token![:](proc_macro2::Span::call_site()),
                                                ty: Box::new(Type::Verbatim(
                                                    proc_macro2::TokenStream::new(),
                                                )),
                                            })
                                        })
                                        .collect(),
                                    variadic: None,
                                    output: ReturnType::Default,
                                })
                            }
                        } else {
                            None
                        }
                    });

                    self.emit_sdk_entrypoint(
                        &callee,
                        &tool_name,
                        line,
                        &caller,
                        closure_sig.as_ref(),
                    );
                }
            }
        }

        // Only the CallFact + sink are dedup'd per span start; distinct calls on
        // the same line still keep distinct columns.
        if self.seen_calls.insert((line, column)) {
            let (normalized_callee, import_alias) = self.resolve_callee(&callee);
            let args = calls::extract_call_args(&node.args);
            let call_id = make_call_id(&self.root, &self.file, line, column);

            self.facts.push(Fact::Call(CallFact {
                base: FactBase {
                    id: call_id.clone(),
                    file: file.clone(),
                    line,
                    extractor: EXTRACTOR_NAME.to_string(),
                },
                caller: caller.clone(),
                callee: callee.clone(),
                normalized_callee: Some(normalized_callee.clone()),
                column: Some(column),
                end_line: Some(line),
                snippet: String::new(),
                args,
                kwargs: BTreeMap::new(),
                resolution: import_alias.map(|alias| crate::model::CallResolution {
                    import_alias: Some(alias),
                    confidence: Confidence::High,
                }),
            }));

            // Check sinks
            self.check_sink(&normalized_callee, &call_id, line);
        }

        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let line = self.line_of(node);
        let column = self.column_of(node);
        let file = self.rel_path();
        let method = node.method.to_string();
        let receiver = display::expr_to_string(&node.receiver);
        let callee = format!("{receiver}.{method}");
        let caller = self.caller_function_id().unwrap_or_default();

        // MCP registration detection runs for every method call, even dedup'd
        // levels of a method chain, so chained registrations are not lost.
        if mcp::is_mcp_registration(&method)
            && let Some(first_arg) = node.args.first()
        {
            let tool_name = display::expr_to_string(first_arg).trim_matches('"').to_string();
            if !tool_name.is_empty() {
                let closure_sig = node.args.iter().nth(1).and_then(|arg| {
                    if let Expr::Closure(closure) = arg {
                        Some(Signature {
                            constness: None,
                            asyncness: None,
                            unsafety: None,
                            abi: None,
                            fn_token: Token![fn](proc_macro2::Span::call_site()),
                            ident: proc_macro2::Ident::new("handler", proc_macro2::Span::call_site()),
                            generics: Generics::default(),
                            paren_token: syn::token::Paren::default(),
                            inputs: closure
                                .inputs
                                .iter()
                                .map(|pat| {
                                    FnArg::Typed(PatType {
                                        attrs: Vec::new(),
                                        pat: Box::new(pat.clone()),
                                        colon_token: Token![:](proc_macro2::Span::call_site()),
                                        ty: Box::new(Type::Verbatim(
                                            proc_macro2::TokenStream::new(),
                                        )),
                                    })
                                })
                                .collect(),
                            variadic: None,
                            output: ReturnType::Default,
                        })
                    } else {
                        None
                    }
                });

                self.emit_sdk_entrypoint(
                    &callee,
                    &tool_name,
                    line,
                    &caller,
                    closure_sig.as_ref(),
                );
            }
        }

        // Only the CallFact + sink are dedup'd per span start; distinct calls on
        // the same line still keep distinct columns.
        if self.seen_calls.insert((line, column)) {
            let (normalized_callee, import_alias) = self.resolve_callee(&callee);
            let args = calls::extract_method_chain_args(node);
            let call_id = make_call_id(&self.root, &self.file, line, column);

            self.facts.push(Fact::Call(CallFact {
                base: FactBase {
                    id: call_id.clone(),
                    file: file.clone(),
                    line,
                    extractor: EXTRACTOR_NAME.to_string(),
                },
                caller: caller.clone(),
                callee: callee.clone(),
                normalized_callee: Some(normalized_callee.clone()),
                column: Some(column),
                end_line: Some(line),
                snippet: String::new(),
                args,
                kwargs: BTreeMap::new(),
                resolution: import_alias.map(|alias| crate::model::CallResolution {
                    import_alias: Some(alias),
                    confidence: Confidence::High,
                }),
            }));

            self.check_sink(&normalized_callee, &call_id, line);
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_local(&mut self, node: &'ast Local) {
        let line = self.line_of(node);
        let file = self.rel_path();

        if let Some(init) = &node.init {
            let target = display::pat_to_string(&node.pat);
            let value = display::expr_to_string(&init.expr);
            if !target.is_empty() && !value.is_empty() {
                self.facts.push(Fact::Assign(AssignFact {
                    base: FactBase {
                        id: make_assign_id(&self.root, &self.file, line, &target),
                        file: file.clone(),
                        line,
                        extractor: EXTRACTOR_NAME.to_string(),
                    },
                    function_id: self.caller_function_id().unwrap_or_default(),
                    target,
                    value,
                    snippet: String::new(),
                }));
            }
        }

        syn::visit::visit_local(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast ExprAssign) {
        let line = self.line_of(node);
        let file = self.rel_path();
        let target = display::expr_to_string(&node.left);
        let value = display::expr_to_string(&node.right);

        if !target.is_empty() && !value.is_empty() {
            self.facts.push(Fact::Assign(AssignFact {
                base: FactBase {
                    id: make_assign_id(&self.root, &self.file, line, &target),
                    file: file.clone(),
                    line,
                    extractor: EXTRACTOR_NAME.to_string(),
                },
                function_id: self.caller_function_id().unwrap_or_default(),
                target,
                value,
                snippet: String::new(),
            }));
        }

        syn::visit::visit_expr_assign(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        let line = self.line_of(node);
        let file = self.rel_path();
        let call_id = make_call_id(&self.root, &self.file, line, 0);

        let (severity_base, reason) = if unsafe_block_is_dangerous(&node.block) {
            (
                Severity::Medium,
                "Unsafe block can bypass Rust's memory safety guarantees",
            )
        } else {
            (
                Severity::Low,
                "Unsafe block present but no dangerous unsafe operation detected (no raw pointer deref / transmute / uninitialized memory)",
            )
        };

        self.facts.push(Fact::Sink(SinkFact {
            base: FactBase {
                id: make_sink_id("unsafe_block", &self.root, &self.file, line),
                file: file.clone(),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            call_id,
            category: "unsafe_block".to_string(),
            rule_id: "rust.unsafe_block".to_string(),
            sink_name: "unsafe".to_string(),
            severity_base,
            reason: reason.to_string(),
            conditions: BTreeMap::new(),
            confidence: Confidence::High,
        }));

        syn::visit::visit_expr_unsafe(self, node);
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn extract_rust_facts(
    root: &Path,
    file: &Path,
    source: &str,
    sinks: &[SinkModel],
) -> RustExtractionResult {
    let ast = match syn::parse_file(source) {
        Ok(file_ast) => file_ast,
        Err(err) => {
            return RustExtractionResult {
                facts: Vec::new(),
                diagnostics: vec![ExtractionDiagnostic {
                    file: display_path(file),
                    line: 1,
                    kind: "syntax_error".to_string(),
                    message: err.to_string(),
                }],
            };
        }
    };

    let mut extractor = RustFactExtractor::new(root, file, source, sinks);
    extractor.visit_file(&ast);

    // Sort facts by line
    extractor.facts.sort_by_key(fact_sort_key);

    RustExtractionResult {
        facts: extractor.facts,
        diagnostics: extractor.diagnostics,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::model::EntryPointKind;
    use super::*;

    fn extract(source: &str) -> RustExtractionResult {
        extract_rust_facts(
            Path::new("/repo"),
            Path::new("/repo/src/main.rs"),
            source,
            crate::models::default_catalog().sinks_for_language("rust"),
        )
    }

    fn import_facts(result: &RustExtractionResult) -> Vec<&ImportFact> {
        result
            .facts
            .iter()
            .filter_map(|f| match f {
                Fact::Import(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn function_facts(result: &RustExtractionResult) -> Vec<&FunctionFact> {
        result
            .facts
            .iter()
            .filter_map(|f| match f {
                Fact::Function(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn entrypoint_facts(result: &RustExtractionResult) -> Vec<&EntryPointFact> {
        result
            .facts
            .iter()
            .filter_map(|f| match f {
                Fact::Entrypoint(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn sink_facts(result: &RustExtractionResult) -> Vec<&SinkFact> {
        result
            .facts
            .iter()
            .filter_map(|f| match f {
                Fact::Sink(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn call_facts(result: &RustExtractionResult) -> Vec<&CallFact> {
        result
            .facts
            .iter()
            .filter_map(|f| match f {
                Fact::Call(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn source_facts(result: &RustExtractionResult) -> Vec<&SourceFact> {
        result
            .facts
            .iter()
            .filter_map(|f| match f {
                Fact::Source(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn assign_facts(result: &RustExtractionResult) -> Vec<&AssignFact> {
        result
            .facts
            .iter()
            .filter_map(|f| match f {
                Fact::Assign(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn syntax_errors_return_diagnostic_without_facts() {
        let result = extract("fn broken( {\n}\n");

        assert!(result.facts.is_empty());
        assert_eq!(result.diagnostics.len(), 1);
        let diagnostic = &result.diagnostics[0];
        assert_eq!(diagnostic.file, "/repo/src/main.rs");
        assert_eq!(diagnostic.kind, "syntax_error");
        assert!(!diagnostic.message.is_empty());
    }

    #[test]
    fn extracts_use_import_facts() {
        let result = extract(
            r#"
use std::process::Command;
use std::fs::File as FsFile;
use std::io::prelude::*;
use std::collections::{HashMap, BTreeMap};
"#,
        );

        assert!(result.diagnostics.is_empty());
        let imports = import_facts(&result);
        assert!(
            imports.iter().any(|i| i.module == "std::process::Command" && i.kind == ImportKind::Use)
        );
        assert!(
            imports.iter().any(|i| i.module == "std::fs::File" && i.kind == ImportKind::UseAs && i.alias.as_deref() == Some("FsFile"))
        );
        assert!(
            imports.iter().any(|i| i.kind == ImportKind::UseGlob)
        );
        assert!(
            imports.iter().any(|i| i.kind == ImportKind::UseGroup)
        );
    }

    #[test]
    fn extracts_function_facts_with_params_and_return_type() {
        let result = extract(
            r#"
/// Run a command with the given arguments.
fn run_command(command: &str, args: Vec<String>) -> std::io::Result<String> {
    let output = std::process::Command::new(command).args(&args).output()?;
    String::from_utf8(output.stdout).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

async fn async_handler(params: serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let functions = function_facts(&result);
        assert_eq!(functions.len(), 2);

        let run_cmd = functions.iter().find(|f| f.name == "run_command").expect("run_command");
        assert_eq!(run_cmd.language, "rust");
        assert_eq!(run_cmd.qualified_name, "run_command");
        assert_eq!(run_cmd.params.len(), 2);
        assert_eq!(run_cmd.params[0].name, "command");
        assert_eq!(run_cmd.params[0].annotation.as_deref(), Some("&str"));
        assert_eq!(run_cmd.params[1].name, "args");
        assert_eq!(run_cmd.return_type.as_deref(), Some("std::io::Result<String>"));
        assert_eq!(run_cmd.docstring.as_deref(), Some("Run a command with the given arguments."));

        let async_fn = functions.iter().find(|f| f.name == "async_handler").expect("async_handler");
        assert!(async_fn.return_type.as_deref().unwrap().contains("Result"));
    }

    #[test]
    fn extracts_method_facts_from_impl_blocks() {
        let result = extract(
            r#"
struct MyTool;

impl MyTool {
    /// Handle a tool request.
    fn handle(&self, input: String) -> String {
        format!("processed: {input}")
    }
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let functions = function_facts(&result);
        let handle = functions.iter().find(|f| f.name == "handle").expect("handle");
        assert_eq!(handle.qualified_name, "MyTool.handle");
        assert_eq!(handle.enclosing_class.as_deref(), Some("MyTool"));
        assert_eq!(handle.docstring.as_deref(), Some("Handle a tool request."));
        assert_eq!(handle.params[0].name, "&self");
    }

    #[test]
    fn extracts_call_facts_with_alias_resolution() {
        let result = extract(
            r#"
use std::process::Command;

fn do_work() {
    let cmd = Command::new("ls");
    let output = cmd.output();
    std::fs::read_to_string("/etc/passwd");
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let calls = call_facts(&result);
        assert!(!calls.is_empty());

        let cmd_new = calls.iter().find(|c| c.callee == "Command::new").expect("Command::new call");
        assert_eq!(cmd_new.normalized_callee.as_deref(), Some("std::process::Command::new"));
        assert!(cmd_new.resolution.as_ref().and_then(|r| r.import_alias.as_deref()) == Some("Command"));

        let cmd_output = calls.iter().find(|c| c.callee == "cmd.output").expect("cmd.output call");
        assert_eq!(cmd_output.normalized_callee.as_deref(), Some("cmd.output"));
    }

    #[test]
    fn detects_rust_mcp_attribute_tools() {
        let result = extract(
            r#"
use serde_json::Value;

#[tool]
async fn my_tool(params: Value) -> Result<String, String> {
    Ok(format!("received: {params:?}"))
}

#[resource("file://{path}")]
fn read_resource(path: String) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let entries = entrypoint_facts(&result);
        assert_eq!(entries.len(), 2);

        let tool_entry = entries.iter().find(|e| e.name == "my_tool").expect("my_tool entrypoint");
        assert_eq!(tool_entry.kind, EntryPointKind::McpTool);
        assert_eq!(tool_entry.evidence.as_ref().unwrap().kind, "attribute_macro");
        assert!(tool_entry.evidence.as_ref().unwrap().text.contains("tool"));

        let resource_entry = entries.iter().find(|e| e.name == "read_resource").expect("read_resource entrypoint");
        assert_eq!(resource_entry.kind, EntryPointKind::McpResource);

        let sources = source_facts(&result);
        assert!(sources.iter().any(|s| s.name == "params"));
        assert!(sources.iter().any(|s| s.name == "path"));
    }

    #[test]
    fn detects_rust_sinks() {
        let result = extract(
            r##"
use std::process::Command;
use std::net::TcpStream;

fn risky_ops() {
    Command::new("rm -rf /").output();
    TcpStream::connect("evil.com:443");
    std::env::var("SECRET_KEY");
    serde_json::from_str::<serde_json::Value>(r#"{"key": "value"}"#);
    unsafe {
        let ptr = 0xdeadbeef as *const u8;
        let _val = *ptr;
    }
}
"##,
        );

        assert!(result.diagnostics.is_empty());
        let sinks = sink_facts(&result);
        let categories: Vec<&str> = sinks.iter().map(|s| s.category.as_str()).collect();

        assert!(categories.contains(&"command_execution"));
        assert!(categories.contains(&"network_request"));
        assert!(categories.contains(&"env_access"));
        assert!(categories.contains(&"deserialization"));
        assert!(categories.contains(&"unsafe_block"));
    }

    #[test]
    fn unsafe_block_without_dangerous_op_is_low_severity() {
        let result = extract(
            r#"
fn f() {
    unsafe {
        let x = 5;
        let _ = x;
    }
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let sinks = sink_facts(&result);
        let unsafe_sink = sinks
            .iter()
            .find(|s| s.category == "unsafe_block")
            .expect("unsafe_block sink");
        assert_eq!(unsafe_sink.severity_base, Severity::Low);
    }

    #[test]
    fn unsafe_block_with_pointer_deref_is_medium_severity() {
        let result = extract(
            r#"
fn f() {
    unsafe {
        let ptr = 0xdeadbeef as *const u8;
        let _ = *ptr;
    }
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let sinks = sink_facts(&result);
        let unsafe_sink = sinks
            .iter()
            .find(|s| s.category == "unsafe_block")
            .expect("unsafe_block sink");
        assert_eq!(unsafe_sink.severity_base, Severity::Medium);
    }

    #[test]
    fn dedups_method_chain_to_single_call_and_sink() {
        let result = extract(
            r#"
use std::process::Command;

fn run(shell_cmd: &str) {
    Command::new("sh").arg("-c").arg(shell_cmd).output();
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let sinks = sink_facts(&result);
        let calls = call_facts(&result);

        assert_eq!(sinks.len(), 1, "expected a single sink, got {sinks:?}");
        assert_eq!(calls.len(), 1, "expected a single call, got {calls:?}");

        assert_eq!(sinks[0].category, "command_execution");
        // The emitted call is the outermost, most complete chain.
        assert!(calls[0].callee.contains("Command::new"));
        assert!(calls[0].callee.contains(".output"));
        // Accurate column resolved (not the old hardcoded 0).
        assert_ne!(calls[0].column, Some(0));
        // Sink's call_id points at the surviving call.
        assert_eq!(sinks[0].call_id, calls[0].base.id);
    }

    #[test]
    fn keeps_distinct_calls_on_same_line_separate() {
        let result = extract(
            r#"
use std::process::Command;

fn run() {
    let _ = (Command::new("a").output(), Command::new("b").output());
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let sinks = sink_facts(&result);
        let calls = call_facts(&result);

        // Two separate chains on the same line must NOT be collapsed together.
        assert_eq!(sinks.len(), 2, "expected two sinks, got {sinks:?}");
        assert_eq!(calls.len(), 2, "expected two calls, got {calls:?}");

        // Their call ids differ only in the (accurate) column component.
        assert_ne!(calls[0].base.id, calls[1].base.id);
        assert_ne!(calls[0].column, calls[1].column);
    }

    #[test]
    fn extracts_assign_facts() {
        let result = extract(
            r#"
fn process() {
    let cmd = std::process::Command::new("echo");
    let result = "hello".to_string();
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let assigns = assign_facts(&result);
        assert!(assigns.iter().any(|a| a.target == "cmd"));
        assert!(assigns.iter().any(|a| a.target == "result"));
    }

    #[test]
    fn detects_rust_mcp_sdk_entrypoint_with_inline_closure() {
        let result = extract(
            r#"
fn register(server: &mut Server) {
    server.tool("my_tool", |params: Value| {
        println!("got: {:?}", params);
        Ok(())
    });
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let entries = entrypoint_facts(&result);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "my_tool");
        assert_eq!(entries[0].kind, EntryPointKind::McpTool);
        assert_eq!(entries[0].evidence.as_ref().unwrap().kind, "sdk_call");
        assert!(
            entries[0]
                .evidence
                .as_ref()
                .unwrap()
                .text
                .contains("server.tool")
        );
        assert_eq!(entries[0].params, vec!["params"]);
        assert_eq!(entries[0].confidence, Confidence::Medium);

        let sources = source_facts(&result);
        assert!(sources.iter().any(|s| s.name == "params"));
    }

    #[test]
    fn detects_rust_mcp_sdk_entrypoint_with_named_handler() {
        let result = extract(
            r#"
fn register(server: &mut Server) {
    server.tool("my_tool", my_handler);
}

fn my_handler(params: Value) -> Result<(), String> {
    Ok(())
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let entries = entrypoint_facts(&result);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "my_tool");
        assert_eq!(entries[0].evidence.as_ref().unwrap().kind, "sdk_call");
        assert_eq!(entries[0].params, Vec::<String>::new());
    }

    #[test]
    fn preserves_chained_mcp_registration_entrypoints_under_dedup() {
        let result = extract(
            r#"
fn register(server: &mut Server) {
    server.tool("tool_a", |params: Value| {
        println!("got: {:?}", params);
        Ok(())
    })
    .tool("tool_b", |params: Value| {
        println!("got: {:?}", params);
        Ok(())
    });
}
"#,
        );

        assert!(result.diagnostics.is_empty());
        let entries = entrypoint_facts(&result);

        // Dedup collapses the chain to a single call/sink, but BOTH chained
        // MCP registrations must still be detected as entrypoints.
        assert_eq!(entries.len(), 2, "expected two entrypoints, got {entries:?}");
        assert!(entries.iter().any(|e| e.name == "tool_a"));
        assert!(entries.iter().any(|e| e.name == "tool_b"));
        assert!(entries.iter().all(|e| e.kind == EntryPointKind::McpTool));
    }
}
