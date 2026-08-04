use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use syn::{
    punctuated::Punctuated,
    spanned::Spanned,
    visit::Visit,
    *,
};

use crate::model::{
    AssignFact, CallArg, CallFact, Confidence, EntryPointEvidence, EntryPointFact, EntryPointKind,
    Fact, FactBase, FunctionFact, ImportFact, ImportKind, ParamInfo, Severity, SinkFact, SourceFact,
};

use super::{
    ExtractionDiagnostic, display_path, make_assign_id, make_call_id, make_entrypoint_id,
    make_function_id, make_import_id, make_sink_id, make_source_id,
};

const EXTRACTOR_NAME: &str = "rust_syn_phase9";

// ---------------------------------------------------------------------------
// MCP attribute patterns for Rust
// ---------------------------------------------------------------------------

const MCP_ATTR_PATTERNS: &[&str] = &[
    "tool",
    "resource",
    "prompt",
    "mcp::tool",
    "mcp::resource",
    "mcp::prompt",
    "mcp_tool",
    "mcp_resource",
    "mcp_prompt",
    "server_tool",
    "server_resource",
    "server_prompt",
];

// ---------------------------------------------------------------------------
// Sink classification for Rust APIs
// ---------------------------------------------------------------------------

struct SinkRule {
    patterns: &'static [&'static str],
    category: &'static str,
    rule_id: &'static str,
    severity: Severity,
    reason: &'static str,
}

static SINK_RULES: &[SinkRule] = &[
    SinkRule {
        patterns: &[
            "std::process::Command",
            "Command::new",
            "Command::output",
            "Command::spawn",
            "std::process::Command::new",
        ],
        category: "command_execution",
        rule_id: "rust.command_execution",
        severity: Severity::High,
        reason: "Executes external commands via std::process::Command",
    },
    SinkRule {
        patterns: &[
            "std::fs::read",
            "std::fs::read_to_string",
            "std::fs::File::open",
            "File::open",
        ],
        category: "file_read",
        rule_id: "rust.file_read",
        severity: Severity::Medium,
        reason: "File read access can leak sensitive data",
    },
    SinkRule {
        patterns: &[
            "std::fs::write",
            "std::fs::File::create",
            "File::create",
            "std::io::Write::write",
            "std::io::Write::write_all",
        ],
        category: "file_write",
        rule_id: "rust.file_write",
        severity: Severity::Medium,
        reason: "File write can modify filesystem contents",
    },
    SinkRule {
        patterns: &[
            "std::net::TcpStream::connect",
            "TcpStream::connect",
            "std::os::unix::net::UnixStream::connect",
            "reqwest::get",
            "reqwest::blocking::get",
            "reqwest::Client::new",
            "hyper::client",
            "ureq::get",
        ],
        category: "network_request",
        rule_id: "rust.network_request",
        severity: Severity::Medium,
        reason: "Network request can reach attacker-controlled URLs (SSRF)",
    },
    SinkRule {
        patterns: &[
            "std::env::var",
            "std::env::var_os",
            "std::env::vars",
            "std::env::vars_os",
        ],
        category: "credential_leak",
        rule_id: "rust.credential_leak",
        severity: Severity::High,
        reason: "Access to environment variables can leak credentials",
    },
    SinkRule {
        patterns: &[
            "serde_json::from_str",
            "serde_json::from_slice",
            "serde_json::from_reader",
            "serde_yaml::from_str",
        ],
        category: "deserialization",
        rule_id: "rust.deserialization",
        severity: Severity::Medium,
        reason: "Deserialization of untrusted input can cause type-confusion or RCE",
    },
    SinkRule {
        patterns: &[
            "libloading::Library::new",
            "dlopen",
            "libc::dlopen",
        ],
        category: "dynamic_loading",
        rule_id: "rust.dynamic_loading",
        severity: Severity::High,
        reason: "Dynamic library loading can execute attacker-controlled code",
    },
];

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

struct RustFactExtractor {
    root: PathBuf,
    file: PathBuf,
    facts: Vec<Fact>,
    diagnostics: Vec<ExtractionDiagnostic>,

    /// Maps alias name → full path (e.g. "Command" → "std::process::Command")
    use_aliases: BTreeMap<String, String>,

    /// Tracks the current function scope for qualified names
    scope: Vec<String>,

    /// Tracks the current impl/struct context (e.g. "MyServer")
    impl_stack: Vec<String>,
}

impl RustFactExtractor {
    fn new(root: &Path, file: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            file: file.to_path_buf(),
            facts: Vec::new(),
            diagnostics: Vec::new(),
            use_aliases: BTreeMap::new(),
            scope: Vec::new(),
            impl_stack: Vec::new(),
        }
    }

    fn line_of(&self, _node: &impl Spanned) -> u32 {
        // FIXME: proc_macro2::Span does not expose line/column on stable Rust.
        // Accurate line numbers require either nightly proc_macro2 features or
        // byte-offset counting from source text. For Phase 9, use stub (matching
        // JS/TS Phase 8 approach).
        1
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
        // Direct alias match
        if let Some(resolved) = self.use_aliases.get(callee) {
            return (resolved.clone(), Some(callee.to_string()));
        }
        // Member expression alias (e.g. "Command::new" where "Command" is aliased)
        if let Some((head, tail)) = callee.split_once("::")
            && let Some(resolved) = self.use_aliases.get(head)
        {
            return (format!("{resolved}::{tail}"), Some(head.to_string()));
        }
        (callee.to_string(), None)
    }

    /// Emit a SinkFact if the callee matches known dangerous APIs.
    fn check_sink(&mut self, normalized_callee: &str, call_id: &str, line: u32) {
        for rule in SINK_RULES {
            if matches_sink(normalized_callee, rule.patterns) {
                let file = self.rel_path();
                self.facts.push(Fact::Sink(SinkFact {
                    base: FactBase {
                        id: make_sink_id(rule.category, &self.root, &self.file, line),
                        file: file.clone(),
                        line,
                        extractor: EXTRACTOR_NAME.to_string(),
                    },
                    call_id: call_id.to_string(),
                    category: rule.category.to_string(),
                    rule_id: rule.rule_id.to_string(),
                    sink_name: normalized_callee.to_string(),
                    severity_base: rule.severity.clone(),
                    reason: rule.reason.to_string(),
                    conditions: BTreeMap::new(),
                    confidence: Confidence::High,
                }));
                return;
            }
        }
    }

    /// Check if the callee matches an MCP registration pattern.
    fn is_mcp_registration(&self, callee: &str) -> bool {
        MCP_ATTR_PATTERNS.iter().any(|pattern| {
            callee == *pattern
                || callee.ends_with(&format!(".{pattern}"))
        })
    }

    /// Determine EntryPointKind from callee string.
    fn entrypoint_kind(&self, callee: &str) -> EntryPointKind {
        let method = callee.rsplit('.').next().unwrap_or(callee);
        if method.contains("resource") {
            EntryPointKind::McpResource
        } else if method.contains("prompt") {
            EntryPointKind::McpPrompt
        } else {
            EntryPointKind::McpTool
        }
    }
}

// ---------------------------------------------------------------------------
// syn Visit trait implementation
// ---------------------------------------------------------------------------

impl<'ast> Visit<'ast> for RustFactExtractor {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        let line = self.line_of(node);
        let file = self.rel_path();
        self.extract_use_tree(&node.tree, &file, line, &mut String::new());
        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let name = node.sig.ident.to_string();
        let qual_name = Self::build_qualified_name(&self.impl_stack, &name);
        self.scope.push(qual_name.clone());

        let line = 1; // FIXME: accurate span line
        let end_line = 1; // FIXME: accurate span line
        let file = self.rel_path();
        let func_id = make_function_id("rust", &self.root, &self.file, &qual_name);
        let params = params_from_signature(&node.sig);
        let decorators = attrs_to_strings(&node.attrs);
        let docstring = doc_from_attrs(&node.attrs);
        let return_type = return_type_to_string(&node.sig.output);
        let enclosing_class = self.impl_stack.last().cloned();

        self.facts.push(Fact::Function(FunctionFact {
            base: FactBase {
                id: func_id.clone(),
                file: file.clone(),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            language: "rust".to_string(),
            name: name.clone(),
            qualified_name: qual_name.clone(),
            end_line,
            params: params.clone(),
            decorators: decorators.clone(),
            docstring,
            return_type,
            enclosing_class,
        }));

        // Check for MCP attribute macros (#[tool], #[resource], #[prompt])
        if let Some((kind, evidence_text)) =
            decorators.iter().find_map(|attr| classify_mcp_attr(attr).map(|k| (k, attr.clone())))
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
                name,
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

        // Recurse into function body
        syn::visit::visit_item_fn(self, node);
        self.scope.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        // Push impl type name to the impl stack
        let type_name = type_to_string(&node.self_ty);
        self.impl_stack.push(type_name);
        syn::visit::visit_item_impl(self, node);
        self.impl_stack.pop();
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        let name = node.ident.to_string();
        // Structs aren't functions but they provide context (e.g. for impl blocks).
        // We don't emit a fact for the struct itself, but we track it.
        syn::visit::visit_item_struct(self, node);
        let _ = name; // suppress unused warning
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let name = node.sig.ident.to_string();
        let qual_name = Self::build_qualified_name(&self.impl_stack, &name);
        self.scope.push(qual_name.clone());

        let line = 1; // FIXME: accurate span line
        let end_line = 1; // FIXME: accurate span line
        let file = self.rel_path();
        let func_id = make_function_id("rust", &self.root, &self.file, &qual_name);
        let params = params_from_signature(&node.sig);
        let decorators = attrs_to_strings(&node.attrs);
        let docstring = doc_from_attrs(&node.attrs);
        let return_type = return_type_to_string(&node.sig.output);
        let enclosing_class = self.impl_stack.last().cloned();

        self.facts.push(Fact::Function(FunctionFact {
            base: FactBase {
                id: func_id.clone(),
                file: file.clone(),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            language: "rust".to_string(),
            name: name.clone(),
            qualified_name: qual_name.clone(),
            end_line,
            params: params.clone(),
            decorators: decorators.clone(),
            docstring,
            return_type,
            enclosing_class,
        }));

        // Check for MCP attribute macros on methods
        if let Some((kind, evidence_text)) =
            decorators.iter().find_map(|attr| classify_mcp_attr(attr).map(|k| (k, attr.clone())))
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
                name,
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

        syn::visit::visit_impl_item_fn(self, node);
        self.scope.pop();
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let line = self.line_of(node);
        let column = 0; // FIXME: accurate span column
        let file = self.rel_path();
        let callee = expr_to_string(&node.func);
        let (normalized_callee, import_alias) = self.resolve_callee(&callee);
        let args = extract_call_args(&node.args);
        let call_id = make_call_id(&self.root, &self.file, line, column);
        let caller = self.caller_function_id().unwrap_or_default();

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

        // Check MCP registration via builder pattern (e.g. "server.tool(...)")
        if self.is_mcp_registration(&callee) {
            // Try to extract tool name from first string argument
            if let Some(first_arg) = node.args.first() {
                let tool_name = expr_to_string(first_arg).trim_matches('"').to_string();
                if !tool_name.is_empty() {
                    let entry_id = make_entrypoint_id(
                        &self.root,
                        &self.file,
                        &format!("{callee}.{tool_name}"),
                    );
                    let kind = self.entrypoint_kind(&callee);

                    self.facts.push(Fact::Entrypoint(EntryPointFact {
                        base: FactBase {
                            id: entry_id,
                            file: file.clone(),
                            line,
                            extractor: EXTRACTOR_NAME.to_string(),
                        },
                        kind,
                        name: tool_name,
                        function_id: caller.clone(),
                        evidence: Some(EntryPointEvidence {
                            kind: "sdk_call".to_string(),
                            text: callee.clone(),
                        }),
                        params: Vec::new(),
                        confidence: Confidence::Medium,
                    }));
                }
            }
        }

        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let line = self.line_of(node);
        let column = 0; // FIXME: accurate span column
        let file = self.rel_path();
        let method = node.method.to_string();
        let receiver = expr_to_string(&node.receiver);
        let callee = format!("{receiver}.{method}");
        let (normalized_callee, import_alias) = self.resolve_callee(&callee);
        let args = extract_call_args(&node.args);
        let call_id = make_call_id(&self.root, &self.file, line, column);
        let caller = self.caller_function_id().unwrap_or_default();

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

        // Check MCP registration (e.g. server.tool(...))
        if self.is_mcp_registration(&method)
            && let Some(first_arg) = node.args.first()
        {
            let tool_name = expr_to_string(first_arg).trim_matches('"').to_string();
            if !tool_name.is_empty() {
                    let entry_id = make_entrypoint_id(
                        &self.root,
                        &self.file,
                        &format!("{callee}.{tool_name}"),
                    );
                    let kind = self.entrypoint_kind(&method);

                    self.facts.push(Fact::Entrypoint(EntryPointFact {
                        base: FactBase {
                            id: entry_id,
                            file: file.clone(),
                            line,
                            extractor: EXTRACTOR_NAME.to_string(),
                        },
                        kind,
                        name: tool_name,
                        function_id: caller.clone(),
                        evidence: Some(EntryPointEvidence {
                            kind: "sdk_call".to_string(),
                            text: callee.clone(),
                        }),
                        params: Vec::new(),
                        confidence: Confidence::Medium,
                    }));
                }
            }

            syn::visit::visit_expr_method_call(self, node);
        }

    fn visit_local(&mut self, node: &'ast Local) {
        // Handle `let x = expr;` — Rust's primary assignment form
        let line = self.line_of(node);
        let file = self.rel_path();

        if let Some(init) = &node.init {
            let target = pat_to_string(&node.pat);
            let value = expr_to_string(&init.expr);
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
        let target = expr_to_string(&node.left);
        let value = expr_to_string(&node.right);

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
        // Emit an AssignFact (or similar) for unsafe blocks as a warning indicator
        let line = self.line_of(node);
        let file = self.rel_path();
        let call_id = make_call_id(&self.root, &self.file, line, 0);

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
            severity_base: Severity::Medium,
            reason: "Unsafe block can bypass Rust's memory safety guarantees".to_string(),
            conditions: BTreeMap::new(),
            confidence: Confidence::High,
        }));

        syn::visit::visit_expr_unsafe(self, node);
    }
}

// ---------------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------------

impl RustFactExtractor {
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
                    let item_str = use_tree_summary(item);
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

                    // Recurse for alias building
                    let old_len = prefix.len();
                    self.extract_use_tree(item, file, line, prefix);
                    prefix.truncate(old_len);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Expression → string conversion
// ---------------------------------------------------------------------------

fn expr_to_string(expr: &Expr) -> String {
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
            let name = mac.mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
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

fn syn_path_to_string(path: &syn::Path) -> String {
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

fn lit_to_string(lit: &Lit) -> String {
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

fn member_to_string(member: &Member) -> String {
    match member {
        Member::Named(ident) => ident.to_string(),
        Member::Unnamed(index) => index.index.to_string(),
    }
}

fn type_to_string(ty: &Type) -> String {
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
            let bounds: Vec<String> = trait_ty.bounds.iter().map(type_param_bound_to_string).collect();
            format!("impl {}", bounds.join(" + "))
        }
        _ => format!("<{ty:?}>"),
    }
}

fn type_param_bound_to_string(bound: &TypeParamBound) -> String {
    match bound {
        TypeParamBound::Trait(trait_bound) => syn_path_to_string(&trait_bound.path),
        TypeParamBound::Lifetime(lt) => lt.ident.to_string(),
        _ => "<bound>".to_string(),
    }
}

fn return_type_to_string(output: &ReturnType) -> Option<String> {
    match output {
        ReturnType::Type(_, ty) => Some(type_to_string(ty)),
        ReturnType::Default => None,
    }
}

fn use_tree_summary(tree: &UseTree) -> String {
    match tree {
        UseTree::Path(path) => format!("{}::{}", path.ident, use_tree_summary(&path.tree)),
        UseTree::Name(name) => name.ident.to_string(),
        UseTree::Rename(rename) => format!("{} as {}", rename.ident, rename.rename),
        UseTree::Glob(_) => "*".to_string(),
        UseTree::Group(_) => "{...}".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Parameter extraction
// ---------------------------------------------------------------------------

fn params_from_signature(sig: &Signature) -> Vec<ParamInfo> {
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

fn pat_to_string(pat: &Pat) -> String {
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

// ---------------------------------------------------------------------------
// Attribute handling
// ---------------------------------------------------------------------------

fn attrs_to_strings(attrs: &[Attribute]) -> Vec<String> {
    attrs.iter().map(attr_to_string).collect()
}

fn attr_to_string(attr: &Attribute) -> String {
    let path = syn_path_to_string(attr.path());
    if path.starts_with("doc") {
        return path;
    }
    // Use Debug representation for attribute tokens
    let tokens = format!("{:?}", attr.meta);
    if tokens.is_empty() || tokens == "Meta::Path(Path { leading_colon: None, segments: [] })" {
        format!("#[{path}]")
    } else {
        format!("#[{path}(...)]")
    }
}

fn doc_from_attrs(attrs: &[Attribute]) -> Option<String> {
    let doc_lines: Vec<String> = attrs
        .iter()
        .filter_map(|attr| {
            if attr.path().is_ident("doc") {
                match &attr.meta {
                    Meta::NameValue(nv) => {
                        let s = expr_to_string(&nv.value);
                        // Strip surrounding quotes
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

fn classify_mcp_attr(attr: &str) -> Option<EntryPointKind> {
    // Strip #[ and ] and any trailing (...)
    let normalized = attr
        .trim_start_matches("#[")
        .trim_end_matches(']')
        .trim_end_matches("(...)")
        .trim_end_matches("()");

    if !MCP_ATTR_PATTERNS.iter().any(|pattern| {
        normalized == *pattern
            || normalized.starts_with(&format!("{pattern}("))
            || normalized == format!("{pattern}()")
    }) {
        return None;
    }

    if normalized.contains("resource") {
        Some(EntryPointKind::McpResource)
    } else if normalized.contains("prompt") {
        Some(EntryPointKind::McpPrompt)
    } else {
        Some(EntryPointKind::McpTool)
    }
}

// ---------------------------------------------------------------------------
// Call argument extraction
// ---------------------------------------------------------------------------

fn extract_call_args(args: &Punctuated<Expr, Token![,]>) -> Vec<CallArg> {
    args.iter()
        .enumerate()
        .map(|(i, expr)| CallArg {
            index: i as u32,
            expr: expr_to_string(expr),
            kind: "positional".to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Sink matching
// ---------------------------------------------------------------------------

fn matches_sink(callee: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| {
        callee == *pattern
            || callee.ends_with(&format!("::{pattern}"))
            || callee.starts_with(&format!("{pattern}::"))
            || callee.starts_with(&format!("{pattern}<"))
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn extract_rust_facts(root: &Path, file: &Path, source: &str) -> RustExtractionResult {
    let ast = match syn::parse_file(source) {
        Ok(file_ast) => file_ast,
        Err(err) => {
            return RustExtractionResult {
                facts: Vec::new(),
                diagnostics: vec![ExtractionDiagnostic {
                    file: display_path(file),
                    line: 1, // FIXME: accurate span line
                    kind: "syntax_error".to_string(),
                    message: err.to_string(),
                }],
            };
        }
    };

    let mut extractor = RustFactExtractor::new(root, file);
    extractor.visit_file(&ast);

    // Sort facts by line
    extractor.facts.sort_by_key(fact_sort_key);

    RustExtractionResult {
        facts: extractor.facts,
        diagnostics: extractor.diagnostics,
    }
}

fn fact_sort_key(fact: &Fact) -> String {
    match fact {
        Fact::Function(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Import(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Entrypoint(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Call(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Sink(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Source(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Assign(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Dataflow(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::RuntimeEvent(item) => format!("{:010}:{}", item.base.line, item.base.id),
        Fact::Finding(item) => format!("{:010}:{}", item.base.line, item.base.id),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn extract(source: &str) -> RustExtractionResult {
        extract_rust_facts(Path::new("/repo"), Path::new("/repo/src/main.rs"), source)
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
        assert!(categories.contains(&"credential_leak"));
        assert!(categories.contains(&"deserialization"));
        assert!(categories.contains(&"unsafe_block"));
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
}
