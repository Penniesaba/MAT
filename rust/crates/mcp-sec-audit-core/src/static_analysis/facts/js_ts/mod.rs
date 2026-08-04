mod ids;
pub(crate) mod calls;
pub(crate) mod functions;
pub(crate) mod imports;
pub(crate) mod mcp;
pub(crate) mod sinks;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use swc_core::{
    common::{FileName, SourceMap, Span, Spanned},
    ecma::{
        ast::*,
        parser::{Parser, StringInput, Syntax, TsSyntax},
        visit::{Visit, VisitWith},
    },
};

use crate::model::{
    AssignFact, CallFact, Fact, FactBase, ImportFact, ImportKind, SourceFact,
};

use super::ExtractionDiagnostic;

// Re-export diagnostics types for external consumers.
pub use self::types::{JsTsDiagnostic, JsTsExtractionResult};

mod types {
    use crate::model::Fact;

    use super::ExtractionDiagnostic;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum JsTsDiagnostic {
        Fatal { file: String, message: String },
        NonFatal {
            file: String,
            line: u32,
            kind: String,
            message: String,
        },
    }

    impl From<JsTsDiagnostic> for ExtractionDiagnostic {
        fn from(d: JsTsDiagnostic) -> Self {
            match d {
                JsTsDiagnostic::Fatal { file, message } => ExtractionDiagnostic {
                    file,
                    line: 0,
                    kind: "fatal_parse_error".to_string(),
                    message,
                },
                JsTsDiagnostic::NonFatal {
                    file,
                    line,
                    kind,
                    message,
                } => ExtractionDiagnostic { file, line, kind, message },
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct JsTsExtractionResult {
        pub facts: Vec<Fact>,
        pub diagnostics: Vec<JsTsDiagnostic>,
    }

    impl JsTsExtractionResult {
        pub fn empty() -> Self {
            Self {
                facts: Vec::new(),
                diagnostics: Vec::new(),
            }
        }

        pub fn has_fatal(&self) -> bool {
            self.diagnostics
                .iter()
                .any(|d| matches!(d, JsTsDiagnostic::Fatal { .. }))
        }
    }
}

const EXTRACTOR_NAME: &str = "rust_swc_phase8";

/// Main extractor struct implementing SWC's Visit trait.
pub(crate) struct JsTsFactExtractor {
    root: PathBuf,
    file: PathBuf,
    facts: Vec<Fact>,
    diagnostics: Vec<JsTsDiagnostic>,

    // Alias tracking (two independent systems)
    import_aliases: BTreeMap<String, String>,
    require_aliases: BTreeMap<String, String>,

    // Scope tracking
    function_stack: Vec<String>,
    class_stack: Vec<String>,

    // MCP handler context
    current_mcp_handler_id: Option<String>,

    // Named handler deferred processing
    named_handlers: BTreeMap<String, String>, // handler_name -> entrypoint_id
}

impl JsTsFactExtractor {
    fn new(root: &Path, file: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            file: file.to_path_buf(),
            facts: Vec::new(),
            diagnostics: Vec::new(),
            import_aliases: BTreeMap::new(),
            require_aliases: BTreeMap::new(),
            function_stack: Vec::new(),
            class_stack: Vec::new(),
            current_mcp_handler_id: None,
            named_handlers: BTreeMap::new(),
        }
    }

    fn rel_path(&self) -> String {
        self.file
            .strip_prefix(&self.root)
            .unwrap_or(&self.file)
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    }

    fn current_caller_id(&self) -> String {
        if let Some(handler_id) = &self.current_mcp_handler_id {
            return handler_id.clone();
        }
        if let Some(top) = self.function_stack.last() {
            ids::make_js_ts_function_id(&self.root, &self.file, top)
        } else {
            format!("javascript:{}:<module>", self.rel_path())
        }
    }

    fn line_of(&self, _span: Span) -> u32 {
        // SWC Span.lo is a byte offset; accurate line computation requires a
        // SourceMap lookup.  For initial implementation return 1 and add
        // precise position tracking in a follow-up task.
        1
    }

    /// Convert expression to string for AssignFact value extraction.
    fn expr_to_string_for_assign(expr: &Expr) -> String {
        match expr {
            Expr::Ident(id) => id.sym.to_string(),
            Expr::Lit(Lit::Str(s)) => s.value.to_string(),
            Expr::Lit(Lit::Num(n)) => n.value.to_string(),
            Expr::Lit(Lit::Bool(b)) => b.value.to_string(),
            Expr::Member(m) => {
                calls::callee_to_string(&Callee::Expr(Box::new(Expr::Member(m.clone()))))
            }
            Expr::Call(_) => "<call>".to_string(),
            _ => String::new(),
        }
    }

    /// Convert an ArrowExpr body into the Option<BlockStmt> expected by Function.
    /// SWC 0.101 ArrowExpr.body is Box<BlockStmtOrExpr> (not Option).
    fn arrow_body_to_function_body(arrow: &ArrowExpr) -> Option<BlockStmt> {
        Some(match arrow.body.as_ref() {
            BlockStmtOrExpr::BlockStmt(block) => block.clone(),
            BlockStmtOrExpr::Expr(_) => BlockStmt {
                span: arrow.span,
                ctxt: Default::default(),
                stmts: Vec::new(),
            },
        })
    }

    /// Build a synthetic Function struct from an arrow expression for
    /// parameter extraction.
    fn function_from_arrow(arrow: &ArrowExpr) -> Function {
        Function {
            params: arrow
                .params
                .iter()
                .map(|p| Param {
                    span: p.span(),
                    decorators: Vec::new(),
                    pat: p.clone(),
                })
                .collect(),
            decorators: Vec::new(),
            span: arrow.span,
            body: Self::arrow_body_to_function_body(arrow),
            is_generator: false,
            is_async: arrow.is_async,
            type_params: None,
            return_type: None,
            ctxt: Default::default(),
        }
    }

    /// Post-processing pass: backfill SourceFacts for named handler references
    /// and fix up EntryPointFact function_ids to match qualified FunctionFact IDs.
    fn backfill_named_handlers(&mut self) {
        // Collect FunctionFact info into owned data so we can mutate self.facts
        // freely afterward.
        struct FuncInfo {
            func_id: String,
            qualified_name: String,
            line: u32,
            params: Vec<crate::model::ParamInfo>,
        }

        let mut func_by_name: BTreeMap<String, FuncInfo> = BTreeMap::new();
        for fact in &self.facts {
            if let Fact::Function(f) = fact {
                func_by_name.insert(
                    f.name.clone(),
                    FuncInfo {
                        func_id: f.base.id.clone(),
                        qualified_name: f.qualified_name.clone(),
                        line: f.base.line,
                        params: f.params.clone(),
                    },
                );
            }
        }

        // Fix up EntryPointFact function_ids to match the actual qualified
        // FunctionFact ID (e.g. class method "MyClass.myHandler" rather than
        // the bare handler name used in process_named_handler).
        for (handler_name, ep_id) in &self.named_handlers {
            if let Some(info) = func_by_name.get(handler_name) {
                for fact in &mut self.facts {
                    if let Fact::Entrypoint(ep) = fact {
                        if ep.base.id == *ep_id {
                            ep.function_id = info.func_id.clone();
                            break;
                        }
                    }
                }
            }
        }

        // Generate SourceFacts for each named handler's parameters.
        let mut new_sources: Vec<Fact> = Vec::new();

        for (handler_name, _ep_id) in &self.named_handlers {
            if let Some(info) = func_by_name.get(handler_name) {
                for param in &info.params {
                    if param.name.starts_with("...") {
                        continue;
                    }
                    new_sources.push(Fact::Source(SourceFact {
                        base: FactBase {
                            id: format!(
                                "source:{}:{}:{}",
                                self.rel_path(),
                                info.qualified_name,
                                param.name
                            ),
                            file: self.rel_path(),
                            line: info.line,
                            extractor: EXTRACTOR_NAME.to_string(),
                        },
                        kind: "mcp_tool_parameter".to_string(),
                        function_id: info.func_id.clone(),
                        name: param.name.clone(),
                        confidence: crate::model::Confidence::High,
                    }));
                }
            }
        }

        self.facts.extend(new_sources);
    }
}

/// Detect SWC parse syntax from file extension.
fn detect_syntax(file: &Path) -> Syntax {
    match file.extension().and_then(|e| e.to_str()) {
        Some("ts" | "mts" | "cts") => Syntax::Typescript(TsSyntax {
            tsx: false,
            ..Default::default()
        }),
        Some("tsx") => Syntax::Typescript(TsSyntax {
            tsx: true,
            ..Default::default()
        }),
        _ => Syntax::Es(Default::default()),
    }
}

/// Public entry point: extract facts from a JS/TS source file.
pub fn extract_js_ts_facts(
    root: &Path,
    file: &Path,
    source: &str,
) -> JsTsExtractionResult {
    // Skip .d.ts / .d.mts / .d.cts declaration files
    if let Some(name) = file.file_stem() {
        let name_str = name.to_string_lossy();
        if name_str.ends_with(".d") {
            return JsTsExtractionResult::empty();
        }
    }

    let syntax = detect_syntax(file);
    let cm = SourceMap::default();
    let fm = cm.new_source_file(
        FileName::Custom(file.display().to_string()).into(),
        source.to_string(),
    );

    // Parser::new in swc_core 0.101 returns Parser directly (infallible).
    let mut parser = Parser::new(syntax, StringInput::from(&*fm), None);

    let module = match parser.parse_module() {
        Ok(m) => m,
        Err(e) => {
            return JsTsExtractionResult {
                facts: Vec::new(),
                diagnostics: vec![JsTsDiagnostic::Fatal {
                    file: file.display().to_string(),
                    message: format!("Parse error: {e:?}"),
                }],
            };
        }
    };

    let mut extractor = JsTsFactExtractor::new(root, file);
    module.visit_with(&mut extractor);

    // Post-processing
    extractor.backfill_named_handlers();

    // Sort facts by line
    extractor.facts.sort_by_key(|fact| match fact {
        Fact::Function(f) => f.base.line,
        Fact::Import(i) => i.base.line,
        Fact::Entrypoint(e) => e.base.line,
        Fact::Call(c) => c.base.line,
        Fact::Sink(s) => s.base.line,
        Fact::Source(s) => s.base.line,
        Fact::Assign(a) => a.base.line,
        _ => u32::MAX,
    });

    JsTsExtractionResult {
        facts: extractor.facts,
        diagnostics: extractor.diagnostics,
    }
}

// --- SWC Visit trait implementation ---

impl Visit for JsTsFactExtractor {
    fn visit_import_decl(&mut self, n: &ImportDecl) {
        let file = self.rel_path();
        let line = self.line_of(n.span);
        imports::extract_esm_import(
            n, &file, line, EXTRACTOR_NAME,
            &mut self.facts, &mut self.import_aliases,
        );
        n.visit_children_with(self);
    }

    fn visit_fn_decl(&mut self, n: &FnDecl) {
        let name = n.ident.sym.to_string();
        let qual_name = functions::build_qualified_name(
            &self.function_stack, &self.class_stack, &name,
        );
        self.function_stack.push(qual_name.clone());

        let file = self.rel_path();
        let line = self.line_of(n.function.span);
        let func_id = ids::make_js_ts_function_id(&self.root, &self.file, &qual_name);
        let params = functions::params_from_fn(&n.function, "");

        self.facts.push(Fact::Function(functions::create_function_fact(
            func_id, file.clone(), line, EXTRACTOR_NAME.to_string(),
            "javascript".to_string(), name, qual_name,
            self.line_of(n.function.span), params,
            self.class_stack.last().cloned(),
        )));

        n.visit_children_with(self);
        self.function_stack.pop();
    }

    fn visit_class_decl(&mut self, n: &ClassDecl) {
        let name = n.ident.sym.to_string();
        self.class_stack.push(name);
        n.visit_children_with(self);
        self.class_stack.pop();
    }

    fn visit_var_decl(&mut self, n: &VarDecl) {
        let file = self.rel_path();

        for declarator in &n.decls {
            // Check for require() calls
            if let Some(init) = &declarator.init {
                if let Expr::Call(call) = init.as_ref() {
                    let callee_str = calls::callee_to_string(&call.callee);
                    if callee_str == "require" {
                        let line = self.line_of(declarator.span);

                        // Simple require: const fs = require("fs")
                        if let Pat::Ident(id) = &declarator.name {
                            let var_name = id.sym.to_string();
                            if let Some(first_arg) = call.args.first() {
                                if let Expr::Lit(Lit::Str(s)) = first_arg.expr.as_ref() {
                                    let module = s.value.to_string();
                                    self.require_aliases.insert(var_name.clone(), module.clone());
                                    self.facts.push(Fact::Import(ImportFact {
                                        base: FactBase {
                                            id: format!("import:{file}:{line}:{module}"),
                                            file: file.clone(),
                                            line,
                                            extractor: EXTRACTOR_NAME.to_string(),
                                        },
                                        language: "javascript".to_string(),
                                        module,
                                        imported_name: None,
                                        alias: Some(var_name),
                                        kind: ImportKind::Require,
                                    }));
                                }
                            }
                        }

                        // Destructured require: const { readFile, writeFile: wf } = require("fs")
                        if let Pat::Object(_) = &declarator.name {
                            if let Some(first_arg) = call.args.first() {
                                if let Expr::Lit(Lit::Str(s)) = first_arg.expr.as_ref() {
                                    let module = s.value.to_string();
                                    imports::extract_destructured_require(
                                        declarator, &module, &file, line, EXTRACTOR_NAME,
                                        &mut self.facts, &mut self.require_aliases,
                                    );
                                }
                            }
                        }
                    }
                }

                // Check for arrow/function expression assigned to variable
                if let Expr::Arrow(arrow) = init.as_ref() {
                    if let Pat::Ident(id) = &declarator.name {
                        let name = id.sym.to_string();
                        let qual_name = functions::build_qualified_name(
                            &self.function_stack, &self.class_stack, &name,
                        );
                        let line = self.line_of(declarator.span);
                        let func_id = ids::make_js_ts_function_id(&self.root, &self.file, &qual_name);
                        let synthetic_fn = Self::function_from_arrow(arrow);
                        let params = functions::params_from_fn(&synthetic_fn, "");

                        self.facts.push(Fact::Function(functions::create_function_fact(
                            func_id, file.clone(), line, EXTRACTOR_NAME.to_string(),
                            "javascript".to_string(), name.clone(), qual_name.clone(),
                            self.line_of(arrow.span), params,
                            self.class_stack.last().cloned(),
                        )));
                    }
                }

                // Handle function expression: const handler = function(params) { ... }
                if let Expr::Fn(fn_expr) = init.as_ref() {
                    if let Pat::Ident(id) = &declarator.name {
                        let name = id.sym.to_string();
                        let qual_name = functions::build_qualified_name(
                            &self.function_stack, &self.class_stack, &name,
                        );
                        let line = self.line_of(declarator.span);
                        let func_id = ids::make_js_ts_function_id(&self.root, &self.file, &qual_name);
                        let params = functions::params_from_fn(&fn_expr.function, "");

                        self.facts.push(Fact::Function(functions::create_function_fact(
                            func_id, file.clone(), line, EXTRACTOR_NAME.to_string(),
                            "javascript".to_string(), name.clone(), qual_name.clone(),
                            self.line_of(fn_expr.function.span), params,
                            self.class_stack.last().cloned(),
                        )));
                    }
                }

                // Simple assignment: const x = expr -> AssignFact
                if let Pat::Ident(id) = &declarator.name {
                    if let Some(init_expr) = &declarator.init {
                        let value_str = Self::expr_to_string_for_assign(init_expr);
                        if !value_str.is_empty() && value_str != "<call>" {
                            let line = self.line_of(declarator.span);
                            let assign_id = format!(
                                "assign:{}:{}:{}",
                                file, line, id.sym
                            );
                            self.facts.push(Fact::Assign(AssignFact {
                                base: FactBase {
                                    id: assign_id,
                                    file: file.clone(),
                                    line,
                                    extractor: EXTRACTOR_NAME.to_string(),
                                },
                                function_id: self.current_caller_id(),
                                target: id.sym.to_string(),
                                value: value_str,
                                snippet: String::new(),
                            }));
                        }
                    }
                }
            }
        }
        n.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, n: &CallExpr) {
        let callee_str = calls::callee_to_string(&n.callee);
        let file = self.rel_path();
        let line = self.line_of(n.span);

        // Check for MCP registration first
        if mcp::is_mcp_registration(&callee_str) {
            // MCP registration: server.tool("name", handler)
            if let Some(second_arg) = n.args.get(1) {
                let tool_name = n.args.first()
                    .and_then(|a| match a.expr.as_ref() {
                        Expr::Lit(Lit::Str(s)) => Some(s.value.to_string()),
                        Expr::Ident(id) => Some(id.sym.to_string()),
                        _ => None,
                    })
                    .unwrap_or_else(|| "<anonymous>".to_string());

                match second_arg.expr.as_ref() {
                    Expr::Arrow(arrow) => {
                        // Inline arrow handler
                        let handler_name = format!("{tool_name}_handler");
                        let qual_name = functions::build_qualified_name(
                            &self.function_stack, &self.class_stack, &handler_name,
                        );
                        let handler_func_id =
                            ids::make_js_ts_function_id(&self.root, &self.file, &qual_name);
                        let synthetic_fn = Self::function_from_arrow(arrow);
                        let params = functions::params_from_fn(&synthetic_fn, "");

                        // Create FunctionFact for handler
                        self.facts.push(Fact::Function(functions::create_function_fact(
                            handler_func_id.clone(),
                            file.clone(),
                            line,
                            EXTRACTOR_NAME.to_string(),
                            "javascript".to_string(),
                            handler_name,
                            qual_name,
                            self.line_of(arrow.span),
                            params,
                            self.class_stack.last().cloned(),
                        )));

                        // Create EntryPointFact + SourceFacts
                        mcp::process_inline_arrow_handler(
                            &mut self.facts,
                            handler_func_id.clone(),
                            tool_name,
                            &callee_str,
                            &file,
                            line,
                            EXTRACTOR_NAME,
                            arrow,
                            "",
                        );

                        // Walk arrow body with handler context
                        let prev_handler = self.current_mcp_handler_id.take();
                        self.current_mcp_handler_id = Some(handler_func_id);
                        n.visit_children_with(self);
                        self.current_mcp_handler_id = prev_handler;
                        return;
                    }

                    Expr::Ident(id) => {
                        // Named handler reference
                        let handler_name = id.sym.to_string();
                        mcp::process_named_handler(
                            &mut self.named_handlers,
                            &handler_name,
                            &tool_name,
                            &callee_str,
                            &file,
                            line,
                            EXTRACTOR_NAME,
                            &mut self.facts,
                        );
                    }

                    _ => {}
                }
            }
            n.visit_children_with(self);
            return;
        }

        // Regular call: create CallFact
        let (normalized_callee, import_alias) = calls::resolve_callee(
            &callee_str, &self.import_aliases, &self.require_aliases,
        );
        let caller = self.current_caller_id();
        let args = calls::extract_call_args(n);
        let call_id = format!("call:{file}:{line}:0");

        self.facts.push(Fact::Call(CallFact {
            base: FactBase {
                id: call_id.clone(),
                file: file.clone(),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            caller,
            callee: callee_str,
            normalized_callee: Some(normalized_callee.clone()),
            column: None,
            end_line: None,
            snippet: String::new(),
            args,
            kwargs: BTreeMap::new(),
            resolution: import_alias.map(|alias| crate::model::CallResolution {
                import_alias: Some(alias),
                confidence: crate::model::Confidence::High,
            }),
        }));

        // Check sinks
        sinks::check_sink(&normalized_callee, &call_id, line, &file, EXTRACTOR_NAME, &mut self.facts);

        n.visit_children_with(self);
    }

    fn visit_class_method(&mut self, n: &ClassMethod) {
        let name = match &n.key {
            PropName::Ident(id) => id.sym.to_string(),
            _ => "<method>".to_string(),
        };
        let qual_name = functions::build_qualified_name(
            &self.function_stack, &self.class_stack, &name,
        );
        self.function_stack.push(qual_name.clone());

        let file = self.rel_path();
        let line = self.line_of(n.function.span);
        let func_id = ids::make_js_ts_function_id(&self.root, &self.file, &qual_name);
        let params = functions::params_from_fn(&n.function, "");

        self.facts.push(Fact::Function(functions::create_function_fact(
            func_id, file, line, EXTRACTOR_NAME.to_string(),
            "javascript".to_string(), name, qual_name,
            self.line_of(n.function.span), params,
            self.class_stack.last().cloned(),
        )));

        n.visit_children_with(self);
        self.function_stack.pop();
    }
}
