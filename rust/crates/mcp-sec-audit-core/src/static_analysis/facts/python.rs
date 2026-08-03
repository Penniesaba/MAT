use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use rustpython_parser::{Parse, ast};

use crate::model::{
    AssignFact, CallArg, CallFact, CallKwarg, CallResolution, Confidence, EntryPointEvidence,
    EntryPointFact, EntryPointKind, Fact, FactBase, FunctionFact, ImportFact, ImportKind,
    ParamInfo, Severity, SinkFact, SourceFact,
};

use super::{
    ExtractionDiagnostic, PythonExtractionResult, display_path, make_assign_id, make_call_id,
    make_entrypoint_id, make_function_id, make_import_id, make_sink_id, make_source_id,
};

const EXTRACTOR_NAME: &str = "rust_python_ast_phase7";
const MCP_DECORATOR_PATTERNS: &[&str] = &[
    "mcp.tool",
    "mcp.resource",
    "mcp.prompt",
    "server.tool",
    "server.resource",
    "server.prompt",
    "mcp_tools",
    "mcp_tool",
    "server_tools",
];

pub fn extract_python_facts(root: &Path, file: &Path, source: &str) -> PythonExtractionResult {
    let mut extractor = PythonFactExtractor::new(root, file, source);
    extractor.extract()
}

struct PythonFactExtractor<'a> {
    root: PathBuf,
    file: PathBuf,
    source: &'a str,
    facts: Vec<Fact>,
    diagnostics: Vec<ExtractionDiagnostic>,
    import_aliases: BTreeMap<String, String>,
    assignment_aliases: BTreeMap<String, String>,
    scope: Vec<String>,
    class_stack: Vec<String>,
}

impl<'a> PythonFactExtractor<'a> {
    fn new(root: &Path, file: &Path, source: &'a str) -> Self {
        Self {
            root: root.to_path_buf(),
            file: file.to_path_buf(),
            source,
            facts: Vec::new(),
            diagnostics: Vec::new(),
            import_aliases: BTreeMap::new(),
            assignment_aliases: BTreeMap::new(),
            scope: Vec::new(),
            class_stack: Vec::new(),
        }
    }

    fn extract(&mut self) -> PythonExtractionResult {
        let path = display_path(&self.file);
        let suite = match ast::Suite::parse(self.source, &path) {
            Ok(suite) => suite,
            Err(err) => {
                self.diagnostics.push(ExtractionDiagnostic {
                    file: path,
                    line: 1,
                    kind: "syntax_error".to_string(),
                    message: err.to_string(),
                });
                return PythonExtractionResult {
                    facts: Vec::new(),
                    diagnostics: std::mem::take(&mut self.diagnostics),
                };
            }
        };

        self.visit_suite(&suite);
        self.facts.sort_by_key(fact_sort_key);

        PythonExtractionResult {
            facts: std::mem::take(&mut self.facts),
            diagnostics: std::mem::take(&mut self.diagnostics),
        }
    }

    fn visit_suite(&mut self, suite: &[ast::Stmt]) {
        for stmt in suite {
            self.visit_stmt(stmt);
        }
    }

    fn visit_stmt(&mut self, stmt: &ast::Stmt) {
        match stmt {
            ast::Stmt::Import(import) => self.visit_import(import),
            ast::Stmt::ImportFrom(import) => self.visit_import_from(import),
            ast::Stmt::FunctionDef(function) => self.visit_function_def(
                function.name.as_str(),
                &function.args,
                &function.body,
                &function.decorator_list,
                function.range.start().to_u32(),
                function.range.end().to_u32(),
            ),
            ast::Stmt::AsyncFunctionDef(function) => self.visit_function_def(
                function.name.as_str(),
                &function.args,
                &function.body,
                &function.decorator_list,
                function.range.start().to_u32(),
                function.range.end().to_u32(),
            ),
            ast::Stmt::ClassDef(class_def) => {
                let name = class_def.name.to_string();
                self.class_stack.push(name.clone());
                self.scope.push(name);
                self.visit_suite(&class_def.body);
                self.scope.pop();
                self.class_stack.pop();
            }
            ast::Stmt::Assign(assign) => {
                self.visit_assign_stmt(assign);
            }
            ast::Stmt::AnnAssign(assign) => {
                self.visit_ann_assign_stmt(assign);
            }
            ast::Stmt::AugAssign(assign) => {
                self.visit_expr(&assign.target);
                self.visit_expr(&assign.value);
            }
            ast::Stmt::Expr(expr_stmt) => self.visit_expr(&expr_stmt.value),
            ast::Stmt::Return(return_stmt) => {
                if let Some(value) = &return_stmt.value {
                    self.visit_expr(value);
                }
            }
            _ => self.visit_child_statements(stmt),
        }
    }

    fn visit_child_statements(&mut self, stmt: &ast::Stmt) {
        match stmt {
            ast::Stmt::For(item) => {
                self.visit_expr(&item.target);
                self.visit_expr(&item.iter);
                self.visit_suite(&item.body);
                self.visit_suite(&item.orelse);
            }
            ast::Stmt::AsyncFor(item) => {
                self.visit_expr(&item.target);
                self.visit_expr(&item.iter);
                self.visit_suite(&item.body);
                self.visit_suite(&item.orelse);
            }
            ast::Stmt::While(item) => {
                self.visit_expr(&item.test);
                self.visit_suite(&item.body);
                self.visit_suite(&item.orelse);
            }
            ast::Stmt::If(item) => {
                self.visit_expr(&item.test);
                self.visit_suite(&item.body);
                self.visit_suite(&item.orelse);
            }
            ast::Stmt::With(item) => {
                for with_item in &item.items {
                    self.visit_expr(&with_item.context_expr);
                    if let Some(optional_vars) = &with_item.optional_vars {
                        self.visit_expr(optional_vars);
                    }
                }
                self.visit_suite(&item.body);
            }
            ast::Stmt::AsyncWith(item) => {
                for with_item in &item.items {
                    self.visit_expr(&with_item.context_expr);
                    if let Some(optional_vars) = &with_item.optional_vars {
                        self.visit_expr(optional_vars);
                    }
                }
                self.visit_suite(&item.body);
            }
            ast::Stmt::Try(item) => {
                self.visit_suite(&item.body);
                for handler in &item.handlers {
                    match handler {
                        ast::ExceptHandler::ExceptHandler(handler) => {
                            self.visit_suite(&handler.body)
                        }
                    }
                }
                self.visit_suite(&item.orelse);
                self.visit_suite(&item.finalbody);
            }
            ast::Stmt::TryStar(item) => {
                self.visit_suite(&item.body);
                for handler in &item.handlers {
                    match handler {
                        ast::ExceptHandler::ExceptHandler(handler) => {
                            self.visit_suite(&handler.body)
                        }
                    }
                }
                self.visit_suite(&item.orelse);
                self.visit_suite(&item.finalbody);
            }
            ast::Stmt::Match(item) => {
                self.visit_expr(&item.subject);
                for case in &item.cases {
                    if let Some(guard) = &case.guard {
                        self.visit_expr(guard);
                    }
                    self.visit_suite(&case.body);
                }
            }
            _ => {}
        }
    }

    fn visit_import(&mut self, import: &ast::StmtImport) {
        let (line, _) = line_col_for_offset(self.source, import.range.start().to_u32());
        for alias in &import.names {
            let module = alias.name.to_string();
            let alias_name = alias.asname.as_ref().map(|item| item.to_string());
            if let Some(alias_name) = &alias_name {
                self.import_aliases
                    .insert(alias_name.clone(), module.clone());
            } else {
                let root_name = module.split('.').next().unwrap_or(&module).to_string();
                self.import_aliases.insert(root_name, module.clone());
            }
            self.facts.push(Fact::Import(ImportFact {
                base: FactBase {
                    id: make_import_id(&self.root, &self.file, line, &module),
                    file: display_path(&self.file),
                    line,
                    extractor: EXTRACTOR_NAME.to_string(),
                },
                language: "python".to_string(),
                module,
                imported_name: None,
                alias: alias_name.clone(),
                kind: if alias_name.is_some() {
                    ImportKind::ImportAs
                } else {
                    ImportKind::Import
                },
            }));
        }
    }

    fn visit_import_from(&mut self, import: &ast::StmtImportFrom) {
        let (line, _) = line_col_for_offset(self.source, import.range.start().to_u32());
        let module = import
            .module
            .as_ref()
            .map(|item| item.to_string())
            .unwrap_or_default();
        for alias in &import.names {
            let imported_name = alias.name.to_string();
            let alias_name = alias.asname.as_ref().map(|item| item.to_string());
            let normalized = if module.is_empty() {
                imported_name.clone()
            } else {
                format!("{module}.{imported_name}")
            };
            self.import_aliases.insert(
                alias_name.clone().unwrap_or_else(|| imported_name.clone()),
                normalized,
            );
            self.facts.push(Fact::Import(ImportFact {
                base: FactBase {
                    id: make_import_id(&self.root, &self.file, line, &imported_name),
                    file: display_path(&self.file),
                    line,
                    extractor: EXTRACTOR_NAME.to_string(),
                },
                language: "python".to_string(),
                module: module.clone(),
                imported_name: Some(imported_name),
                alias: alias_name.clone(),
                kind: if alias_name.is_some() {
                    ImportKind::FromImportAs
                } else {
                    ImportKind::FromImport
                },
            }));
        }
    }

    fn visit_expr(&mut self, expr: &ast::Expr) {
        match expr {
            ast::Expr::Call(call) => {
                self.visit_call_expr(call);
                self.visit_expr(&call.func);
                for arg in &call.args {
                    self.visit_expr(arg);
                }
                for keyword in &call.keywords {
                    self.visit_expr(&keyword.value);
                }
            }
            ast::Expr::Attribute(attr) => self.visit_expr(&attr.value),
            ast::Expr::Subscript(subscript) => {
                self.visit_expr(&subscript.value);
                self.visit_expr(&subscript.slice);
            }
            ast::Expr::BoolOp(bool_op) => {
                for value in &bool_op.values {
                    self.visit_expr(value);
                }
            }
            ast::Expr::BinOp(bin_op) => {
                self.visit_expr(&bin_op.left);
                self.visit_expr(&bin_op.right);
            }
            ast::Expr::UnaryOp(unary) => self.visit_expr(&unary.operand),
            ast::Expr::Compare(compare) => {
                self.visit_expr(&compare.left);
                for comparator in &compare.comparators {
                    self.visit_expr(comparator);
                }
            }
            ast::Expr::IfExp(if_exp) => {
                self.visit_expr(&if_exp.test);
                self.visit_expr(&if_exp.body);
                self.visit_expr(&if_exp.orelse);
            }
            ast::Expr::List(list) => {
                for item in &list.elts {
                    self.visit_expr(item);
                }
            }
            ast::Expr::Tuple(tuple) => {
                for item in &tuple.elts {
                    self.visit_expr(item);
                }
            }
            ast::Expr::Set(set) => {
                for item in &set.elts {
                    self.visit_expr(item);
                }
            }
            ast::Expr::Dict(dict) => {
                for key in dict.keys.iter().flatten() {
                    self.visit_expr(key);
                }
                for value in &dict.values {
                    self.visit_expr(value);
                }
            }
            ast::Expr::ListComp(comp) => {
                self.visit_expr(&comp.elt);
                for generator in &comp.generators {
                    self.visit_expr(&generator.target);
                    self.visit_expr(&generator.iter);
                    for condition in &generator.ifs {
                        self.visit_expr(condition);
                    }
                }
            }
            ast::Expr::SetComp(comp) => {
                self.visit_expr(&comp.elt);
                for generator in &comp.generators {
                    self.visit_expr(&generator.target);
                    self.visit_expr(&generator.iter);
                    for condition in &generator.ifs {
                        self.visit_expr(condition);
                    }
                }
            }
            ast::Expr::DictComp(comp) => {
                self.visit_expr(&comp.key);
                self.visit_expr(&comp.value);
                for generator in &comp.generators {
                    self.visit_expr(&generator.target);
                    self.visit_expr(&generator.iter);
                    for condition in &generator.ifs {
                        self.visit_expr(condition);
                    }
                }
            }
            ast::Expr::GeneratorExp(comp) => {
                self.visit_expr(&comp.elt);
                for generator in &comp.generators {
                    self.visit_expr(&generator.target);
                    self.visit_expr(&generator.iter);
                    for condition in &generator.ifs {
                        self.visit_expr(condition);
                    }
                }
            }
            ast::Expr::Await(await_expr) => self.visit_expr(&await_expr.value),
            ast::Expr::Yield(yield_expr) => {
                if let Some(value) = &yield_expr.value {
                    self.visit_expr(value);
                }
            }
            ast::Expr::YieldFrom(yield_from) => self.visit_expr(&yield_from.value),
            ast::Expr::Lambda(lambda) => self.visit_expr(&lambda.body),
            _ => {}
        }
    }

    fn visit_call_expr(&mut self, call: &ast::ExprCall) {
        let (line, column) = line_col_for_offset(self.source, call.range.start().to_u32());
        let (end_line, _) = line_col_for_offset(self.source, call.range.end().to_u32());
        let callee = expr_to_string(&call.func);
        let (normalized_callee, import_alias) = self.normalize_callee(&callee);
        let args = call
            .args
            .iter()
            .enumerate()
            .map(|(index, arg)| CallArg {
                index: index as u32,
                expr: expr_to_string(arg),
                kind: "positional".to_string(),
            })
            .collect::<Vec<_>>();
        let kwargs = call
            .keywords
            .iter()
            .map(|keyword| {
                let key = keyword
                    .arg
                    .as_ref()
                    .map(|item| item.to_string())
                    .unwrap_or_else(|| "**".to_string());
                (
                    key,
                    CallKwarg {
                        expr: expr_to_string(&keyword.value),
                        value: serde_json::Value::Null,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        let call_id = make_call_id(&self.root, &self.file, line, column);
        let call_fact = CallFact {
            base: FactBase {
                id: call_id,
                file: display_path(&self.file),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            caller: self.caller_function_id().unwrap_or_default(),
            callee: callee.clone(),
            normalized_callee: Some(normalized_callee),
            column: Some(column),
            end_line: Some(end_line),
            snippet: snippet_for_range(
                self.source,
                call.range.start().to_u32(),
                call.range.end().to_u32(),
            ),
            args,
            kwargs,
            resolution: import_alias.map(|alias| CallResolution {
                import_alias: Some(alias),
                confidence: Confidence::High,
            }),
        };
        self.emit_sink_for_call(&call_fact);
        self.facts.push(Fact::Call(call_fact));
    }

    fn emit_sink_for_call(&mut self, call: &CallFact) {
        let sink_name = canonical_sink_name(
            call.normalized_callee
                .as_deref()
                .unwrap_or(call.callee.as_str()),
        );

        let Some(classification) = classify_sink(&sink_name, call) else {
            return;
        };

        let mut conditions = BTreeMap::new();
        conditions.insert(
            "callee".to_string(),
            serde_json::Value::String(call.callee.clone()),
        );
        conditions.insert(
            "normalized_callee".to_string(),
            serde_json::Value::String(sink_name.clone()),
        );
        conditions.insert(
            "snippet".to_string(),
            serde_json::Value::String(call.snippet.clone()),
        );

        self.facts.push(Fact::Sink(SinkFact {
            base: FactBase {
                id: make_sink_id(
                    classification.category,
                    &self.root,
                    &self.file,
                    call.base.line,
                ),
                file: call.base.file.clone(),
                line: call.base.line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            call_id: call.base.id.clone(),
            category: classification.category.to_string(),
            rule_id: format!("python.{}", classification.category),
            sink_name,
            severity_base: classification.severity,
            reason: classification.reason.to_string(),
            conditions,
            confidence: classification.confidence,
        }));
    }

    fn visit_assign_stmt(&mut self, assign: &ast::StmtAssign) {
        self.visit_assignment_alias(&assign.targets, &assign.value);
        for target in &assign.targets {
            self.emit_assign_fact(
                target,
                &assign.value,
                assign.range.start().to_u32(),
                assign.range.end().to_u32(),
            );
        }
        self.visit_expr(&assign.value);
        for target in &assign.targets {
            self.visit_expr(target);
        }
    }

    fn visit_ann_assign_stmt(&mut self, assign: &ast::StmtAnnAssign) {
        if let Some(value) = &assign.value {
            self.visit_assignment_alias(std::slice::from_ref(&assign.target), value);
            self.emit_assign_fact(
                &assign.target,
                value,
                assign.range.start().to_u32(),
                assign.range.end().to_u32(),
            );
            self.visit_expr(value);
        }
        self.visit_expr(&assign.target);
    }

    fn emit_assign_fact(&mut self, target: &ast::Expr, value: &ast::Expr, start: u32, end: u32) {
        if matches!(target, ast::Expr::Tuple(_) | ast::Expr::List(_)) {
            return;
        }

        let target_text = expr_to_string(target);
        if target_text.is_empty() {
            return;
        }

        let (line, _) = line_col_for_offset(self.source, start);
        self.facts.push(Fact::Assign(AssignFact {
            base: FactBase {
                id: make_assign_id(&self.root, &self.file, line, &target_text),
                file: display_path(&self.file),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            function_id: self.caller_function_id().unwrap_or_default(),
            target: target_text,
            value: expr_to_string(value),
            snippet: snippet_for_range(self.source, start, end),
        }));
    }

    fn visit_assignment_alias(&mut self, targets: &[ast::Expr], value: &ast::Expr) {
        if targets.len() != 1 {
            return;
        }
        let ast::Expr::Name(target) = &targets[0] else {
            return;
        };
        let value_text = expr_to_string(value);
        let (normalized, _) = self.normalize_callee(&value_text);
        if normalized != value_text || looks_like_callable_reference(&value_text) {
            self.assignment_aliases
                .insert(target.id.to_string(), normalized);
        }
    }

    fn caller_function_id(&self) -> Option<String> {
        if self.scope.is_empty() {
            None
        } else {
            Some(make_function_id(
                "python",
                &self.root,
                &self.file,
                &self.scope.join("."),
            ))
        }
    }

    fn normalize_callee(&self, callee: &str) -> (String, Option<String>) {
        if let Some(target) = self.assignment_aliases.get(callee) {
            return (target.clone(), Some(callee.to_string()));
        }
        self.resolve_alias(callee)
    }

    fn resolve_alias(&self, callee: &str) -> (String, Option<String>) {
        if let Some(target) = self.import_aliases.get(callee) {
            return (target.clone(), Some(callee.to_string()));
        }
        if let Some((head, tail)) = callee.split_once('.') {
            if let Some(target) = self.import_aliases.get(head) {
                return (format!("{target}.{tail}"), Some(head.to_string()));
            }
        }
        (callee.to_string(), None)
    }

    fn visit_function_def(
        &mut self,
        name: &str,
        args: &ast::Arguments,
        body: &[ast::Stmt],
        decorators: &[ast::Expr],
        start: u32,
        end: u32,
    ) {
        self.scope.push(name.to_string());
        let qualified_name = self.scope.join(".");
        let (line, _) = line_col_for_offset(self.source, start);
        let (end_line, _) = line_col_for_offset(self.source, end);
        let function_id = make_function_id("python", &self.root, &self.file, &qualified_name);
        let params = params_from_arguments(args);
        let decorator_texts = decorators.iter().map(expr_to_string).collect::<Vec<_>>();
        let enclosing_class = self.class_stack.last().cloned();

        self.facts.push(Fact::Function(FunctionFact {
            base: FactBase {
                id: function_id,
                file: display_path(&self.file),
                line,
                extractor: EXTRACTOR_NAME.to_string(),
            },
            language: "python".to_string(),
            name: name.to_string(),
            qualified_name: qualified_name.clone(),
            end_line,
            params: params.clone(),
            decorators: decorator_texts.clone(),
            docstring: docstring_from_body(body),
            enclosing_class,
        }));

        if let Some((kind, evidence_text)) = decorator_texts.iter().find_map(|decorator| {
            classify_mcp_decorator(decorator).map(|kind| (kind, decorator.clone()))
        }) {
            let entry_id = make_entrypoint_id(&self.root, &self.file, &qualified_name);
            let param_names = params
                .iter()
                .map(|param| param.name.clone())
                .filter(|name| name != "self" && name != "cls")
                .collect::<Vec<_>>();
            let function_id = make_function_id("python", &self.root, &self.file, &qualified_name);

            self.facts.push(Fact::Entrypoint(EntryPointFact {
                base: FactBase {
                    id: entry_id,
                    file: display_path(&self.file),
                    line,
                    extractor: EXTRACTOR_NAME.to_string(),
                },
                kind,
                name: name.to_string(),
                function_id: function_id.clone(),
                evidence: Some(EntryPointEvidence {
                    kind: "decorator".to_string(),
                    text: evidence_text,
                }),
                params: param_names.clone(),
                confidence: Confidence::High,
            }));

            for param in param_names {
                self.facts.push(Fact::Source(SourceFact {
                    base: FactBase {
                        id: make_source_id(&self.root, &self.file, &qualified_name, &param),
                        file: display_path(&self.file),
                        line,
                        extractor: EXTRACTOR_NAME.to_string(),
                    },
                    kind: "mcp_tool_parameter".to_string(),
                    function_id: function_id.clone(),
                    name: param,
                    confidence: Confidence::High,
                }));
            }
        }

        self.visit_suite(body);
        self.scope.pop();
    }
}

#[derive(Debug, Clone)]
struct SinkClassification {
    category: &'static str,
    severity: Severity,
    reason: &'static str,
    confidence: Confidence,
}

fn canonical_sink_name(callee: &str) -> String {
    if let Some(prefix) = callee.strip_suffix(".write_text") {
        if prefix == "Path" || prefix.ends_with(".Path") || prefix.ends_with("(...)") {
            return "Path.write_text".to_string();
        }
    }
    if let Some(prefix) = callee.strip_suffix(".write_bytes") {
        if prefix == "Path" || prefix.ends_with(".Path") || prefix.ends_with("(...)") {
            return "Path.write_bytes".to_string();
        }
    }
    callee.to_string()
}

fn classify_sink(callee: &str, call: &CallFact) -> Option<SinkClassification> {
    match callee {
        "subprocess.run" | "subprocess.Popen" | "os.system" | "os.popen" => {
            Some(SinkClassification {
                category: "command_execution",
                severity: Severity::High,
                reason: "Python command execution call can execute attacker-controlled commands",
                confidence: Confidence::High,
            })
        }
        "Path.write_text" | "Path.write_bytes" => Some(SinkClassification {
            category: "file_write",
            severity: Severity::Medium,
            reason: "Python file write call can modify filesystem contents",
            confidence: Confidence::High,
        }),
        "open" if open_call_writes(call) => Some(SinkClassification {
            category: "file_write",
            severity: Severity::Medium,
            reason: "Python open call uses a write-capable file mode",
            confidence: Confidence::High,
        }),
        "eval" | "exec" => Some(SinkClassification {
            category: "dynamic_execution",
            severity: Severity::Critical,
            reason: "Python dynamic execution call can execute attacker-controlled code",
            confidence: Confidence::High,
        }),
        "requests.get"
        | "requests.post"
        | "requests.request"
        | "httpx.get"
        | "httpx.post"
        | "httpx.request"
        | "urllib.request.urlopen" => Some(SinkClassification {
            category: "network_request",
            severity: Severity::Medium,
            reason: "Python network request call can reach attacker-controlled URLs",
            confidence: Confidence::Medium,
        }),
        "importlib.import_module" | "__import__" => Some(SinkClassification {
            category: "dynamic_import",
            severity: Severity::Medium,
            reason: "Python dynamic import call can load attacker-controlled modules",
            confidence: Confidence::Medium,
        }),
        _ => None,
    }
}

fn open_call_writes(call: &CallFact) -> bool {
    if let Some(mode) = call.kwargs.get("mode") {
        return file_mode_writes(&mode.expr);
    }
    call.args
        .get(1)
        .map(|arg| file_mode_writes(&arg.expr))
        .unwrap_or(false)
}

fn file_mode_writes(mode: &str) -> bool {
    let trimmed = mode.trim_matches(|ch| ch == '\'' || ch == '"');
    trimmed.contains('w') || trimmed.contains('a') || trimmed.contains('x') || trimmed.contains('+')
}

fn classify_mcp_decorator(decorator: &str) -> Option<EntryPointKind> {
    let normalized = decorator.trim_end_matches("()");
    if !MCP_DECORATOR_PATTERNS.iter().any(|pattern| {
        normalized == *pattern
            || normalized.starts_with(&format!("{pattern}."))
            || normalized.starts_with(&format!("{pattern}("))
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

fn line_col_for_offset(source: &str, offset: u32) -> (u32, u32) {
    let offset = offset as usize;
    let prefix = &source[..offset.min(source.len())];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() as u32 + 1;
    let column = prefix
        .rsplit('\n')
        .next()
        .map(|item| item.chars().count() as u32)
        .unwrap_or(0);
    (line, column)
}

fn snippet_for_range(source: &str, start: u32, end: u32) -> String {
    let start = start as usize;
    let end = end as usize;
    source
        .get(start.min(source.len())..end.min(source.len()))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn looks_like_callable_reference(value: &str) -> bool {
    value.contains('.')
        || value
            .chars()
            .all(|item| item == '_' || item.is_ascii_alphanumeric())
}

fn params_from_arguments(args: &ast::Arguments) -> Vec<ParamInfo> {
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
        annotation: arg.annotation.as_deref().map(expr_to_string),
        default: default.map(expr_to_string),
    }
}

fn docstring_from_body(body: &[ast::Stmt]) -> Option<String> {
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

fn expr_to_string(expr: &ast::Expr) -> String {
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::model::{
        AssignFact, CallFact, Confidence, EntryPointFact, EntryPointKind, Fact, FunctionFact,
        ImportFact, ImportKind, SinkFact, SourceFact,
    };

    use super::*;

    fn extract(source: &str) -> PythonExtractionResult {
        extract_python_facts(Path::new("/repo"), Path::new("/repo/server.py"), source)
    }

    fn import_facts(result: &PythonExtractionResult) -> Vec<&ImportFact> {
        result
            .facts
            .iter()
            .filter_map(|fact| match fact {
                Fact::Import(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn function_facts(result: &PythonExtractionResult) -> Vec<&FunctionFact> {
        result
            .facts
            .iter()
            .filter_map(|fact| match fact {
                Fact::Function(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn entrypoint_facts(result: &PythonExtractionResult) -> Vec<&EntryPointFact> {
        result
            .facts
            .iter()
            .filter_map(|fact| match fact {
                Fact::Entrypoint(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn source_facts(result: &PythonExtractionResult) -> Vec<&SourceFact> {
        result
            .facts
            .iter()
            .filter_map(|fact| match fact {
                Fact::Source(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn call_facts(result: &PythonExtractionResult) -> Vec<&CallFact> {
        result
            .facts
            .iter()
            .filter_map(|fact| match fact {
                Fact::Call(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn assign_facts(result: &PythonExtractionResult) -> Vec<&AssignFact> {
        result
            .facts
            .iter()
            .filter_map(|fact| match fact {
                Fact::Assign(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    fn sink_facts(result: &PythonExtractionResult) -> Vec<&SinkFact> {
        result
            .facts
            .iter()
            .filter_map(|fact| match fact {
                Fact::Sink(item) => Some(item),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn syntax_errors_return_diagnostic_without_facts() {
        let result = extract("def broken(:\n    pass\n");

        assert!(result.facts.is_empty());
        assert_eq!(result.diagnostics.len(), 1);
        let diagnostic = &result.diagnostics[0];
        assert_eq!(diagnostic.file, "/repo/server.py");
        assert_eq!(diagnostic.kind, "syntax_error");
        assert!(diagnostic.line >= 1);
        assert!(!diagnostic.message.is_empty());
    }

    #[test]
    fn extracts_sink_facts_from_dangerous_python_calls() {
        let result = extract(
            r#"
import importlib
import os
import subprocess as sp
from pathlib import Path
import requests

@mcp.tool()
def run_command(command: str, url: str, path: str):
    sp.run(command, shell=True)
    subprocess.Popen(command)
    os.system(command)
    open(path, "w").write(command)
    Path(path).write_text(command)
    requests.get(url)
    eval(command)
    importlib.import_module(command)
"#,
        );

        assert!(result.diagnostics.is_empty());
        let sinks = sink_facts(&result);
        let sink_names = sinks
            .iter()
            .map(|item| item.sink_name.as_str())
            .collect::<Vec<_>>();

        assert!(sink_names.contains(&"subprocess.run"));
        assert!(sink_names.contains(&"subprocess.Popen"));
        assert!(sink_names.contains(&"os.system"));
        assert!(sink_names.contains(&"open"));
        assert!(sink_names.contains(&"Path.write_text"));
        assert!(sink_names.contains(&"requests.get"));
        assert!(sink_names.contains(&"eval"));
        assert!(sink_names.contains(&"importlib.import_module"));

        let command_sink = sinks
            .iter()
            .find(|item| item.sink_name == "subprocess.run")
            .expect("subprocess.run sink");
        assert_eq!(command_sink.category, "command_execution");
        assert_eq!(command_sink.rule_id, "python.command_execution");
        assert!(command_sink.call_id.starts_with("call:server.py:"));
        assert!(command_sink.reason.contains("command execution"));
        assert_eq!(command_sink.confidence, Confidence::High);
    }

    #[test]
    fn prints_phase7_task8_intermediate_facts() {
        let result = extract(
            r#"
import os
import subprocess as sp

@mcp.tool()
def run_command(command: str):
    sp.run(command, shell=True)
    os.system(command)
"#,
        );

        assert!(result.diagnostics.is_empty());
        println!(
            "{}",
            serde_json::to_string_pretty(&result.facts).expect("serialize intermediate facts")
        );
        assert!(!call_facts(&result).is_empty());
        assert!(!sink_facts(&result).is_empty());
    }

    #[test]
    fn extracts_assign_facts_and_assignment_aliases() {
        let result = extract(
            r#"
import subprocess as sp
from typing import Callable

@mcp.tool()
def run_command(command: str):
    runner: Callable = sp.run
    command_text = command.strip()
    output = runner(command_text, shell=True)
    return output
"#,
        );

        assert!(result.diagnostics.is_empty());
        let assigns = assign_facts(&result);
        assert_eq!(assigns.len(), 3);

        let runner_assign = assigns
            .iter()
            .find(|item| item.target == "runner")
            .expect("runner assignment fact");
        assert_eq!(runner_assign.value, "sp.run");
        assert_eq!(runner_assign.function_id, "python:server.py:run_command");
        assert!(runner_assign.snippet.contains("runner: Callable = sp.run"));
        assert!(runner_assign.base.id.starts_with("assign:server.py:"));

        let command_assign = assigns
            .iter()
            .find(|item| item.target == "command_text")
            .expect("command_text assignment fact");
        assert_eq!(command_assign.value, "command.strip()");

        let calls = call_facts(&result);
        let assignment_alias_call = calls
            .iter()
            .find(|item| item.callee == "runner")
            .expect("assignment alias call");
        assert_eq!(
            assignment_alias_call.normalized_callee.as_deref(),
            Some("subprocess.run")
        );
    }

    #[test]
    fn prints_phase7_task7_intermediate_facts() {
        let result = extract(
            r#"
import subprocess as sp

@mcp.tool()
def run_command(command: str):
    runner = sp.run
    command_text = command.strip()
    return runner(command_text, shell=True)
"#,
        );

        assert!(result.diagnostics.is_empty());
        println!(
            "{}",
            serde_json::to_string_pretty(&result.facts).expect("serialize intermediate facts")
        );
        assert!(!assign_facts(&result).is_empty());
        assert!(!call_facts(&result).is_empty());
    }

    #[test]
    fn extracts_calls_with_args_kwargs_and_alias_resolution() {
        let result = extract(
            r#"
import subprocess as sp
from subprocess import run

@mcp.tool()
def run_command(command: str, timeout=30):
    direct = subprocess.run(command)
    aliased = sp.run(command, shell=True, timeout=timeout)
    imported = run(command)
    runner = sp.run
    return runner(command, shell=True)
"#,
        );

        assert!(result.diagnostics.is_empty());
        let calls = call_facts(&result);
        let direct_call = calls
            .iter()
            .find(|item| item.callee == "subprocess.run")
            .expect("direct subprocess.run call");
        assert_eq!(
            direct_call.normalized_callee.as_deref(),
            Some("subprocess.run")
        );
        assert!(direct_call.resolution.is_none());

        let from_import_call = calls
            .iter()
            .find(|item| item.callee == "run")
            .expect("from import run call");
        assert_eq!(
            from_import_call.normalized_callee.as_deref(),
            Some("subprocess.run")
        );
        assert_eq!(
            from_import_call
                .resolution
                .as_ref()
                .and_then(|item| item.import_alias.as_deref()),
            Some("run")
        );

        let normalized = calls
            .iter()
            .map(|item| {
                item.normalized_callee
                    .as_deref()
                    .unwrap_or(item.callee.as_str())
            })
            .collect::<Vec<_>>();

        assert!(normalized.contains(&"subprocess.run"));
        assert_eq!(
            normalized
                .iter()
                .filter(|callee| **callee == "subprocess.run")
                .count(),
            4
        );

        let shell_call = calls
            .iter()
            .find(|item| item.kwargs.contains_key("shell"))
            .expect("call with shell kwarg");
        assert_eq!(shell_call.callee, "sp.run");
        assert_eq!(
            shell_call.normalized_callee.as_deref(),
            Some("subprocess.run")
        );
        assert_eq!(shell_call.args[0].index, 0);
        assert_eq!(shell_call.args[0].expr, "command");
        assert_eq!(shell_call.kwargs["shell"].expr, "True");
        assert_eq!(shell_call.caller, "python:server.py:run_command");
        assert!(shell_call.column.is_some());
        assert!(shell_call.snippet.contains("sp.run"));
        assert_eq!(
            shell_call
                .resolution
                .as_ref()
                .and_then(|item| item.import_alias.as_deref()),
            Some("sp")
        );

        let assignment_alias_call = calls
            .iter()
            .find(|item| item.callee == "runner")
            .expect("assignment alias call");
        assert_eq!(
            assignment_alias_call.normalized_callee.as_deref(),
            Some("subprocess.run")
        );
        assert_eq!(
            assignment_alias_call
                .resolution
                .as_ref()
                .and_then(|item| item.import_alias.as_deref()),
            Some("runner")
        );
    }

    #[test]
    fn prints_phase7_task6_intermediate_facts() {
        let result = extract(
            r#"
import subprocess as sp
from subprocess import run

@mcp.tool()
def run_command(command: str, timeout=30):
    runner = sp.run
    direct = subprocess.run(command)
    aliased = sp.run(command, shell=True, timeout=timeout)
    imported = run(command)
    return runner(command, shell=True)
"#,
        );

        assert!(result.diagnostics.is_empty());
        println!(
            "{}",
            serde_json::to_string_pretty(&result.facts).expect("serialize intermediate facts")
        );
        assert!(!import_facts(&result).is_empty());
        assert!(!function_facts(&result).is_empty());
        assert!(!entrypoint_facts(&result).is_empty());
        assert!(!source_facts(&result).is_empty());
        assert!(!call_facts(&result).is_empty());
    }

    #[test]
    fn prints_phase7_task5_intermediate_facts() {
        let result = extract(
            r#"
@mcp.tool()
def run_command(command: str, timeout=30):
    return command
"#,
        );

        assert!(result.diagnostics.is_empty());
        println!(
            "{}",
            serde_json::to_string_pretty(&result.facts).expect("serialize intermediate facts")
        );
        assert_eq!(entrypoint_facts(&result).len(), 1);
        assert_eq!(source_facts(&result).len(), 2);
    }

    #[test]
    fn extracts_mcp_entrypoints_and_parameter_sources() {
        let result = extract(
            r#"
@mcp.tool()
def run_command(command: str, timeout=30):
    return command

@server.resource("file://{path}")
def read_resource(path):
    return path

@mcp.prompt
def build_prompt(topic):
    return topic

class Tools:
    @server.tool()
    def method_tool(self, value):
        return value
"#,
        );

        assert!(result.diagnostics.is_empty());
        let entries = entrypoint_facts(&result);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].name, "run_command");
        assert_eq!(entries[0].kind, EntryPointKind::McpTool);
        assert_eq!(entries[1].kind, EntryPointKind::McpResource);
        assert_eq!(entries[2].kind, EntryPointKind::McpPrompt);

        let sources = source_facts(&result);
        let names = sources
            .iter()
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"command"));
        assert!(names.contains(&"timeout"));
        assert!(names.contains(&"path"));
        assert!(names.contains(&"topic"));
        assert!(names.contains(&"value"));
        assert!(!names.contains(&"self"));
    }

    #[test]
    fn prints_phase7_task4_intermediate_facts() {
        let result = extract(
            r#"
import subprocess
from pathlib import Path

def top_level(command: str, timeout=30):
    """Run a command."""
    return command
"#,
        );

        assert!(result.diagnostics.is_empty());
        println!(
            "{}",
            serde_json::to_string_pretty(&result.facts).expect("serialize intermediate facts")
        );
        assert_eq!(import_facts(&result).len(), 2);
        assert_eq!(function_facts(&result).len(), 1);
    }

    #[test]
    fn extracts_import_facts_and_aliases() {
        let result = extract(
            r#"
import subprocess
import os as operating_system
from pathlib import Path
from subprocess import run as subprocess_run
"#,
        );

        assert!(result.diagnostics.is_empty());
        let imports = import_facts(&result);
        assert_eq!(imports.len(), 4);
        assert_eq!(imports[0].module, "subprocess");
        assert_eq!(imports[0].kind, ImportKind::Import);
        assert_eq!(imports[1].module, "os");
        assert_eq!(imports[1].alias.as_deref(), Some("operating_system"));
        assert_eq!(imports[1].kind, ImportKind::ImportAs);
        assert_eq!(imports[2].module, "pathlib");
        assert_eq!(imports[2].imported_name.as_deref(), Some("Path"));
        assert_eq!(imports[2].kind, ImportKind::FromImport);
        assert_eq!(imports[3].module, "subprocess");
        assert_eq!(imports[3].imported_name.as_deref(), Some("run"));
        assert_eq!(imports[3].alias.as_deref(), Some("subprocess_run"));
        assert_eq!(imports[3].kind, ImportKind::FromImportAs);
    }

    #[test]
    fn extracts_functions_async_methods_nested_and_docstrings() {
        let result = extract(
            r#"
def top_level(command: str, timeout=30):
    """Run a command."""
    return command

async def async_tool(path):
    return path

class Server:
    def method(self, value: int):
        def nested(inner):
            return inner
        return nested(value)
"#,
        );

        assert!(result.diagnostics.is_empty());
        let functions = function_facts(&result);
        let names = functions
            .iter()
            .map(|item| item.qualified_name.as_str())
            .collect::<Vec<_>>();

        assert!(names.contains(&"top_level"));
        assert!(names.contains(&"async_tool"));
        assert!(names.contains(&"Server.method"));
        assert!(names.contains(&"Server.method.nested"));

        let top = functions
            .iter()
            .find(|item| item.qualified_name == "top_level")
            .expect("top_level function");
        assert_eq!(top.params[0].name, "command");
        assert_eq!(top.params[0].annotation.as_deref(), Some("str"));
        assert_eq!(top.params[1].name, "timeout");
        assert_eq!(top.params[1].default.as_deref(), Some("30"));
        assert_eq!(top.docstring.as_deref(), Some("Run a command."));

        let method = functions
            .iter()
            .find(|item| item.qualified_name == "Server.method")
            .expect("method fact");
        assert_eq!(method.enclosing_class.as_deref(), Some("Server"));
    }
}
