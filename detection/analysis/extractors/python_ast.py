"""Python AST extractor for security fact extraction.

This module provides the `extract_python_facts` function that extracts security-relevant
facts from Python source code using the `ast` module.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import NamedTuple

from ..facts.ids import (
    make_call_id,
    make_entrypoint_id,
    make_function_id,
    make_import_id,
    make_sink_id,
    make_source_id,
    make_assign_id,
)
from ..facts.schema import (
    AssignFact,
    CallArg,
    CallFact,
    CallKwarg,
    CallResolution,
    Confidence,
    EntryPointEvidence,
    EntryPointFact,
    EntryPointKind,
    Fact,
    FunctionFact,
    ImportFact,
    ImportKind,
    ParamInfo,
    Severity,
    SinkFact,
    SourceFact,
)


# ----------------------------------------------------------------------
# Error types for graceful failure handling
# ----------------------------------------------------------------------


class ExtractionError(NamedTuple):
    """Non-fatal error encountered during extraction."""

    file: str
    line: int
    message: str
    exception_type: str


# ----------------------------------------------------------------------
# Sink detection rules
# ----------------------------------------------------------------------


class SinkRule(NamedTuple):
    """A rule for detecting sensitive function calls."""

    patterns: tuple[str, ...]
    category: str
    rule_id: str
    severity: Severity
    reason: str


# Initial minimal sink rules for RCE / file / network
_SINK_RULES: list[SinkRule] = [
    SinkRule(
        patterns=("subprocess.run", "subprocess.Popen", "subprocess.call",
                   "subprocess.exec", "subprocess.check_output"),
        category="rce",
        rule_id="rce_subprocess",
        severity=Severity.HIGH,
        reason="Executes external commands",
    ),
    SinkRule(
        patterns=("os.system", "os.popen", "os.exec", "os.spawn"),
        category="rce",
        rule_id="rce_os",
        severity=Severity.HIGH,
        reason="Executes external commands via os module",
    ),
    SinkRule(
        patterns=("eval", "exec", "compile"),
        category="rce",
        rule_id="rce_dynamic",
        severity=Severity.HIGH,
        reason="Dynamic code execution",
    ),
    SinkRule(
        patterns=("builtins.open", "io.open", "pathlib.Path.open", "__builtins__"),
        category="file",
        rule_id="file_access",
        severity=Severity.MEDIUM,
        reason="File system access",
    ),
    SinkRule(
        patterns=("requests.get", "requests.post", "requests.put", "requests.delete",
                   "requests.patch", "urllib.request", "urllib3", "http.client"),
        category="network",
        rule_id="network_access",
        severity=Severity.MEDIUM,
        reason="Network access",
    ),
    SinkRule(
        patterns=("socket.create_connection", "socket.connect"),
        category="network",
        rule_id="network_socket",
        severity=Severity.MEDIUM,
        reason="Socket connection",
    ),
]


# ----------------------------------------------------------------------
# MCP decorator detection patterns
# ----------------------------------------------------------------------


_MCP_DECORATOR_PATTERNS: tuple[str, ...] = (
    "mcp.tool",
    "mcp.resource",
    "mcp.prompt",
    "server.tool",
    "server.resource",
    "server.prompt",
    "mcp_tools",
    "mcp_tool",
    "server_tools",
)


def _is_mcp_decorator(decorator_name: str) -> bool:
    """Check if a decorator name matches MCP entry patterns.

    Uses proper boundary matching to avoid false positives:
    - Patterns with dots (mcp.tool) match exactly or as prefix with separator
    - Patterns with underscores (mcp_tools) match exactly or as prefix with separator
    - No bare word matches like 'tool' matching '@my_tool'
    """
    dec_lower = decorator_name.lower()

    for pattern in _MCP_DECORATOR_PATTERNS:
        pattern_lower = pattern.lower()
        if "." in pattern:
            # Dot-separated: match exact or as attribute access
            # e.g., "mcp.tool" matches "mcp.tool" or "something.mcp.tool"
            if dec_lower == pattern_lower or dec_lower.endswith(f".{pattern_lower}"):
                return True
        elif "_" in pattern or pattern.isalpha():
            # Underscore-separated or bare word: match at identifier boundary
            # e.g., "mcp_tool" matches "mcp_tool" but not "my_mcp_tool"
            if dec_lower == pattern_lower:
                return True
            # Check if decorator ends with _pattern (but not _pattern_xxx)
            if dec_lower.endswith(f"_{pattern_lower}") and not dec_lower[len(dec_lower) - len(pattern_lower) - 1].isalnum():
                return True
    return False


# ----------------------------------------------------------------------
# Extractor implementation
# ----------------------------------------------------------------------


class PythonFactExtractor(ast.NodeVisitor):
    """AST visitor that extracts security facts from Python source."""

    def __init__(self, root: Path, file: Path) -> None:
        self.root = root
        self.file = file
        self.facts: list[Fact] = []
        self.errors: list[ExtractionError] = []

        # Alias tracking for symbol resolution
        # Maps alias name -> resolved full name (e.g., 'subprocess.run' or 'os.system')
        self._import_aliases: dict[str, str] = {}
        # Maps alias name -> resolved name (for assignment aliasing)
        self._assignment_aliases: dict[str, str] = {}

        # Current context for qualified name building
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []

        # Entry points detected (function name -> fact)
        self._entry_points: dict[str, EntryPointFact] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, source: str) -> tuple[list[Fact], list[ExtractionError]]:
        """Parse and extract facts from Python source code.

        Args:
            source: The Python source code to analyze.

        Returns:
            A tuple of (facts, non_fatal_errors).
        """
        try:
            tree = ast.parse(source, filename=str(self.file))
        except SyntaxError as e:
            self.errors.append(ExtractionError(
                file=self._get_relative_path(),
                line=e.lineno or 0,
                message=f"SyntaxError: {e.msg}",
                exception_type="SyntaxError",
            ))
            return [], self.errors
        except Exception as e:  # noqa: BLE001
            # Catch other parse errors (e.g., encoding issues)
            self.errors.append(ExtractionError(
                file=self._get_relative_path(),
                line=0,
                message=f"Parse error: {str(e)}",
                exception_type=type(e).__name__,
            ))
            return [], self.errors

        # Extract imports first
        self._extract_imports(tree)

        # Extract definitions and calls using generic visit
        # with explicit context management for functions/classes
        self.generic_visit(tree)

        return self.facts, self.errors

    # ------------------------------------------------------------------
    # Helper: project-relative path
    # ------------------------------------------------------------------

    def _get_relative_path(self) -> str:
        """Get project-relative file path as POSIX string.

        Returns:
            The file path relative to root, converted to POSIX format.
            Falls back to absolute path string if not relative, and logs error.
        """
        try:
            rel = self.file.relative_to(self.root)
            return str(rel).replace("\\", "/")
        except ValueError:
            # file is not relative to root - this is a non-fatal error
            self.errors.append(ExtractionError(
                file=str(self.file),
                line=0,
                message=f"File path '{self.file}' is not relative to root '{self.root}'",
                exception_type="PathError",
            ))
            return str(self.file)

    # ------------------------------------------------------------------
    # Import handling
    # ------------------------------------------------------------------

    def _extract_imports(self, tree: ast.AST) -> None:
        """Extract all import statements."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._handle_import(node)
            elif isinstance(node, ast.ImportFrom):
                self._handle_import_from(node)

    def _handle_import(self, node: ast.Import) -> None:
        """Handle: import foo [as bar], import foo.bar [as baz]"""
        for alias in node.names:
            real_name = alias.name
            as_name = alias.asname or real_name

            # Track import alias - for import X, the resolved name is just X
            self._import_aliases[as_name] = real_name

            # Create ImportFact with lowercase type key
            fact = ImportFact(
                type="import",
                id=make_import_id(self.root, self.file, node.lineno, real_name),
                file=self._get_relative_path(),
                line=node.lineno,
                extractor="python_ast",
                language="python",
                module=real_name,
                imported_name=None,  # For 'import X', we're importing the module itself
                alias=as_name if as_name != real_name else None,
                kind=ImportKind.IMPORT if not alias.asname else ImportKind.IMPORT_AS,
            )
            self.facts.append(fact)

    def _handle_import_from(self, node: ast.ImportFrom) -> None:
        """Handle: from foo import bar [as baz]"""
        module = node.module or ""
        for alias in node.names:
            real_name = alias.name
            as_name = alias.asname or real_name

            # Track from-import alias - resolved name is module.real_name
            if module:
                self._import_aliases[as_name] = f"{module}.{real_name}"

            kind = ImportKind.FROM_IMPORT if not alias.asname else ImportKind.FROM_IMPORT_AS
            fact = ImportFact(
                type="import",
                id=make_import_id(
                    self.root, self.file, node.lineno,
                    f"{module}.{real_name}" if module else real_name
                ),
                file=self._get_relative_path(),
                line=node.lineno,
                extractor="python_ast",
                language="python",
                module=module,
                imported_name=real_name,
                alias=as_name if as_name != real_name else None,
                kind=kind,
            )
            self.facts.append(fact)

    # ------------------------------------------------------------------
    # Context tracking for definitions
    # ------------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class definition with proper context tracking."""
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit a function definition with proper context tracking."""
        self._handle_function_def(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit an async function definition with proper context tracking."""
        self._handle_function_def(node)

    def _handle_function_def(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Handle function definition."""
        # Build qualified name BEFORE pushing to stack
        qual_name = self._build_qualified_name(node)

        # Push to function stack
        self._function_stack.append(qual_name)

        # Extract decorators
        decorators = [self._get_decorator_name(d) for d in node.decorator_list]

        # Check if this is an MCP entry point
        is_entry_point = self._is_mcp_entry_decorator(decorators)
        entry_point_kind: EntryPointKind | None = None
        if is_entry_point:
            entry_point_kind = self._infer_entry_point_kind(decorators)

        # Build params
        params = self._extract_params(node.args)

        # Create FunctionFact with lowercase type key
        enclosing_class = self._class_stack[-1] if self._class_stack else None

        func_fact = FunctionFact(
            type="function",
            id=make_function_id("python", self.root, self.file, qual_name),
            file=self._get_relative_path(),
            line=node.lineno,
            extractor="python_ast",
            language="python",
            name=node.name,
            qualified_name=qual_name,
            end_line=node.end_lineno or node.lineno,
            params=params,
            decorators=decorators,
            enclosing_class=enclosing_class,
        )
        self.facts.append(func_fact)

        # If it's an MCP entry point, create EntryPointFact and SourceFacts
        if is_entry_point and entry_point_kind:
            self._handle_entry_point(node, qual_name, decorators, entry_point_kind, params)

        # Visit children (body, decorators, etc.)
        self.generic_visit(node)

        # Pop from function stack
        self._function_stack.pop()

    # ------------------------------------------------------------------
    # Definition helpers
    # ------------------------------------------------------------------

    def _build_qualified_name(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        """Build fully qualified name including class context."""
        name = node.name

        if len(self._class_stack) > 0:
            # Inside a class
            class_name = self._class_stack[-1]
            if len(self._function_stack) > 0:
                # Nested function in class: ClassName.outer_func.inner
                return f"{self._function_stack[-1]}.{name}"
            return f"{class_name}.{name}"
        elif len(self._function_stack) > 0:
            # Nested function: outer_func.inner
            return f"{self._function_stack[-1]}.{name}"

        return name

    def _get_decorator_name(self, decorator: ast.expr) -> str:
        """Get the full name of a decorator."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            parts = []
            current: ast.expr = decorator
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return "<unknown>"

    def _is_mcp_entry_decorator(self, decorators: list[str]) -> bool:
        """Check if any decorator matches MCP entry patterns."""
        for dec in decorators:
            if _is_mcp_decorator(dec):
                return True
        return False

    def _infer_entry_point_kind(self, decorators: list[str]) -> EntryPointKind:
        """Infer the entry point kind from decorator names."""
        for dec in decorators:
            dec_lower = dec.lower()
            if "resource" in dec_lower:
                return EntryPointKind.MCP_RESOURCE
            elif "prompt" in dec_lower:
                return EntryPointKind.MCP_PROMPT
        return EntryPointKind.MCP_TOOL

    def _extract_params(self, args: ast.arguments) -> list[ParamInfo]:
        """Extract parameter information from function arguments."""
        params: list[ParamInfo] = []

        # Handle positional args
        for i, arg in enumerate(args.args):
            annotation = None
            if arg.annotation and isinstance(arg.annotation, ast.Name):
                annotation = arg.annotation.id
            elif arg.annotation:
                annotation = self._get_annotation_str(arg.annotation)

            default = None
            if i >= len(args.args) - len(args.defaults):
                default_idx = i - (len(args.args) - len(args.defaults))
                if default_idx >= 0 and args.defaults[default_idx]:
                    default = self._get_default_str(args.defaults[default_idx])

            params.append(ParamInfo(
                name=arg.arg,
                annotation=annotation,
                default=default,
            ))

        # Handle *args and **kwargs
        if args.vararg:
            params.append(ParamInfo(name=f"*{args.vararg.arg}"))
        if args.kwarg:
            params.append(ParamInfo(name=f"**{args.kwarg.arg}"))

        return params

    def _get_annotation_str(self, node: ast.expr) -> str:
        """Get string representation of an annotation."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_annotation_str(node.value)}.{node.attr}"
        elif isinstance(node, ast.Subscript):
            return f"{self._get_annotation_str(node.value)}[{self._get_annotation_str(node.slice)}]"
        return "<complex>"

    def _get_default_str(self, node: ast.expr) -> str | None:
        """Get string representation of a default value."""
        if isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_annotation_str(node.value)}.{node.attr}"
        return None

    def _handle_entry_point(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        qual_name: str,
        decorators: list[str],
        kind: EntryPointKind,
        params: list[ParamInfo],
    ) -> None:
        """Create EntryPointFact and SourceFacts for MCP entry function."""
        func_id = make_function_id("python", self.root, self.file, qual_name)

        # Get entry point name
        ep_name = self._extract_entry_point_name(decorators, node.name)

        ep_fact = EntryPointFact(
            type="entrypoint",
            id=make_entrypoint_id(self.root, self.file, ep_name),
            file=self._get_relative_path(),
            line=node.lineno,
            extractor="python_ast",
            kind=kind,
            name=ep_name,
            function_id=func_id,
            evidence=EntryPointEvidence(
                kind="decorator",
                text=", ".join(decorators),
            ),
            params=[p.name for p in params],
            confidence=Confidence.HIGH,
        )
        self.facts.append(ep_fact)
        self._entry_points[qual_name] = ep_fact

        # Create SourceFacts for each parameter
        for param in params:
            # Skip *args/**kwargs
            if param.name.startswith("*"):
                continue

            source_fact = SourceFact(
                type="source",
                id=make_source_id(self.root, self.file, qual_name, param.name),
                file=self._get_relative_path(),
                line=node.lineno,
                extractor="python_ast",
                kind="mcp_tool_parameter",
                function_id=func_id,
                name=param.name,
                confidence=Confidence.HIGH,
            )
            self.facts.append(source_fact)

    def _extract_entry_point_name(self, decorators: list[str], default_name: str) -> str:
        """Extract explicit entry point name from decorator if available."""
        # For now, return the function name
        # Could be enhanced to parse @mcp.tool("name") style decorators
        return default_name

    # ------------------------------------------------------------------
    # Call handling
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        """Handle function call."""
        callee_str = self._get_callee_str(node.func)
        caller_id = self._get_current_function_id()

        # Extract positional args
        args_list: list[CallArg] = []
        for i, arg in enumerate(node.args):
            args_list.append(CallArg(
                index=i,
                expr=self._get_expr_str(arg),
                kind=self._get_expr_kind(arg),
            ))

        # Extract keyword args
        kwargs_dict: dict[str, CallKwarg] = {}
        for kw in node.keywords:
            if kw.arg:
                value = self._get_kwarg_value(kw.value)
                kwargs_dict[kw.arg] = CallKwarg(
                    expr=self._get_expr_str(kw.value),
                    value=value,
                )

        # Build normalized callee (try to resolve aliases through the chain)
        # Returns (resolved_name, original_alias_used_if_any)
        normalized_callee, original_alias = self._resolve_callee(callee_str)

        # Create CallFact with lowercase type key
        call_fact = CallFact(
            type="call",
            id=make_call_id(self.root, self.file, node.lineno, node.col_offset or 0),
            file=self._get_relative_path(),
            line=node.lineno,
            extractor="python_ast",
            caller=caller_id,
            callee=callee_str,
            normalized_callee=normalized_callee,
            column=node.col_offset,
            end_line=node.end_lineno,
            snippet=self._get_snippet(node),
            args=args_list,
            kwargs=kwargs_dict,
            resolution=self._build_resolution(normalized_callee, original_alias, callee_str),
        )
        self.facts.append(call_fact)

        # Check if this is a sink call
        self._check_sink(node, call_fact.id, normalized_callee)

        # Continue visiting children
        self.generic_visit(node)

    def _get_current_function_id(self) -> str:
        """Get the current function ID in python:<rel_path>:<qual_name> format."""
        if self._function_stack:
            qual_name = self._function_stack[-1]
            return make_function_id("python", self.root, self.file, qual_name)
        if self._class_stack and self._class_stack[-1]:
            return f"python:{self._get_relative_path()}:{self._class_stack[-1]}"
        return f"python:{self._get_relative_path()}:<module>"

    def _get_callee_str(self, func: ast.expr) -> str:
        """Get string representation of the callee."""
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            value_str = self._get_callee_str(func.value)
            return f"{value_str}.{func.attr}"
        elif isinstance(func, ast.Subscript):
            return f"{self._get_callee_str(func.value)}[{self._get_callee_str(func.slice)}]"
        return "<unknown>"

    def _resolve_callee(self, callee: str) -> tuple[str, str | None]:
        """Resolve callee through known alias chains.

        Iterates through both import and assignment aliases until no more
        resolution is possible. Returns (resolved_name, original_alias).

        For `from os import system as s; x = s; x()`:
        - First pass: 'x' -> 's' (via assignment alias)
        - Second pass: 's' -> 'os.system' (via import alias)
        - Result: ('os.system', 's') - 's' is the import alias used
        """
        current = callee
        max_iterations = 10  # Prevent infinite loops
        import_alias_used: str | None = None

        for _ in range(max_iterations):
            parts = current.split(".")

            # Try import alias first (this is the "ground truth" resolution)
            if parts[0] in self._import_aliases:
                # Only set import_alias_used if this is the first import in the chain
                # This captures the import alias that actually resolves the symbol
                if import_alias_used is None:
                    import_alias_used = parts[0]
                resolved = self._import_aliases[parts[0]]
                if len(parts) > 1:
                    current = f"{resolved}.{'.'.join(parts[1:])}"
                else:
                    current = resolved
                continue

            # Try assignment alias (intermediate step)
            if parts[0] in self._assignment_aliases:
                resolved = self._assignment_aliases[parts[0]]
                if len(parts) > 1:
                    current = f"{resolved}.{'.'.join(parts[1:])}"
                else:
                    current = resolved
                continue

            # No more resolution possible
            break

        return current, import_alias_used

    def _build_resolution(
        self, normalized_callee: str, original_alias: str | None, original_callee: str
    ) -> CallResolution | None:
        """Build resolution info for the call.

        Uses the original_alias captured during resolution to look up
        import alias information, since the normalized name has already
        been transformed and won't match the alias key.
        """
        if original_alias is None:
            return None

        # Check if the original alias was an import alias
        if original_alias in self._import_aliases:
            return CallResolution(
                import_alias=original_alias,
                confidence=Confidence.HIGH,
            )
        return None

    def _get_expr_str(self, node: ast.expr) -> str:
        """Get string representation of an expression."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return repr(node.value)
            return str(node.value)
        elif isinstance(node, ast.Attribute):
            return f"{self._get_expr_str(node.value)}.{node.attr}"
        elif isinstance(node, ast.BinOp):
            return f"({self._get_expr_str(node.left)} {self._get_op_str(node.op)} {self._get_expr_str(node.right)})"
        elif isinstance(node, ast.UnaryOp):
            return f"{self._get_op_str(node.op)}{self._get_expr_str(node.operand)}"
        elif isinstance(node, ast.BoolOp):
            op = " and " if isinstance(node.op, ast.And) else " or "
            return op.join(self._get_expr_str(v) for v in node.values)
        elif isinstance(node, ast.Call):
            return f"{self._get_callee_str(node.func)}(...)"
        elif isinstance(node, ast.Subscript):
            return f"{self._get_expr_str(node.value)}[{self._get_expr_str(node.slice)}]"
        elif isinstance(node, ast.Dict):
            return "{...}"
        elif isinstance(node, ast.List):
            return "[...]"
        elif isinstance(node, ast.Tuple):
            return "(...)"
        return "<expr>"

    def _get_op_str(self, op: ast.operator) -> str:
        """Get string representation of an operator."""
        ops = {
            ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/",
            ast.FloorDiv: "//", ast.Mod: "%", ast.Pow: "**", ast.LShift: "<<",
            ast.RShift: ">>", ast.BitOr: "|", ast.BitXor: "^", ast.BitAnd: "&",
        }
        if isinstance(op, ast.Not):
            return "not "
        if isinstance(op, ast.UAdd):
            return "+"
        if isinstance(op, ast.USub):
            return "-"
        return ops.get(type(op), "?")

    def _get_expr_kind(self, node: ast.expr) -> str:
        """Get the kind of expression."""
        if isinstance(node, ast.Name):
            return "name"
        elif isinstance(node, ast.Constant):
            return "literal"
        elif isinstance(node, ast.Attribute):
            return "attribute"
        elif isinstance(node, ast.Call):
            return "call"
        elif isinstance(node, ast.BinOp):
            return "binop"
        elif isinstance(node, ast.Dict):
            return "dict"
        elif isinstance(node, ast.List):
            return "list"
        elif isinstance(node, ast.Tuple):
            return "tuple"
        return "other"

    def _get_kwarg_value(self, node: ast.expr) -> object:
        """Extract a Python literal value from a kwarg if possible."""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Name):
            return f"<var:{node.id}>"
        elif isinstance(node, ast.Attribute):
            return f"<attr:{self._get_expr_str(node)}>"
        elif isinstance(node, ast.Call):
            return f"<call:{self._get_callee_str(node.func)}>"
        return "<complex>"

    def _get_snippet(self, node: ast.Call) -> str:
        """Get a code snippet for the call."""
        try:
            # Use ast.unparse if available (Python 3.9+)
            if sys.version_info >= (3, 9):
                return ast.unparse(node)
        except Exception:  # noqa: BLE001
            pass
        return self._get_expr_str(node)

    # ------------------------------------------------------------------
    # Assignment handling (for alias tracking)
    # ------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        """Handle assignment for alias tracking: x = y or x = module.func"""
        # Only handle single-target assignments
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            self.generic_visit(node)
            return

        target = node.targets[0]
        target_name = target.id
        value_expr = self._get_expr_str(node.value)
        resolved_value: str | None = None

        if isinstance(node.value, ast.Name):
            # Simple alias: x = y
            resolved_value = node.value.id
        elif isinstance(node.value, ast.Attribute):
            # Module attribute alias: x = module.func
            resolved_value = self._get_callee_str(node.value)

        if resolved_value:
            self._assignment_aliases[target_name] = resolved_value

        # Only produce AssignFact if we're inside a function body (not module level)
        current_func_id = self._get_current_function_id()
        if current_func_id and resolved_value is not None and not current_func_id.endswith("<module>"):
            # Only produce for name-to-name or name-to-attribute assignments
            # Skip literal assignments (x = "string", x = 42)
            if isinstance(node.value, (ast.Name, ast.Attribute)):
                self.facts.append(AssignFact(
                    type="assign",
                    id=make_assign_id(self.root, self.file, node.lineno, target_name),
                    file=self._get_relative_path(),
                    line=node.lineno,
                    extractor="python_ast",
                    function_id=current_func_id,
                    target=target_name,
                    value=resolved_value,
                    snippet=f"{target_name} = {value_expr}",
                ))

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Sink detection
    # ------------------------------------------------------------------

    def _check_sink(
        self, node: ast.Call, call_id: str, normalized_callee: str
    ) -> None:
        """Check if a call matches sink rules and create SinkFact if so."""
        for rule in _SINK_RULES:
            for pattern in rule.patterns:
                if self._matches_sink_pattern(normalized_callee, pattern):
                    sink_fact = SinkFact(
                        type="sink",
                        id=make_sink_id(rule.category, self.root, self.file, node.lineno),
                        file=self._get_relative_path(),
                        line=node.lineno,
                        extractor="python_ast",
                        call_id=call_id,
                        category=rule.category,
                        rule_id=rule.rule_id,
                        sink_name=normalized_callee,
                        severity_base=rule.severity,
                        reason=rule.reason,
                        confidence=Confidence.HIGH,
                    )
                    self.facts.append(sink_fact)
                    return

    def _matches_sink_pattern(self, callee: str, pattern: str) -> bool:
        """Check if callee matches a sink pattern."""
        # Direct match
        if callee == pattern:
            return True
        # Ends with the pattern (handles module.path.pattern)
        if callee.endswith(f".{pattern}"):
            return True
        # Check if any part of the callee matches
        parts = callee.split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) == pattern:
                return True
        return False


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------


def extract_python_facts(
    root: Path,
    file: Path,
    source: str,
) -> tuple[list[Fact], list[ExtractionError]]:
    """Extract security facts from Python source code.

    Args:
        root: The project root directory (used for ID generation).
        file: The file path being analyzed (must be relative to root).
        source: The Python source code to analyze.

    Returns:
        A tuple of (facts, non_fatal_errors).
        The facts list may contain FunctionFact, ImportFact, CallFact,
        EntryPointFact, SourceFact, and SinkFact instances.
        Errors are non-fatal and represent unsupported constructs or
        parse errors that prevented full extraction.

    Example:
        >>> root = Path("/project")
        >>> file = Path("/project/src/server.py")
        >>> source = "import subprocess\\nsubprocess.run(['ls'])"
        >>> facts, errors = extract_python_facts(root, file, source)
        >>> len(facts) > 0
        True
    """
    extractor = PythonFactExtractor(root, file)
    return extractor.extract(source)
