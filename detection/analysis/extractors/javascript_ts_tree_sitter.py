"""JavaScript/TypeScript Tree-sitter extractor for security fact extraction.

This module provides the `extract_jsts_facts` function that extracts security-relevant
facts from JavaScript/TypeScript source code using the `tree_sitter` library.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, NamedTuple

import tree_sitter
import tree_sitter_javascript
import tree_sitter_typescript

from ..facts.ids import (
    make_call_id,
    make_entrypoint_id,
    make_function_id,
    make_import_id,
    make_sink_id,
)
from ..facts.schema import (
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
        patterns=("child_process.exec", "child_process.execSync", "child_process.spawn",
                   "child_process.spawnSync", "child_process.execFile", "child_process.fork"),
        category="rce",
        rule_id="rce_child_process",
        severity=Severity.HIGH,
        reason="Executes external commands via child_process",
    ),
    SinkRule(
        patterns=("eval", "exec", "Function", "new Function"),
        category="rce",
        rule_id="rce_dynamic",
        severity=Severity.HIGH,
        reason="Dynamic code execution",
    ),
    SinkRule(
        patterns=("fs.readFile", "fs.readFileSync", "fs.writeFile", "fs.writeFileSync",
                   "fs.createReadStream", "fs.createWriteStream", "fs.readFileSync",
                   "fs.promises.readFile", "fs.promises.writeFile"),
        category="file",
        rule_id="file_access",
        severity=Severity.MEDIUM,
        reason="File system access",
    ),
    SinkRule(
        patterns=("http.request", "https.request", "net.connect",
                   "fetch", "axios", "node-fetch"),
        category="network",
        rule_id="network_access",
        severity=Severity.MEDIUM,
        reason="Network access",
    ),
]


# ----------------------------------------------------------------------
# MCP tool/server registration patterns
# ----------------------------------------------------------------------


_MCP_REGISTRATION_PATTERNS: tuple[str, ...] = (
    "server.tool",
    "server.resource",
    "server.prompt",
    "mcp.tool",
    "mcp.resource",
    "mcp.prompt",
)


# ----------------------------------------------------------------------
# Language detection and parser management
# ----------------------------------------------------------------------


_JAVASCRIPT_PARSER: tree_sitter.Parser | None = None
_TYPESCRIPT_PARSER: tree_sitter.Parser | None = None
_TSX_PARSER: tree_sitter.Parser | None = None


def _get_javascript_parser() -> tree_sitter.Parser:
    """Get or create a Tree-sitter parser for JavaScript."""
    global _JAVASCRIPT_PARSER
    if _JAVASCRIPT_PARSER is None:
        lang = tree_sitter.Language(tree_sitter_javascript.language())
        _JAVASCRIPT_PARSER = tree_sitter.Parser()
        _JAVASCRIPT_PARSER.language = lang
    return _JAVASCRIPT_PARSER


def _get_typescript_parser() -> tree_sitter.Parser:
    """Get or create a Tree-sitter parser for TypeScript."""
    global _TYPESCRIPT_PARSER
    if _TYPESCRIPT_PARSER is None:
        lang = tree_sitter.Language(tree_sitter_typescript.language_typescript())
        _TYPESCRIPT_PARSER = tree_sitter.Parser()
        _TYPESCRIPT_PARSER.language = lang
    return _TYPESCRIPT_PARSER


def _get_tsx_parser() -> tree_sitter.Parser:
    """Get or create a Tree-sitter parser for TSX."""
    global _TSX_PARSER
    if _TSX_PARSER is None:
        lang = tree_sitter.Language(tree_sitter_typescript.language_tsx())
        _TSX_PARSER = tree_sitter.Parser()
        _TSX_PARSER.language = lang
    return _TSX_PARSER


def _detect_parser(file_path: Path) -> tree_sitter.Parser:
    """Detect the appropriate parser based on file extension."""
    suffix = file_path.suffix.lower()
    if suffix in (".ts", ".mts", ".cts"):
        return _get_typescript_parser()
    elif suffix in (".tsx", ".mtsx", ".ctsx"):
        return _get_tsx_parser()
    else:
        return _get_javascript_parser()


# ----------------------------------------------------------------------
# JSTS Fact Extractor
# ----------------------------------------------------------------------


class JSTSFactExtractor:
    """Tree-sitter visitor that extracts security facts from JS/TS source."""

    def __init__(self, root: Path, file: Path) -> None:
        self.root = root
        self.file = file
        self.facts: list[Fact] = []
        self.errors: list[ExtractionError] = []

        # Context stacks
        self._function_stack: list[str] = []
        self._class_stack: list[str] = []

        # MCP handler context for inline arrow function handlers
        self._current_mcp_handler_id: str | None = None
        # Track call IDs processed by MCP handlers to avoid duplicates
        self._processed_handler_call_ids: set[str] = set()

        # Current tree being processed (set in extract method)
        self._current_tree: tree_sitter.Tree | None = None

        # Alias tracking
        self._import_aliases: dict[str, str] = {}
        self._require_aliases: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(
        self, source: str, parser: tree_sitter.Parser
    ) -> tuple[list[Fact], list[ExtractionError]]:
        """Parse and extract facts from JS/TS source code.

        Args:
            source: The source code to analyze.
            parser: The Tree-sitter parser to use.

        Returns:
            A tuple of (facts, non_fatal_errors).
        """
        try:
            tree = parser.parse(source.encode())
        except Exception as e:  # noqa: BLE001
            self.errors.append(ExtractionError(
                file=self._get_relative_path(),
                line=0,
                message=f"Parse error: {str(e)}",
                exception_type=type(e).__name__,
            ))
            return [], self.errors

        # Set current tree for use in _check_mcp_registration
        self._current_tree = tree

        # Walk the tree
        self._walk_node(tree.root_node, source, tree)

        return self.facts, self.errors

    # ------------------------------------------------------------------
    # Helper: project-relative path
    # ------------------------------------------------------------------

    def _get_relative_path(self) -> str:
        """Get project-relative file path as POSIX string."""
        try:
            rel = self.file.relative_to(self.root)
            return str(rel).replace("\\", "/")
        except ValueError:
            self.errors.append(ExtractionError(
                file=str(self.file),
                line=0,
                message=f"File path '{self.file}' is not relative to root '{self.root}'",
                exception_type="PathError",
            ))
            return str(self.file)

    # ------------------------------------------------------------------
    # Tree walking
    # ------------------------------------------------------------------

    def _walk_node(
        self, node: tree_sitter.Node, source: str, tree: tree_sitter.Tree
    ) -> None:
        """Walk a tree-sitter node and extract facts."""
        node_type = node.type

        if node_type == "import_statement":
            # Handle imports (only at the top-level import_statement)
            self._handle_import(node)

        elif node_type == "call_expression":
            self._handle_call(node, source)

        elif node_type in ("function_declaration", "lexical_function_declaration"):
            self._handle_function_def(node)

        elif node_type == "method_definition":
            self._handle_method_def(node)

        elif node_type == "variable_declarator":
            self._handle_variable_declarator(node, source)

        # Recurse into children
        for child in node.children:
            self._walk_node(child, source, tree)

        # Pop context after processing children
        if node_type == "function_declaration":
            self._function_stack.pop()
        elif node_type == "lexical_function_declaration":
            self._function_stack.pop()
        elif node_type == "class":
            self._class_stack.pop()

    # ------------------------------------------------------------------
    # Import handling
    # ------------------------------------------------------------------

    def _handle_import(self, node: tree_sitter.Node) -> None:
        """Handle ESM import statements."""
        # Get the import statement node
        parent = node.parent
        if parent is None or parent.type != "import_statement":
            parent = node

        if parent.type != "import_statement":
            return

        # Get source module (first string child)
        source_node = self._find_child_by_type(parent, "string")
        if source_node is None:
            return

        module = self._get_string_value(source_node)

        # Handle: import foo from "module"
        # Handle: import { foo, bar } from "module"
        # Handle: import foo from "module"
        for child in parent.children:
            if child.type == "import_clause":
                self._extract_import_clause(child, module, parent.start_point[0] + 1)

    def _extract_import_clause(
        self, node: tree_sitter.Node, module: str, line: int
    ) -> None:
        """Extract facts from an import clause."""
        for child in node.children:
            if child.type == "identifier":
                name = child.text.decode()
                alias = self._find_import_alias(child)

                fact = ImportFact(
                    type="import",
                    id=make_import_id(self.root, self.file, line, f"{module}.{name}"),
                    file=self._get_relative_path(),
                    line=line,
                    extractor="javascript_ts_tree_sitter",
                    language="javascript",
                    module=module,
                    imported_name=name,
                    alias=alias,
                    kind=ImportKind.ESM_IMPORT if not alias else ImportKind.ESM_IMPORT_AS,
                )
                self.facts.append(fact)

                # Track alias
                resolved = f"{module}.{name}"
                alias_key = alias if alias else name
                self._import_aliases[alias_key] = resolved

            elif child.type == "named_imports":
                self._handle_named_imports(child, module, line)

            elif child.type == "namespace_import":
                # import * as foo from "module"
                star_node = self._find_child_by_type(child, "identifier")
                if star_node:
                    name = star_node.text.decode()
                    fact = ImportFact(
                        type="import",
                        id=make_import_id(self.root, self.file, line, f"{module}.*"),
                        file=self._get_relative_path(),
                        line=line,
                        extractor="javascript_ts_tree_sitter",
                        language="javascript",
                        module=module,
                        imported_name="*",
                        alias=name,
                        kind=ImportKind.ESM_IMPORT_AS,
                    )
                    self.facts.append(fact)
                    self._import_aliases[name] = f"{module}.*"

    def _handle_named_imports(
        self, node: tree_sitter.Node, module: str, line: int
    ) -> None:
        """Handle named imports: import { foo, bar } from "module"."""
        for child in node.children:
            if child.type == "import_specifier":
                name_node = self._find_child_by_type(child, "identifier")
                if name_node is None:
                    continue

                name = name_node.text.decode()
                alias = self._find_import_alias(child)

                fact = ImportFact(
                    type="import",
                    id=make_import_id(self.root, self.file, line, f"{module}.{name}"),
                    file=self._get_relative_path(),
                    line=line,
                    extractor="javascript_ts_tree_sitter",
                    language="javascript",
                    module=module,
                    imported_name=name,
                    alias=alias,
                    kind=ImportKind.ESM_NAMED_IMPORT if not alias else ImportKind.ESM_IMPORT_AS,
                )
                self.facts.append(fact)

                alias_key = alias if alias else name
                self._import_aliases[alias_key] = f"{module}.{name}"

    def _find_import_alias(self, node: tree_sitter.Node) -> str | None:
        """Find alias in import specifier (foo as bar)."""
        for child in node.children:
            if child.type == "identifier" and child != node.children[0]:
                return child.text.decode()
        return None

    # ------------------------------------------------------------------
    # Function/Method handling
    # ------------------------------------------------------------------

    def _handle_function_def(self, node: tree_sitter.Node) -> None:
        """Handle function declarations."""
        name_node = self._find_child_by_type(node, "identifier")
        if name_node is None:
            return

        name = name_node.text.decode()
        qual_name = self._build_qualified_name(name)
        self._function_stack.append(qual_name)

        line = node.start_point[0] + 1

        # Create FunctionFact
        func_fact = FunctionFact(
            type="function",
            id=make_function_id("javascript", self.root, self.file, qual_name),
            file=self._get_relative_path(),
            line=line,
            extractor="javascript_ts_tree_sitter",
            language="javascript",
            name=name,
            qualified_name=qual_name,
            end_line=node.end_point[0] + 1 if node.end_point else line,
            params=self._extract_params(node),
        )
        self.facts.append(func_fact)

    def _handle_method_def(self, node: tree_sitter.Node) -> None:
        """Handle class method definitions."""
        name_node = self._find_child_by_type(node, "property_identifier")
        if name_node is None:
            name_node = self._find_child_by_type(node, "formal_parameters")

        if name_node is None:
            return

        name = name_node.text.decode()
        qual_name = self._build_qualified_name(name)
        self._function_stack.append(qual_name)

        line = node.start_point[0] + 1

        enclosing_class = self._class_stack[-1] if self._class_stack else None

        func_fact = FunctionFact(
            type="function",
            id=make_function_id("javascript", self.root, self.file, qual_name),
            file=self._get_relative_path(),
            line=line,
            extractor="javascript_ts_tree_sitter",
            language="javascript",
            name=name,
            qualified_name=qual_name,
            end_line=node.end_point[0] + 1 if node.end_point else line,
            params=self._extract_params(node),
            enclosing_class=enclosing_class,
        )
        self.facts.append(func_fact)

    def _build_qualified_name(self, name: str) -> str:
        """Build qualified name including class context."""
        if self._class_stack:
            class_name = self._class_stack[-1]
            if self._function_stack:
                return f"{self._function_stack[-1]}.{name}"
            return f"{class_name}.{name}"
        elif self._function_stack:
            return f"{self._function_stack[-1]}.{name}"
        return name

    def _extract_params(self, node: tree_sitter.Node) -> list[ParamInfo]:
        """Extract parameters from a function node."""
        params: list[ParamInfo] = []

        # Find formal_parameters child
        param_node = self._find_child_by_type(node, "formal_parameters")
        if param_node is None:
            return params

        for child in param_node.children:
            if child.type == "required_parameter":
                name_node = self._find_child_by_type(child, "identifier")
                if name_node:
                    params.append(ParamInfo(name=name_node.text.decode()))
            elif child.type == "optional_parameter":
                name_node = self._find_child_by_type(child, "identifier")
                if name_node:
                    params.append(ParamInfo(name=name_node.text.decode()))
            elif child.type == "rest_parameter":
                name_node = self._find_child_by_type(child, "identifier")
                if name_node:
                    params.append(ParamInfo(name=f"...{name_node.text.decode()}"))

        return params

    # ------------------------------------------------------------------
    # Variable declarator (for require alias tracking)
    # ------------------------------------------------------------------

    def _handle_variable_declarator(
        self, node: tree_sitter.Node, source: str
    ) -> None:
        """Handle variable declarations for alias tracking."""
        # Check for destructured require: const { readFile } = require("fs")
        # The left side is object_pattern, right side is call_expression
        left_node = self._find_child_by_type(node, "object_pattern")
        right_node = self._find_child_by_type(node, "call_expression")

        if left_node is not None and right_node is not None:
            # This is a destructuring pattern
            name_node = self._find_child_by_type(right_node, "identifier")
            if name_node and name_node.text.decode() == "require":
                # Get the module from arguments node's string child
                args_node = self._find_child_by_type(right_node, "arguments")
                if args_node:
                    module_node = self._find_child_by_type(args_node, "string")
                    if module_node:
                        module = self._get_string_value(module_node)
                        # Extract each destructured name
                        for child in left_node.children:
                            if child.type == "shorthand_property_identifier_pattern":
                                name = child.text.decode()
                                fact = ImportFact(
                                    type="import",
                                    id=make_import_id(self.root, self.file, node.start_point[0] + 1, f"{module}.{name}"),
                                    file=self._get_relative_path(),
                                    line=node.start_point[0] + 1,
                                    extractor="javascript_ts_tree_sitter",
                                    language="javascript",
                                    module=module,
                                    imported_name=name,
                                    kind=ImportKind.REQUIRE_DESTRUCTURE,
                                )
                                self.facts.append(fact)
                                self._require_aliases[name] = f"{module}.{name}"
            return

        # Check for simple require: const fs = require("fs")
        name_node = self._find_child_by_type(node, "identifier")
        value_node = self._find_child_by_type(node, "call_expression")

        if name_node is None or value_node is None:
            return

        name = name_node.text.decode()

        # Check if it's a require call
        callee = self._find_child_by_type(value_node, "identifier")
        if callee and callee.text.decode() == "require":
            args_node = self._find_child_by_type(value_node, "arguments")
            if args_node:
                module_node = self._find_child_by_type(args_node, "string")
                if module_node:
                    module = self._get_string_value(module_node)
                    # Create ImportFact for simple require
                    fact = ImportFact(
                        type="import",
                        id=make_import_id(self.root, self.file, node.start_point[0] + 1, module),
                        file=self._get_relative_path(),
                        line=node.start_point[0] + 1,
                        extractor="javascript_ts_tree_sitter",
                        language="javascript",
                        module=module,
                        imported_name=None,
                        alias=name,
                        kind=ImportKind.REQUIRE,
                    )
                    self.facts.append(fact)
                    self._require_aliases[name] = module

    # ------------------------------------------------------------------
    # Call handling
    # ------------------------------------------------------------------

    def _handle_call(self, node: tree_sitter.Node, source: str) -> None:
        """Handle call expressions."""
        # Get callee
        callee_node = self._find_child_by_type(node, "member_expression")
        if callee_node is None:
            callee_node = self._find_child_by_type(node, "identifier")

        if callee_node is None:
            return

        callee_str = self._get_callee_str(callee_node)
        line = node.start_point[0] + 1
        column = node.start_point[1]

        # Compute call_id to check if already processed by MCP handler
        call_id = make_call_id(self.root, self.file, line, column)

        # Skip if this call was already processed by an MCP handler inline
        if call_id in self._processed_handler_call_ids:
            return

        # Determine caller: use MCP handler's function_id if in that context
        if self._current_mcp_handler_id is not None:
            caller_id = self._current_mcp_handler_id
            # Track this call as processed by an MCP handler
            self._processed_handler_call_ids.add(call_id)
        else:
            caller_id = self._get_current_caller_id()

        # Extract arguments
        args_list: list[CallArg] = []
        kwargs_dict: dict[str, CallKwarg] = {}

        args = self._find_children_by_type(node, "arguments")
        if args:
            arg_list_node = args[0]
            for i, child in enumerate(arg_list_node.children):
                if child.type == "argument":
                    for arg_child in child.children:
                        if arg_child.type in ("identifier", "string", "number",
                                              "member_expression", "call_expression"):
                            args_list.append(CallArg(
                                index=i,
                                expr=self._get_expr_str(arg_child),
                                kind=self._get_expr_kind(arg_child),
                            ))

        # Build normalized callee
        normalized_callee = self._resolve_callee(callee_str)

        # Create CallFact
        call_fact = CallFact(
            type="call",
            id=call_id,
            file=self._get_relative_path(),
            line=line,
            extractor="javascript_ts_tree_sitter",
            caller=caller_id,
            callee=callee_str,
            normalized_callee=normalized_callee,
            column=column,
            snippet=self._get_snippet(node, source),
            args=args_list,
            kwargs=kwargs_dict,
        )
        self.facts.append(call_fact)

        # Check for MCP tool registration pattern
        self._check_mcp_registration(node, call_fact.id, callee_str, normalized_callee, source, self._current_tree)

        # Check for sinks
        self._check_sink(node, call_fact.id, normalized_callee)

    def _get_callee_str(self, node: tree_sitter.Node) -> str:
        """Get string representation of callee."""
        if node.type == "identifier":
            return node.text.decode()
        elif node.type == "member_expression":
            obj = self._find_child_by_type(node, "identifier")
            prop = self._find_child_by_type(node, "property_identifier")
            if obj and prop:
                return f"{obj.text.decode()}.{prop.text.decode()}"
            elif obj:
                return obj.text.decode()
        return "<unknown>"

    def _resolve_callee(self, callee: str) -> str:
        """Resolve callee through known aliases."""
        parts = callee.split(".")

        # Try import aliases
        if parts[0] in self._import_aliases:
            resolved = self._import_aliases[parts[0]]
            if len(parts) > 1:
                return f"{resolved}.{'.'.join(parts[1:])}"
            return resolved

        # Try require aliases
        if parts[0] in self._require_aliases:
            resolved = self._require_aliases[parts[0]]
            if len(parts) > 1:
                return f"{resolved}.{'.'.join(parts[1:])}"
            return resolved

        return callee

    def _get_current_caller_id(self) -> str:
        """Get current function ID."""
        if self._function_stack:
            qual_name = self._function_stack[-1]
            return make_function_id("javascript", self.root, self.file, qual_name)
        return f"javascript:{self._get_relative_path()}:<module>"

    def _get_expr_str(self, node: tree_sitter.Node) -> str:
        """Get string representation of expression."""
        if node.type == "identifier":
            return node.text.decode()
        elif node.type == "string":
            return self._get_string_value(node)
        elif node.type == "number":
            return node.text.decode()
        elif node.type == "member_expression":
            obj = self._find_child_by_type(node, "identifier")
            prop = self._find_child_by_type(node, "property_identifier")
            if obj and prop:
                return f"{obj.text.decode()}.{prop.text.decode()}"
        elif node.type == "call_expression":
            callee = self._find_child_by_type(node, "member_expression")
            if callee is None:
                callee = self._find_child_by_type(node, "identifier")
            if callee:
                return f"{self._get_callee_str(callee)}(...)"
        return "<expr>"

    def _get_expr_kind(self, node: tree_sitter.Node) -> str:
        """Get expression kind."""
        return node.type

    def _get_snippet(self, node: tree_sitter.Node, source: str) -> str:
        """Get code snippet for call."""
        start = node.start_point
        end = node.end_point
        lines = source.split("\n")

        if start[0] == end[0]:
            line = lines[start[0]] if start[0] < len(lines) else ""
            return line[start[1]:end[1]]
        else:
            # Multi-line, return first line truncated
            line = lines[start[0]] if start[0] < len(lines) else ""
            return line[start[1]:start[1] + 50] + "..."

    # ------------------------------------------------------------------
    # MCP registration detection
    # ------------------------------------------------------------------

    def _check_mcp_registration(
        self,
        node: tree_sitter.Node,
        call_id: str,
        callee_str: str,
        normalized_callee: str,
        source: str,
        tree: tree_sitter.Tree | None,
    ) -> None:
        """Check if call is an MCP tool/server registration."""
        # Check if callee matches MCP registration patterns
        is_mcp_call = False
        for pattern in _MCP_REGISTRATION_PATTERNS:
            if callee_str == pattern or callee_str.endswith(f".{pattern}"):
                is_mcp_call = True
                break

        if not is_mcp_call:
            return

        # Get function name from first argument if it's a string or identifier
        args = self._find_children_by_type(node, "arguments")
        ep_name = "<anonymous>"
        if args:
            arg_list = args[0]
            first_arg = self._find_child_by_type(arg_list, "string")
            if first_arg:
                ep_name = self._get_string_value(first_arg)
            else:
                first_id = self._find_child_by_type(arg_list, "identifier")
                if first_id:
                    ep_name = first_id.text.decode()

        # Get function being registered (second argument - arrow function or identifier)
        if len(args) > 0:
            arg_list = args[0]
            children = [
                c for c in arg_list.children
                if c.type in ("arrow_function", "identifier", "member_expression", "string")
            ]
            func_id = ""
            if len(children) > 1:
                # Second argument is the handler (first is tool name string)
                handler = children[1]
                if handler.type == "arrow_function":
                    # Create inline function fact for arrow function
                    qual_name = f"{ep_name}_handler"
                    func_id = make_function_id("javascript", self.root, self.file, qual_name)

                    func_fact = FunctionFact(
                        type="function",
                        id=func_id,
                        file=self._get_relative_path(),
                        line=handler.start_point[0] + 1,
                        extractor="javascript_ts_tree_sitter",
                        language="javascript",
                        name=f"{ep_name}_handler",
                        qualified_name=qual_name,
                        end_line=handler.end_point[0] + 1 if handler.end_point else handler.start_point[0] + 1,
                        params=self._extract_arrow_params(handler),
                    )
                    self.facts.append(func_fact)

                    # Walk the arrow function body with the handler as current context
                    # This ensures calls inside the handler have correct caller attribution
                    previous_handler_id = self._current_mcp_handler_id
                    self._current_mcp_handler_id = func_id
                    try:
                        self._walk_node(handler, source, tree)
                    finally:
                        self._current_mcp_handler_id = previous_handler_id
                elif handler.type == "identifier":
                    func_id = make_function_id("javascript", self.root, self.file, handler.text.decode())

            if func_id:
                ep_fact = EntryPointFact(
                    type="entrypoint",
                    id=make_entrypoint_id(self.root, self.file, ep_name),
                    file=self._get_relative_path(),
                    line=node.start_point[0] + 1,
                    extractor="javascript_ts_tree_sitter",
                    kind=EntryPointKind.MCP_TOOL,
                    name=ep_name,
                    function_id=func_id,
                    evidence=EntryPointEvidence(
                        kind="call_registration",
                        text=callee_str,
                    ),
                    confidence=Confidence.HIGH,
                )
                self.facts.append(ep_fact)

    def _extract_arrow_params(self, node: tree_sitter.Node) -> list[ParamInfo]:
        """Extract parameters from an arrow function."""
        params: list[ParamInfo] = []
        param_node = self._find_child_by_type(node, "formal_parameters")
        if param_node is None:
            return params

        for child in param_node.children:
            if child.type == "required_parameter":
                name_node = self._find_child_by_type(child, "identifier")
                if name_node:
                    params.append(ParamInfo(name=name_node.text.decode()))
        return params

    # ------------------------------------------------------------------
    # Sink detection
    # ------------------------------------------------------------------

    def _check_sink(
        self, node: tree_sitter.Node, call_id: str, normalized_callee: str
    ) -> None:
        """Check if call matches sink rules."""
        for rule in _SINK_RULES:
            for pattern in rule.patterns:
                if self._matches_sink_pattern(normalized_callee, pattern):
                    sink_fact = SinkFact(
                        type="sink",
                        id=make_sink_id(rule.category, self.root, self.file, node.start_point[0] + 1),
                        file=self._get_relative_path(),
                        line=node.start_point[0] + 1,
                        extractor="javascript_ts_tree_sitter",
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
        """Check if callee matches sink pattern."""
        if callee == pattern:
            return True
        if callee.endswith(f".{pattern}"):
            return True
        parts = callee.split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) == pattern:
                return True
        return False

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    def _find_child_by_type(self, node: tree_sitter.Node, child_type: str) -> tree_sitter.Node | None:
        """Find first child of given type."""
        for child in node.children:
            if child.type == child_type:
                return child
        return None

    def _find_children_by_type(self, node: tree_sitter.Node, child_type: str) -> list[tree_sitter.Node]:
        """Find all children of given type."""
        return [child for child in node.children if child.type == child_type]

    def _get_string_value(self, node: tree_sitter.Node) -> str:
        """Extract string value from string node."""
        text = node.text.decode()
        if len(text) >= 2:
            # Remove quotes
            return text[1:-1]
        return text


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------


def extract_jsts_facts(
    root: Path,
    file: Path,
    source: str,
) -> tuple[list[Fact], list[ExtractionError]]:
    """Extract security facts from JavaScript/TypeScript source code.

    Args:
        root: The project root directory (used for ID generation).
        file: The file path being analyzed (must be relative to root).
        source: The JS/TS source code to analyze.

    Returns:
        A tuple of (facts, non_fatal_errors).
        The facts list may contain FunctionFact, ImportFact, CallFact,
        EntryPointFact, and SinkFact instances.
        Errors are non-fatal and represent unsupported constructs or
        parse errors that prevented full extraction.

    Example:
        >>> root = Path("/project")
        >>> file = Path("/project/src/server.js")
        >>> source = 'import { exec } from \"child_process\"; exec(args.cmd);'
        >>> facts, errors = extract_jsts_facts(root, file, source)
        >>> len(facts) > 0
        True
    """
    parser = _detect_parser(file)
    extractor = JSTSFactExtractor(root, file)
    return extractor.extract(source, parser)
