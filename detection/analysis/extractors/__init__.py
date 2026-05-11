"""Python AST extractors for security fact extraction."""

from .javascript_ts_tree_sitter import extract_jsts_facts
from .python_ast import extract_python_facts

__all__ = ["extract_python_facts", "extract_jsts_facts"]