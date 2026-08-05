use crate::model::EntryPointKind;

pub(crate) const MCP_DECORATOR_PATTERNS: &[&str] = &[
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

pub(crate) fn classify_mcp_decorator(decorator: &str) -> Option<EntryPointKind> {
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
