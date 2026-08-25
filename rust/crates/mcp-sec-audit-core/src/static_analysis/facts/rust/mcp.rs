use crate::model::EntryPointKind;

// ---------------------------------------------------------------------------
// MCP attribute patterns for Rust
// ---------------------------------------------------------------------------

pub(crate) const MCP_ATTR_PATTERNS: &[&str] = &[
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

pub(crate) fn classify_mcp_attr(attr: &str) -> Option<EntryPointKind> {
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

/// Determine EntryPointKind from callee string (for SDK call patterns).
pub(crate) fn entrypoint_kind_from_callee(callee: &str) -> EntryPointKind {
    let method = callee.rsplit('.').next().unwrap_or(callee);
    if method.contains("resource") {
        EntryPointKind::McpResource
    } else if method.contains("prompt") {
        EntryPointKind::McpPrompt
    } else {
        EntryPointKind::McpTool
    }
}

/// Check if a callee matches an MCP registration pattern (SDK call style).
pub(crate) fn is_mcp_registration(callee: &str) -> bool {
    MCP_ATTR_PATTERNS
        .iter()
        .any(|pattern| callee == *pattern || callee.ends_with(&format!(".{pattern}")))
}
