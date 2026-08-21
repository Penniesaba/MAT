use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// Summary of a single file for prompt rendering.
pub struct FileSummary {
    pub path: String,
    pub language: String,
    pub line_count: usize,
}

/// Built-in MCP security audit prompt template.
const BUILT_IN_TEMPLATE: &str = r#"## Role

You are an MCP security auditor. Your task is to analyze MCP (Model
Context Protocol) server source code for security vulnerabilities.

## MCP Vulnerability Taxonomy

MCP servers expose tools, resources, and prompts to AI models. The
following vulnerability categories are specific to MCP server contexts:

1. **Tool Poisoning** — A tool's description misrepresents its actual
   behavior, causing the calling AI to invoke it under false assumptions.
   Check whether tool descriptions match implementation.

2. **Prompt Injection** — User-controlled input reaches prompt
   construction or template rendering without sanitization, allowing
   injection of instructions that override system behavior.

3. **Command Injection** — MCP tool parameters flow into shell command
   execution (e.g., os.system, subprocess, exec, Command::new) without
   proper validation or sanitization.

4. **Path Traversal** — Tool parameters specifying file paths are not
   validated, allowing access to files outside intended directories
   (e.g., ../ escapes, absolute paths to sensitive files).

5. **Credential Leaks** — API keys, tokens, or secrets are hardcoded in
   source, passed through tool parameters in plaintext, or logged
   unsafely.

6. **Capability Over-Exposure** — The MCP server exposes more tools or
   capabilities than necessary for its stated purpose. Each tool should
   be evaluated: does it need to exist? Could it be abused?

7. **Context Over-Sharing** — Tools that read or return large amounts of
   data (file contents, database dumps, memory/vector-store queries) may
   leak sensitive context to the calling AI model.

## Target Overview

- Project root: {target_root}
- Primary language: {language}

### Files

{file_list}

## Instructions

1. Read each source file thoroughly using available tools (Read, Grep,
   Glob). Focus on MCP tool/resource/prompt definitions and their
   implementations.

2. For each file, identify:
   - MCP entrypoints (tools, resources, prompts) — their names,
     descriptions, parameters
   - Where user-controlled parameters flow within the code
   - Dangerous operations (command execution, file I/O, network calls,
     deserialization) that consume these parameters
   - Missing validation, sanitization, or authorization checks
   - Tool descriptions that differ from actual implementation behavior

3. Prioritize findings that:
   - Are NOT trivially catchable by simple pattern matching (e.g.,
     grep for "subprocess" alone)
   - Involve semantic risks: logic flaws, auth bypass, composite
     vulnerabilities from tool combinations
   - Represent MCP-specific attack surfaces: prompt injection,
     capability over-exposure, context over-sharing

4. For each finding, provide:
   - A clear title describing the vulnerability
   - The exact file:line locations affected. Every location MUST be
     `path:LINE` with a single positive integer line number, using the
     exact path string as listed in the Files section above (e.g.
     `/abs/path/server.py:86`). Never use ranges (e.g. `10-20`), bare
     filenames without a line, or "around line N". The line MUST point
     at the actual vulnerable statement (the dangerous call), not at a
     comment, docstring, or function signature.
   - A reasoning summary explaining the risk
   - Code snippets as evidence
   - Your confidence level (high/medium/low)
   - Any limitations or caveats about your analysis

## Output Format

After completing your analysis, output EXACTLY ONE JSON block (wrapped in a
```json code fence) with TWO arrays:

1. `findings` — vulnerabilities you verified or discovered semantically.
2. `model_candidates` — new sink/source/sanitizer models you inferred while
   reading the code. A "model" is a reusable fact about a library function,
   NOT a single vulnerability. Only propose a model when you are confident it
   generalizes beyond the one call site you saw.

For each model candidate use:
- kind: "sink" (dangerous operation consuming untrusted data), "source"
  (user-controllable entrypoint), or "sanitizer" (function that neutralizes
  taint).
- name: the exact callee, e.g. "openpyxl.load_workbook".
- category: one of command_execution, dynamic_execution, file_read,
  file_write, file_delete, network_request, database_injection,
  deserialization, template_injection, path_traversal, prompt_injection,
  data_exfiltration.
- language: python | javascript | rust.
- argument: the 0-based index of the dangerous parameter (sink only).
- confidence: high | medium | low.
- evidence_snippets: the exact source lines that justify the model.
```

```json
{
  "findings": [
    { "candidate_title": "...", "affected_locations": ["path/to/file.rs:42"], "reasoning_summary": "...", "evidence_snippets": ["..."], "confidence": "high", "limitations": [] }
  ],
  "model_candidates": [
    { "kind": "sink", "name": "openpyxl.load_workbook", "category": "file_read", "language": "python", "argument": 0, "confidence": "medium", "evidence_snippets": ["wb = openpyxl.load_workbook(filepath)"] }
  ]
}
```

If you find NO vulnerabilities and NO models, return `{"findings": [], "model_candidates": []}`.

Begin your analysis now. Read the source files and identify
vulnerabilities.
"#;

/// Determine the primary language label from a slice of file summaries.
pub fn primary_language(files: &[FileSummary]) -> String {
    let mut counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    for f in files {
        *counts.entry(&f.language).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(lang, _)| lang.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Build the bullet list of files for template rendering.
pub fn file_list_text(files: &[FileSummary]) -> String {
    files
        .iter()
        .map(|f| format!("- {} ({}, {} lines)", f.path, f.language, f.line_count))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Load template content: custom file path if provided, otherwise built-in.
fn load_template(custom_path: Option<&str>) -> Result<String> {
    match custom_path {
        Some(path) => {
            let p = Path::new(path);
            if !p.exists() {
                bail!("prompt template not found: {}", path);
            }
            fs::read_to_string(p)
                .with_context(|| format!("read prompt template: {}", path))
        }
        None => Ok(BUILT_IN_TEMPLATE.to_string()),
    }
}

/// Render the prompt template with variable substitution.
pub fn render(
    custom_template_path: Option<&str>,
    files: &[FileSummary],
    target_root: &str,
) -> Result<String> {
    let template = load_template(custom_template_path)?;
    let language = primary_language(files);
    let file_list = file_list_text(files);

    let prompt = template
        .replace("{target_root}", target_root)
        .replace("{language}", &language)
        .replace("{file_list}", &file_list);

    Ok(prompt)
}

/// 注入验证提示词的一条 finding 引用。
// M3 接线：两阶段编排在阶段 2 用 a-only 分区渲染 `prompt'`。接线前仅单测驱动。
#[allow(dead_code)]
pub(crate) struct PromptFinding {
    pub(crate) location: String, // "file:line"
    pub(crate) category: String,
    pub(crate) note: String,     // 证据，或「为什么可能是误报」
}

/// 渲染验证提示词（`prompt'`）：基础 prompt 加上两段标签——a1 项「请复核」（你可能漏了）
/// 和 a2 项「请勿重复报告」（这些疑似误报）。
// M3 接线：阶段 2 用阶段 1 的 a-only（a1 复核 / a2 勿重复）填充这两段。
#[allow(dead_code)]
pub(crate) fn render_verification_prompt(
    base: &str,
    recheck: &[PromptFinding],
    do_not_report: &[PromptFinding],
) -> String {
    let mut out = base.to_string();
    if !recheck.is_empty() {
        out.push_str("\n\n## 上一轮标准工具发现、但你可能遗漏的（请重点复核是否真实）\n");
        for f in recheck {
            out.push_str(&format!("- {} ({})：{}\n", f.location, f.category, f.note));
        }
    }
    if !do_not_report.is_empty() {
        out.push_str("\n## 上一轮标准工具报告、但疑似误报的（请勿重复报告）\n");
        for f in do_not_report {
            out.push_str(&format!("- {} ({})：{}\n", f.location, f.category, f.note));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_builtin_template_substitutes_variables() {
        let files = vec![
            FileSummary {
                path: "src/main.rs".into(),
                language: "rust".into(),
                line_count: 100,
            },
            FileSummary {
                path: "src/lib.rs".into(),
                language: "rust".into(),
                line_count: 50,
            },
        ];
        let prompt = render(None, &files, "/tmp/test-project")
            .expect("render template");
        assert!(prompt.contains("/tmp/test-project"));
        assert!(prompt.contains("rust"));
        assert!(prompt.contains("src/main.rs"));
        assert!(prompt.contains("100 lines"));
        assert!(prompt.contains("src/lib.rs"));
        assert!(prompt.contains("50 lines"));
        // Verify key template sections are present
        assert!(prompt.contains("Tool Poisoning"));
        assert!(prompt.contains("Command Injection"));
        assert!(prompt.contains("## Output Format"));
    }

    #[test]
    fn render_missing_custom_template_fails() {
        let err = render(
            Some("/nonexistent/path/template.md"),
            &[],
            "/tmp/test",
        )
        .expect_err("missing template should fail");
        assert!(err.to_string().contains("prompt template not found"));
    }

    #[test]
    fn primary_language_picks_most_common() {
        let files = vec![
            FileSummary { path: "a.py".into(), language: "python".into(), line_count: 10 },
            FileSummary { path: "b.py".into(), language: "python".into(), line_count: 20 },
            FileSummary { path: "c.js".into(), language: "javascript".into(), line_count: 5 },
        ];
        assert_eq!(primary_language(&files), "python");
    }

    #[test]
    fn primary_language_empty_returns_unknown() {
        assert_eq!(primary_language(&[]), "unknown");
    }

    #[test]
    fn file_list_text_formats_correctly() {
        let files = vec![FileSummary {
            path: "server.py".into(),
            language: "python".into(),
            line_count: 42,
        }];
        let text = file_list_text(&files);
        assert_eq!(text, "- server.py (python, 42 lines)");
    }

    #[test]
    fn render_builtin_template_requires_precise_line_numbers() {
        let prompt = render(None, &[], "/tmp/test").expect("render");
        assert!(prompt.contains("single positive integer line number"));
        assert!(prompt.contains("model_candidates"));
    }

    #[test]
    fn renders_recheck_and_do_not_report_sections() {
        let base = "Role: auditor\n";
        let out = render_verification_prompt(
            base,
            &[PromptFinding { location: "a.py:10".into(), category: "command_execution".into(), note: "os.system(cmd)".into() }],
            &[PromptFinding { location: "b.py:20".into(), category: "network_request".into(), note: "get_excel_path is local".into() }],
        );
        assert!(out.contains("请重点复核"));
        assert!(out.contains("a.py:10"));
        assert!(out.contains("请勿重复报告"));
        assert!(out.contains("b.py:20"));
        assert!(out.starts_with(base));
    }

    #[test]
    fn empty_inputs_return_base_unchanged() {
        let base = "just the base\n";
        assert_eq!(render_verification_prompt(base, &[], &[]), base);
    }
}
