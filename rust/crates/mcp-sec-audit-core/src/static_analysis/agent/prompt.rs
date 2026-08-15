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
     `relative/path:LINE` with a single positive integer line number
     (e.g. `server.py:86`). Never use ranges (e.g. `10-20`), bare
     filenames without a line, or "around line N". The line MUST point
     at the actual vulnerable statement (the dangerous call), not at a
     comment, docstring, or function signature.
   - A reasoning summary explaining the risk
   - Code snippets as evidence
   - Your confidence level (high/medium/low)
   - Any limitations or caveats about your analysis

## Output Format

After completing your analysis, output EXACTLY ONE JSON block (wrapped
in a ```json code fence) containing all findings. Do not include any
other JSON blocks in your response.

Before emitting each finding, re-read the cited file to confirm each
line number is correct; a finding with an imprecise location will be
discarded.

```json
{
  "findings": [
    {
      "candidate_title": "Clear vulnerability description",
      "affected_locations": ["path/to/file.rs:42", "path/to/file.rs:58"],
      "reasoning_summary": "Explanation of why this is a vulnerability,
          how it could be exploited, and what the impact would be.",
      "evidence_snippets": [
        "let output = Command::new(\"sh\").arg(user_input).output()",
        "fn run_tool(cmd: String) {"
      ],
      "confidence": "high",
      "limitations": [
        "Did not verify if input validation happens in caller"
      ]
    }
  ]
}
```

If you find NO vulnerabilities, return:
```json
{"findings": []}
```

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
        assert!(prompt.contains("imprecise location will be"));
    }
}
