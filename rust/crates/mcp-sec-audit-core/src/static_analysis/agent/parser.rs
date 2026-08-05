use anyhow::Result;
use serde::Deserialize;

use crate::model::{AgentAnalysisResult, Confidence};

/// Metadata attached to every agent-produced result.
pub struct AgentMetadata {
    pub agent_id: String,
    pub prompt_profile: String,
    pub input_scope: Vec<String>,
}

/// Raw finding from agent JSON output before enrichment.
#[derive(Debug, Deserialize)]
struct RawFinding {
    candidate_title: String,
    #[serde(default)]
    affected_locations: Vec<String>,
    #[serde(default)]
    reasoning_summary: String,
    #[serde(default)]
    evidence_snippets: Vec<String>,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawOutput {
    #[serde(default)]
    findings: Vec<RawFinding>,
}

/// Hardcoded minimum confidence threshold. Findings whose confidence is not
/// recognized (or ranks below this level) are discarded. Since "low" is the
/// lowest recognized level, every recognized confidence passes; only
/// unrecognized values fail.
const MIN_CONFIDENCE: &str = "low";

fn parse_confidence(raw: &str) -> Confidence {
    match raw.to_lowercase().as_str() {
        "high" => Confidence::High,
        "medium" => Confidence::Medium,
        "low" => Confidence::Low,
        _ => Confidence::Low,
    }
}

fn confidence_meets_threshold(confidence: &str) -> bool {
    let rank = |level: &str| match level {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    };
    let raw = confidence.to_lowercase();
    rank(raw.as_str()) <= rank(MIN_CONFIDENCE)
}

/// Truncate a string at a UTF-8 character boundary for error messages.
fn truncate_for_display(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Locate the JSON block in agent output.
/// Tries ```json ... ``` code fence first, then bare { ... }.
fn extract_json_block(stdout: &str) -> Option<&str> {
    // Try fenced JSON block
    if let Some(start) = stdout.find("```json") {
        let after_fence = &stdout[start + 7..];
        if let Some(end) = after_fence.find("```") {
            return Some(after_fence[..end].trim());
        }
    }
    // Try bare JSON object
    if let Some(start) = stdout.find("{\"findings\"") {
        return Some(&stdout[start..]);
    }
    // Also try { "findings" (with space)
    if let Some(start) = stdout.find("{ \"findings\"") {
        return Some(&stdout[start..]);
    }
    None
}

/// Parse agent stdout into structured results.
pub fn parse_agent_output(
    stdout: &str,
    metadata: &AgentMetadata,
) -> Result<Vec<AgentAnalysisResult>> {
    let json_str = extract_json_block(stdout)
        .ok_or_else(|| anyhow::anyhow!(
            "no valid JSON output from agent provider. \
             Expected a ```json code fence or a {{\"findings\": [...]}} block.\n\
             Raw output (first 500 chars): {}",
            truncate_for_display(stdout, 500)
        ))?;

    let raw: RawOutput = serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!(
            "failed to parse agent JSON output: {}\n\
             JSON excerpt (first 500 chars): {}",
            e,
            truncate_for_display(json_str, 500)
        ))?;

    let mut results = Vec::new();
    for (i, finding) in raw.findings.into_iter().enumerate() {
        // Validate required fields
        if finding.candidate_title.trim().is_empty() {
            continue; // skip empty titles, don't fail the whole batch
        }
        if finding.affected_locations.is_empty() {
            continue; // skip findings without locations
        }
        if finding.reasoning_summary.trim().is_empty() {
            continue;
        }

        if !confidence_meets_threshold(&finding.confidence) {
            continue; // confidence too low
        }

        results.push(AgentAnalysisResult {
            result_id: format!("agent:{}:{}", metadata.agent_id, i),
            agent_id: metadata.agent_id.clone(),
            prompt_profile: metadata.prompt_profile.clone(),
            model_provider: Some(metadata.agent_id.clone()),
            input_scope: metadata.input_scope.clone(),
            candidate_title: finding.candidate_title,
            affected_locations: finding.affected_locations,
            reasoning_summary: finding.reasoning_summary,
            evidence_snippets: finding.evidence_snippets,
            related_rule_result_ids: Vec::new(),    // Phase 13
            related_taint_result_ids: Vec::new(),   // Phase 13
            confidence: parse_confidence(&finding.confidence),
            verification_status: "uncorroborated".to_string(), // Phase 13
            limitations: finding.limitations,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> AgentMetadata {
        AgentMetadata {
            agent_id: "test-agent".to_string(),
            prompt_profile: "mcp_security_audit".to_string(),
            input_scope: vec!["test.py".to_string()],
        }
    }

    #[test]
    fn parse_fenced_json_block() {
        let stdout = r#"
Some preamble text...

```json
{
  "findings": [
    {
      "candidate_title": "Command injection in run_cmd",
      "affected_locations": ["server.py:42"],
      "reasoning_summary": "User input flows to os.system without validation",
      "evidence_snippets": ["os.system(cmd)"],
      "confidence": "high",
      "limitations": []
    }
  ]
}
```

Some trailing text.
"#;
        let results = parse_agent_output(stdout, &metadata()).expect("parse");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].candidate_title, "Command injection in run_cmd");
        assert_eq!(results[0].affected_locations, vec!["server.py:42"]);
        assert_eq!(results[0].confidence, Confidence::High);
        assert_eq!(results[0].verification_status, "uncorroborated");
        assert!(results[0].related_rule_result_ids.is_empty());
        assert!(results[0].related_taint_result_ids.is_empty());
        assert_eq!(results[0].agent_id, "test-agent");
    }

    #[test]
    fn parse_bare_json() {
        let stdout = r#"{"findings":[{"candidate_title":"Test","affected_locations":["a.rs:1"],"reasoning_summary":"x","confidence":"medium"}]}"#;
        let results = parse_agent_output(stdout, &metadata()).expect("parse");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].confidence, Confidence::Medium);
    }

    #[test]
    fn no_json_returns_error() {
        let stdout = "Just some random text without any JSON.";
        let err = parse_agent_output(stdout, &metadata()).expect_err("should fail");
        assert!(err.to_string().contains("no valid JSON output"));
    }

    #[test]
    fn invalid_json_returns_error() {
        let stdout = r#"```json
{"findings": [{"candidate_title": "incomplete
```"#;
        let err = parse_agent_output(stdout, &metadata()).expect_err("should fail");
        assert!(err.to_string().contains("failed to parse"));
    }

    #[test]
    fn empty_findings_returns_empty_vec() {
        let stdout = r#"```json
{"findings": []}
```"#;
        let results = parse_agent_output(stdout, &metadata()).expect("parse");
        assert!(results.is_empty());
    }

    #[test]
    fn skips_invalid_entries() {
        let stdout = r#"```json
{
  "findings": [
    {
      "candidate_title": "",
      "affected_locations": [],
      "reasoning_summary": "",
      "confidence": "high"
    },
    {
      "candidate_title": "Valid finding",
      "affected_locations": ["f.rs:10"],
      "reasoning_summary": "This one is valid",
      "confidence": "high"
    }
  ]
}
```"#;
        let results = parse_agent_output(stdout, &metadata()).expect("parse");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].candidate_title, "Valid finding");
    }

    #[test]
    fn extract_json_handles_whitespace_variations() {
        // JSON with space after {
        let stdout = r#"{ "findings": [{"candidate_title":"T","affected_locations":["x:1"],"reasoning_summary":"r","confidence":"high"}] }"#;
        let results = parse_agent_output(stdout, &metadata()).expect("parse");
        assert_eq!(results.len(), 1);
    }
}
