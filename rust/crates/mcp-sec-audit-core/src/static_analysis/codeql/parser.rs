use anyhow::Result;

use crate::model::{CodeqlAnalysisResult, DataFlowPath, DataFlowPathStep, Location, Severity};
use crate::static_analysis::category::{is_known_category, normalize_category};

/// Metadata attached to every result from this CodeQL run.
#[derive(Debug, Clone)]
pub struct CodeqlMetadata {
    pub query_source: String, // "built-in" or custom path
    pub languages: Vec<String>,
}

fn normalize_tag(tag: &str) -> String {
    tag.trim()
        .replace('-', "_")
        .replace(' ', "_")
        .to_lowercase()
}

/// Extract a shared-vocabulary category from a SARIF rule's `properties.tags`.
fn category_from_tags(rule: &serde_json::Value) -> Option<String> {
    let tags = rule.get("properties")?.get("tags")?;
    let list: Vec<String> = if let Some(arr) = tags.as_array() {
        arr.iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect()
    } else if let Some(s) = tags.as_str() {
        s.split(',').map(|t| t.trim().to_string()).collect()
    } else {
        return None;
    };
    list.iter().find_map(|t| {
        let n = normalize_tag(t);
        is_known_category(&n).then(|| normalize_category(&n))
    })
}

/// Curated map from official CodeQL rule ids to shared categories.
fn category_from_rule_id(rule_id: &str) -> Option<String> {
    let cat = match rule_id {
        "rust/sql-injection" => "database_injection",
        "rust/request-forgery" => "network_request",
        "rust/path-injection" => "path_traversal",
        "rust/access-invalid-pointer" | "rust/access-after-lifetime-ended" => "unsafe_block",
        "py/cmd-injection" | "py/command-injection" => "command_execution",
        "py/sql-injection" => "database_injection",
        "py/ssrf" => "network_request",
        "py/path-injection" => "path_traversal",
        "py/deserialization" => "deserialization",
        "py/code-injection" => "dynamic_execution",
        "js/command-line-injection" => "command_execution",
        "js/sql-injection" => "database_injection",
        "js/ssrf" => "network_request",
        "js/path-injection" => "path_traversal",
        "js/code-injection" => "dynamic_execution",
        _ => return None,
    };
    Some(cat.to_string())
}

/// Resolve a result's category: our query's `@tags` first, then the curated
/// official rule_id map, then "uncategorized".
pub fn resolve_category(rule_id: &str, rule: Option<&serde_json::Value>) -> String {
    if let Some(rule) = rule {
        if let Some(cat) = category_from_tags(rule) {
            return cat;
        }
    }
    category_from_rule_id(rule_id).unwrap_or_else(|| "uncategorized".to_string())
}

/// Parse SARIF v2.1.0 JSON output from CodeQL into structured results.
pub fn parse_sarif(
    sarif_json: &str,
    metadata: &CodeqlMetadata,
) -> Result<Vec<CodeqlAnalysisResult>> {
    let root: serde_json::Value = serde_json::from_str(sarif_json)
        .map_err(|e| anyhow::anyhow!("invalid SARIF JSON: {}", e))?;

    let runs = root["runs"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("SARIF missing 'runs' array"))?;

    let mut results = Vec::new();

    for (run_idx, run) in runs.iter().enumerate() {
        let tool_name = run["tool"]["driver"]["name"].as_str().unwrap_or("CodeQL");

        let rule_index: std::collections::HashMap<&str, &serde_json::Value> = run["tool"]["driver"]
            ["rules"]
            .as_array()
            .map(|rules| {
                rules
                    .iter()
                    .filter_map(|r| r["id"].as_str().map(|id| (id, r)))
                    .collect()
            })
            .unwrap_or_default();

        let sarif_results = match run["results"].as_array() {
            Some(arr) => arr,
            None => continue,
        };

        for (result_idx, sr) in sarif_results.iter().enumerate() {
            let rule_id = match sr["ruleId"].as_str() {
                Some(id) => id.to_string(),
                None => continue, // skip results without ruleId
            };

            let rule_name = rule_index
                .get(rule_id.as_str())
                .and_then(|r| r["name"].as_str())
                .unwrap_or(&rule_id)
                .to_string();

            let rule = rule_index.get(rule_id.as_str()).copied();
            let category = resolve_category(&rule_id, rule);

            let message = sr["message"]["text"].as_str().unwrap_or("").to_string();

            if message.is_empty() {
                continue;
            }

            let severity = parse_severity(
                sr.get("level").and_then(|l| l.as_str()),
                rule_index
                    .get(rule_id.as_str())
                    .and_then(|r| r["defaultConfiguration"]["level"].as_str()),
            );

            let locations = parse_locations(sr.get("locations"));

            if locations.is_empty() {
                continue; // must have at least one location
            }

            let dataflow_path = parse_code_flows(sr.get("codeFlows"));

            // Extract the raw SARIF snippet for this result
            let sarif_snippet = serde_json::to_string_pretty(sr).ok();

            let result_id = format!(
                "codeql:{}:{}:r{}:{}",
                tool_name, rule_id, run_idx, result_idx
            );

            results.push(CodeqlAnalysisResult {
                result_id,
                rule_id,
                rule_name,
                category,
                query_source: metadata.query_source.clone(),
                languages: metadata.languages.clone(),
                message,
                severity,
                locations,
                dataflow_path,
                sarif_snippet,
                related_rule_ids: Vec::new(),
                related_taint_ids: Vec::new(),
                related_agent_ids: Vec::new(),
                verification_status: "uncorroborated".to_string(),
                limitations: Vec::new(),
            });
        }
    }

    Ok(results)
}

fn parse_severity(result_level: Option<&str>, rule_level: Option<&str>) -> Severity {
    let level = result_level.or(rule_level).unwrap_or("warning");
    match level {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "note" => Severity::Low,
        _ => Severity::Medium,
    }
}

fn parse_locations(locations_val: Option<&serde_json::Value>) -> Vec<Location> {
    let arr = match locations_val.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };

    arr.iter()
        .filter_map(|loc| {
            let pl = &loc["physicalLocation"];
            let artifact = pl["artifactLocation"]["uri"].as_str()?;
            let region = &pl["region"];
            let line = region["startLine"].as_u64().map(|l| l as u32).unwrap_or(1);
            let column = region["startColumn"].as_u64().map(|c| c as u32);
            let message = loc["message"]["text"].as_str().map(|s| s.to_string());
            Some(Location {
                file: artifact.to_string(),
                line,
                column,
                message,
            })
        })
        .collect()
}

fn parse_code_flows(code_flows_val: Option<&serde_json::Value>) -> Option<DataFlowPath> {
    let flows = code_flows_val?.as_array()?;
    if flows.is_empty() {
        return None;
    }

    // Take the first codeFlow's threadFlows
    let thread_flows = flows[0]["threadFlows"].as_array()?;
    if thread_flows.is_empty() {
        return None;
    }

    let mut steps = Vec::new();
    for tf in thread_flows {
        let locations = tf["locations"].as_array()?;
        for loc in locations {
            let pl = &loc["location"]["physicalLocation"];
            let artifact = pl["artifactLocation"]["uri"].as_str()?;
            let region = &pl["region"];
            let line = region["startLine"].as_u64().map(|l| l as u32).unwrap_or(1);
            let column = region["startColumn"].as_u64().map(|c| c as u32);
            let snippet = loc["location"]["message"]["text"]
                .as_str()
                .map(|s| s.to_string());

            steps.push(DataFlowPathStep {
                location: Location {
                    file: artifact.to_string(),
                    line,
                    column,
                    message: None,
                },
                snippet,
            });
        }
    }

    if steps.is_empty() {
        None
    } else {
        Some(DataFlowPath { steps })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_sarif_with_result() -> String {
        r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "rules": [{
          "id": "py/command-injection",
          "name": "Uncontrolled command line"
        }]
      }
    },
    "results": [{
      "ruleId": "py/command-injection",
      "level": "error",
      "message": { "text": "This command depends on user input." },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "server.py" },
          "region": { "startLine": 42, "startColumn": 10 }
        }
      }]
    }]
  }]
}"#
        .to_string()
    }

    fn metadata() -> CodeqlMetadata {
        CodeqlMetadata {
            query_source: "built-in".to_string(),
            languages: vec!["python".to_string()],
        }
    }

    #[test]
    fn parse_valid_sarif_returns_result() {
        let sarif = minimal_sarif_with_result();
        let results = parse_sarif(&sarif, &metadata()).expect("parse SARIF");
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.rule_id, "py/command-injection");
        assert_eq!(r.rule_name, "Uncontrolled command line");
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.locations.len(), 1);
        assert_eq!(r.locations[0].file, "server.py");
        assert_eq!(r.locations[0].line, 42);
        assert_eq!(r.verification_status, "uncorroborated");
    }

    #[test]
    fn empty_runs_returns_empty() {
        let sarif = r#"{"version": "2.1.0", "runs": []}"#;
        let results = parse_sarif(sarif, &metadata()).expect("parse empty SARIF");
        assert!(results.is_empty());
    }

    #[test]
    fn invalid_json_returns_error() {
        let err = parse_sarif("not json", &metadata()).expect_err("invalid JSON should fail");
        assert!(err.to_string().contains("invalid SARIF JSON"));
    }

    #[test]
    fn missing_runs_key_returns_error() {
        let sarif = r#"{"version": "2.1.0"}"#;
        let err = parse_sarif(sarif, &metadata()).expect_err("missing runs should fail");
        assert!(err.to_string().contains("missing 'runs'"));
    }

    #[test]
    fn skips_results_without_rule_id() {
        let sarif = r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "CodeQL", "rules": [] } },
    "results": [{
      "message": { "text": "No rule here." },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "server.py" },
          "region": { "startLine": 1 }
        }
      }]
    }]
  }]
}"#;
        let results = parse_sarif(sarif, &metadata()).expect("parse SARIF");
        assert!(
            results.is_empty(),
            "results without ruleId should be skipped"
        );
    }

    #[test]
    fn skips_results_with_empty_message() {
        let sarif = r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "CodeQL", "rules": [{ "id": "x/t", "name": "Test" }] } },
    "results": [{
      "ruleId": "x/t",
      "message": { "text": "" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "server.py" },
          "region": { "startLine": 1 }
        }
      }]
    }]
  }]
}"#;
        let results = parse_sarif(sarif, &metadata()).expect("parse SARIF");
        assert!(
            results.is_empty(),
            "results with empty message should be skipped"
        );
    }

    #[test]
    fn parse_code_flows_when_present() {
        let sarif = r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "rules": [{ "id": "py/test", "name": "Test" }]
      }
    },
    "results": [{
      "ruleId": "py/test",
      "message": { "text": "Data flows to sink." },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "server.py" },
          "region": { "startLine": 42 }
        }
      }],
      "codeFlows": [{
        "threadFlows": [{
          "locations": [
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "server.py" },
                  "region": { "startLine": 10 }
                },
                "message": { "text": "source" }
              }
            },
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "server.py" },
                  "region": { "startLine": 42 }
                },
                "message": { "text": "sink" }
              }
            }
          ]
        }]
      }]
    }]
  }]
}"#;
        let results = parse_sarif(sarif, &metadata()).expect("parse SARIF");
        let r = &results[0];
        assert!(r.dataflow_path.is_some());
        let dfp = r.dataflow_path.as_ref().unwrap();
        assert_eq!(dfp.steps.len(), 2);
        assert_eq!(dfp.steps[0].location.line, 10);
        assert_eq!(dfp.steps[1].location.line, 42);
    }

    #[test]
    fn multiple_results_are_all_parsed() {
        let sarif = r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "rules": [
          { "id": "py/a", "name": "A" },
          { "id": "py/b", "name": "B" }
        ]
      }
    },
    "results": [
      {
        "ruleId": "py/a",
        "message": { "text": "Issue A." },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "a.py" },
            "region": { "startLine": 1 }
          }
        }]
      },
      {
        "ruleId": "py/b",
        "message": { "text": "Issue B." },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "b.py" },
            "region": { "startLine": 2 }
          }
        }]
      }
    ]
  }]
}"#;
        let results = parse_sarif(sarif, &metadata()).expect("parse SARIF");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn extracts_category_from_tags_and_rule_id_map() {
        // Our query: @tags carry the category directly (kebab → snake).
        assert_eq!(
            resolve_category(
                "mcp/python/command-execution",
                Some(&serde_json::json!({
                    "properties": { "tags": ["security", "mcp", "command-execution"] }
                }))
            ),
            "command_execution"
        );
        // Official query: curated rule_id → category map.
        assert_eq!(
            resolve_category("rust/sql-injection", None),
            "database_injection"
        );
        assert_eq!(
            resolve_category("rust/request-forgery", None),
            "network_request"
        );
        assert_eq!(
            resolve_category("rust/access-after-lifetime-ended", None),
            "unsafe_block"
        );
        // Unknown: uncategorized fallback.
        assert_eq!(
            resolve_category("rust/unknown-thing", None),
            "uncategorized"
        );
    }

    #[test]
    fn tags_use_shared_alias_normalization() {
        // A tag using a rule-style alias must normalize to the canonical category.
        assert_eq!(
            resolve_category(
                "mcp/python/command-exec",
                Some(&serde_json::json!({
                    "properties": { "tags": ["mcp", "command_exec"] }
                }))
            ),
            "command_execution"
        );
    }
}
