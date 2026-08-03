use std::{collections::BTreeSet, fs};

use anyhow::{Context, Result};
use regex::RegexBuilder;
use serde_json::Value;

use crate::{
    CapabilityRule, Confidence, IndicatorRule, RuleAnalysisResult, RuleBook, Severity,
    static_analysis::{DiscoveredFile, ScanLanguage, pipeline::StaticScanContext},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RuleMatch {
    file: String,
    line: u32,
    matched_text: String,
}

#[derive(Debug, Default)]
struct CapabilityAccumulator {
    matches: Vec<RuleMatch>,
    files_with_hits: BTreeSet<String>,
    indicator_boosts: Vec<(String, f64)>,
}

pub fn analyze_rule_line(
    ctx: &StaticScanContext,
    rulebook: &RuleBook,
) -> Result<Vec<RuleAnalysisResult>> {
    let inputs = collect_inputs(&ctx.discovered_files)?;
    let mut results = Vec::new();

    for capability in rulebook.capabilities.values() {
        let mut accumulator = CapabilityAccumulator::default();

        for input in &inputs {
            for (indicator_index, indicator) in capability.indicators.iter().enumerate() {
                if !indicator_applies_to_language(indicator, input.language) {
                    continue;
                }

                let matches = match_indicator(indicator, &input.text).with_context(|| {
                    format!("match indicator for capability '{}'", capability.name)
                })?;
                if matches.is_empty() {
                    continue;
                }

                let indicator_key =
                    format!("{}:{}:{}", capability.name, input.language, indicator_index);
                if !accumulator
                    .indicator_boosts
                    .iter()
                    .any(|(key, _)| key == &indicator_key)
                {
                    accumulator
                        .indicator_boosts
                        .push((indicator_key, indicator.confidence_boost));
                }

                accumulator.files_with_hits.insert(input.file.clone());
                for matched in matches {
                    accumulator.matches.push(RuleMatch {
                        file: input.file.clone(),
                        line: line_number_for_offset(&input.text, matched.offset),
                        matched_text: matched.text,
                    });
                }
            }
        }

        if accumulator.matches.is_empty() {
            continue;
        }

        accumulator.matches.sort();
        let primary = accumulator
            .matches
            .first()
            .expect("non-empty matches after check");
        let evidence = accumulator
            .matches
            .iter()
            .map(|item| format!("{}:{}:{}", item.file, item.line, item.matched_text))
            .collect::<Vec<_>>();
        let confidence_score = confidence_score(capability, &accumulator);

        results.push(RuleAnalysisResult {
            result_id: format!("rule-result:{}:{}", capability.name, results.len() + 1),
            rule_id: capability.name.clone(),
            category: capability.name.clone(),
            owasp_mcp: None,
            file: primary.file.clone(),
            line: primary.line,
            matched_text: Some(primary.matched_text.clone()),
            evidence,
            severity: severity_from_weight(capability.weight),
            confidence: confidence_from_score(confidence_score),
            recommendation: None,
            related_facts_exist: false,
        });
    }

    Ok(results)
}

#[derive(Debug)]
struct RuleInput {
    file: String,
    language: &'static str,
    text: String,
}

#[derive(Debug)]
struct TextMatch {
    offset: usize,
    text: String,
}

fn collect_inputs(files: &[DiscoveredFile]) -> Result<Vec<RuleInput>> {
    let mut inputs = Vec::new();
    for file in files {
        let Some(text) = load_text_for_rule_analysis(file)? else {
            continue;
        };
        inputs.push(RuleInput {
            file: file.path.display().to_string(),
            language: effective_language(file),
            text,
        });
    }
    Ok(inputs)
}

fn effective_language(file: &DiscoveredFile) -> &'static str {
    match file.language {
        ScanLanguage::Python => "python",
        ScanLanguage::JavaScript => "javascript",
        ScanLanguage::TypeScript => "typescript",
        ScanLanguage::Rust => "rust",
        ScanLanguage::Json => "metadata",
    }
}

fn load_text_for_rule_analysis(file: &DiscoveredFile) -> Result<Option<String>> {
    let bytes = fs::read(&file.path)
        .with_context(|| format!("read discovered file {}", file.path.display()))?;
    let text = String::from_utf8_lossy(&bytes).to_string();

    if file.language != ScanLanguage::Json {
        return Ok(Some(text));
    }

    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return Ok(None);
    };
    let Some(tool_content) = value.get("tool_content").and_then(Value::as_str) else {
        return Ok(None);
    };
    if tool_content.is_empty() {
        return Ok(None);
    }

    Ok(Some(tool_content.to_string()))
}

fn indicator_applies_to_language(indicator: &IndicatorRule, language: &str) -> bool {
    indicator.languages.iter().any(|item| item == language)
}

fn match_indicator(indicator: &IndicatorRule, text: &str) -> Result<Vec<TextMatch>> {
    match indicator.indicator_type.as_str() {
        "keyword" => Ok(match_keyword_indicator(indicator, text)),
        "regex" => match_regex_indicator(indicator, text),
        _ => Ok(Vec::new()),
    }
}

fn match_keyword_indicator(indicator: &IndicatorRule, text: &str) -> Vec<TextMatch> {
    let haystack = if indicator.case_sensitive {
        text.to_string()
    } else {
        text.to_lowercase()
    };

    let mut matches = Vec::new();
    for pattern in &indicator.patterns {
        let needle = if indicator.case_sensitive {
            pattern.clone()
        } else {
            pattern.to_lowercase()
        };
        if let Some(offset) = haystack.find(&needle) {
            matches.push(TextMatch {
                offset,
                text: pattern.clone(),
            });
        }
    }
    matches
}

fn match_regex_indicator(indicator: &IndicatorRule, text: &str) -> Result<Vec<TextMatch>> {
    let Some(pattern) = indicator.pattern.as_deref() else {
        return Ok(Vec::new());
    };
    let regex = RegexBuilder::new(pattern)
        .case_insensitive(!indicator.case_sensitive)
        .build()
        .with_context(|| format!("compile regex indicator '{pattern}'"))?;

    Ok(regex
        .find_iter(text)
        .map(|matched| TextMatch {
            offset: matched.start(),
            text: matched.as_str().to_string(),
        })
        .collect())
}

fn line_number_for_offset(text: &str, offset: usize) -> u32 {
    text[..offset.min(text.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count() as u32
        + 1
}

fn confidence_score(capability: &CapabilityRule, accumulator: &CapabilityAccumulator) -> f64 {
    let files_with_hits = accumulator.files_with_hits.len() as f64;
    let total_hits = accumulator.matches.len() as f64;
    let extra_hits = (total_hits - files_with_hits).max(0.0);
    let boost = accumulator
        .indicator_boosts
        .iter()
        .map(|(_, value)| *value)
        .sum::<f64>();

    (capability.base_confidence + 0.1 * files_with_hits + 0.05 * extra_hits + boost).min(0.99)
}

fn confidence_from_score(score: f64) -> Confidence {
    if score >= 0.85 {
        Confidence::High
    } else if score >= 0.5 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

fn severity_from_weight(weight: f64) -> Severity {
    if weight >= 20.0 {
        Severity::High
    } else if weight >= 10.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{RuntimeConfig, parse_rulebook_toml, static_analysis::DiscoveredFile};

    #[test]
    fn python_keyword_match_produces_rule_result() {
        let root = temp_dir("rule-python-keyword");
        let file = root.join("server.py");
        fs::write(&file, "import subprocess\nsubprocess.run('id')\n").expect("write source");
        let rulebook = parse_rulebook_toml(
            r#"
            [[capabilities]]
            name = "command_exec"
            weight = 25.0
            base_confidence = 0.4
              [[capabilities.indicators]]
              languages = ["python"]
              patterns = ["subprocess.run"]
            "#,
        )
        .expect("parse rules");
        let ctx = context_with_files(vec![DiscoveredFile {
            path: file.clone(),
            language: ScanLanguage::Python,
        }]);

        let results = analyze_rule_line(&ctx, &rulebook).expect("analyze rules");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "command_exec");
        assert_eq!(results[0].severity, Severity::High);
        assert_eq!(results[0].line, 2);
        assert!(results[0].evidence[0].contains("subprocess.run"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn regex_indicator_detects_file_write() {
        let root = temp_dir("rule-regex");
        let file = root.join("server.py");
        fs::write(&file, "open('/tmp/out', 'w')\nopen('/tmp/other', 'a')\n").expect("write source");
        let rulebook = parse_rulebook_toml(
            r#"
            [[capabilities]]
            name = "file_write"
            weight = 15.0
            base_confidence = 0.35
              [[capabilities.indicators]]
              languages = ["python"]
              type = "regex"
              pattern = "open\\([^,]+,\\s*['\"](a|w)"
            "#,
        )
        .expect("parse rules");
        let ctx = context_with_files(vec![DiscoveredFile {
            path: file,
            language: ScanLanguage::Python,
        }]);

        let results = analyze_rule_line(&ctx, &rulebook).expect("analyze rules");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "file_write");
        assert_eq!(results[0].severity, Severity::Medium);
        assert_eq!(results[0].confidence, Confidence::Low);
        assert_eq!(results[0].evidence.len(), 2);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn metadata_tool_content_is_analyzed_case_insensitively() {
        let root = temp_dir("rule-metadata");
        let file = root.join("tool.json");
        fs::write(
            &file,
            r#"{"tool_content":"This tool can run BASH commands"}"#,
        )
        .expect("write metadata");
        let rulebook = parse_rulebook_toml(
            r#"
            [[capabilities]]
            name = "command_exec"
            weight = 25.0
              [[capabilities.indicators]]
              languages = ["metadata"]
              case_sensitive = false
              patterns = ["bash"]
            "#,
        )
        .expect("parse rules");
        let ctx = context_with_files(vec![DiscoveredFile {
            path: file,
            language: ScanLanguage::Json,
        }]);

        let results = analyze_rule_line(&ctx, &rulebook).expect("analyze metadata");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "command_exec");
        assert_eq!(results[0].matched_text.as_deref(), Some("bash"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn invalid_metadata_json_is_skipped() {
        let root = temp_dir("rule-invalid-json");
        let file = root.join("tool.json");
        fs::write(&file, "not json").expect("write metadata");
        let rulebook = parse_rulebook_toml(
            r#"
            [[capabilities]]
            name = "command_exec"
              [[capabilities.indicators]]
              languages = ["metadata"]
              patterns = ["bash"]
            "#,
        )
        .expect("parse rules");
        let ctx = context_with_files(vec![DiscoveredFile {
            path: file,
            language: ScanLanguage::Json,
        }]);

        let results = analyze_rule_line(&ctx, &rulebook).expect("analyze metadata");
        assert!(results.is_empty());

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn multiple_files_aggregate_into_single_capability_result() {
        let root = temp_dir("rule-aggregate");
        let first = root.join("a.py");
        let second = root.join("b.py");
        fs::write(&first, "subprocess.run('id')\n").expect("write first");
        fs::write(&second, "os.system('id')\n").expect("write second");
        let rulebook = parse_rulebook_toml(
            r#"
            [[capabilities]]
            name = "command_exec"
            weight = 25.0
            base_confidence = 0.7
              [[capabilities.indicators]]
              languages = ["python"]
              patterns = ["subprocess.run", "os.system"]
            "#,
        )
        .expect("parse rules");
        let ctx = context_with_files(vec![
            DiscoveredFile {
                path: second,
                language: ScanLanguage::Python,
            },
            DiscoveredFile {
                path: first,
                language: ScanLanguage::Python,
            },
        ]);

        let results = analyze_rule_line(&ctx, &rulebook).expect("analyze rules");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].evidence.len(), 2);
        assert_eq!(results[0].confidence, Confidence::High);
        assert!(results[0].evidence[0].contains("a.py"));
        assert!(results[0].evidence[1].contains("b.py"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    fn context_with_files(discovered_files: Vec<DiscoveredFile>) -> StaticScanContext {
        StaticScanContext {
            config: RuntimeConfig::default(),
            rulebook_paths: Vec::new(),
            discovered_files,
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mcp-sec-audit-{name}-{suffix}"));
        fs::create_dir_all(&root).expect("create temp dir");
        root
    }
}
