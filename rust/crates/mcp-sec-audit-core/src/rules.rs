use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndicatorRule {
    pub languages: Vec<String>,
    #[serde(rename = "type")]
    pub indicator_type: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default = "default_case_sensitive")]
    pub case_sensitive: bool,
    #[serde(default)]
    pub confidence_boost: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityRule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub weight: f64,
    #[serde(default = "default_base_confidence")]
    pub base_confidence: f64,
    #[serde(default)]
    pub indicators: Vec<IndicatorRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleBook {
    pub capabilities: BTreeMap<String, CapabilityRule>,
}

#[derive(Debug, Deserialize)]
struct RawRuleBook {
    #[serde(default)]
    capabilities: Vec<RawCapabilityRule>,
}

#[derive(Debug, Deserialize)]
struct RawCapabilityRule {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    weight: f64,
    #[serde(default = "default_base_confidence")]
    base_confidence: f64,
    #[serde(default)]
    indicators: Vec<RawIndicatorRule>,
}

#[derive(Debug, Deserialize)]
struct RawIndicatorRule {
    #[serde(default)]
    languages: Vec<String>,
    #[serde(default = "default_indicator_type", rename = "type")]
    indicator_type: String,
    #[serde(default)]
    patterns: Vec<String>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default = "default_case_sensitive")]
    case_sensitive: bool,
    #[serde(default)]
    confidence_boost: f64,
}

impl RuleBook {
    pub fn for_language(&self, language: &str) -> BTreeMap<String, CapabilityRule> {
        let key = language.to_lowercase();
        self.capabilities
            .iter()
            .filter(|(_, rule)| {
                rule.indicators
                    .iter()
                    .any(|indicator| indicator.languages.iter().any(|lang| lang == &key))
            })
            .map(|(name, rule)| (name.clone(), rule.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }
}

pub fn parse_rulebook_toml(input: &str) -> Result<RuleBook> {
    let raw: RawRuleBook = toml::from_str(input).context("parse rulebook TOML")?;
    let mut capabilities = BTreeMap::new();

    for capability in raw.capabilities {
        let mut indicators = Vec::new();
        for indicator in capability.indicators {
            indicators.push(parse_indicator(indicator, &capability.name)?);
        }

        let name = capability.name;
        capabilities.insert(
            name.clone(),
            CapabilityRule {
                name,
                description: capability.description,
                weight: capability.weight,
                base_confidence: capability.base_confidence,
                indicators,
            },
        );
    }

    Ok(RuleBook { capabilities })
}

pub fn load_rulebook(path: &Path) -> Result<RuleBook> {
    let input = fs::read_to_string(path)
        .with_context(|| format!("read rulebook from {}", path.display()))?;
    parse_rulebook_toml(&input)
}

fn parse_indicator(raw: RawIndicatorRule, capability_name: &str) -> Result<IndicatorRule> {
    if raw.languages.is_empty() {
        bail!("Indicator in capability '{capability_name}' is missing 'languages' definition");
    }

    let languages = raw
        .languages
        .into_iter()
        .map(|language| language.to_lowercase())
        .collect::<Vec<_>>();
    let indicator_type = raw.indicator_type.to_lowercase();

    match indicator_type.as_str() {
        "keyword" => {
            if raw.patterns.is_empty() {
                bail!("Keyword indicator in capability '{capability_name}' requires 'patterns'");
            }
        }
        "regex" => {
            if raw.pattern.as_deref().unwrap_or_default().is_empty() {
                bail!("Regex indicator in capability '{capability_name}' requires 'pattern'");
            }
        }
        _ => bail!(
            "Unsupported indicator type '{}' in capability '{}'",
            indicator_type,
            capability_name
        ),
    }

    Ok(IndicatorRule {
        languages,
        indicator_type,
        patterns: raw.patterns,
        pattern: raw.pattern,
        case_sensitive: raw.case_sensitive,
        confidence_boost: raw.confidence_boost,
    })
}

fn default_indicator_type() -> String {
    "keyword".to_string()
}

fn default_case_sensitive() -> bool {
    true
}

fn default_base_confidence() -> f64 {
    0.3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rulebook_parses_keyword_and_regex_indicators() {
        let rulebook = parse_rulebook_toml(
            r#"
            [[capabilities]]
            name = "command_exec"
            description = "Command execution"
            weight = 25.0
            base_confidence = 0.4

              [[capabilities.indicators]]
              languages = ["Python"]
              type = "keyword"
              patterns = ["subprocess."]

              [[capabilities.indicators]]
              languages = ["python"]
              type = "regex"
              pattern = "subprocess\\.(run|Popen)"
            "#,
        )
        .expect("parse rulebook");

        let rule = rulebook
            .capabilities
            .get("command_exec")
            .expect("command_exec rule");
        assert_eq!(rule.indicators.len(), 2);
        assert_eq!(rule.indicators[0].languages, vec!["python"]);
        assert_eq!(rule.indicators[1].indicator_type, "regex");
    }

    #[test]
    fn rulebook_filters_by_language() {
        let rulebook = parse_rulebook_toml(
            r#"
            [[capabilities]]
            name = "command_exec"
              [[capabilities.indicators]]
              languages = ["python"]
              patterns = ["subprocess."]

            [[capabilities]]
            name = "metadata_risk"
              [[capabilities.indicators]]
              languages = ["metadata"]
              patterns = ["shell"]
            "#,
        )
        .expect("parse rulebook");

        assert!(rulebook.for_language("python").contains_key("command_exec"));
        assert!(
            !rulebook
                .for_language("python")
                .contains_key("metadata_risk")
        );
        assert!(
            rulebook
                .for_language("metadata")
                .contains_key("metadata_risk")
        );
    }

    #[test]
    fn invalid_keyword_indicator_is_rejected() {
        let err = parse_rulebook_toml(
            r#"
            [[capabilities]]
            name = "bad"
              [[capabilities.indicators]]
              languages = ["python"]
              type = "keyword"
            "#,
        )
        .expect_err("missing keyword patterns should fail");

        assert!(err.to_string().contains("requires 'patterns'"));
    }

    #[test]
    fn invalid_regex_indicator_is_rejected() {
        let err = parse_rulebook_toml(
            r#"
            [[capabilities]]
            name = "bad"
              [[capabilities.indicators]]
              languages = ["python"]
              type = "regex"
            "#,
        )
        .expect_err("missing regex pattern should fail");

        assert!(err.to_string().contains("requires 'pattern'"));
    }
}
