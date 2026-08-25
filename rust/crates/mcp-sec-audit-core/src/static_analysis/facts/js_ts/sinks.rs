use std::collections::BTreeMap;

use crate::model::{Fact, FactBase, SinkFact};
use crate::models::SinkModel;

pub(crate) fn check_sink(
    normalized_callee: &str,
    call_id: &str,
    line: u32,
    file: &str,
    extractor_name: &str,
    facts: &mut Vec<Fact>,
    sinks: &[SinkModel],
) {
    for model in sinks {
        if matches_sink(normalized_callee, &model.patterns) {
            facts.push(Fact::Sink(SinkFact {
                base: FactBase {
                    id: format!("sink:{}:{}:{}", model.category, file, line),
                    file: file.to_string(),
                    line,
                    extractor: extractor_name.to_string(),
                },
                call_id: call_id.to_string(),
                category: model.category.clone(),
                rule_id: model.rule_id(),
                sink_name: normalized_callee.to_string(),
                severity_base: model.severity.clone(),
                reason: model.reason.clone(),
                conditions: BTreeMap::new(),
                confidence: model.confidence.clone(),
            }));
            return;
        }
    }
}

fn matches_sink(callee: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        callee == pattern
            || callee.ends_with(&format!(".{pattern}"))
            || callee.starts_with(&format!("{pattern}."))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::default_catalog;

    fn category_for(callee: &str) -> Option<String> {
        default_catalog()
            .sinks_for_language("javascript")
            .iter()
            .find(|m| matches_sink(callee, &m.patterns))
            .map(|m| m.category.clone())
    }

    #[test]
    fn classifies_extended_js_sinks() {
        assert_eq!(
            category_for("child_process.execSync").as_deref(),
            Some("command_execution")
        );
        assert_eq!(
            category_for("fs.readFileSync").as_deref(),
            Some("file_read")
        );
        assert_eq!(
            category_for("fs.unlinkSync").as_deref(),
            Some("file_delete")
        );
        assert_eq!(
            category_for("https.get").as_deref(),
            Some("network_request")
        );
        assert_eq!(category_for("process.env").as_deref(), Some("env_access"));
        assert_eq!(
            category_for("pg.query").as_deref(),
            Some("database_injection")
        );
        assert_eq!(
            category_for("ejs.render").as_deref(),
            Some("template_injection")
        );
        assert_eq!(category_for("eval").as_deref(), Some("dynamic_execution"));
        assert_eq!(
            category_for("vm.runInNewContext").as_deref(),
            Some("deserialization_rce")
        );
    }
}
