use std::collections::{BTreeMap, BTreeSet};

use super::recon::PackageInventory;
use crate::model::{CallFact, Confidence, Fact, FactBase, Severity, SinkFact};
use crate::models::{PackageRule, rule_prefix};

const EXTRACTOR_NAME: &str = "rust_semantic_inference";

const READ_PREFIXES: &[&str] = &["load", "read", "open"];
const WRITE_PREFIXES: &[&str] = &["save", "write", "dump", "to_"];

/// Layer 2: classify calls by their package's classification rule.
/// Skips calls that already produced a manual sink (exact-name layer 1).
pub(crate) fn infer_by_package(
    facts: &[Fact],
    inventory: &PackageInventory,
    rules: &[PackageRule],
) -> Vec<Fact> {
    let already: BTreeSet<String> = facts
        .iter()
        .filter_map(|f| match f {
            Fact::Sink(s) => Some(s.call_id.clone()),
            _ => None,
        })
        .collect();

    let mut out = Vec::new();
    for fact in facts {
        let Fact::Call(call) = fact else { continue };
        if already.contains(&call.base.id) {
            continue;
        }
        let language = language_from_file(&call.base.file);
        let callee = call.normalized_callee.as_deref().unwrap_or(&call.callee);
        let Some(rule) = rules.iter().find(|r| {
            r.language == language
                && inventory
                    .packages_for(language)
                    .is_some_and(|pkgs| pkgs.contains(&r.package))
                && package_matches(callee, &r.package)
        }) else {
            continue;
        };
        let method = callee
            .strip_prefix(&rule.package)
            .and_then(|rest| rest.strip_prefix(['.', ':']));
        let (category, confidence) = classify_method(method, rule);
        let Some(category) = category else { continue };
        out.push(make_inferred_sink(call, callee, category, confidence, language));
    }
    out
}

fn classify_method<'a>(method: Option<&str>, rule: &'a PackageRule) -> (Option<&'a str>, Confidence) {
    if let Some(category) = rule.category.as_deref() {
        return (Some(category), Confidence::Medium);
    }
    let method = method.unwrap_or("").to_lowercase();
    if let Some(cat) = rule.read_category.as_deref()
        && READ_PREFIXES.iter().any(|p| method.starts_with(p))
    {
        return (Some(cat), Confidence::Medium);
    }
    if let Some(cat) = rule.write_category.as_deref()
        && WRITE_PREFIXES.iter().any(|p| method.starts_with(p))
    {
        return (Some(cat), Confidence::Medium);
    }
    (None, Confidence::Medium)
}

/// True when `callee` is `<package>` itself or a member of `<package>`.
fn package_matches(callee: &str, package: &str) -> bool {
    callee == package
        || callee.starts_with(&format!("{package}."))
        || callee.starts_with(&format!("{package}::"))
}

/// Best-effort language key from a source file path's extension.
fn language_from_file(file: &str) -> &str {
    let ext = std::path::Path::new(file)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    match ext {
        "rs" => "rust",
        "js" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" => "javascript",
        _ => "python",
    }
}

fn make_inferred_sink(
    call: &CallFact,
    callee: &str,
    category: &str,
    confidence: Confidence,
    language: &str,
) -> Fact {
    let rule_id = format!("{}.{}", rule_prefix(language), category);
    Fact::Sink(SinkFact {
        base: FactBase {
            id: format!("sink:inferred:{}:{category}", call.base.id),
            file: call.base.file.clone(),
            line: call.base.line,
            extractor: EXTRACTOR_NAME.to_string(),
        },
        call_id: call.base.id.clone(),
        category: category.to_string(),
        rule_id,
        sink_name: callee.to_string(),
        severity_base: Severity::Medium,
        reason: format!("inferred {category} sink from package classification"),
        conditions: BTreeMap::new(),
        confidence,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::static_analysis::facts::extract_python_facts;
    use crate::static_analysis::recon::collect_packages;

    fn extract(source: &str) -> Vec<Fact> {
        extract_python_facts(
            Path::new("/repo"),
            Path::new("/repo/server.py"),
            source,
            crate::models::default_catalog().sinks_for_language("python"),
        )
        .facts
    }

    fn infer_pkg(facts: &[Fact], rules: &[PackageRule]) -> Vec<Fact> {
        let inventory = collect_packages(facts);
        infer_by_package(facts, &inventory, rules)
    }

    fn sink_names(facts: &[Fact]) -> Vec<(&str, &str)> {
        facts
            .iter()
            .filter_map(|f| match f {
                Fact::Sink(s) => Some((s.sink_name.as_str(), s.category.as_str())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn infers_file_read_from_openpyxl() {
        let facts = extract(
            r#"
import openpyxl

@mcp.tool()
def handle(path: str):
    return openpyxl.load_workbook(path)
"#,
        );
        let inferred = infer_pkg(&facts, &crate::models::default_package_rules());
        let names = sink_names(&inferred);
        assert!(names.contains(&("openpyxl.load_workbook", "file_read")));
        assert!(inferred.iter().all(|f| matches!(f, Fact::Sink(s) if s.confidence == Confidence::Medium)));
    }

    #[test]
    fn infers_read_write_split_by_method_prefix() {
        let facts = extract(
            r#"
import csv

@mcp.tool()
def handle(f):
    csv.reader(f)
    csv.writer(f)
"#,
        );
        let inferred = infer_pkg(&facts, &crate::models::default_package_rules());
        let names = sink_names(&inferred);
        assert!(names.contains(&("csv.reader", "file_read")));
        assert!(names.contains(&("csv.writer", "file_write")));
    }

    #[test]
    fn does_not_reinfer_already_modeled_sinks() {
        let facts = extract("import subprocess\nsubprocess.run('id')\nsubprocess.getoutput('id')\n");
        let custom_rules = vec![PackageRule {
            language: "python".into(),
            package: "subprocess".into(),
            category: Some("command_execution".into()),
            read_category: None,
            write_category: None,
        }];
        let inferred = infer_pkg(&facts, &custom_rules);
        // subprocess.run is already a manual sink; subprocess.getoutput is not.
        assert!(!inferred
            .iter()
            .any(|f| matches!(f, Fact::Sink(s) if s.sink_name == "subprocess.run")));
        assert!(inferred
            .iter()
            .any(|f| matches!(f, Fact::Sink(s) if s.sink_name == "subprocess.getoutput" && s.category == "command_execution")));
    }

    #[test]
    fn infers_single_category_package() {
        let facts = extract("import sh\nsh.ls('-la')\n");
        let inferred = infer_pkg(&facts, &crate::models::default_package_rules());
        assert!(inferred.iter().any(|f| matches!(f, Fact::Sink(s)
            if s.sink_name == "sh.ls" && s.category == "command_execution")));
    }
}
