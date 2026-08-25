# Model Assembly: Package Inventory + Semantic Sink Inference (R3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the static analyzer detect unmodeled third-party sinks (e.g. `openpyxl.load_workbook`) by inferring sink models from the target's import inventory (package classification) and from function naming patterns — without hand-writing a model per function.

**Architecture:** A new post-extraction "model assembly" pass runs after fact extraction. It (1) collects the package inventory from `Fact::Import` facts, (2) infers target-specific sink models from a package→category knowledge base (TOML data), (3) applies those models plus a naming-pattern heuristic to already-extracted `Fact::Call` facts, emitting additional `Fact::Sink` facts that the existing taint/fusion engines consume unchanged. This keeps fact extraction and sink application separate (the seam R5's warm re-injection reuses).

**Tech Stack:** Rust (edition 2024), `toml` 0.8 (already a workspace dep), `rustpython-parser`/`swc_core`/`syn` (existing extractors — untouched).

**Spec:** `docs/ARCHITECTURE_REDESIGN.md` §4 (阶段① 侦察 / 阶段② 建模), §5.1, §5.2, §7, §8 (R3); `docs/GENERALITY_STRATEGY.md` §5.1 (三层识别), §5.2 (models-as-data), §6.1.

## Global Constraints

- TDD: write the failing test first, run it red, implement, run it green, commit per task.
- Model catalog data format is **TOML** (R2 switched from YAML); the package knowledge base is also TOML.
- Use exactly the canonical category strings from `static_analysis/category.rs` (e.g. `command_execution`, `file_read`, `file_write`, `network_request`, `deserialization`, `template_injection`).
- Inferred sinks carry `confidence: Medium` (layer 2) or `Low` (layer 3). `source`/`learned_from` provenance fields are **deferred to R5** — do not add them now.
- `cargo test -p mcp-sec-audit-core` and `cargo test -p mcp-sec-audit-cli` must stay green at every commit.
- Do not modify the three extractors (`facts/python`, `facts/js_ts`, `facts/rust`) — inference is applied post-extraction.

---

## File Structure

- **Create** `crates/mcp-sec-audit-core/models/package_inference.toml` — package→category knowledge base (embedded).
- **Modify** `crates/mcp-sec-audit-core/src/models/mod.rs` — add `PackageRule` + `parse_package_rules` + `default_package_rules`; expose `rule_prefix` as `pub(crate)`.
- **Create** `crates/mcp-sec-audit-core/src/static_analysis/recon.rs` — package inventory.
- **Create** `crates/mcp-sec-audit-core/src/static_analysis/infer.rs` — semantic inference.
- **Modify** `crates/mcp-sec-audit-core/src/static_analysis/mod.rs` — register `pub(crate) mod recon;` and `pub(crate) mod infer;`.
- **Modify** `crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs` — call `assemble` after the extraction loop and extend facts.

---

### Task 1: PackageRule model + package knowledge base data

**Files:**
- Create: `crates/mcp-sec-audit-core/models/package_inference.toml`
- Modify: `crates/mcp-sec-audit-core/src/models/mod.rs`

**Interfaces:**
- Produces: `pub struct PackageRule { pub language: String, pub package: String, pub category: Option<String>, pub read_category: Option<String>, pub write_category: Option<String> }`, `pub fn parse_package_rules(toml: &str) -> Result<Vec<PackageRule>>`, `pub fn default_package_rules() -> Vec<PackageRule>`.

- [ ] **Step 1: Write the failing test**

Append to the `#[cfg(test)] mod tests` in `src/models/mod.rs`:

```rust
    #[test]
    fn parse_package_rules_reads_category_and_readwrite_split() {
        let rules = parse_package_rules(
            r#"
[[packages]]
language = "python"
package = "openpyxl"
read_category = "file_read"
write_category = "file_write"

[[packages]]
language = "python"
package = "subprocess"
category = "command_execution"
"#,
        )
        .expect("parse rules");

        assert_eq!(rules.len(), 2);
        let openpyxl = &rules[0];
        assert_eq!(openpyxl.language, "python");
        assert_eq!(openpyxl.package, "openpyxl");
        assert_eq!(openpyxl.read_category.as_deref(), Some("file_read"));
        assert_eq!(openpyxl.write_category.as_deref(), Some("file_write"));
        assert_eq!(openpyxl.category, None);

        let subprocess = &rules[1];
        assert_eq!(subprocess.category.as_deref(), Some("command_execution"));
        assert_eq!(subprocess.read_category, None);
        assert_eq!(subprocess.write_category, None);
    }

    #[test]
    fn default_package_rules_include_openpyxl() {
        let rules = default_package_rules();
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.package == "openpyxl"
            && r.read_category.as_deref() == Some("file_read")
            && r.write_category.as_deref() == Some("file_write")));
        assert!(rules.iter().any(|r| r.package == "sh" && r.category.as_deref() == Some("command_execution")));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mcp-sec-audit-core models::tests::parse_package_rules_reads_category_and_readwrite_split`
Expected: FAIL — `PackageRule` / `parse_package_rules` / `default_package_rules` are not defined.

- [ ] **Step 3: Create the data file**

Write `crates/mcp-sec-audit-core/models/package_inference.toml`:

```toml
# Package -> dangerous-category classification for semantic inference (layer 2).
# Exactly one of `category` (whole package) or the `read_category`/`write_category`
# pair (methods split by read/write naming prefix) must be set.

[[packages]]
language = "python"
package = "openpyxl"
read_category = "file_read"
write_category = "file_write"

[[packages]]
language = "python"
package = "pandas"
read_category = "file_read"
write_category = "file_write"

[[packages]]
language = "python"
package = "xlrd"
category = "file_read"

[[packages]]
language = "python"
package = "xlsxwriter"
category = "file_write"

[[packages]]
language = "python"
package = "csv"
read_category = "file_read"
write_category = "file_write"

[[packages]]
language = "python"
package = "sh"
category = "command_execution"

[[packages]]
language = "python"
package = "fabric"
category = "command_execution"

[[packages]]
language = "python"
package = "pexpect"
category = "command_execution"

[[packages]]
language = "python"
package = "aiohttp"
category = "network_request"

[[packages]]
language = "python"
package = "websockets"
category = "network_request"

[[packages]]
language = "python"
package = "joblib"
category = "deserialization"

[[packages]]
language = "python"
package = "dill"
category = "deserialization"

[[packages]]
language = "python"
package = "mako"
category = "template_injection"

[[packages]]
language = "javascript"
package = "xlsx"
read_category = "file_read"
write_category = "file_write"

[[packages]]
language = "javascript"
package = "exceljs"
read_category = "file_read"
write_category = "file_write"
```

- [ ] **Step 4: Implement the model + parse + default**

In `src/models/mod.rs`, after the `SinkModel` impl (before `ModelCatalog`), add:

```rust
/// A package → dangerous-category classification rule for semantic inference.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PackageRule {
    pub language: String,
    pub package: String,
    /// Whole package is this category (e.g. subprocess → command_execution).
    #[serde(default)]
    pub category: Option<String>,
    /// Read methods (load*/read*/open*) are this category (file I/O split).
    #[serde(default)]
    pub read_category: Option<String>,
    /// Write methods (save*/write*/dump*/to_*) are this category (file I/O split).
    #[serde(default)]
    pub write_category: Option<String>,
}
```

Change the visibility of the existing `rule_prefix` helper from `fn` to `pub(crate) fn`:

```rust
pub(crate) fn rule_prefix(language: &str) -> &'static str {
```

After `parse_sinks`, add:

```rust
/// Parse a TOML document of package classification rules (a `[[packages]]` array).
pub fn parse_package_rules(toml_str: &str) -> Result<Vec<PackageRule>> {
    #[derive(Deserialize)]
    struct PackageFile {
        packages: Vec<PackageRule>,
    }
    let file: PackageFile =
        toml::from_str(toml_str).context("parse package inference rules TOML")?;
    Ok(file.packages)
}

/// Built-in package classification rules, compiled from
/// `models/package_inference.toml` at build time.
pub fn default_package_rules() -> Vec<PackageRule> {
    parse_package_rules(include_str!("../../models/package_inference.toml"))
        .expect("package inference rules")
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core models::tests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/mcp-sec-audit-core/src/models/mod.rs crates/mcp-sec-audit-core/models/package_inference.toml
git commit -m "feat(models): add package inference rules (package -> category)"
```

---

### Task 2: recon — package inventory

**Files:**
- Create: `crates/mcp-sec-audit-core/src/static_analysis/recon.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/mod.rs`

**Interfaces:**
- Produces: `pub(crate) struct PackageInventory { packages: BTreeMap<String, BTreeSet<String>> }` with `packages_for(&self, language) -> Option<&BTreeSet<String>>`, `len()`, `is_empty()`; `pub(crate) fn collect_packages(facts: &[Fact]) -> PackageInventory`.
- Consumes: `crate::model::{Fact, ImportFact, ImportKind}`.

- [ ] **Step 1: Write the failing test**

Create `src/static_analysis/recon.rs` with the struct, the test module, and a test-only `import` helper (implementation functions come in Step 3):

```rust
use std::collections::{BTreeMap, BTreeSet};

use crate::model::{Fact, ImportFact};

/// Per-language set of top-level package roots, derived from `Fact::Import`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PackageInventory {
    packages: BTreeMap<String, BTreeSet<String>>,
}

impl PackageInventory {
    pub(crate) fn packages_for(&self, language: &str) -> Option<&BTreeSet<String>> {
        self.packages.get(language)
    }
    pub(crate) fn len(&self) -> usize {
        self.packages.values().map(BTreeSet::len).sum()
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.packages.values().all(BTreeSet::is_empty)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::model::{Fact, FactBase, ImportFact, ImportKind};

    use super::*;

    fn import(language: &str, module: &str) -> Fact {
        Fact::Import(ImportFact {
            base: FactBase {
                id: format!("import:{language}:{module}"),
                file: "f".to_string(),
                line: 1,
                extractor: "test".to_string(),
            },
            language: language.to_string(),
            module: module.to_string(),
            imported_name: None,
            alias: None,
            kind: ImportKind::Import,
        })
    }

    #[test]
    fn collects_package_roots_across_languages() {
        let facts = vec![
            import("python", "subprocess"),
            import("python", "os.path"),
            import("python", "openpyxl"),
            import("javascript", "child_process"),
            import("javascript", "xlsx"),
            import("rust", "std::process::Command"),
        ];
        let inv = collect_packages(&facts);
        assert_eq!(inv.len(), 6);
        assert!(inv.packages_for("python").unwrap().contains("subprocess"));
        assert!(inv.packages_for("python").unwrap().contains("os"));
        assert!(inv.packages_for("python").unwrap().contains("openpyxl"));
        assert!(inv.packages_for("javascript").unwrap().contains("child_process"));
        assert!(inv.packages_for("javascript").unwrap().contains("xlsx"));
        assert!(inv.packages_for("rust").unwrap().contains("std"));
        assert!(inv.packages_for("go").is_none());
    }

    #[test]
    fn skips_relative_imports() {
        let facts = vec![import("javascript", "./local"), import("javascript", "fs")];
        let inv = collect_packages(&facts);
        assert_eq!(inv.len(), 1);
        assert!(inv.packages_for("javascript").unwrap().contains("fs"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mcp-sec-audit-core recon::tests::collects_package_roots_across_languages`
Expected: FAIL — `collect_packages` not defined (and `recon` module not registered).

- [ ] **Step 3: Implement `collect_packages`**

Add above the `#[cfg(test)]` module in `recon.rs`:

```rust
/// First path segment of a package name, using the language's separator.
fn package_root(name: &str, language: &str) -> &str {
    if language == "rust" {
        name.split("::").next().unwrap_or(name)
    } else {
        name.split('.').next().unwrap_or(name)
    }
}

/// Derive the set of imported top-level packages from import facts.
pub(crate) fn collect_packages(facts: &[Fact]) -> PackageInventory {
    let mut packages: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for fact in facts {
        let Fact::Import(import) = fact else { continue };
        let root = package_root(&import.module, &import.language);
        if root.is_empty() || root.starts_with('.') {
            continue; // skip empty and relative imports ("./x", "../x")
        }
        packages
            .entry(import.language.clone())
            .or_default()
            .insert(root.to_string());
    }
    PackageInventory { packages }
}
```

- [ ] **Step 4: Register the module**

In `src/static_analysis/mod.rs`, add `pub(crate) mod recon;` next to the other `mod` declarations (alongside `pub(crate) mod category;`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core recon::tests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/recon.rs crates/mcp-sec-audit-core/src/static_analysis/mod.rs
git commit -m "feat(recon): collect package inventory from import facts"
```

---

### Task 3: infer — layer 2 (package classification)

**Files:**
- Create: `crates/mcp-sec-audit-core/src/static_analysis/infer.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/mod.rs`

**Interfaces:**
- Produces: `pub(crate) fn infer_by_package(facts: &[Fact], rules: &[PackageRule]) -> Vec<Fact>`.
- Consumes: `models::{PackageRule, rule_prefix}`, `model::{CallFact, Confidence, Fact, FactBase, Severity, SinkFact}`, `std::collections::BTreeSet`.

- [ ] **Step 1: Write the failing test**

Create `src/static_analysis/infer.rs` with helpers + tests (implementation functions come in Step 3):

```rust
use std::collections::{BTreeMap, BTreeSet};

use crate::model::{Confidence, Fact, FactBase, Severity, SinkFact};
use crate::models::{PackageRule, default_package_rules, rule_prefix};

const EXTRACTOR_NAME: &str = "rust_semantic_inference";

const READ_PREFIXES: &[&str] = &["load", "read", "open"];
const WRITE_PREFIXES: &[&str] = &["save", "write", "dump", "to_"];

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::static_analysis::facts::extract_python_facts;

    fn extract(source: &str) -> Vec<Fact> {
        extract_python_facts(
            Path::new("/repo"),
            Path::new("/repo/server.py"),
            source,
            crate::models::default_catalog().sinks_for_language("python"),
        )
        .facts
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
    fn infers_file_read_and_write_for_openpyxl() {
        let facts = extract(
            r#"
import openpyxl

@mcp.tool()
def handle(path: str, out: str):
    wb = openpyxl.load_workbook(path)
    wb.save(out)
"#,
        );
        let inferred = infer_by_package(&facts, &default_package_rules());
        let names = sink_names(&inferred);
        assert!(names.contains(&("openpyxl.load_workbook", "file_read")));
        assert!(names.contains(&("openpyxl.save", "file_write")));
        assert!(inferred.iter().all(|f| matches!(f, Fact::Sink(s) if s.confidence == Confidence::Medium)));
    }

    #[test]
    fn does_not_reinfer_already_modeled_sinks() {
        let facts = extract("import subprocess\nsubprocess.run('id')\n");
        let inferred = infer_by_package(&facts, &default_package_rules());
        assert!(inferred.is_empty());
    }

    #[test]
    fn infers_single_category_package() {
        let facts = extract("import sh\nsh.ls('-la')\n");
        let inferred = infer_by_package(&facts, &default_package_rules());
        assert!(inferred.iter().any(|f| matches!(f, Fact::Sink(s)
            if s.sink_name == "sh.ls" && s.category == "command_execution")));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mcp-sec-audit-core infer::tests::infers_file_read_and_write_for_openpyxl`
Expected: FAIL — `infer_by_package` not defined (and `infer` module not registered). (`import sh` → `import_aliases["sh"] = "sh"`, so `sh.ls` normalizes to `sh.ls`; the manual catalog has no `sh` model, so this is a clean package-inference case.)

- [ ] **Step 3: Implement `infer_by_package` + helpers**

Add above the `#[cfg(test)]` module in `infer.rs`:

```rust
/// Layer 2: classify calls by their package's classification rule.
/// Skips calls that already produced a manual sink (exact-name layer 1).
pub(crate) fn infer_by_package(facts: &[Fact], rules: &[PackageRule]) -> Vec<Fact> {
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
        let Some(rule) = rules
            .iter()
            .find(|r| r.language == language && package_matches(callee, &r.package))
        else {
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

fn classify_method(method: Option<&str>, rule: &PackageRule) -> (Option<&str>, Confidence) {
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
    call: &crate::model::CallFact,
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
```

- [ ] **Step 4: Register the module**

In `src/static_analysis/mod.rs`, add `pub(crate) mod infer;` next to `pub(crate) mod recon;`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core infer::tests`
Expected: PASS (all three).

- [ ] **Step 6: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/infer.rs crates/mcp-sec-audit-core/src/static_analysis/mod.rs
git commit -m "feat(infer): package-classification sink inference (layer 2)"
```

---

### Task 4: infer — layer 3 (naming pattern)

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/infer.rs`

**Interfaces:**
- Produces: `pub(crate) fn infer_by_name(facts: &[Fact], skip_call_ids: &BTreeSet<String>) -> Vec<Fact>`.

- [ ] **Step 1: Write the failing test**

Add to the `infer.rs` test module:

```rust
    #[test]
    fn infers_low_confidence_sink_from_naming_pattern() {
        let facts = extract(
            r#"
@mcp.tool()
def handle(filepath: str, url: str):
    load_config(filepath)
    fetch_url(url)
    compute(123)
"#,
        );
        let inferred = infer_by_name(&facts, &BTreeSet::new());
        let names = sink_names(&inferred);
        assert!(names.contains(&("load_config", "file_read")));
        assert!(names.contains(&("fetch_url", "network_request")));
        assert!(!inferred.iter().any(|f| matches!(f, Fact::Sink(s) if s.sink_name == "compute")));
        assert!(inferred.iter().all(|f| matches!(f, Fact::Sink(s) if s.confidence == Confidence::Low)));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mcp-sec-audit-core infer::tests::infers_low_confidence_sink_from_naming_pattern`
Expected: FAIL — `infer_by_name` not defined. (`load_config`/`fetch_url`/`compute` have no import, so `normalized_callee` equals the callee; their first-arg exprs are the identifiers `filepath`, `url`, and the literal `123` respectively, so only the first two match a path hint.)

- [ ] **Step 3: Implement `infer_by_name`**

Add above the `#[cfg(test)]` module in `infer.rs`:

```rust
const NAME_PREFIX_CATEGORY: &[(&str, &str)] = &[
    ("load", "file_read"),
    ("read", "file_read"),
    ("open", "file_read"),
    ("save", "file_write"),
    ("write", "file_write"),
    ("dump", "file_write"),
    ("exec", "dynamic_execution"),
    ("eval", "dynamic_execution"),
    ("run", "command_execution"),
    ("get", "network_request"),
    ("post", "network_request"),
    ("fetch", "network_request"),
    ("download", "network_request"),
    ("upload", "network_request"),
    ("delete", "file_delete"),
    ("remove", "file_delete"),
    ("unlink", "file_delete"),
    ("rmdir", "file_delete"),
];

const ARG_PATH_HINTS: &[&str] = &["path", "file", "url", "cmd", "command", "dir", "host"];

/// Layer 3: weak naming-pattern heuristic for calls whose package is unmodeled.
/// Fires only for calls with a dangerous method-name prefix AND a first argument
/// that looks like a path/url/command. Low confidence — never reported alone.
pub(crate) fn infer_by_name(
    facts: &[Fact],
    skip_call_ids: &BTreeSet<String>,
) -> Vec<Fact> {
    let mut out = Vec::new();
    for fact in facts {
        let Fact::Call(call) = fact else { continue };
        if skip_call_ids.contains(&call.base.id) {
            continue;
        }
        let callee = call.normalized_callee.as_deref().unwrap_or(&call.callee);
        let method = callee
            .rsplit(['.', ':'])
            .next()
            .unwrap_or(callee)
            .to_lowercase();
        let Some((_, category)) = NAME_PREFIX_CATEGORY
            .iter()
            .find(|(prefix, _)| method.starts_with(prefix))
        else {
            continue;
        };
        let first_arg = call
            .args
            .first()
            .map(|a| a.expr.to_lowercase())
            .unwrap_or_default();
        if !ARG_PATH_HINTS.iter().any(|h| first_arg.contains(h)) {
            continue;
        }
        out.push(make_inferred_sink(
            call,
            callee,
            category,
            Confidence::Low,
            language_from_file(&call.base.file),
        ));
    }
    out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core infer::tests`
Expected: PASS (all four).

- [ ] **Step 5: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/infer.rs
git commit -m "feat(infer): naming-pattern sink inference (layer 3)"
```

---

### Task 5: assemble + pipeline integration

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/infer.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`

**Interfaces:**
- Produces: `pub(crate) fn assemble(facts: &[Fact], rules: &[PackageRule]) -> Vec<Fact>`.

- [ ] **Step 1: Write the failing pipeline test**

Add to the `#[cfg(test)] mod tests` in `facts/pipeline.rs`:

```rust
    #[test]
    fn semantic_inference_detects_unmodeled_package_sink() {
        let root = temp_dir("infer-pipeline");
        let file = root.join("server.py");
        fs::write(
            &file,
            r#"
import openpyxl

@mcp.tool()
def read_workbook(path: str):
    return openpyxl.load_workbook(path)
"#,
        )
        .expect("write Python file");

        let ctx = StaticScanContext {
            config: RuntimeConfig::default(),
            rulebook_paths: Vec::new(),
            discovered_files: vec![DiscoveredFile {
                path: file,
                language: ScanLanguage::Python,
            }],
        };

        let facts = extract_static_facts(&ctx).expect("extract facts");
        assert!(facts.iter().any(|f| matches!(f, Fact::Sink(s)
            if s.sink_name == "openpyxl.load_workbook"
               && s.category == "file_read"
               && s.confidence == crate::Confidence::Medium)));

        fs::remove_dir_all(root).expect("cleanup");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mcp-sec-audit-core semantic_inference_detects_unmodeled_package_sink`
Expected: FAIL — no `file_read` sink for `openpyxl.load_workbook`.

- [ ] **Step 3: Implement `assemble`**

Add above the `#[cfg(test)]` module in `infer.rs`:

```rust
/// Full model-assembly pass: layer 2 (package) then layer 3 (naming) inference.
/// Returns only the additional sink facts to append to the extraction output.
pub(crate) fn assemble(facts: &[Fact], rules: &[PackageRule]) -> Vec<Fact> {
    let mut inferred = infer_by_package(facts, rules);
    let skip: BTreeSet<String> = facts
        .iter()
        .chain(inferred.iter())
        .filter_map(|f| match f {
            Fact::Sink(s) => Some(s.call_id.clone()),
            _ => None,
        })
        .collect();
    inferred.extend(infer_by_name(facts, &skip));
    inferred
}
```

- [ ] **Step 4: Wire into the pipeline**

In `facts/pipeline.rs`, add the import at the top:

```rust
use crate::static_analysis::{infer, recon};
```

In `extract_static_facts`, after the `if !diagnostics.is_empty() { ... bail!(...) }` block and before `Ok(facts)`, insert:

```rust
    let inferred = infer::assemble(&facts, &crate::models::default_package_rules());
    tracing::info!(
        target: "mcp_sec_audit::taint",
        inferred_sinks = inferred.len(),
        packages = recon::collect_packages(&facts).len(),
        "semantic sink inference complete"
    );
    facts.extend(inferred);

    Ok(facts)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p mcp-sec-audit-core` then `cargo test -p mcp-sec-audit-cli`
Expected: PASS (all, including the new pipeline test).

- [ ] **Step 6: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/infer.rs crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs
git commit -m "feat(pipeline): run semantic sink inference after fact extraction"
```

---

### Task 6: full suite + CLI smoke test + finish

- [ ] **Step 1: Run the full workspace test suite**

Run: `cargo test`
Expected: PASS (206+ core tests, 4 CLI tests, plus the new ones).

- [ ] **Step 2: CLI smoke test**

Run the CLI against a small target that imports `openpyxl` and calls `load_workbook`, with `[static.taint] enabled = true`. Confirm the report/log mentions an inferred `file_read` sink for `openpyxl.load_workbook` (medium confidence), with no Rust change needed to add it.

- [ ] **Step 3: Finish the branch**

Announce "I'm using the finishing-a-development-branch skill to complete this work", verify tests, and present the standard 3-option menu (merge to master / push PR / keep).
