# Model Catalog Data Layer (R2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the three hardcoded `SINK_RULES` tables (`facts/{python,rust,js_ts}/sinks.rs`) into a unified YAML model catalog so adding a sink model no longer requires editing Rust.

**Architecture:** A new `models` module defines a single language-agnostic `SinkModel` schema and a `ModelCatalog` that groups models by language. The default catalog is compiled from real `models/sinks/*.yaml` files via `include_str!`; an optional `[static].models_dir` config loads and merges extra YAML at runtime (the seam R5's `learned/` directory will reuse). The three language extractors consume `&[SinkModel]` slices threaded from `extract_static_facts`, keeping their per-language matching logic (`::` vs `.`) but dropping the static rule tables.

**Tech Stack:** Rust, `serde` + `serde_yaml` (new dep), `include_str!`, `tracing`.

**Spec:** `docs/ARCHITECTURE_REDESIGN.md` §7 阶段② 模型目录 + §8 里程碑 **R2**:
> 模型目录数据化:迁移 `SINK_RULES` → YAML,加 `models/` 加载;三类模型统一 schema;加模型无需改 Rust.

## Global Constraints

- Rust edition 2024, `rust-version = 1.88`.
- `cargo test` must stay green (currently 198 core + 4 CLI) after every task.
- `rule_id` is **derived** as `{prefix}.{category}` where `prefix` = `python` | `rust` | `js` (js covers both `javascript` and `typescript`). This reproduces the current data exactly (rust/js already store `{prefix}.{category}`; python derives `python.{category}`).
- Model `category` values are stored **raw** (e.g. `deserialization_rce`, `dynamic_import`); fusion already normalizes them via `category::normalize_category` (R1).
- Python's mode-sensitive `open()` classification stays in code (it reads `mode` from kwargs/args — not a pattern list).
- YAML entry order is preserved (`Vec`), so first-match-wins semantics (e.g. Rust's two `deserialization` entries) are preserved by keeping the memory-safe entry first.

---

### Task 1: `models` module + `SinkModel`/`ModelCatalog` + YAML dependency

**Files:**
- Modify: `crates/mcp-sec-audit-core/Cargo.toml`
- Modify: `Cargo.toml` (workspace deps)
- Create: `crates/mcp-sec-audit-core/src/models/mod.rs`
- Modify: `crates/mcp-sec-audit-core/src/lib.rs`

**Interfaces:**
- Produces (used by Tasks 3–4):
  - `pub struct SinkModel { language, category, severity, confidence, reason, patterns }` (+ `rule_id(&self) -> String`)
  - `pub struct ModelCatalog` (+ `from_sinks`, `sinks_for_language(&self, &str) -> &[SinkModel]`, `merge`, `sink_count`, `is_empty`)
  - `pub fn parse_sinks(yaml: &str) -> Result<Vec<SinkModel>>`
  - `pub fn default_catalog() -> ModelCatalog`
  - `pub fn load_models_dir(dir: &Path) -> Result<ModelCatalog>`

- [ ] **Step 1: Add the workspace + crate dependency**

In `Cargo.toml` workspace `[workspace.dependencies]`, add after `serde_json = "1.0"`:
```toml
serde_yaml = "0.9"
```
In `crates/mcp-sec-audit-core/Cargo.toml` `[dependencies]`, add after `serde_json.workspace = true`:
```toml
serde_yaml.workspace = true
```

- [ ] **Step 2: Write the failing test first** — append to the new `models/mod.rs` (below; the test references `default_catalog` which will not exist until Step 3):

```rust
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{Confidence, Severity};

/// A single sink model in the shared, language-agnostic schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SinkModel {
    /// Language key: "python" | "javascript" | "rust" (javascript covers TS).
    pub language: String,
    /// Canonical category (snake_case), e.g. "command_execution".
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub reason: String,
    /// Callee patterns matched with the language's separator rules.
    pub patterns: Vec<String>,
}

impl SinkModel {
    /// Derived rule_id: `{prefix}.{category}` ("python"/"rust"/"js").
    pub fn rule_id(&self) -> String {
        format!("{}.{}", rule_prefix(&self.language), self.category)
    }
}

fn rule_prefix(language: &str) -> &'static str {
    match language {
        "python" => "python",
        "rust" => "rust",
        _ => "js", // javascript + typescript
    }
}

/// All sink models, grouped by language key.
#[derive(Debug, Clone, Default)]
pub struct ModelCatalog {
    sinks: BTreeMap<String, Vec<SinkModel>>,
}

impl ModelCatalog {
    /// Build a catalog by grouping a flat model list by `language`.
    pub fn from_sinks(models: Vec<SinkModel>) -> Self {
        let mut sinks: BTreeMap<String, Vec<SinkModel>> = BTreeMap::new();
        for model in models {
            sinks.entry(model.language.clone()).or_default().push(model);
        }
        Self { sinks }
    }

    /// Models for a language key ("python" | "javascript" | "rust"), or `[]`.
    pub fn sinks_for_language(&self, language: &str) -> &[SinkModel] {
        self.sinks
            .get(language)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Append another catalog's models (user/learned models override nothing;
    /// they extend the lists, so they are tried after the built-in models).
    pub fn merge(&mut self, other: ModelCatalog) {
        for (lang, models) in other.sinks {
            self.sinks.entry(lang).or_default().extend(models);
        }
    }

    /// Total number of sink models across all languages.
    pub fn sink_count(&self) -> usize {
        self.sinks.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.values().all(Vec::is_empty)
    }
}

/// Parse a YAML list of sink models.
pub fn parse_sinks(yaml: &str) -> Result<Vec<SinkModel>> {
    serde_yaml::from_str(yaml).context("parse sink models YAML")
}

/// The default catalog, compiled from `models/sinks/*.yaml` at build time.
pub fn default_catalog() -> ModelCatalog {
    let mut models = Vec::new();
    models.extend(
        parse_sinks(include_str!("../../models/sinks/python.yaml")).expect("python sink models"),
    );
    models.extend(
        parse_sinks(include_str!("../../models/sinks/javascript.yaml"))
            .expect("javascript sink models"),
    );
    models.extend(
        parse_sinks(include_str!("../../models/sinks/rust.yaml")).expect("rust sink models"),
    );
    ModelCatalog::from_sinks(models)
}

/// Load + merge all `*.yaml` files in a directory (used by `models_dir` / `learned/`).
pub fn load_models_dir(dir: &Path) -> Result<ModelCatalog> {
    let mut models = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("read models dir {}", dir.display()))?
        .collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml")
            && path.extension().and_then(|e| e.to_str()) != Some("yml")
        {
            continue;
        }
        let yaml = std::fs::read_to_string(&path)
            .with_context(|| format!("read model file {}", path.display()))?;
        models.extend(parse_sinks(&yaml)?);
    }
    Ok(ModelCatalog::from_sinks(models))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sinks_reads_a_model_list() {
        let yaml = r#"
- language: python
  category: command_execution
  severity: high
  confidence: high
  reason: "Runs commands"
  patterns:
    - subprocess.run
    - os.system
"#;
        let models = parse_sinks(yaml).expect("parse models");
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].language, "python");
        assert_eq!(models[0].severity, Severity::High);
        assert_eq!(models[0].confidence, Confidence::High);
        assert_eq!(models[0].patterns, vec!["subprocess.run", "os.system"]);
        assert_eq!(models[0].rule_id(), "python.command_execution");
    }

    #[test]
    fn rule_id_prefix_is_js_for_javascript() {
        let model = SinkModel {
            language: "javascript".into(),
            category: "command_execution".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            reason: "x".into(),
            patterns: vec![],
        };
        assert_eq!(model.rule_id(), "js.command_execution");
    }

    #[test]
    fn catalog_groups_and_merges_by_language() {
        let a = parse_sinks("- language: python\n  category: command_execution\n  severity: high\n  confidence: high\n  reason: x\n  patterns: [subprocess.run]\n").unwrap();
        let b = parse_sinks("- language: rust\n  category: file_read\n  severity: medium\n  confidence: high\n  reason: y\n  patterns: [std::fs::read]\n").unwrap();
        let mut cat = ModelCatalog::from_sinks(a);
        cat.merge(ModelCatalog::from_sinks(b));
        assert_eq!(cat.sink_count(), 2);
        assert_eq!(cat.sinks_for_language("python").len(), 1);
        assert_eq!(cat.sinks_for_language("rust").len(), 1);
        assert!(cat.sinks_for_language("javascript").is_empty());
    }
}
```

- [ ] **Step 3: Run to verify it fails to compile**

Run: `cargo test -p mcp-sec-audit-core models`
Expected: FAIL — `include_str!("../../models/sinks/python.yaml")` and friends do not exist yet (Task 2 creates them).

- [ ] **Step 4: Register the module** — in `lib.rs`, add `pub mod models;` after `pub mod model;`, and extend the `pub use model::{...}` re-export block is NOT needed for `models` (export `models` types separately):

```rust
pub use models::{ModelCatalog, SinkModel, default_catalog, load_models_dir, parse_sinks};
```

(Add this after the `pub use reporting::{...}` block.)

- [ ] **Step 5: Commit** (the module + dep; the compile is still broken until Task 2 — commit only the dep + module after Task 2's YAML exists, OR commit both in Task 2)

```bash
git add Cargo.toml crates/mcp-sec-audit-core/Cargo.toml crates/mcp-sec-audit-core/src/models/mod.rs crates/mcp-sec-audit-core/src/lib.rs Cargo.lock
git commit -m "feat(models): add SinkModel/ModelCatalog schema and YAML loader"
```

---

### Task 2: Migrate the three `SINK_RULES` tables into YAML

**Files:**
- Create: `crates/mcp-sec-audit-core/models/sinks/python.yaml`
- Create: `crates/mcp-sec-audit-core/models/sinks/javascript.yaml`
- Create: `crates/mcp-sec-audit-core/models/sinks/rust.yaml`

**Interfaces:**
- Consumes: `parse_sinks` / `default_catalog` (Task 1).
- Produces: the embedded default catalog (data only).

- [ ] **Step 1: Create `models/sinks/python.yaml`** (verbatim from `facts/python/sinks.rs` `SINK_RULES`; the mode-sensitive `open()` is NOT listed — it stays in code):

```yaml
# Python sink models. `open()` is omitted: it is mode-sensitive and stays in code.
- language: python
  category: command_execution
  severity: high
  confidence: high
  reason: "Python command execution call can execute attacker-controlled commands"
  patterns:
    - subprocess.run
    - subprocess.Popen
    - subprocess.call
    - subprocess.check_call
    - subprocess.check_output
    - os.system
    - os.popen
    - os.execl
    - os.execle
    - os.execlp
    - os.execv
    - os.execve
    - os.execvp
    - os.execvpe
    - os.spawnl
    - os.spawnlp
    - os.spawnv
    - os.spawnvp
    - os.spawnve
    - os.spawnvpe
- language: python
  category: dynamic_execution
  severity: critical
  confidence: high
  reason: "Python dynamic execution call can execute attacker-controlled code"
  patterns: [eval, exec, compile]
- language: python
  category: dynamic_import
  severity: medium
  confidence: medium
  reason: "Python dynamic import call can load attacker-controlled modules"
  patterns:
    - importlib.import_module
    - __import__
    - importlib.util.spec_from_file_location
    - importlib.machinery.SourceFileLoader
- language: python
  category: file_read
  severity: medium
  confidence: high
  reason: "Python file read call can leak sensitive data from attacker-controlled paths"
  patterns: [Path.read_text, Path.read_bytes, read_text, read_bytes]
- language: python
  category: file_write
  severity: medium
  confidence: high
  reason: "Python file write call can modify filesystem contents"
  patterns: [Path.write_text, Path.write_bytes, write_text, write_bytes]
- language: python
  category: network_request
  severity: medium
  confidence: medium
  reason: "Python network request call can reach attacker-controlled URLs (SSRF)"
  patterns:
    - requests.get
    - requests.post
    - requests.put
    - requests.delete
    - requests.patch
    - requests.head
    - requests.request
    - httpx.get
    - httpx.post
    - httpx.put
    - httpx.delete
    - httpx.request
    - urllib.request.urlopen
    - urllib.request.urlretrieve
    - urllib.request.Request
    - aiohttp.ClientSession.get
    - aiohttp.ClientSession.post
    - aiohttp.ClientSession.request
    - socket.create_connection
- language: python
  category: deserialization
  severity: critical
  confidence: high
  reason: "Deserializing untrusted input can cause arbitrary code execution"
  patterns: [pickle.load, pickle.loads, cPickle.load, cPickle.loads, yaml.load, yaml.unsafe_load, marshal.loads, dill.load, dill.loads]
- language: python
  category: database_injection
  severity: critical
  confidence: medium
  reason: "Database query may be vulnerable to SQL injection"
  patterns: [execute, executemany, executescript, sqlite3, pymysql, psycopg2, MySQLdb, sqlalchemy.text, sqlalchemy.execute]
- language: python
  category: template_injection
  severity: critical
  confidence: high
  reason: "Template rendering can execute attacker-controlled code (SSTI)"
  patterns: [render_template_string, jinja2.Template, jinja2.Environment.from_string, Template.render, Template.from_string]
- language: python
  category: xml_parsing
  severity: medium
  confidence: medium
  reason: "XML parsing can be vulnerable to XXE or billion-laughs attacks"
  patterns:
    - lxml.etree.parse
    - lxml.etree.fromstring
    - lxml.etree.XML
    - xml.etree.ElementTree.parse
    - xml.etree.ElementTree.fromstring
    - ElementTree.parse
    - ElementTree.fromstring
    - xml.sax.parse
- language: python
  category: xpath_injection
  severity: medium
  confidence: medium
  reason: "XPath query built from untrusted input can be vulnerable to injection"
  patterns: [lxml.etree.XPath, ElementTree.Element.find, Element.findall, Element.xpath]
- language: python
  category: file_delete
  severity: medium
  confidence: high
  reason: "File deletion can remove attacker-controlled paths"
  patterns: [os.remove, os.unlink, os.rmdir, shutil.rmtree, Path.unlink, Path.rmdir]
- language: python
  category: env_access
  severity: high
  confidence: high
  reason: "Environment variable access can leak credentials"
  patterns: [os.environ, os.getenv, os.putenv]
```

- [ ] **Step 2: Create `models/sinks/rust.yaml`** (verbatim from `facts/rust/sinks.rs`; preserve order — the memory-safe `deserialization` entry precedes the RCE one):

```yaml
- language: rust
  category: command_execution
  severity: high
  confidence: high
  reason: "Executes external commands via std::process::Command"
  patterns: [std::process::Command, Command::new, Command::output, Command::spawn, std::process::Command::new]
- language: rust
  category: file_read
  severity: medium
  confidence: high
  reason: "File read access can leak sensitive data"
  patterns: [std::fs::read, std::fs::read_to_string, std::fs::File::open, File::open]
- language: rust
  category: file_write
  severity: medium
  confidence: high
  reason: "File write can modify filesystem contents"
  patterns: [std::fs::write, std::fs::File::create, File::create, std::io::Write::write, std::io::Write::write_all]
- language: rust
  category: network_request
  severity: medium
  confidence: high
  reason: "Network request can reach attacker-controlled URLs (SSRF)"
  patterns: [std::net::TcpStream::connect, TcpStream::connect, std::os::unix::net::UnixStream::connect, reqwest::get, reqwest::blocking::get, reqwest::Client::new, hyper::client, ureq::get, isahc::get, minreq::get, surf::get, curl, attohttpc]
- language: rust
  category: env_access
  severity: high
  confidence: high
  reason: "Access to environment variables can leak credentials"
  patterns: [std::env::var, std::env::var_os, std::env::vars, std::env::vars_os]
- language: rust
  category: deserialization
  severity: medium
  confidence: high
  reason: "Deserialization of untrusted input (memory-safe format; still lacks schema validation)"
  patterns: [serde_json::from_str, serde_json::from_slice, serde_json::from_reader, toml, ron]
- language: rust
  category: deserialization
  severity: high
  confidence: high
  reason: "Deserialization of untrusted input can cause type-confusion or RCE"
  patterns: [bincode::deserialize, serde_yaml::from_str]
- language: rust
  category: dynamic_loading
  severity: high
  confidence: high
  reason: "Dynamic library loading can execute attacker-controlled code"
  patterns: [libloading::Library::new, dlopen, libc::dlopen]
- language: rust
  category: database_injection
  severity: critical
  confidence: medium
  reason: "Database query may be vulnerable to SQL injection"
  patterns: [rusqlite, sqlx, diesel, mysql, postgres, tokio_postgres, sea_orm]
- language: rust
  category: file_delete
  severity: medium
  confidence: high
  reason: "File deletion can remove attacker-controlled paths"
  patterns: [std::fs::remove_file, std::fs::remove_dir, std::fs::remove_dir_all, std::fs::rename]
- language: rust
  category: template_injection
  severity: critical
  confidence: high
  reason: "Template rendering can execute attacker-controlled code (SSTI)"
  patterns: [tera, handlebars, minijinja, askama]
```

- [ ] **Step 3: Create `models/sinks/javascript.yaml`** (verbatim from `facts/js_ts/sinks.rs`; confidence is `high` for every entry, matching the current hardcoded `Confidence::High`):

```yaml
- language: javascript
  category: command_execution
  severity: high
  confidence: high
  reason: "Executes external commands via child_process"
  patterns: [child_process.exec, child_process.execSync, child_process.spawn, child_process.spawnSync, child_process.execFile, child_process.fork, shelljs.exec, shell.exec]
- language: javascript
  category: dynamic_execution
  severity: critical
  confidence: high
  reason: "Dynamic code execution can run attacker-controlled code"
  patterns: [eval, "new Function", Function]
- language: javascript
  category: file_read
  severity: medium
  confidence: high
  reason: "File read access can leak sensitive data"
  patterns: [fs.readFile, fs.readFileSync, fs.createReadStream, fs.promises.readFile, fs.readdir, fs.readdirSync]
- language: javascript
  category: file_write
  severity: medium
  confidence: high
  reason: "File write can modify filesystem contents"
  patterns: [fs.writeFile, fs.writeFileSync, fs.createWriteStream, fs.promises.writeFile, fs.appendFile, fs.appendFileSync, fs.mkdir]
- language: javascript
  category: file_delete
  severity: medium
  confidence: high
  reason: "File deletion can remove attacker-controlled paths"
  patterns: [fs.unlink, fs.unlinkSync, fs.rm, fs.rmSync, fs.rmdir, fs.rmdirSync, fs.promises.rm]
- language: javascript
  category: network_request
  severity: medium
  confidence: high
  reason: "Network request can reach attacker-controlled URLs (SSRF)"
  patterns: [http.request, https.request, http.get, https.get, fetch, net.connect, axios]
- language: javascript
  category: env_access
  severity: high
  confidence: high
  reason: "Access to environment variables can leak credentials"
  patterns: [process.env]
- language: javascript
  category: database_injection
  severity: critical
  confidence: high
  reason: "Database query may be vulnerable to injection"
  patterns: [connection.query, connection.execute, db.run, Model.find, mysql.createConnection, mysql.createPool, mysql.query, mongoose.Model, mongoose.Query.prototype.exec, pg.query, sqlite3, sequelize.query, collection.find, collection.findOne, collection.aggregate, collection.update, knex]
- language: javascript
  category: deserialization_rce
  severity: critical
  confidence: high
  reason: "Deserialization/vm execution can run attacker-controlled code"
  patterns: [vm.runInNewContext, vm.Script, "new WebAssembly.Module"]
- language: javascript
  category: template_injection
  severity: critical
  confidence: high
  reason: "Template rendering can execute attacker-controlled code (SSTI)"
  patterns: [ejs.render, ejs.renderFile, ejs.compile, pug.render, pug.renderFile, pug.compile, handlebars.compile, mustache.render, nunjucks.render, nunjucks.renderString, "_.template", lodash.template]
```

- [ ] **Step 4: Add a migration-fidelity test** — append to `models/mod.rs` tests:

```rust
#[test]
fn default_catalog_matches_legacy_sink_counts() {
    let cat = default_catalog();
    // Legacy counts: python 13, rust 11, javascript 10.
    assert_eq!(cat.sinks_for_language("python").len(), 13);
    assert_eq!(cat.sinks_for_language("rust").len(), 11);
    assert_eq!(cat.sinks_for_language("javascript").len(), 10);
    assert_eq!(cat.sink_count(), 34);
    // Spot-check a few derived rule_ids.
    assert!(cat
        .sinks_for_language("rust")
        .iter()
        .any(|m| m.category == "dynamic_loading" && m.rule_id() == "rust.dynamic_loading"));
    assert!(cat
        .sinks_for_language("javascript")
        .iter()
        .any(|m| m.category == "deserialization_rce" && m.rule_id() == "js.deserialization_rce"));
}
```

- [ ] **Step 5: Run to verify tests pass**

Run: `cargo test -p mcp-sec-audit-core models`
Expected: PASS — Task 1's tests + the new migration-fidelity test all green.

- [ ] **Step 6: Commit** (includes the Task 1 module + dep if not already committed)

```bash
git add crates/mcp-sec-audit-core/models/ crates/mcp-sec-audit-core/src/models/ crates/mcp-sec-audit-core/src/lib.rs Cargo.toml crates/mcp-sec-audit-core/Cargo.toml Cargo.lock
git commit -m "feat(models): migrate SINK_RULES to YAML sink models"
```

---

### Task 3: Refactor the three `sinks.rs` + extractors to consume `&[SinkModel]`

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/python/sinks.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/python/mod.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/rust/sinks.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/rust/mod.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/sinks.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/js_ts/mod.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/taint/mod.rs` (test helper only)

**Interfaces:**
- Consumes: `SinkModel` (Task 1).
- Produces (changed signatures):
  - `extract_python_facts(root, file, source, sinks: &[SinkModel]) -> PythonExtractionResult`
  - `extract_rust_facts(root, file, source, sinks: &[SinkModel]) -> RustExtractionResult`
  - `extract_js_ts_facts(root, file, source, sinks: &[SinkModel]) -> JsTsExtractionResult`

- [ ] **Step 1: Python — rewrite `sinks.rs`**

Replace the entire `SinkRule` struct + `SINK_RULES` static (keep `canonical_sink_name`, `is_open_callee`, `open_call_writes`, `file_mode_writes`, `matches_sink`). The new `classify_sink` takes the models slice and owns its `String` fields:

```rust
use crate::model::{CallFact, Confidence, Severity};
use crate::models::SinkModel;

#[derive(Debug, Clone)]
pub(crate) struct SinkClassification {
    pub category: String,
    pub severity: Severity,
    pub reason: String,
    pub confidence: Confidence,
}

pub(crate) fn canonical_sink_name(callee: &str) -> String {
    // ... unchanged body (keep as-is) ...
}

pub(crate) fn classify_sink(
    callee: &str,
    call: &CallFact,
    sinks: &[SinkModel],
) -> Option<SinkClassification> {
    if is_open_callee(callee) {
        return if open_call_writes(call) {
            Some(SinkClassification {
                category: "file_write".to_string(),
                severity: Severity::Medium,
                reason: "Python open call uses a write-capable file mode".to_string(),
                confidence: Confidence::High,
            })
        } else {
            Some(SinkClassification {
                category: "file_read".to_string(),
                severity: Severity::Medium,
                reason: "Python open call reads a file path that may be attacker-controlled (path traversal)".to_string(),
                confidence: Confidence::High,
            })
        };
    }

    for model in sinks {
        if matches_sink(callee, &model.patterns) {
            return Some(SinkClassification {
                category: model.category.clone(),
                severity: model.severity.clone(),
                reason: model.reason.clone(),
                confidence: model.confidence.clone(),
            });
        }
    }
    None
}

fn matches_sink(callee: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        callee == pattern
            || callee.ends_with(&format!(".{pattern}"))
            || callee.starts_with(&format!("{pattern}."))
    })
}

// is_open_callee / open_call_writes / file_mode_writes unchanged
```

- [ ] **Step 2: Python — thread `sinks` through the extractor**

In `python/mod.rs`:
- `struct PythonFactExtractor<'a>` gains a field `sinks: &'a [SinkModel]` (add `use crate::models::SinkModel;`).
- `fn new(root, file, source)` → `fn new(root, file, source, sinks: &'a [SinkModel])` and set the field.
- `pub fn extract_python_facts(root, file, source)` → add `sinks: &[SinkModel]` param and pass to `new`.
- In `emit_sink_for_call`, replace `sinks::classify_sink(&sink_name, call)` with `sinks::classify_sink(&sink_name, call, self.sinks)`; replace `classification.category.to_string()` with `classification.category.clone()` (and use `make_sink_id(&classification.category, ...)`), `classification.reason.to_string()` with `classification.reason.clone()`, and `rule_id: format!("python.{}", classification.category)` stays but now reads the owned `String` (adjust to `format!("python.{}", classification.category)`).

- [ ] **Step 3: Rust — rewrite `sinks.rs`**

Delete `SinkRule`, `SINK_RULES`, and the test module's `category_for`/`matched_sink` helpers. Keep only `matches_sink` (now over `&[String]`):

```rust
pub(crate) fn matches_sink(callee: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        callee == pattern
            || callee.ends_with(&format!("::{pattern}"))
            || callee.starts_with(&format!("{pattern}::"))
            || callee.starts_with(&format!("{pattern}<"))
            || callee.starts_with(&format!("{pattern}("))
    })
}
```

- [ ] **Step 4: Rust — thread `sinks` through the extractor**

In `rust/mod.rs`:
- `struct RustFactExtractor<'a>` gains `sinks: &'a [SinkModel]`; `new(root, file, source)` → `new(root, file, source, sinks: &'a [SinkModel])`.
- `fn check_sink` iterates `self.sinks` instead of `sinks::SINK_RULES`; build `SinkFact.rule_id` with `model.rule_id()` and use `model.category.clone()`, `model.severity.clone()`, `model.reason.clone()`, `model.confidence.clone()`.
- `pub fn extract_rust_facts(root, file, source)` → add `sinks: &[SinkModel]` and pass to `new`.
- Update the single test helper at line ~870 to pass `&[]` (or a real slice).

- [ ] **Step 5: JS/TS — rewrite `sinks.rs` `check_sink`**

Delete the `SinkRule` struct + `SINK_RULES` + `matches_sink` local copy (keep a `matches_sink` over `&[String]`). New signature:

```rust
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
```

- [ ] **Step 6: JS/TS — thread `sinks` through the extractor**

In `js_ts/mod.rs`:
- `struct JsTsFactExtractor<'a>` gains `sinks: &'a [SinkModel]`; `new(root, file, source, cm)` → add `sinks: &'a [SinkModel]` and set the field.
- The call site `sinks::check_sink(&normalized_callee, &call_id, line, &file, EXTRACTOR_NAME, &mut self.facts)` → add `self.sinks` as the last arg.
- `pub fn extract_js_ts_facts(root, file, source)` → add `sinks: &[SinkModel]` and pass to `new`.

- [ ] **Step 7: Thread the catalog through `extract_static_facts`**

In `facts/pipeline.rs`, at the top of `extract_static_facts`, build the catalog (default only for now — Task 4 adds `models_dir`):

```rust
use crate::models::default_catalog;
// inside extract_static_facts:
let catalog = default_catalog();
```

Then pass slices at each call site:
- `extract_python_facts(root, &file.path, &source, catalog.sinks_for_language("python"))`
- `extract_js_ts_facts(root, &file.path, &source, catalog.sinks_for_language("javascript"))`
- `extract_rust_facts(root, &file.path, &source, catalog.sinks_for_language("rust"))`

- [ ] **Step 8: Fix the remaining direct test helper call sites**

- `facts/python/mod.rs` test helper (line ~720) and `taint/mod.rs` test helper (line ~419): pass `&default_catalog().sinks_for_language("python")` — or, simpler, `&[]` if the test only needs the `open()` path. Use the default catalog slice to preserve existing assertions.

- [ ] **Step 9: Add the "add model without editing Rust" proof test**

Append to `facts/pipeline.rs` tests:

```rust
#[test]
fn custom_sink_model_is_picked_up_from_models_slice() {
    // A sink not in the default catalog, injected via the models slice, is
    // classified — proving new sinks need no Rust change.
    let model = crate::models::SinkModel {
        language: "python".into(),
        category: "command_execution".into(),
        severity: crate::Severity::High,
        confidence: crate::Confidence::High,
        reason: "custom".into(),
        patterns: vec!["totally.custom.sink".into()],
    };
    let source = "import os\ntotally.custom.sink('x')\n";
    let result = extract_python_facts(Path::new("/repo"), Path::new("/repo/a.py"), source, std::slice::from_ref(&model));
    assert!(result.facts.iter().any(|f| matches!(f, Fact::Sink(s) if s.sink_name == "totally.custom.sink")));
}
```

- [ ] **Step 10: Run the full core suite**

Run: `cargo test -p mcp-sec-audit-core`
Expected: PASS — all existing facts/taint/pipeline tests green (classification behavior unchanged) + the new test.

- [ ] **Step 11: Commit**

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/facts/ crates/mcp-sec-audit-core/src/static_analysis/taint/mod.rs
git commit -m "refactor(facts): consume sink models from the catalog instead of static SINK_RULES"
```

---

### Task 4: `models_dir` config + runtime load/merge + logging

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/config.rs`
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`

**Interfaces:**
- Consumes: `load_models_dir` (Task 1).
- Produces: `StaticConfig.models_dir: Option<String>` (serde default `None`).

- [ ] **Step 1: Write the failing test** — in `config.rs` tests:

```rust
#[test]
fn models_dir_parses_from_toml() {
    let config = parse_runtime_config_toml(
        r#"
        [scan]
        targets = ["src"]

        [static]
        models_dir = "models/custom"
        "#,
    )
    .expect("parse config");
    assert_eq!(config.static_.models_dir.as_deref(), Some("models/custom"));
}
```

(Use the exact `parse_runtime_config_toml` helper name present in `config.rs` — verify it exists, otherwise use `parse_runtime_config_toml`/`load_runtime_config` as exported in `lib.rs`.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mcp-sec-audit-core config`
Expected: FAIL — `StaticConfig` has no `models_dir` field.

- [ ] **Step 3: Add the config field**

In `config.rs` `StaticConfig`, after `pub codeql: StaticCodeqlConfig,` add:

```rust
    #[serde(default)]
    pub models_dir: Option<String>,
```

In the `Default for RuntimeConfig` (and `StaticConfig::default()` if it has a manual impl — verify), ensure `models_dir: None`. Add to the `Default` impl of `StaticConfig`:

```rust
            models_dir: None,
```

- [ ] **Step 4: Wire runtime load/merge + logging in `extract_static_facts`**

In `facts/pipeline.rs`, replace the `let catalog = default_catalog();` line with:

```rust
use crate::models::{default_catalog, load_models_dir};
// inside extract_static_facts:
let mut catalog = default_catalog();
if let Some(dir) = &ctx.config.static_.models_dir {
    let extra = load_models_dir(std::path::Path::new(dir))?;
    tracing::info!(
        target: "mcp_sec_audit::taint",
        models_dir = %dir,
        loaded = extra.sink_count(),
        "loaded extra sink models"
    );
    catalog.merge(extra);
}
tracing::info!(
    target: "mcp_sec_audit::taint",
    sinks = catalog.sink_count(),
    "sink model catalog ready"
);
```

- [ ] **Step 5: Add a runtime-merge test** — in `facts/pipeline.rs` tests:

```rust
#[test]
fn models_dir_loads_and_merges_custom_sinks() {
    use std::fs;
    let root = temp_dir("models-dir");
    let models_dir = root.join("models");
    fs::create_dir_all(&models_dir).expect("create models dir");
    fs::write(
        models_dir.join("custom.yaml"),
        "- language: python\n  category: command_execution\n  severity: high\n  confidence: high\n  reason: custom\n  patterns: [totally.custom.sink]\n",
    ).expect("write custom model");
    let file = root.join("a.py");
    fs::write(&file, "totally.custom.sink('x')\n").expect("write source");

    let mut config = RuntimeConfig::default();
    config.static_.models_dir = Some(models_dir.display().to_string());
    let ctx = StaticScanContext {
        config,
        rulebook_paths: Vec::new(),
        discovered_files: vec![DiscoveredFile { path: file.clone(), language: ScanLanguage::Python }],
    };
    let facts = extract_static_facts(&ctx).expect("extract facts");
    assert!(facts.iter().any(|f| matches!(f, Fact::Sink(s) if s.sink_name == "totally.custom.sink")));

    fs::remove_dir_all(root).expect("cleanup");
}
```

- [ ] **Step 6: Run the full workspace suite**

Run: `cargo test`
Expected: PASS (core + CLI).

- [ ] **Step 7: Commit**

```bash
git add crates/mcp-sec-audit-core/src/config.rs crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs
git commit -m "feat(models): load and merge extra sink models from [static].models_dir"
```

---

## Final Verification

- [ ] Run the full workspace suite: `cargo test` (all green).
- [ ] CLI smoke test with a custom models_dir: add a `models/custom.yaml` with a unique sink, point a config's `[static].models_dir` at it, run the CLI against a target that calls it, and confirm the terminal logs `loaded extra sink models` and the sink shows up.
