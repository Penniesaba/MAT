# CodeQL Line v2 — Industrial-Grade MCP Taint & Vulnerability Mining (Design Spec)

**Status:** Draft (pending review)
**Date:** 2026-08-19
**Supersedes:** `2026-08-05-codeql-analysis-line-design.md` (the "Rust skipped" era)
**Companion narrative:** `rust/docs/CODEQL_MASTER_PLAN.md` (tutorial + diagnosis)

---

## 1. Goal

Upgrade the CodeQL analysis line from a 3-query Python-only prototype into an
**industrial-grade, multi-language (Python / JavaScript / TypeScript / Rust)
MCP-server taint-and-vulnerability engine**. Three concrete deltas over v1:

1. **Rust is now a first-class CodeQL language.** CodeQL 2.26.2 ships a Rust
   extractor (`rust.dbscheme` present). v1's "Rust targets are skipped" rule is
   obsolete and must be removed.
2. **Authoritative query sourcing.** Lean on GitHub's official query packs
   (`codeql/{python,javascript,rust}-queries`) for breadth, and author a **thin
   MCP-specific query layer** for the attack surface official packs do not
   model. Every query cites its authoritative source.
3. **First-class fusion.** CodeQL results gain a `category` aligned with the
   rule/taint vocabulary so stage-2 (category) fusion works, not just line
   proximity.

The MCP query layer must be **comprehensive** — a production-grade matrix
covering the full MCP attack surface across three source models and thirteen
vulnerability categories — not a handful of example queries.

---

## 2. Verified Environment Facts (2026-08-19)

- CodeQL CLI **2.26.2** at `/home/xiao/App/codeql/codeql/codeql`, on PATH.
- `codeql resolve languages` lists: `python`, `javascript`, `typescript` (via
  `javascript`), `rust`, plus `java`, `go`, `csharp`, `cpp`, `ruby`, `swift`,
  `yaml`, `html`, `xml`, `actions`, `properties`, `csv`.
- **No standard query packs are installed.** `codeql resolve packs` returns only
  `legacy-upgrades`. The v1 code already references `codeql/python-queries` and
  `codeql/javascript-queries` — those references would fail at runtime today.
  **M0 must download them** (`codeql pack download codeql/python-queries
  codeql/javascript-queries codeql/rust-queries`).
- Rust standard query pack is `codeql/rust-queries` (library `codeql/rust-all`),
  covering SQL injection, SSRF, path traversal, XSS, disabled certificate
  check, log injection, weak crypto, hardcoded credentials, and more.

---

## 3. Authoritative Sources

These ground the query matrix and are cited in each query's header comment.

| Source | What we take from it |
|---|---|
| `github/codeql` (official) | Standard library APIs, canonical source/sink/sanitizer patterns |
| `codeql/rust-queries` + `codeql/rust-all` | Rust breadth; `rust/sql-injection`, `rust/ssrf`, `rust/path-injection`, `rust/unsafe`… |
| `codeql/python-queries`, `codeql/javascript-queries` | Python/JS breadth |
| `github/securitylab` `CodeQL_Queries/` | Real-CVE taint-tracking models; sanitizer/guard patterns |
| CodeQL Community Packs | Model packs for framework source/sink/summary |
| Invariant Labs (tool poisoning / toxic flows) | S3 metadata-poisoning model; `<IMPORTANT>` marker detection |
| Unit 42 (MCP sampling prompt injection) | S1→LLM prompt-injection model |
| Safeguard.sh / MCP-DPT taxonomy (arXiv 2604.07551) | Category coverage; resource-URI traversal; credential leakage |
| `rmcp` (`modelcontextprotocol/rust-sdk`) | Rust `#[tool]` / `#[tool_router]` / `Parameters<T>` source shape |

---

## 4. Architecture

```
crates/mcp-sec-audit-core/src/static_analysis/codeql/
├── mod.rs           # language filter (py/js/ts/rust) → db → analyze → parse
├── provider.rs      # CliCodeqlProvider (unchanged surface; per-language query select)
├── queries.rs       # resolve per-language QueryPack; language→pack registry
├── parser.rs        # SARIF → result; extract category from @tags / rule-id map
└── queries/
    ├── mcp-python/  qlpack.yml (deps: codeql/python-all)      # ~12 .ql
    ├── mcp-js/      qlpack.yml (deps: codeql/javascript-all)  # ~10 .ql
    └── mcp-rust/    qlpack.yml (deps: codeql/rust-all)        # ~8 .ql
```

Key changes over v1:

- `SUPPORTED_LANGUAGES = ["python", "javascript", "typescript", "rust"]`.
- `queries.rs` replaces the single `builtin_mcp_query_dir()` + "skip builtin for
  non-python" hack with a **language → query-pack-directory registry**.
- `provider.rs` selects query files by the database's language (each pack's
  `.ql` files are language-native, so a Python DB never receives a Rust `.ql`).
- `mod.rs` derives `target_root` from `ctx` scan targets (fixes the
  `first().parent()` fragility).
- Standard suite refs per language: `codeql/{python,javascript,rust}-queries`.

---

## 5. Three Source Models

The MCP attack surface is **three source models × dangerous sinks** (the
"lethal trifecta" framing from Invariant Labs). Queries are authored per source
model + category.

| Model | Definition | Attacker-controlled? | Categories it feeds |
|---|---|---|---|
| **S1 · MCP input** | tool params, resource URI/content, prompt args | Yes (LLM-generated / injected) | command, dynamic, sql, file_read, file_write, ssrf, deserialize, template, path_traversal, prompt_injection |
| **S2 · Sensitive data** | env vars, secret files (`~/.ssh`, `.env`), upstream sensitive data | No — but *exfiltration* = breach | data_exfiltration |
| **S3 · MCP metadata** | tool/resource/prompt **description** strings | Tool-poisoning vector | tool_poisoning |

### 5.1 Per-language source detection

- **Python (S1)**: `@mcp.tool()` / `@fastmcp.tool()` / any `.tool()` decorator
  (decorator name ends in `tool`), **and** registration `server.tool("name", fn)`
  / `mcp.tool(...)`; all handler params are sources (not just arg 0).
- **Python (S2)**: `os.environ`, `os.getenv`, `open("~/.ssh/…")` / `.env` reads.
- **Python (S3)**: description string literal/expr passed to `@mcp.tool(description=…)`
  or `server.tool(..., description=…)`.
- **JS/TS (S1)**: `server.tool(name, handler)` / `tool(name, handler)` registration;
  handler params. (Also `mcp.tool(...)` from `@modelcontextprotocol/sdk`.)
- **JS/TS (S2)**: `process.env`, `fs.readFileSync('.env')`, secret-file reads.
- **JS/TS (S3)**: `description:` string in tool/`z.tool` registration.
- **Rust (S1)**: `#[tool]` / `#[mcp::tool]` / `#[mcp_tool]` / `#[server_tool]`
  attributed fns (matches `facts/rust/mcp.rs`); `#[tool_router]` impl blocks;
  `Parameters<T>` and plain args. rmcp + poem-mcp shape.
- **Rust (S2)**: `std::env::var`, `std::fs::read_to_string` of sensitive paths.
- **Rust (S3)**: `#[tool(description = "…")]` / `#[tool(description = "…", name = "…")]`
  literal args.

> ⚠️ **Rust QL API spike (M1 gate).** The Rust CodeQL library is `0.1.x` and its
> attribute/`Function`/`DataFlow` API surface is less documented than Python/JS.
> M1 opens with a spike that reads `rust.dbscheme` + the bundled example queries
> (`rust/examples/simple-sql-injection`) to confirm the exact predicates for
> "function attribute name" and "parameter node" **before** the Rust source model
> is committed. If the API differs, the source predicates are adapted — the
> category/sink model is unchanged.

---

## 6. Vulnerability Category Matrix (comprehensive)

Canonical vocabulary = existing 9 (`command_execution`, `database_injection`,
`deserialization`, `dynamic_execution`, `env_access`, `file_read`, `file_write`,
`network_request`, `unsafe_block`) + 5 new (`path_traversal`,
`template_injection`, `prompt_injection`, `data_exfiltration`,
`tool_poisoning`) = **14 total**. Of these, **13 map to CodeQL queries** (the
table below); `env_access` remains rule-line-only for now.

> The "Official pack fallback" column records what the Rust query pack is
> *documented* to cover (SQL injection, SSRF, path injection, invalid-pointer
> access, XSS, disabled certificate check, log injection, weak crypto,
> hardcoded credentials, cleartext storage). Exact per-query coverage is
> **confirmed during M0** by inspecting the downloaded `codeql/rust-queries`.

| # | Category | Source | Sink(s) | Py | JS/TS | Rust | Official pack fallback |
|---|---|---|---|---|---|---|---|
| 1 | `command_execution` | S1 | `os.system`, `subprocess.*(shell=True)`, `exec`; `child_process.exec/spawn`; `std::process::Command` | ✅(fix) | M3 | M4 | — |
| 2 | `dynamic_execution` | S1 | `eval`/`exec`/`compile`; `eval`/`Function()` | ✅ | M3 | — | — |
| 3 | `database_injection` | S1 | `cursor.execute`/`conn.execute`; `.query(`; `sqlx::query` | M2 | M3 | M4 | rust✅ |
| 4 | `file_read` | S1 | `open(r)`, `Path.read`; `fs.readFileSync`; `fs::read_to_string` | M2 | M3 | M4 | — |
| 5 | `file_write` | S1 | `open(w/a)`, `shutil.move/copy`, `os.remove`; `fs.writeFileSync`; `fs::write`/`File::create` | M2 | M3 | M4 | — |
| 6 | `network_request` (SSRF) | S1 | `requests`/`httpx`/`urllib`/`aiohttp`; `fetch`/`axios`; `reqwest`/`ureq` | M2 | M3 | M4 | rust✅ |
| 7 | `deserialization` | S1 | `pickle.loads`, `yaml.load`; `JSON.parse`+eval (guarded); `serde_json::from_str`/`bincode` | ✅ | M3 | M4 | — |
| 8 | `template_injection` | S1 | `jinja2` render, `render_template_string`; template literals→render | M2 | M3 | — | — |
| 9 | `path_traversal` | S1 | `open`/`Path` without `realpath`/prefix guard; `fs.*`; `fs::*` | M2 | M3 | M4 | rust✅ |
| 10 | `prompt_injection` | S1 | tool/resource/prompt content → LLM API call (`openai`, `anthropic`, etc.) | ✅(fix) | M3 | M4 | — |
| 11 | `data_exfiltration` | S2 | env/secret → network/log sink | ✅(fix) | M3 | M4 | — |
| 12 | `tool_poisoning` | S3 | description literal w/ instruction markers **OR** untrusted→description→LLM | M2 | M3 | M4 | — |
| 13 | `unsafe_block` | — | `unsafe {}`, raw pointer ops | — | — | M4 | rust✅ |

Total authored queries ≈ **30** (Python ~12, JS/TS ~10, Rust ~8), plus official
pack breadth. Each query has `@id` (`mcp/<lang>/<category>`), `@name`, `@tags`
(`security mcp <category>`), a comment naming the sink + the authoritative
source + the acceptance test sample.

### 6.1 `tool_poisoning` (first-class, delivered in M2–M4)

Two sub-detectors, both reporting category `tool_poisoning`:

- **TP-pattern (heuristic):** the tool/resource/prompt **description string
  literal** contains instruction-injection markers — `<IMPORTANT>`,
  `<SYSTEM>`, `ignore previous instructions`, `do not mention`, `do not tell`,
  `~/.ssh`, `~/.aws`, `mcp.json`, `exfiltrate`, hidden-command phrasing. Not a
  taint query; a string-content query over the registration's description arg.
- **TP-taint:** a description built from **untrusted input** (S1) that reaches
  the LLM context (tool registration → `tools/list` → client context is not
  statically observable, so we model "untrusted → description field" as the
  proxy sink).

> TP-pattern is inherently lower-precision; its results are emitted with
> `verification_status = "needs_review"` and do **not** auto-confirm fusion, but
> still carry the `tool_poisoning` category for cross-line proximity.

---

## 7. Category Alignment & Fusion Integration

The root-cause fix for fusion (v1 used `rule_id` as category).

1. **Model**: add `category: String` to `CodeqlAnalysisResult`; add
   `query_source: String` and `languages: Vec<String>` (un-dead the
   `CodeqlMetadata`).
2. **Parser**: derive `category` from two places, in priority order:
   - (a) our queries' `@tags` → map kebab (`command-execution`) to snake
     (`command_execution`) via a shared tag;
   - (b) a **curated `rule_id → category` map** for official-pack results
     (`rust/sql-injection → database_injection`, `py/cmd-injection →
     command_execution`, `js/command-line-injection → command_execution`, …).
     Unknown ids → `uncategorized` (still fuse by proximity).
3. **Fusion**: `matcher.rs` (`category: Some(c.rule_id)`) and `merger.rs`
   (`build_category`'s `c.rule_id`) switch to `c.category`.
4. **Vocabulary**: add `path_traversal`, `template_injection`,
   `prompt_injection`, `data_exfiltration`, `tool_poisoning` to
   `rules/languages/keywords.toml` and the fusion category vocab so rule/taint
   can cross-verify them too.
5. **`target_root`**: derive from scan targets, not `first().parent()`.

---

## 8. Data Model & Config Changes

### 8.1 `CodeqlAnalysisResult` (additions)

```rust
pub struct CodeqlAnalysisResult {
    pub result_id: String,
    pub rule_id: String,            // unchanged: "mcp/python/command_execution" | "rust/sql-injection"
    pub rule_name: String,
    pub category: String,           // NEW: shared-vocab category
    pub message: String,
    pub severity: Severity,
    pub locations: Vec<Location>,
    pub dataflow_path: Option<DataFlowPath>,
    pub sarif_snippet: Option<String>,
    pub query_source: String,       // NEW: "built-in" | custom path
    pub languages: Vec<String>,     // NEW
    pub related_rule_ids: Vec<String>,
    pub related_taint_ids: Vec<String>,
    pub related_agent_ids: Vec<String>,
    pub verification_status: String,
    pub limitations: Vec<String>,
}
```

### 8.2 Config

`StaticCodeqlConfig` is unchanged. The new per-language packs are **built-in**
(the default when `query_pack_path` is unset). A custom `query_pack_path` still
overrides all built-ins (its `.ql` files run for every language; caller is
responsible for language correctness — same as v1).

---

## 9. Milestones (M0–M5)

| M | Scope | Acceptance |
|---|---|---|
| **M0** env baseline | `codeql pack download codeql/{python,javascript,rust}-queries`; smoke DB+analyze on all three test targets | non-empty SARIF for py/js/rust |
| **M1** Python strengthen + Rust QL spike | fix S1 source (decorator+registration, all params), refine sinks, add sanitizers, `@tags`; **Rust QL API spike** | `run_shell` (+alias) hit; `shlex.quote` not flagged; spike doc recorded |
| **M2** Python full matrix | author remaining ~9 Python queries incl. `tool_poisoning` | `server.py` vulns hit per category; TP-pattern flags a seeded poisoned-description sample |
| **M3** JS/TS matrix | registration-source + full sink set + `tool_poisoning` | `js-mcp-server` eval/file-write/ssrf hit |
| **M4** Rust matrix | rmcp/poem source model + Rust sinks + `unsafe_block` + `tool_poisoning` | `rust-mcp-server` 3 vulns hit |
| **M5** fusion + regression | category mapping, matcher/merger switch, `cargo test` green, 3-target E2E | rule+taint+codeql triple corroboration appears |

---

## 10. Testing

| Module | Tests | Needs CodeQL? |
|---|---|---|
| `queries.rs` | per-language pack resolution; rust pack exists; suite-refs per lang | No |
| `parser.rs` | SARIF→result incl. `category` from tags & rule-id map; metadata populated | No |
| `mod.rs` | rust in supported set; target_root from targets | No |
| `matcher.rs`/`merger.rs` | category-based codeql fusion | No |
| `.ql` acceptance | one seeded vulnerable + one safe sample per query (no-vuln ⇒ 0 hits) | Yes (M0+) |

---

## 11. Risk Assessment

| Risk | Mitigation |
|---|---|
| Rust QL API unknown/drifting (0.1.x) | M1 spike reads `rust.dbscheme` + bundled examples before committing source model |
| Standard packs missing at runtime | M0 hard prerequisite; diagnostics if `codeql pack download` incomplete |
| `tool_poisoning` TP-pattern false positives | `verification_status = needs_review`; excluded from auto-confirm |
| Category map drift as official queries add ids | curated map is a single table with a test asserting every known id maps; unknown → `uncategorized` |
| Official pack over-reporting (breadth noise) | official results keep original `rule_id`; only our queries drive cross-line category fusion |

---

## 12. Non-Goals

- Go/Java/C#/C++ support (architecture leaves a language-registry extension
  point; not in this phase).
- Client-side (agent/host) hardening — this line audits the **server**.
- Runtime prompt-injection *classification* (that's agent/host policy, not
  static taint).
- Vendoring official query packs into the repo (we reference via
  `codeql pack download` + `import` their libraries).

---

## 13. References

- CodeQL Rust query help — https://codeql.github.com/codeql-query-help/rust/
- `github/codeql` — https://github.com/github/codeql
- `github/securitylab` — https://github.com/github/securitylab
- CodeQL Community Packs — https://github.blog/security/vulnerability-research/announcing-codeql-community-packs/
- Invariant Labs, MCP tool poisoning — https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- Invariant Labs, Toxic Flows — https://invariantlabs.ai/blog/toxic-flow-analysis1
- Unit 42, MCP sampling injection — https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/
- Safeguard, MCP security/CVEs — https://safeguard.sh/resources/blog/securing-model-context-protocol-mcp-servers
- MCP-DPT taxonomy (arXiv 2604.07551) — https://ar5iv.labs.arxiv.org/html/2604.07551
- `rmcp` macros — https://github.com/modelcontextprotocol/rust-sdk/blob/main/crates/rmcp-macros/README.md
