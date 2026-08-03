# Phase 7 Completion Design: Python Fact Extraction Integration

## Scope

This design covers the remaining work required to complete Phase 7 of the Rust static-analysis refactor for `mcp-sec-audit`.

Phase 7 is Rust-native Python fact extraction. It is not full taint analysis, full call graph construction, dynamic analysis, agent analysis, or finding fusion. Those later lines must not be represented as implemented during this phase.

The current Phase 7 implementation already supports result-model facts, report rendering controls, Python import facts, function facts, MCP entrypoint facts, MCP parameter source facts, call facts, import alias normalization, and a narrow Task 6 assignment alias bridge.

This completion pass adds assign facts, sink facts, syntax diagnostic tests, static fact pipeline integration, static scan result integration, explicit taint-line failure semantics, default taint disabling, phase constant update, final documentation updates, and end-to-end verification.

## Goals

- Emit `Fact::Assign` for Python direct assignments that the existing model can represent.
- Emit `Fact::Sink` for a focused deterministic set of dangerous Python calls needed by later taint work.
- Keep syntax errors visible and safe: no panic, no forged facts, diagnostic with file, line, kind, and message.
- Replace the empty `extract_static_facts` placeholder with a real Python file extraction pipeline.
- Wire extracted facts into `run_static_scan` and `StaticAnalysisSummary.fact_count`.
- Make unimplemented taint analysis fail clearly when explicitly enabled.
- Disable taint by default in TOML config and Rust defaults.
- Update the public phase constant only after the Phase 7 behavior is implemented and verified.
- Update Chinese documentation to mark Phase 7 complete while preserving boundaries for later phases.
- Run focused and end-to-end verification before branch finishing.

## Non-goals

- Do not implement JavaScript, TypeScript, or Rust fact extraction.
- Do not implement full assignment/dataflow semantics.
- Do not implement full Python scoping or shadowing semantics.
- Do not implement taint propagation.
- Do not implement call graph construction.
- Do not implement agent analysis.
- Do not implement finding fusion.
- Do not claim Phase 10/11 functionality exists.

## Architecture

The implementation remains inside the existing Rust static-analysis modules.

Primary files:

- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`
  - Extends the Python AST extractor with assign fact emission and sink classification.
- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/ids.rs`
  - Reuses existing `make_assign_id` and `make_sink_id` helpers.
- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/pipeline.rs`
  - Replaces the placeholder `extract_static_facts` implementation with real Python extraction over discovered files.
- `rust/crates/mcp-sec-audit-core/src/static_analysis/pipeline.rs`
  - Wires static facts into `run_static_scan` results and summary.
- `rust/crates/mcp-sec-audit-core/src/static_analysis/lines.rs`
  - Changes enabled taint behavior from empty result to explicit error.
- `rust/crates/mcp-sec-audit-core/src/config.rs`
  - Changes taint default to disabled.
- `rust/config/default.toml`
  - Changes `[static.taint].enabled` to `false`.
- `rust/crates/mcp-sec-audit-core/src/lib.rs`
  - Updates `CURRENT_PHASE` after completion.
- `rust/docs/PHASE7_STATUS.md`, `rust/docs/REFACTOR_PLAN.md`, `rust/docs/STATIC_ANALYSIS_REFACTOR_DESIGN.md`
  - Documents the completed Phase 7 boundary.

## Assign facts

The extractor emits `Fact::Assign` for:

- `Assign` with simple target names such as `command = request.command`.
- `Assign` with simple attribute/subscript targets rendered by the existing conservative expression renderer when they are representable as a single target string.
- `AnnAssign` when a value exists, such as `runner: Callable = sp.run`.

The extractor does not emit assign facts for tuple/list unpacking in this phase because the current `AssignFact` model represents one target and one value.

`AugAssign` is traversed for nested expressions and calls but does not emit `Fact::Assign` in Phase 7. This avoids overstating dataflow semantics.

Each assign fact includes:

- ID from `make_assign_id(root, file, line, target)`.
- file, line, extractor.
- current function ID or empty string outside a function.
- rendered target.
- rendered value.
- source snippet.

The existing assignment alias map is updated through the same assignment handling path so Task 6 call normalization behavior is preserved and extended for annotated assignments.

## Sink facts

Sink facts are derived deterministically from call facts during Python extraction. This is classification only; no taint propagation is performed.

Phase 7 sink coverage includes:

- Command execution:
  - `subprocess.run`
  - `subprocess.Popen`
  - `os.system`
  - `os.popen`
- File write:
  - `open` when a mode argument or `mode=` kwarg contains write/append/update intent: `w`, `a`, `x`, or `+`.
  - `Path.write_text`
  - `Path.write_bytes`
- Dynamic execution:
  - `eval`
  - `exec`
- Network / SSRF baseline:
  - `requests.get`
  - `requests.post`
  - `requests.request`
  - `httpx.get`
  - `httpx.post`
  - `httpx.request`
  - `urllib.request.urlopen`
- Dynamic import / plugin loading:
  - `importlib.import_module`
  - `__import__`

Each sink fact includes:

- ID from `make_sink_id(category, root, file, line)`.
- linked `call_id`.
- category.
- rule ID using a stable `python.<category>` style.
- sink name using the normalized callee when available.
- severity baseline.
- reason string.
- conditions map with relevant call evidence.
- confidence.

## Syntax diagnostics

Syntax diagnostics remain non-panicking and file-local. A parse error returns:

- no facts,
- one `syntax_error` diagnostic,
- diagnostic file,
- diagnostic line,
- diagnostic kind,
- diagnostic message.

The static fact pipeline treats diagnostics as explicit extraction errors so enabled extraction does not silently produce empty results.

## Static fact pipeline

`extract_static_facts(ctx)` iterates `ctx.discovered_files`, filters to Python files, reads source from disk, calls `extract_python_facts`, and aggregates facts.

If one or more Python extraction diagnostics exist, `extract_static_facts` returns an error summarizing the diagnostics. This satisfies the Phase 7 rule that enabled but failed extraction must not pretend completion by returning empty facts.

Non-Python files are skipped in Phase 7.

## Static scan integration

`run_static_scan()` calls `extract_static_facts(&ctx)?` after discovery and before constructing the result.

The result sets:

- `StaticAnalysisResult.facts = facts`.
- `StaticAnalysisSummary.fact_count = facts.len()`.

Rule results remain independent. Taint results remain empty by default because taint is disabled by default.

## Taint behavior

When `ctx.config.static_.taint.enabled` is `false`, `run_taint_line()` returns an empty vector.

When it is `true`, `run_taint_line()` returns an explicit error:

```text
taint analysis line is enabled but not implemented until Phase 10/11; disable [static.taint].enabled or continue the refactor roadmap
```

This prevents an enabled unimplemented feature from returning `Ok(Vec::new())`.

## Configuration

The default TOML config changes:

```toml
[static.taint]
enabled = false
```

Rust defaults also use `enabled: false` for `StaticTaintConfig`. Serde defaults for missing `enabled` fields must also resolve to false.

## Documentation and phase constant

After the implementation and tests pass, update:

```rust
pub const CURRENT_PHASE: &str = "phase7-python-fact-extraction";
```

The docs should state that Phase 7 is complete and should list the supported fact types:

- import
- function
- entrypoint
- source
- call
- assign
- sink

The docs must also say Phase 7 does not implement full taint propagation, full call graph, full finding fusion, agent analysis, or dynamic analysis.

## Testing

Focused tests:

- Python extractor assign facts and assignment aliases.
- Python extractor sink facts from dangerous calls.
- Python syntax diagnostics.
- Static facts pipeline extracts real Python facts from discovered files.
- `run_static_scan` includes facts and summary fact count.
- Explicitly enabled taint returns the expected error.
- Default config disables taint.
- Current phase constant is updated after completion.

End-to-end verification:

```bash
cargo fmt --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml --all -- --check
```

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml -p mcp-sec-audit-core
```

```bash
cargo run --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-cli -- scan static \
  --config /home/xiao/Project/mcp-sec-audit/rust/config/default.toml \
  --target <phase7-python-fixture> \
  --rules /home/xiao/Project/mcp-sec-audit/detection/detection/rules/keywords.toml \
  --format json
```

Manual JSON checks:

- top-level `facts` is non-empty,
- `summary.fact_count == facts.len()`,
- `rule_results` remains present when rules match,
- `taint_results` is empty by default,
- explicitly enabling taint returns the clear unimplemented error.

## Acceptance criteria

Phase 7 is complete when:

- Assign facts are emitted and tested.
- Sink facts are emitted and tested.
- Syntax diagnostics behavior is tested.
- `extract_static_facts` is no longer an empty placeholder.
- `run_static_scan` includes facts and correct fact count.
- Taint is disabled by default.
- Explicitly enabled taint errors clearly.
- The phase constant says `phase7-python-fact-extraction`.
- Chinese docs reflect Phase 7 completion and boundaries.
- Focused tests, full core tests, formatting check, and static scan JSON verification pass.
