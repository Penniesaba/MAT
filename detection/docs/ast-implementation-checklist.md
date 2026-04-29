# Multi-language AST Implementation Checklist

This document is the execution playbook for `feat-ast-plan.md`.
It defines development flow, migration steps, acceptance gates, and rollback
rules to make delivery predictable and auditable.

---

## 1. Development Flow (Required)

Every implementation batch must follow this order:

1. Design note update
   - Update ADR or add a short decision note before coding.
2. Schema-first coding
   - Define or update fact model and IDs first.
3. Extractor/passes implementation
   - Add parser/extractor logic and analysis passes.
4. Test coverage
   - Unit tests + integration tests + benchmark delta check.
5. Dual-output verification
   - Verify both `FindingFact` and adapted `CapabilityFinding` outputs.
6. Report compatibility check
   - Confirm JSON/Markdown and web adapter are not broken.

No phase is marked complete without all six steps.

---

## 2. Phase-by-Phase Execution Checklist

## Phase 1 - Fact Schema and Store

- [ ] Add fact base types and schema module.
- [ ] Implement deterministic ID generation with project-relative paths.
- [ ] Implement store-level duplicate ID detection.
- [ ] Add JSON/JSONL serialization and deserialization tests.
- [ ] Add schema version tag for forward compatibility.

Exit gate:

- [ ] Serialization roundtrip passes for all fact types.
- [ ] Same filename in different directories does not collide.

## Phase 2 - Python Extractor MVP

- [ ] Extract `FunctionFact`, `ImportFact`, `CallFact`, `EntryPointFact`,
      `SourceFact` from Python AST.
- [ ] Support import alias and basic assignment alias normalization.
- [ ] Detect MCP entry decorators (`mcp.tool`, `server.tool`, equivalent forms).
- [ ] Emit initial `SinkFact` for high-value RCE/file/network sinks.

Exit gate:

- [ ] Supported-scope fixtures all pass.
- [ ] Unsupported patterns fail gracefully with no crash.

## Phase 3 - Call Graph, Reachability, Sink Detection, Adapter

- [ ] Build call graph from `CallFact` and local function symbols.
- [ ] Compute entrypoint-to-sink reachability.
- [ ] Produce `FindingFact` with call-chain evidence.
- [ ] Implement `FindingFact -> CapabilityFinding` adapter.
- [ ] Validate old report renderers with adapted output.

Exit gate:

- [ ] End-to-end finding includes entrypoint, sink, evidence, confidence.
- [ ] Existing CLI report paths remain functional.

## Phase 4 - JavaScript/TypeScript Extractor

- [ ] Integrate Tree-sitter parser bindings.
- [ ] Support ESM import, CommonJS require, and destructured require.
- [ ] Support MCP tool registration patterns with inline handlers.
- [ ] Emit call and sink facts for node command/file/network behaviors.

Exit gate:

- [ ] JS/TS benchmark fixtures provide valid entry/call/sink extraction.

## Phase 5 - Taint-lite

- [ ] Mark MCP parameters and trusted/untrusted source classes.
- [ ] Track assignment propagation.
- [ ] Track call argument propagation to sink parameters.
- [ ] Emit `DataFlowFact` with ordered path steps.

Exit gate:

- [ ] `source -> assign -> sink_arg` path is reconstructable in reports.

## Phase 6 - Dynamic Correlation

- [ ] Convert runtime telemetry to `RuntimeEventFact`.
- [ ] Implement static/dynamic matching heuristics with confidence scores.
- [ ] Assign finding status (`potential`, `confirmed`, `runtime_only`).
- [ ] Surface dynamic evidence references in final findings.

Exit gate:

- [ ] Confirmed findings always carry runtime evidence IDs.
- [ ] Runtime-only findings are explicit and auditable.

---

## 3. Migration Process (Dual-Track)

## 3.1 Shadow mode

Run new analysis in parallel with legacy static detectors. Do not replace output
consumers yet.

Required outputs per run:

- Legacy capability results.
- New finding facts.
- Adapter-produced legacy-compatible findings.

## 3.2 Comparison mode

For benchmark and selected real targets, compare:

- New facts directly.
- Adapter output vs legacy output.
- Per-category false positive/false negative deltas.

## 3.3 Controlled switchover

Switch primary static result source only after acceptance gates are met for two
consecutive benchmark runs.

## 3.4 Rollback policy

Immediate rollback to legacy primary path if any of these happen:

- Critical regression in high-severity categories.
- Report format break for portal/CLI consumers.
- Unbounded runtime or memory regression in scan pipeline.

---

## 4. Acceptance Metrics (Release Gates)

Metrics must be tracked by risk category and language.

1. Detection quality

- False negative rate (new) <= false negative rate (legacy).
- False positive rate (new) <= false positive rate (legacy).
- High-severity category recall must not regress.

2. Evidence quality

- Entry-to-sink chain completeness rate >= 95% for positive findings.
- Source-to-sink path completeness rate >= 90% where source is present.
- Runtime-confirmed findings must include evidence references (100%).

3. Stability and performance

- Pipeline crash rate: 0 on benchmark.
- P95 scan time regression <= 25% vs legacy static baseline.
- Peak memory regression <= 30% vs baseline.

4. Compatibility

- JSON report schema remains parseable by existing consumers.
- Markdown report generation remains intact.
- Web adapter ingestion success rate = 100% on validation batch.

---

## 5. Validation Dataset and Cadence

- Primary benchmark: MCPTox dataset.
- Secondary fixtures: curated multi-language regression suite.

Cadence:

- Per PR: unit + integration checks for changed modules.
- Nightly: benchmark run with metric diff report.
- Pre-release: two consecutive full benchmark runs with no gate failures.

---

## 6. Ownership and Review

For each phase, assign:

- Engineering owner.
- Security reviewer.
- Benchmark owner.

Required sign-off to close a phase:

1. Code owner approval.
2. Security reviewer approval.
3. Metrics report attached and archived.
