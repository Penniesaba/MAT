# Multi-language AST Security Analysis ADRs

This document records the architecture decisions behind `feat-ast-plan.md`.
It focuses on why choices were made, alternatives considered, tradeoffs, and
what must be true before each decision can be considered successful.

---

## 1. Decision Scope and Constraints

### 1.1 Product Goals

The new analysis layer must provide:

1. Entry-to-sink call-chain evidence for MCP tools.
2. Lightweight source-to-sink flow evidence.
3. Cross-language coverage for Python + JavaScript/TypeScript.
4. Static and dynamic evidence correlation.
5. Backward compatibility with existing reporting and portal consumers.

### 1.2 Constraints

- Existing production pipeline uses `CapabilityFinding` end-to-end.
- Current static analyzers are keyword/regex based.
- Current dynamic analyzer emits capability-style findings from CEF events.
- Migration cannot break benchmark execution or report consumers.
- Team capacity favors incremental milestones over big-bang rewrites.

### 1.3 Non-goals

- No full compiler IR.
- No full context/path/alias-sensitive taint engine in phase 1.
- No immediate removal of legacy regex detectors.

---

## 2. ADR-001: Use Security Facts Instead of Common AST/IR

- Status: Accepted
- Date: 2026-04-29
- Owners: Detection architecture working group

### Context

We need a model that supports semantic security analysis across multiple
languages without implementing a full language-independent compiler frontend.

### Options considered

1. Build a custom language-agnostic AST/IR.
2. Keep language-native trees and unify at the semantic-facts layer.

### Decision

Choose option 2. Extract language-specific facts and run analysis passes on
unified security facts.

### Rationale

- Delivers required security evidence with lower complexity.
- Keeps parser complexity local to each extractor.
- Allows phased rollout and faster benchmark feedback.

### Consequences

Positive:

- Faster initial delivery.
- Easier onboarding for contributors by module.

Negative:

- Some semantic edge cases remain language-specific.
- Requires stricter fact schema versioning discipline.

### Success criteria

- Facts are sufficient to reconstruct entrypoint, call-chain, sink, and
  confidence-evidence in reports.

---

## 3. ADR-002: Keep Legacy CapabilityFinding During Migration

- Status: Accepted
- Date: 2026-04-29

### Context

Current reporting, mitigation, benchmark scripts, and web adapter consume
`CapabilityFinding` and related JSON/JSONL layouts.

### Options considered

1. Replace all downstream consumers immediately.
2. Add `FindingFact -> CapabilityFinding` adapter and run in dual mode.

### Decision

Choose option 2 and keep dual output until acceptance gates pass.

### Rationale

- Avoids breaking existing workflows.
- Enables side-by-side quality comparisons.
- Reduces rollout risk in CI and portal integration.

### Consequences

Positive:

- Safe migration with measurable parity.

Negative:

- Temporary duplication of models and tests.

### Exit criteria

- New findings match or exceed old pipeline accuracy goals.
- JSON and Markdown reports remain complete and stable.

---

## 4. ADR-003: Tree-sitter for JS/TS Parsing

- Status: Accepted
- Date: 2026-04-29

### Context

We need JS/TS parsing from Python runtime with robust grammar support and
reasonable performance for batch scans.

### Options considered

1. Node-based parser toolchain (Babel/TypeScript compiler via subprocess).
2. Tree-sitter bindings in Python.

### Decision

Choose Tree-sitter Python bindings for JS/TS extractor implementation.

### Rationale

- Works inside Python pipeline without Node runtime dependency.
- Fast parser startup and parsing speed.
- Supports both JS and TS with mature grammars.

### Consequences

Positive:

- Consistent extractor runtime model.

Negative:

- CST traversal is less semantic than compiler APIs, requiring stronger symbol
  resolution pass.

### Success criteria

- Correct extraction for import/require patterns, tool registrations, and key
  sink calls on benchmark samples.

---

## 5. ADR-004: Taint-lite First, Full Taint Later

- Status: Accepted
- Date: 2026-04-29

### Context

We need actionable flow evidence quickly, but full taint analysis is expensive
to build and validate across languages.

### Options considered

1. Build full interprocedural path/context-sensitive taint first.
2. Start with taint-lite: parameter source + assignment/call propagation.

### Decision

Choose option 2 for initial rollout.

### Rationale

- Covers high-impact findings with far lower complexity.
- Enables confidence-evidence reporting early.
- Allows measured expansion based on benchmark misses.

### Known limitations

- Complex alias chains and dynamic dispatch remain partial.
- Deep closure/metaprogramming patterns are not first-phase targets.

---

## 6. ADR-005: Dynamic Correlation Uses Confidence Tiers

- Status: Accepted
- Date: 2026-04-29

### Context

Dynamic events can confirm behavior but may be noisy and may not always map to
a precise static path.

### Decision

Use three statuses:

- `potential`: static path exists, no dynamic confirmation yet.
- `confirmed`: dynamic event matches static sink/path with enough confidence.
- `runtime_only`: dynamic event observed but no static path match.

### Rationale

- Preserves evidence transparency.
- Avoids over-claiming certainty.
- Provides practical triage signals.

---

## 7. Decision Review Process

Each significant design update must include:

1. Context statement (problem + constraints).
2. Options and rejected alternatives.
3. Decision and rationale.
4. Risk and rollback plan.
5. Validation metrics and owner.

Review cadence:

- Weekly architecture sync for open ADRs.
- Gate review at each phase exit before wider rollout.

---

## 8. Open Questions and Deferred Decisions

1. How far symbol resolution should go across package boundaries in phase 1.
2. Whether to persist facts on disk for incremental scans.
3. Whether to introduce graph storage for large projects.
4. How to version fact schema changes for backward compatibility.

These are explicitly deferred and must be tracked as new ADR entries when
implementation pressure requires commitment.

---

## 9. Phase 2 Implementation Note (Python Extractor MVP)

- Status: Implemented (Phase 2 scope)
- Date: 2026-04-29

### Scope

This phase implemented the Python Extractor MVP for the following fact types:
Function, Import, Call, EntryPoint, Source, and Sink.

### Implementation choices

1. Alias normalization uses chained resolution across both import aliases and
   assignment aliases.
2. Decorator matching was tightened from substring-style matching to
   boundary/exact matching to reduce false positives.
3. Sink detection first targets a minimal high-risk rule set covering RCE,
   file operations, and network operations.
4. Parser failures are handled with graceful fail: `SyntaxError` returns a
   structured error result instead of crashing the pipeline.

### Known limitations (intentional in this phase)

- Alias handling is baseline-level and not full semantic resolution.
- Sink/source rules still require benchmark-driven tuning in later phases.

### Phase 3 boundary

Out of scope for this implementation note: call graph, reachability analysis,
and adapter-layer work.
