# Phase 7 Task 6 Design: Python Call Facts and Alias Normalization

## Scope

This design covers only Phase 7 Task 6 of the Rust static-analysis refactor: Python call fact extraction and alias normalization.

This task continues from `rust/docs/PHASE7_STATUS.md`, where Phase 7 is partially complete. The current extractor already produces Python import, function, MCP entrypoint, and MCP parameter source facts. Task 6 adds call facts and uses existing import alias state during call normalization.

This task does not implement assign facts, sink facts, static pipeline integration, taint analysis, phase constant updates, final documentation updates, or end-to-end Phase 7 completion.

## Goals

- Extract `Fact::Call` entries from Python AST call expressions.
- Capture original callee text, normalized callee text, positional arguments, keyword arguments, caller function identity, location, and snippet evidence.
- Normalize imported aliases in calls.
- Add a narrow assignment-alias bridge for simple function aliases such as `runner = sp.run` followed by `runner(...)`.
- Preserve the existing extractor style and existing Phase 7 behavior.
- Add focused tests and a printable intermediate-result test for Task 6.

## Non-goals

- Do not generate `Fact::Assign` in this task.
- Do not implement full assignment tracking.
- Do not implement complete Python scope or shadowing semantics.
- Do not implement call graph construction.
- Do not implement taint propagation.
- Do not classify dangerous sinks.
- Do not mark Phase 7 as complete.

## Architecture

The implementation stays inside the Python fact extractor layer.

Primary file:

- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/python.rs`

Supporting existing helper:

- `rust/crates/mcp-sec-audit-core/src/static_analysis/facts/ids.rs`
  - Use existing `make_call_id(root, file, line, column)`.

The extractor remains a RustPython AST visitor. It already parses the Python file, tracks imports, function scope, and class scope, and emits facts into one vector. Task 6 extends that visitor to also traverse expressions and emit call facts.

## Data Flow

1. `extract_python_facts(root, file, source)` parses the file with RustPython.
2. Import statements update `import_aliases` as they do today.
3. Simple alias assignments update `assignment_aliases`, but do not emit assign facts.
4. Statement and expression traversal visits nested expressions.
5. When an `ast::Expr::Call` is found:
   - Render the original callee expression.
   - Resolve the callee through `assignment_aliases`, then `import_aliases`.
   - Render positional arguments as source-like expression strings.
   - Render keyword arguments as name/value pairs.
   - Compute the caller function ID from the current function scope when inside a function.
   - Compute line and column from the call source range.
   - Extract a short source snippet for evidence.
   - Emit `Fact::Call` with ID from `make_call_id`.
6. Sort facts with the existing `fact_sort_key` behavior.

## Alias Normalization Rules

Task 6 supports these cases:

```python
import subprocess as sp
sp.run(command, shell=True)
```

Normalized callee:

```text
subprocess.run
```

```python
from subprocess import run
run(command)
```

Normalized callee:

```text
subprocess.run
```

```python
runner = sp.run
runner(command, shell=True)
```

Normalized callee:

```text
subprocess.run
```

The simple assignment alias rule is deliberately narrow:

- Left side must be a simple name.
- Right side must render to a resolvable callee-like expression.
- The alias map stores the normalized right-side value.
- The task does not emit `Fact::Assign`.

Unsupported cases remain unresolved and fall back to the original callee text:

- Tuple/list unpacking.
- Attribute assignment such as `self.runner = sp.run`.
- Conditional assignment modeling.
- Complex reassignment and shadowing.
- Dynamic mutation of imported objects.

## Error Handling

- Keep current syntax error behavior: return a `syntax_error` diagnostic, return no facts, and do not panic.
- If a callee cannot be normalized, use the original rendered callee.
- If an argument cannot be rendered precisely, use the extractor's conservative expression rendering rather than failing extraction.
- Call extraction should not abort the file extraction unless the parser itself fails.

## Tests

Add focused tests in `python.rs`:

1. `extracts_calls_with_args_kwargs_and_alias_resolution`
   - Verifies direct calls.
   - Verifies `import x as y` alias normalization.
   - Verifies `from x import y` normalization.
   - Verifies simple assignment alias normalization.
   - Verifies positional args and kwargs are captured.
   - Verifies caller function ID is populated for calls inside functions.

2. `prints_phase7_task6_intermediate_facts`
   - Prints Task 6 facts as JSON under `-- --nocapture`.
   - Confirms intermediate inspection includes import, function, entrypoint, source, and call facts.

Recommended verification commands:

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core static_analysis::facts::python::tests
```

```bash
cargo test --manifest-path /home/xiao/Project/mcp-sec-audit/rust/Cargo.toml \
  -p mcp-sec-audit-core prints_phase7_task6_intermediate_facts -- --nocapture
```

## Acceptance Criteria

Task 6 is complete when:

- Python call expressions produce `Fact::Call` records.
- Call facts include callee, normalized callee, args, kwargs, caller function ID, location, and snippet evidence according to the existing model fields.
- Import alias normalization works for `import module as alias` and `from module import name`.
- Simple assignment alias normalization works for `name = imported_or_aliased_callable`.
- Existing Phase 7 tests still pass.
- New Task 6 tests pass.
- Intermediate Task 6 JSON facts can be printed with `-- --nocapture`.

## Implementation Boundaries for Later Tasks

Task 7 should own real assign fact extraction and richer assignment alias behavior.

Task 8 should own sink fact classification.

Later pipeline tasks should connect `extract_static_facts` and `run_static_scan` to real facts.

Taint-line behavior and default taint configuration should be fixed before Phase 7 is marked complete, but not in this Task 6 implementation.
