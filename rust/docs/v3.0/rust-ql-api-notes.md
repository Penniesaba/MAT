# Rust CodeQL API — Spike Reference (2026-08-19)

Source of truth for the follow-up Rust MCP query matrix (spec §6 M4). Everything
below was read directly from the installed `codeql/rust-queries@0.1.39` pack
(library `codeql/rust-all@0.2.18`), not inferred.

Pack locations:

- Query pack: `~/.codeql/packages/codeql/rust-queries/0.1.39/`
- Library: `~/.codeql/packages/codeql/rust-queries/0.1.39/.codeql/libraries/codeql/rust-all/0.2.18/`

The Rust dataflow API is the **same modern `ConfigSig` pattern** as Python/JS —
not the older `TaintTracking::Configuration` class.

---

## 1. Import lines

```ql
import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import codeql.rust.Concepts                     // QuerySink::Range, ActiveThreatModelSource
import codeql.rust.dataflow.FlowSink            // sinkNode(this, "type") — Models-as-Data
import codeql.rust.dataflow.FlowSource          // sourceNode(this, "type")
import codeql.rust.dataflow.FlowBarrier         // barrierNode(this, "type")
```

---

## 2. Taint config shape

### Stateless (the common case — e.g. `SqlInjection.ql`)

```ql
module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof Source }
  predicate isSink(DataFlow::Node node)   { node instanceof Sink }
  predicate isBarrier(DataFlow::Node barrier) { barrier instanceof Barrier }
  predicate observeDiffInformedIncrementalMode() { any() }   // required
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This $@ reaches a sink.",
  source.getNode(), "user-provided value"
```

### Stateful (e.g. `TaintedPath.ql` tracks normalization state)

```ql
module Config implements DataFlow::StateConfigSig {
  class FlowState = NormalizationState;   // newtype in the query
  predicate isSource(DataFlow::Node source, FlowState state) { ... }
  predicate isSink(DataFlow::Node sink, FlowState state) { ... }
  predicate isBarrier(DataFlow::Node node) { ... }
  predicate isBarrier(DataFlow::Node node, FlowState state) { ... }
  predicate isAdditionalFlowStep(DataFlow::Node from, FlowState sf, DataFlow::Node to, FlowState st) { ... }
  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::GlobalWithState<Config>;
```

---

## 3. Identifying a function's attribute (`#[tool]`, `#[mcp::tool]`)

`Function` extends `Item`, which exposes (in `codeql/rust/internal/PathResolution.qll`):

```ql
Attr getAnAttr()                    // any attribute on the item
Attr getAttr(string name)           // attribute whose path is UNQUALIFIED and == name
predicate hasAttr(string name)      // exists(this.getAttr(name))
```

- `#[tool]`  → `f.hasAttr("tool")` works (path `tool` is unqualified).
- `#[mcp::tool]` / `#[server_tool]` → the path is **qualified**, so `getAttr("tool")`
  does **not** match. Match the full path instead:

```ql
predicate hasToolAttr(Function f) {
  f.getAnAttr().getMeta().getPath().toStringDebug() = ["tool", "mcp::tool", "mcp_tool", "server_tool"]
}
```

Attribute path text: `attr.getMeta().getPath().toStringDebug()` → `"mcp::tool"`.

---

## 4. Function parameter nodes

```ql
// Function is a Callable.
callable.getParamList()                  // ParamList
paramList.getAParam() / getParam(int i)  // Param
param.getPat()                           // the binding pattern (IdentPat)
param.getTypeRepr()                      // parameter type

// Param -> the Callable it belongs to
param.(ParamBase).getCallable()          // ParamBaseImpl: getCallable()

// Param -> its DataFlow::Node:
//   DataFlow::Node.asParameter() : ParamBase
//   (i.e. a node IS the parameter node iff node.asParameter() succeeds)
```

MCP **source model** (tool params are attacker-controlled):

```ql
class McpToolParamSource extends DataFlow::Node {
  McpToolParamSource() {
    exists(Function f | hasToolAttr(f) | this.asParameter().getCallable() = f)
  }
}
```

---

## 5. Call expression → callee function / path

`CallExpr` (`codeql/rust/elements/internal/CallExprImpl.qll`):

```ql
call.getFunction()                       // Expr (a PathExpr for `path::to::fn()` calls)
call.getArgList()                        // ArgList
call.getArgList().getArg(int i)          // the i-th syntactic argument
call.(CallExprCall).getPositionalArgument(int i)   // method-aware positional arg
call.(CallExprMethodCall).getReceiver()  // `self` receiver (if a method call)

// Resolving the callee (Impl-internal, but the canonical mechanism):
CallExprImpl::getFunctionPath(CallExpr ce)        // Path of the callee
CallExprImpl::getResolvedFunction(CallExpr ce)    // ItemNode (the resolved Function/etc.)

// Public resolution is exposed via Call (codeql/rust/elements/internal/CallImpl.qll):
call.(Call).getResolvedTarget()          // the resolved Callable (Method / Fn)
```

Path text (`codeql/rust/elements/internal/PathImpl.qll`):

```ql
path.getText()          // last segment only, e.g. "new", "write", "from_str"
path.toStringDebug()    // full qualified text e.g. "std::process::Command::new"
                        //   (doc-commented "for debugging purposes")
path.getQualifier()     // PathAlias of the qualifier (recursive)
path.getSegment()       // PathSegment
```

**Sink model** (match a call by its full path text):

```ql
class CommandSink extends QuerySink::Range {
  CommandSink() {
    this = any(CallExpr c | c.getFunction().(PathExpr).getPath().toStringDebug()
                            = "std::process::Command::new")
        .getFunction()
  }
  override string getSinkType() { result = "command_execution" }
}
```

`Command::new` returns a builder, so the tainted **URL/arg** is the argument to
`Command::new(...)`, and the actual spawn sinks are `.arg(...)` / `.output()` /
`.status()` method calls on the returned `Command` — a method-call chain, so the
follow-up plan must model the intermediate `Command` value (see §8 caveats).

---

## 6. Source / sink abstraction (`codeql/rust/Concepts.qll`)

```ql
abstract class Source extends DataFlow::Node { }          // per-query source
abstract class Sink extends QuerySink::Range {            // per-query sink
  override string getSinkType() { ... }
}

// Threat-model sources (active by default):
ActiveThreatModelSource
  CommandLineArgsSource   // std::env::args
  EnvironmentSource       // std::env::var
  FileSource              // std::fs::read_to_string / File::open
  StdInSource             // stdin
  DatabaseSource          // DB rows
  RemoteSource            // network input

// Models-as-Data (framework sinks come from model packs, not hardcoded QL):
sourceNode(this, "type") / sinkNode(this, "type") / barrierNode(this, "type")
```

The official framework sinks (e.g. `reqwest`, `sqlx`) are **not** hardcoded in the
queries — they arrive via Models-as-Data (`sinkNode(this, "request-url")`,
`sinkNode(this, "sql-injection")`). Our MCP queries should follow the same pattern:
either hardcode the call path (§5) for the few MCP-critical sinks, or contribute a
MaD model pack (out of scope for the core plan).

---

## 7. Official `rust-queries` coverage (authoritative `@id`s)

| Query | `@id` | Maps to shared category |
|---|---|---|
| CWE-089 SqlInjection | `rust/sql-injection` | `database_injection` |
| CWE-918 RequestForgery | `rust/request-forgery` | `network_request` |
| CWE-022 TaintedPath | `rust/path-injection` | `path_traversal` |
| CWE-825 AccessInvalidPointer | `rust/access-invalid-pointer` | `unsafe_block` |
| CWE-825 AccessAfterLifetime | `rust/access-after-lifetime-ended` | `unsafe_block` |
| CWE-079 XSS | `rust/xss` | — (not in vocab) |
| CWE-117 LogInjection | `rust/log-injection` | — |
| CWE-295 DisabledCertificateCheck | `rust/disabled-certificate-check` | — |
| CWE-311/312 Cleartext | `rust/cleartext-*` | — |
| CWE-319 UseOfHttp | `rust/non-https-url` | — |
| CWE-327 Crypto | `rust/weak-cryptographic-algorithm`, `rust/weak-sensitive-data-hashing` | — |
| CWE-614 InsecureCookie | `rust/insecure-cookie` | — |
| CWE-696 BadCtorInit | `rust/ctor-initialization` | — |
| CWE-770 UncontrolledAllocation | `rust/uncontrolled-allocation-size` | — |
| CWE-798 HardcodedCredential | `rust/hard-coded-cryptographic-value` | — |
| CWE-020 RegexInjection | `rust/regex-injection` | — |

> **Coverage gaps** (must be authored as MCP queries): `command_execution`,
> `file_read`, `file_write`, `deserialization`, `dynamic_execution`,
> `template_injection`, `prompt_injection`, `data_exfiltration`, `tool_poisoning`.
>
> Note `rust/ssrf` does **not** exist — the SSRF id is `rust/request-forgery`
> (the parser `rule_id → category` map was corrected to match).

---

## 8. Minimal working example (skeleton for the M4 matrix)

```ql
/**
 * @name MCP tool parameter flows to a command execution sink
 * @id mcp/rust/command_execution
 * @kind path-problem
 * @tags security mcp command_execution
 */
import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import codeql.rust.Concepts

predicate hasToolAttr(Function f) {
  f.getAnAttr().getMeta().getPath().toStringDebug() = ["tool", "mcp::tool", "mcp_tool", "server_tool"]
}

class ToolParamSource extends DataFlow::Node {
  ToolParamSource() {
    exists(Function f | hasToolAttr(f) | this.asParameter().getCallable() = f)
  }
}

class CommandSink extends QuerySink::Range {
  CommandSink() {
    this = any(CallExpr c |
      c.getFunction().(PathExpr).getPath().toStringDebug() = "std::process::Command::new"
    ).getFunction()
  }
  override string getSinkType() { result = "command_execution" }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof ToolParamSource }
  predicate isSink(DataFlow::Node node) { node instanceof CommandSink }
  predicate isBarrier(DataFlow::Node node) { node instanceof ActiveThreatModelSource implies false }
  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Tool parameter reaches a command sink."
```

---

## 9. Caveats to carry into M4

1. **Macro expansion is limited.** Building a DB on `test-targets/rust-mcp-server`
   emits `macro expansion failed for 'format'` / `format_args_nl` warnings and the
   extractor reports "N files extracted with errors". The AST (functions, `#[tool]`
   attributes, call exprs) is still extracted; the warnings are about built-in
   `format!`/`println!` macros. `#[tool]` is a **proc-macro attribute**, so its
   expansion also does not happen at extraction — the attribute node is present but
   its body is opaque. `hasToolAttr` (§3) matches the attribute path, not expansion.
2. **`toStringDebug()` is "debug only"** per its doc comment — prefer matching the
   resolved target (`getResolvedTarget()`) over string equality where possible, but
   string matching on `toStringDebug()` is the pragmatic first cut for `std::…` paths.
3. **`Command::new` is a builder.** The taint flows into `Command::new(arg)` and the
   sink of interest is the subsequent `.arg()/.output()/.status()` method call on the
   returned `Command`. M4's command query must track the builder value (a local-flow
   chain), not just `Command::new` itself.
4. **`serde_json::from_str` is generic** — the deserialization sink needs the call's
   *type argument* / target trait impl, not just the function path. Model it by path
   (`serde_json::from_str`, `serde_json::from_slice`, `bincode::deserialize`) and
   refine precision later.
5. **MaD vs hardcoded.** Official framework sinks use Models-as-Data; for the ~8 MCP
   sinks, hardcoding call paths in QL is sufficient and self-contained. A dedicated
   MaD model pack is a future enhancement, not required for M4.
