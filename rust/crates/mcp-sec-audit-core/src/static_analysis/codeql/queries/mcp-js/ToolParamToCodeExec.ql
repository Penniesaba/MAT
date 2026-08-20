/**
 * @name MCP tool parameter to dynamic code execution
 * @description Tracks server.tool() handler parameters into eval() and the
 *              Function constructor.
 * @kind path-problem
 * @problem.severity error
 * @id mcp-js/tool-param-to-code-exec
 * @tags security mcp dynamic-execution
 */

// Test sample: test-targets/js-mcp-server/server.js — db_query (eval)
import javascript

/** `server.tool("name", handler)` — the handler's parameters are sources. */
class ServerToolSource extends DataFlow::Node {
  ServerToolSource() {
    exists(DataFlow::CallNode call, DataFlow::FunctionNode handler |
      call.getCalleeName() = "tool" and
      handler = call.getAnArgument().getAFunctionValue() and
      this = handler.getAParameter()
    )
  }
}

/** Dynamic code sinks: `eval(code)` and `Function(code)` constructor (arg 0). */
class CodeExecSink extends DataFlow::Node {
  CodeExecSink() {
    exists(DataFlow::InvokeNode call, string name |
      name = call.getCalleeName() and
      (name = "eval" or name = "Function") and
      call.getArgument(0) = this
    )
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) { s instanceof ServerToolSource }
  predicate isSink(DataFlow::Node s) { s instanceof CodeExecSink }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to dynamic code execution (code injection).",
  source.getNode(), "user input"
