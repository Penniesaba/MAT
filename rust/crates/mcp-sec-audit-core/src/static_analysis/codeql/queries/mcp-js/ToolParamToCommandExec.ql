/**
 * @name MCP tool parameter to command execution
 * @description Tracks server.tool() handler parameters into child_process
 *              command execution.
 * @kind path-problem
 * @problem.severity error
 * @id mcp-js/tool-param-to-command-exec
 * @tags security mcp command-execution
 */

// Test sample: test-targets/js-mcp-server/server.js — db_query / run_webhook (command injection)
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

/** `child_process` shell command sinks: exec/spawn (arg 0 = command string). */
class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(DataFlow::CallNode call, string name |
      name = call.getCalleeName() and
      (name = "exec" or name = "execSync" or name = "spawn" or name = "spawnSync") and
      call.getArgument(0) = this
    )
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) { s instanceof ServerToolSource }
  predicate isSink(DataFlow::Node s) { s instanceof CommandSink }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to a shell command (command injection).",
  source.getNode(), "user input"
