/**
 * @name MCP Tool Parameter to Dangerous Sink
 * @description Tracks data flow from MCP tool parameters to dangerous sinks
 *              (command execution, file write, code evaluation).
 * @kind path-problem
 * @problem.severity error
 * @id mcp/tool-parameter-to-sink
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

// MCP tool entrypoints — decorated with @mcp.tool() or server.tool()
class McpToolEntrypoint extends DataFlow::Node {
  McpToolEntrypoint() {
    exists(Function f |
      f.getADecorator().(Call).getFunc().(Attribute).getObject().(Name).getId() = "mcp" and
      f.getADecorator().(Call).getFunc().(Attribute).getName() = "tool" and
      this = DataFlow::parameterNode(f.getArg(0))
    )
  }
}

// Dangerous sinks for MCP context
class DangerousSink extends DataFlow::Node {
  DangerousSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("os").getMember("system").getACall() or
      call = API::moduleImport("subprocess").getMember("run").getACall() or
      call = API::moduleImport("subprocess").getMember("Popen").getACall() or
      call = API::moduleImport("subprocess").getMember("call").getACall() or
      call = API::moduleImport("os").getMember("popen").getACall() or
      call = API::builtin("eval").getACall() or
      call = API::builtin("exec").getACall() or
      call = API::moduleImport("pickle").getMember("loads").getACall() or
      call = API::moduleImport("builtins").getMember("open").getACall()
    |
      this = call.getArg(0)
    )
  }
}

module McpToolToSinkConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof McpToolEntrypoint }
  predicate isSink(DataFlow::Node sink) { sink instanceof DangerousSink }
}

module McpToolToSinkFlow = TaintTracking::Global<McpToolToSinkConfig>;

import McpToolToSinkFlow::PathGraph

from McpToolToSinkFlow::PathNode source, McpToolToSinkFlow::PathNode sink
where McpToolToSinkFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to a dangerous sink without sanitization.",
  source.getNode(), "user input"
