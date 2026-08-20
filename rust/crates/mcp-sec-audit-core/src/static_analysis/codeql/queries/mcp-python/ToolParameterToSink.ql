/**
 * @name MCP tool parameter to dangerous sink
 * @description Tracks data flow from MCP tool parameters (decorator or
 *              registration form) to dangerous sinks without sanitization.
 * @kind path-problem
 * @problem.severity error
 * @id mcp/tool-parameter-to-sink
 * @tags security mcp command-execution
 */

// Test sample: test-targets/python-mcp-server/server.py — run_shell (command injection)
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import semmle.python.frameworks.internal.PoorMansFunctionResolution

/**
 * A decorator `@<obj>.tool(...)` whose attribute name ends in "tool"
 * (`@mcp.tool()`, `@fastmcp.tool()`, `@server.tool()`), OR a registration
 * call `server.tool("name", handler)` / `mcp.tool("name", handler)`.
 */
class McpToolSource extends DataFlow::Node {
  McpToolSource() {
    // Decorator form: @x.tool() on a function — every parameter is a source.
    exists(Function f, Call dec, Attribute attr |
      dec = f.getADecorator() and
      dec.getFunc() = attr and
      attr.getName() = "tool" and
      this = DataFlow::parameterNode(f.getAnArg())
    )
    or
    // Registration form: server.tool("name", handler) — handler's parameters.
    exists(DataFlow::CallCfgNode call, Function handler |
      call = API::moduleImport("mcp").getMember("tool").getACall()
      and poorMansFunctionTracker(handler) = call.getArg(1)
      and this = DataFlow::parameterNode(handler.getAnArg())
    )
  }
}

/** Command execution / dynamic code / deserialization / file sinks. */
class DangerousSink extends DataFlow::Node {
  DangerousSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("os").getMember("system").getACall() or
      call = API::moduleImport("os").getMember("popen").getACall() or
      call = API::moduleImport("subprocess").getMember("run").getACall() or
      call = API::moduleImport("subprocess").getMember("Popen").getACall() or
      call = API::moduleImport("subprocess").getMember("call").getACall() or
      call = API::builtin("eval").getACall() or
      call = API::builtin("exec").getACall() or
      call = API::moduleImport("pickle").getMember("loads").getACall() or
      call = API::moduleImport("builtins").getMember("open").getACall()
    |
      this = call.getArg(0)
    )
  }
}

/** Recognized sanitizers: shell quoting and path canonicalization. */
class Sanitizer extends DataFlow::Node {
  Sanitizer() {
    this = API::moduleImport("shlex").getMember("quote").getACall() or
    this = API::moduleImport("os").getMember("path").getMember("realpath").getACall() or
    this = API::moduleImport("os").getMember("path").getMember("abspath").getACall() or
    this = API::moduleImport("os").getMember("path").getMember("normpath").getACall()
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof McpToolSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof DangerousSink }
  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to a dangerous sink without sanitization.",
  source.getNode(), "user input"
