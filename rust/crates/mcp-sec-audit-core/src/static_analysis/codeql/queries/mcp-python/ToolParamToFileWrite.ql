/**
 * @name MCP tool parameter to file write
 * @description Tracks MCP tool parameters flowing into file writes, indicating
 *              potential arbitrary file write.
 * @kind path-problem
 * @problem.severity warning
 * @id mcp/tool-param-to-file-write
 * @tags security mcp file-write
 */

// Test sample: test-targets/python-mcp-server/server.py (no write-mode sample)
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

/** File writes: `open(path, mode)` in write mode, or `shutil.move(src, dst)`. */
class FileWriteSink extends DataFlow::Node {
  FileWriteSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("builtins").getMember("open").getACall() and
      call.getArg(1).asExpr().(StringLiteral).getText().matches("%w%") and
      this = call.getArg(0)
    )
    or
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("shutil").getMember("move").getACall() and
      this = call.getArg(0)
    )
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof McpToolSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof FileWriteSink }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to a file write (arbitrary file write).",
  source.getNode(), "user input"
