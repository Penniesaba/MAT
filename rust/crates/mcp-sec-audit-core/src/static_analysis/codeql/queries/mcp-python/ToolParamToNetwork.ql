/**
 * @name MCP tool parameter to network request
 * @description Tracks MCP tool parameters flowing into outbound network requests
 *              (SSRF).
 * @kind path-problem
 * @problem.severity warning
 * @id mcp/tool-param-to-network
 * @tags security mcp network-request
 */

// Test sample: test-targets/python-mcp-server/server.py — fetch_url (SSRF via requests.get)
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

/** Outbound network requests whose URL/address is attacker-controllable. */
class NetworkSink extends DataFlow::Node {
  NetworkSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("requests").getMember("get").getACall() or
      call = API::moduleImport("requests").getMember("post").getACall() or
      call = API::moduleImport("httpx").getMember("get").getACall() or
      call = API::moduleImport("httpx").getMember("post").getACall() or
      call = API::moduleImport("urllib").getMember("request").getMember("urlopen").getACall() or
      call = API::moduleImport("socket").getMember("socket").getReturn().getMember("connect").getACall()
    |
      this = call.getArg(0)
    )
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof McpToolSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof NetworkSink }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to an outbound network request (SSRF).",
  source.getNode(), "user input"
