/**
 * @name MCP tool parameter to network request
 * @description Tracks server.tool() handler parameters into outbound network
 *              requests (fetch / http.request / https.request).
 * @kind path-problem
 * @problem.severity warning
 * @id mcp-js/tool-param-to-network
 * @tags security mcp network-request
 */

// Test sample: test-targets/js-mcp-server/server.js (no network sample)
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

/** Outbound request sinks: `fetch(url)` and `http(s).request(url)` (arg 0). */
class NetworkSink extends DataFlow::Node {
  NetworkSink() {
    exists(DataFlow::CallNode call, string name |
      name = call.getCalleeName() and
      (name = "fetch" or name = "request") and
      call.getArgument(0) = this
    )
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) { s instanceof ServerToolSource }
  predicate isSink(DataFlow::Node s) { s instanceof NetworkSink }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to an outbound network request (SSRF).",
  source.getNode(), "user input"
