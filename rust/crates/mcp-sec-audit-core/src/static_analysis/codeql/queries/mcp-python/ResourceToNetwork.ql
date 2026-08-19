/**
 * @name MCP Resource Read to Network Outbound
 * @description Detects MCP resource/content reads that flow into outbound
 *              network calls, indicating potential data exfiltration.
 * @kind path-problem
 * @problem.severity warning
 * @id mcp/resource-to-network
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

// MCP resource handlers
class McpResourceSource extends DataFlow::Node {
  McpResourceSource() {
    exists(Function f |
      f.getADecorator().(Call).getFunc().(Attribute).getObject().(Name).getId() = "mcp" and
      f.getADecorator().(Call).getFunc().(Attribute).getName() = "resource" and
      this = DataFlow::parameterNode(f.getArg(0))
    )
  }
}

// Network outbound sinks
class NetworkSink extends DataFlow::Node {
  NetworkSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("requests").getMember("get").getACall() or
      call = API::moduleImport("requests").getMember("post").getACall() or
      call = API::moduleImport("httpx").getMember("Client").getReturn().getMember("get").getACall() or
      call = API::moduleImport("httpx").getMember("Client").getReturn().getMember("post").getACall() or
      call = API::moduleImport("aiohttp").getMember("ClientSession").getReturn().getMember("get").getACall() or
      call = API::moduleImport("aiohttp").getMember("ClientSession").getReturn().getMember("post").getACall() or
      call = API::moduleImport("urllib").getMember("request").getMember("urlopen").getACall() or
      call = API::moduleImport("socket").getMember("socket").getReturn().getMember("connect").getACall()
    |
      this = call.getArg(0)
    )
  }
}

module ResourceToNetworkConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof McpResourceSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof NetworkSink }
}

module ResourceToNetworkFlow = TaintTracking::Global<ResourceToNetworkConfig>;

import ResourceToNetworkFlow::PathGraph

from ResourceToNetworkFlow::PathNode source, ResourceToNetworkFlow::PathNode sink
where ResourceToNetworkFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP resource data flows from $@ to an outbound network call without sanitization.",
  source.getNode(), "user input"
