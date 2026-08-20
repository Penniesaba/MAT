/**
 * @name MCP tool parameter to file write
 * @description Tracks server.tool() handler parameters into file writes,
 *              indicating potential arbitrary file write.
 * @kind path-problem
 * @problem.severity warning
 * @id mcp-js/tool-param-to-file-write
 * @tags security mcp file-write
 */

// Test sample: test-targets/js-mcp-server/server.js — export_file (fs.writeFileSync)
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

/**
 * File write sinks: `fs.writeFile*`/`appendFile*` (arg 1 = content) and
 * `fs.createWriteStream` (arg 0 = path).
 */
class FileWriteSink extends DataFlow::Node {
  FileWriteSink() {
    exists(DataFlow::CallNode call, string name |
      name = call.getCalleeName() and
      (name = "writeFile" or name = "writeFileSync" or name = "appendFile" or name = "appendFileSync") and
      call.getArgument(1) = this
    )
    or
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "createWriteStream" and
      call.getArgument(0) = this
    )
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) { s instanceof ServerToolSource }
  predicate isSink(DataFlow::Node s) { s instanceof FileWriteSink }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to a file write (arbitrary file write).",
  source.getNode(), "user input"
