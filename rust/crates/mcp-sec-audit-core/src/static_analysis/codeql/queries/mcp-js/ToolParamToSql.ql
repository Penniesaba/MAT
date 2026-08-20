/**
 * @name MCP tool parameter to SQL query
 * @description Tracks server.tool() handler parameters into SQL queries
 *              (connection.query / .execute / .run).
 * @kind path-problem
 * @problem.severity error
 * @id mcp-js/tool-param-to-sql
 * @tags security mcp database-injection
 */

// Test sample: test-targets/js-mcp-server/server.js (db_query builds SQL from user input)
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

/** SQL sinks: `connection.query(sql)` / `.execute(sql)` / `.run(sql)` (arg 0). */
class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(DataFlow::CallNode call, string name |
      name = call.getCalleeName() and
      (name = "query" or name = "execute" or name = "run") and
      call.getArgument(0) = this
    )
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) { s instanceof ServerToolSource }
  predicate isSink(DataFlow::Node s) { s instanceof SqlSink }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to a SQL query (SQL injection).",
  source.getNode(), "user input"
