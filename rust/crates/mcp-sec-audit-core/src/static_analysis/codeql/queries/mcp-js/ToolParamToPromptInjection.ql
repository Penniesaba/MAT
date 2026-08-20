/**
 * @name MCP tool parameter to LLM prompt
 * @description Tracks server.tool() handler parameters into LLM API prompts,
 *              which may enable prompt injection attacks.
 * @kind path-problem
 * @problem.severity warning
 * @id mcp-js/tool-param-to-prompt-injection
 * @tags security mcp prompt-injection
 */

// Test sample: test-targets/js-mcp-server/server.js (no LLM sample)
import javascript
import semmle.javascript.Concepts

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
 * LLM prompt sinks: any argument modeled as an AI prompt via the `AIPrompt`
 * concept (covers OpenAI / Anthropic / Google GenAI / Agent SDK clients).
 */
class PromptInjectionSink extends DataFlow::Node {
  PromptInjectionSink() { this = any(AIPrompt p).getAPrompt() }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) { s instanceof ServerToolSource }
  predicate isSink(DataFlow::Node s) { s instanceof PromptInjectionSink }
}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to an LLM prompt (prompt injection).",
  source.getNode(), "user input"
