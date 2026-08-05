/**
 * @name MCP Prompt Parameter to LLM API Call
 * @description Tracks user-supplied prompt parameters flowing into LLM API
 *              calls, which may enable prompt injection attacks.
 * @kind path-problem
 * @problem.severity warning
 * @id mcp/prompt-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

// MCP prompt entrypoints
class McpPromptSource extends DataFlow::Node {
  McpPromptSource() {
    exists(Function f |
      f.getADecorator().(Call).getFunc().(Attribute).getObject().(Name).getId() = "mcp" and
      f.getADecorator().(Call).getFunc().(Attribute).getName() = "prompt" and
      this = f.getArg(0)
    )
  }
}

// LLM API call sinks
class LlmApiSink extends DataFlow::Node {
  LlmApiSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("openai").getMember("ChatCompletion").getMember("create").getACall() or
      call = API::moduleImport("openai").getMember("Completion").getMember("create").getACall() or
      call = API::moduleImport("anthropic").getMember("messages").getMember("create").getACall() or
      call = API::moduleImport("google").getMember("generativeai").getMember("GenerativeModel").getReturn().getMember("generate_content").getACall()
    |
      this = call.getArg(0)
    )
  }
}

module PromptInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof McpPromptSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof LlmApiSink }
}

module PromptInjectionFlow = TaintTracking::Global<PromptInjectionConfig>;

from PromptInjectionFlow::PathNode source, PromptInjectionFlow::PathNode sink
where PromptInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP prompt parameter flows to LLM API $@, enabling prompt injection.",
  sink.getNode(), sink.getNode().toString()
