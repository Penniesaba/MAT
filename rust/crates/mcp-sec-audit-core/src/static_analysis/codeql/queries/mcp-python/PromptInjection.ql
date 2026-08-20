/**
 * @name MCP Prompt Parameter to LLM API Call
 * @description Tracks user-supplied prompt parameters flowing into LLM API
 *              calls, which may enable prompt injection attacks.
 * @kind path-problem
 * @problem.severity warning
 * @id mcp/prompt-injection
 * @tags security mcp prompt-injection
 */

// Test sample: test-targets/python-mcp-server/server.py
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import semmle.python.frameworks.internal.PoorMansFunctionResolution

// MCP prompt entrypoints — decorated with @mcp.prompt() or registered via mcp.prompt("name", handler)
class McpPromptSource extends DataFlow::Node {
  McpPromptSource() {
    exists(Function f |
      f.getADecorator().(Call).getFunc().(Attribute).getObject().(Name).getId() = "mcp" and
      f.getADecorator().(Call).getFunc().(Attribute).getName() = "prompt" and
      this = DataFlow::parameterNode(f.getArg(0))
    )
    or
    // Registration form: mcp.prompt("name", handler) — handler's parameters.
    exists(DataFlow::CallCfgNode call, Function handler |
      call = API::moduleImport("mcp").getMember("prompt").getACall()
      and poorMansFunctionTracker(handler) = call.getArg(1)
      and this = DataFlow::parameterNode(handler.getAnArg())
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

import PromptInjectionFlow::PathGraph

from PromptInjectionFlow::PathNode source, PromptInjectionFlow::PathNode sink
where PromptInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP prompt parameter flows from $@ to an LLM API call, enabling prompt injection.",
  source.getNode(), "user input"
