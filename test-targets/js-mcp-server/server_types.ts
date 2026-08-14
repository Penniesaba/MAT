/**
 * Test MCP server (TypeScript) with intentional vulnerabilities.
 *
 * This file demonstrates:
 *   - ESM import syntax (TypeScript-specific)
 *   - Type annotations (interfaces, type hints)
 *   - Template literals with user input in shell commands
 *
 * Vulnerability: Command Injection via exec()
 */

import { exec } from "child_process";

// Type definitions — tests that type annotations don't break analysis
interface WebhookParams {
  url: string;
  payload: string;
}

interface ToolResult {
  success: boolean;
  message: string;
  data?: unknown;
}

// Fake MCP server
const server = {
  tool(name: string, handler: (params: any) => Promise<any>) {
    return { name, handler };
  },
};

// ---------------------------------------------------------------------------
// Tool: run_webhook — Command Injection
// ---------------------------------------------------------------------------

server.tool("run_webhook", async (params: WebhookParams): Promise<ToolResult> => {
  const { url, payload } = params;

  // VULNERABILITY: Command Injection
  // User-controlled url and payload interpolated directly into shell command
  const curlCommand = `curl -X POST -d '${payload}' ${url}`;
  exec(curlCommand, (error, stdout, stderr) => {
    if (error) {
      console.error(`Webhook failed: ${stderr}`);
    }
  });

  return {
    success: true,
    message: `Webhook dispatched to ${url}`,
  };
});

export { server };
