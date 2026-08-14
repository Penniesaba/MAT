/**
 * Test MCP server (JavaScript) with intentional vulnerabilities.
 *
 * This file demonstrates:
 *   - CommonJS require (destructured + simple)
 *   - Inline arrow function handlers
 *   - Named function handlers (tests backfill)
 *   - Cross-function taint through helper modules
 *
 * Vulnerabilities:
 *   - db_query:    SQL Injection + Dynamic Code Execution (eval)
 *   - export_file: Arbitrary File Write (fs.writeFileSync)
 */

const { exec } = require("child_process");
const fs = require("fs");
const { writeFile } = require("./helpers");

// Fake MCP server object — mimics @modelcontextprotocol/sdk pattern
const server = {
  tools: {},
  tool(name, handler) {
    this.tools[name] = handler;
    return { name, handler };
  },
};

// ---------------------------------------------------------------------------
// Tool 1: db_query — SQL Injection + eval() vulnerability
// Uses inline arrow handler pattern
// ---------------------------------------------------------------------------

server.tool("db_query", async (params) => {
  const { query, table } = params;

  // VULNERABILITY 1: Dynamic code execution via eval()
  // User input reaches eval() — classic code injection
  const filterFn = eval(`(row) => row.name === '${query}'`);

  // VULNERABILITY 2: SQL Injection
  // Template literal with unsanitized user input
  const sql = `SELECT * FROM ${table} WHERE name = '${query}'`;

  // VULNERABILITY 3: Command execution via exec()
  // Process spawn with user-controlled input
  exec(`echo "Running query: ${sql}"`, (error, stdout) => {
    if (error) console.error("exec error:", error);
  });

  return {
    sql_query: sql,
    filter_function: filterFn.toString(),
    message: "Query executed",
  };
});

// ---------------------------------------------------------------------------
// Tool 2: export_file — Arbitrary File Write
// Uses named handler pattern (tests backfill_named_handlers)
// ---------------------------------------------------------------------------

async function exportFileHandler(params) {
  const { filename, content } = params;

  // Cross-function call: writeFile helper passes through to fs.writeFileSync
  // without path sanitization — taint should propagate
  const result = writeFile(filename, content);

  return {
    file_written: filename,
    bytes: content.length,
    result,
  };
}

server.tool("export_file", exportFileHandler);

module.exports = { server };
