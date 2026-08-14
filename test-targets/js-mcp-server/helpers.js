/**
 * Helper functions for the JS test MCP server.
 *
 * These are deliberately in a separate file to test cross-file
 * require() resolution and taint propagation across module boundaries.
 */

const fs = require("fs");

/**
 * Write content to a file.
 *
 * DELIBERATELY VULNERABLE: no path sanitization before writing.
 * The filename comes directly from the caller (ultimately from user input).
 */
function writeFile(filename, content) {
  // No validation or sanitization — taint should flow through this
  fs.writeFileSync(filename, content, "utf-8");
  return `Wrote ${content.length} bytes to ${filename}`;
}

module.exports = { writeFile };
