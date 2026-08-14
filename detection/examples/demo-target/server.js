/**
 * Demo MCP Server (JavaScript) — intentionally vulnerable for security testing.
 *
 * This file contains multiple security issues that the mcp-sec-audit
 * static analysis engine should detect:
 *
 *   1. RCE via child_process.exec with user input
 *   2. Dynamic code execution via eval()
 *   3. File read with user-controlled path
 *   4. Network outbound via http.request and fetch
 */

const { exec, execSync } = require("child_process");
const fs = require("fs");
const http = require("http");

// ─── MCP server setup ──────────────────────────────────────────────────
const server = { tool: (name, handler) => ({ name, handler }) };

// ─── Vulnerability 1: RCE via child_process.exec ───────────────────────
server.tool("run_command", async (params) => {
    const { command } = params;
    // DANGEROUS: user input passed directly to shell
    exec(command, (error, stdout, stderr) => {
        console.log(stdout);
    });
});

// ─── Vulnerability 2: RCE via child_process.execSync ───────────────────
server.tool("run_sync_command", async (params) => {
    const { cmd } = params;
    // DANGEROUS: synchronous shell execution with user input
    return execSync(cmd).toString();
});

// ─── Vulnerability 3: Dynamic code execution ───────────────────────────
server.tool("eval_code", async (params) => {
    const { code } = params;
    // DANGEROUS: arbitrary code evaluation
    return eval(code);
});

// ─── Vulnerability 4: File read with user path ─────────────────────────
server.tool("read_file", async (params) => {
    const { path } = params;
    // DANGEROUS: path traversal possible
    return fs.readFileSync(path, "utf-8");
});

// ─── Vulnerability 5: Network outbound ─────────────────────────────────
server.tool("fetch_url", async (params) => {
    const { url } = params;
    // DANGEROUS: SSRF — user controls the URL
    const response = await fetch(url);
    return response.text();
});

// ─── Vulnerability 6: Environment variable access ──────────────────────
server.tool("get_env", async (params) => {
    const { varName } = params;
    // DANGEROUS: credential leak
    return process.env[varName];
});

console.log("[demo-server-js] MCP server ready");
