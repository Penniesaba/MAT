# MCP Security Auditor Rust Rewrite

This directory contains the phased Rust rewrite of MCP Security Auditor.

Current scope:

- Rust-native static analysis will be implemented incrementally.
- Dynamic analysis compatibility will be preserved through the existing sandbox, eBPF monitor, and fuzzer until a later Rust-native dynamic runtime decision is made.

Useful commands:

```bash
cargo test
cargo run -p mcp-sec-audit-cli -- --help
cargo run -p mcp-sec-audit-cli -- status
```

Roadmap: [`docs/REFACTOR_PLAN.md`](docs/REFACTOR_PLAN.md)
