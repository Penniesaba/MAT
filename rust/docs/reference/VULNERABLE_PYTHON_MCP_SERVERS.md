# Vulnerable Python MCP Servers — Real-World Test Targets

Curated list of **real, open-source Python-language MCP servers with publicly documented
vulnerabilities** (CVE / GHSA / PySec advisories). Each entry is a candidate test target for
`mcp-sec-audit`'s static-analysis pipeline, and each is mapped to the detection line(s)
(Rule / Taint / Agent / CodeQL) most likely to catch it.

> Selection criteria: (1) Python implementation, (2) public GitHub repo, (3) at least one
> documented CVE/advisory describing a genuine MCP-server security flaw. Advisories and fix
> versions were verified against the GitHub Advisory Database, PyPA advisory database, and
> NVD as of 2026-08-20.

---

## Summary

| #   | Repository                                                                                                                                                                     | Package / Server                  | Vulnerability Class                              | CVE / Advisory                                       | Fixed In                         | This system's detectors               |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------- | ------------------------------------------------ | ---------------------------------------------------- | -------------------------------- | ------------------------------------- |
| 1   | [`modelcontextprotoc[`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers)ol/servers`](https://github.com/modelcontextprotocol/servers) (`src/git`) | `mcp-server-git`                  | Path traversal, argument injection               | CVE-2025-68143 / 68144 / 68145, CVE-2026-27735       | 2025.9.25, 2025.12.18, 2026.1.14 | Rule (path), Taint (CLI args), CodeQL |
| 2   | [`baryhuang/mcp-server-aws-resources-python`](https://github.com/baryhuang/mcp-server-aws-resources-python)                                                                    | `mcp-server-aws-resources-python` | Code injection (`exec`)                          | CVE-2025-63604                                       | — (no patch)                     | CodeQL (code-injection), Agent        |
| 3   | [`MervinPraison/PraisonAI`](https://github.com/MervinPraison/PraisonAI)                                                                                                        | `praisonai`                       | Path traversal → RCE (`.pth`), command injection | GHSA-9mqq-jqxf-grvw (CVE-2026-44336), CVE-2026-41497 | 4.6.9                            | Rule (path), Taint, CodeQL            |
| 4   | [`jlowin/fastmcp`](https://github.com/jlowin/fastmcp)                                                                                                                          | `fastmcp`                         | OS command injection (`shell=True`)              | GHSA-rj5c-58rq-j5g5 (CVE-2025-62801), CVE-2025-64340 | 2.13.0 / 3.2.0                   | Taint (subprocess), Rule              |
| 5   | [`haris-musa/excel-mcp-server`](https://github.com/haris-musa/excel-mcp-server)                                                                                                | `excel-mcp-server`                | Path traversal, missing auth                     | CVE-2026-40576 (PYSEC-2026-331)                      | 0.1.8                            | Rule (path), Taint                    |
| 6   | [`appsecco/vulnerable-mcp-servers-lab`](https://github.com/appsecco/vulnerable-mcp-servers-lab)                                                                                | — (training lab)                  | Deliberate (path join, unsandboxed exec)         | — (intentional)                                      | —                                | All four lines (regression suite)     |

---

## 1. `modelcontextprotocol/servers` — `mcp-server-git` (official)

- **Repo:** https://github.com/modelcontextprotocol/servers (Git server lives in `src/git`)
- **PyPI:** [`mcp-server-git`](https://pypi.org/project/mcp-server-git/) — Anthropic reference server, ~180K weekly downloads.
- **Language:** Python (uses GitPython).

The official Git MCP server accumulated **four** distinct flaws over late 2025 → early 2026,
all stemming from insufficient validation of LLM-supplied paths/arguments, all reachable via
**prompt injection** (malicious READMEs, poisoned issue bodies) rather than direct host access.

| CVE | Weakness | Tool | Impact |
|-----|----------|------|--------|
| [CVE-2025-68143](https://github.com/advisories/GHSA-5cgr-j3jf-jw3v) (GHSA-5cgr-j3jf-jw3v) | CWE-22 path traversal | `git_init` accepts arbitrary filesystem paths | turn any dir into a repo; **tool removed** in 2025.9.25 |
| [CVE-2025-68144](https://github.com/advisories/GHSA-9xwc-hfwc-8w59) (GHSA-9xwc-hfwc-8w59) | CWE-88 argument injection | `git_diff` / `git_checkout` pass user args verbatim to git CLI | flag-like values (`--output=/path`) → arbitrary file overwrite; fixed 2025.12.18 |
| CVE-2025-68145 | path validation bypass | `--repository` flag not validated | escape repo boundary |
| [CVE-2026-27735](https://github.com/advisories/GHSA-vjqx-cfc4-9h6v) (GHSA-vjqx-cfc4-9h6v) | CWE-22 path traversal | `git_add` stages paths with `../` outside repo (GitPython `index.add()`) | stage/overwrite files outside repo; fixed 2026.1.14 |

**Documented attack chain:** chain `git_*` with the Filesystem MCP server to write a malicious
`.git/config` containing a `clean` filter, then trigger arbitrary code execution when `git_add`
invokes the filter. Reported by Cyata / HackerOne (yardenporat).

**Why it's a strong test target:** realistic path traversal + argument injection in a widely
deployed reference server. Checkout a pre-fix tag (e.g. `< 2025.9.25`) to exercise the `git_init`
flaw. Clone: `git clone https://github.com/modelcontextprotocol/servers.git` → `src/git`.

---

## 2. `baryhuang/mcp-server-aws-resources-python` (AWS Resources MCP)

- **Repo:** https://github.com/baryhuang/mcp-server-aws-resources-python
- **Vulnerability:** [CVE-2025-63604](https://github.com/advisories/ghsa-fxw5-f8vf-f238) (GHSA-fxw5-f8vf-f238), CWE-77/94 code injection, CVSS 6.5.
- **Affected version:** 0.1.0 (no patch published at time of advisory).

The `execute_query` tool executes LLM-supplied input with `exec()` in a namespace that exposes
dangerous Python builtins — `__import__`, `getattr`, `hasattr`. Consequences include arbitrary
Python code execution, theft of `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, filesystem
access, and env-var disclosure. PoC references: `issues/8`.

**Why it's a strong test target:** textbook `exec()`-of-user-input, exactly the "dynamic code
execution" sink the CodeQL code-injection query and the Agent line target. Clone:
`git clone https://github.com/baryhuang/mcp-server-aws-resources-python.git`.

---

## 3. `MervinPraison/PraisonAI` (PraisonAI MCP)

- **Repo:** https://github.com/MervinPraison/PraisonAI
- **Vulnerabilities:**
  - [GHSA-9mqq-jqxf-grvw](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-9mqq-jqxf-grvw) (CVE-2026-44336): **path traversal → RCE via Python `.pth` injection.**
  - CVE-2026-41497: **command injection** in `parse_mcp_command()` — arbitrary executables
    (`bash`, `python`, `/bin/sh`) with inline `-c` code pass through to subprocess; CVSS 9.8;
    fixed in 4.6.9.

The path-traversal chain is notable for its escalation: four file tools
(`rules.create/show/delete`, `workflow.show`) are registered **by default with no opt-out**,
use `os.path.join(rules_dir, rule_name)` without `realpath()` containment, and the HTTP-stream
transport binds `127.0.0.1:8080/mcp` with **no authentication** (`--api-key` defaults to `None`).
Writing a `.pth` file into user site-packages via the traversal primitive yields code execution
on the next Python interpreter start (CPython imports `import` lines from every `.pth`).

**Why it's a strong test target:** multi-stage path traversal → RCE plus a separate command
injection — good coverage for Rule (path join without `realpath`) and Taint (subprocess with
user input) lines.

---

## 4. `jlowin/fastmcp` (FastMCP framework)

- **Repo:** https://github.com/jlowin/fastmcp
- **Vulnerability:** [GHSA-rj5c-58rq-j5g5](https://github.com/jlowin/fastmcp/security/advisories/GHSA-rj5c-58rq-j5g5) ([CVE-2025-62801](https://github.com/advisories/GHSA-rj5c-58rq-j5g5)), CWE-78 OS command injection.
- **Affected:** all versions `< 2.13.0`; **fixed in 2.13.0**. (Related: CVE-2025-64340 fixed in 3.2.0.)

The `server_name` field is embedded **verbatim** into a `cursor://…?name=` deeplink; on Windows
`open_deeplink()` runs via `cmd.exe /c start …` with `shell=True`, so cmd metacharacters
(`&`, `|`, `>`, `^`) in `server_name` escape the `start` command and spawn an attacker-chosen
process. Triggered by `fastmcp install cursor`.

```python
mcp = FastMCP(name="test&calc")   # <-- & escapes `start`, launches calc.exe
```

**Why it's a strong test target:** a `shell=True` subprocess sink fed by user-influenced data —
the canonical Taint-line case, with the added twist that the sink lives in a deeplink generator,
not an obvious `os.system` call.

---

## 5. `haris-musa/excel-mcp-server` (Excel MCP)

- **Repo:** https://github.com/haris-musa/excel-mcp-server
- **Vulnerability:** [CVE-2026-40576](https://github.com/advisories/GHSA-j98m-w3xp-9f56) (GHSA-j98m-w3xp-9f56, [PYSEC-2026-331](https://github.com/pypa/advisory-database/blob/main/vulns/excel-mcp-server/PYSEC-2026-331.yaml)), CWE-22 path traversal, CVSS 9.4 critical / 8.2 high.
- **Affected:** `<= 0.1.7`; **fixed in 0.1.8** (patch `f51340ecd5778952405044b203d3a2d4c8a46833`).

`get_excel_path()` (`src/excel_mcp/server.py:75-94`) fails to confine file operations in two
ways: (1) `if os.path.isabs(filename): return filename` returns absolute paths (`/etc/shadow`)
unchecked; (2) `os.path.join(EXCEL_FILES_PATH, filename)` does not resolve/validate `../`.
Every one of the **25 exposed `@mcp.tool()` handlers** calls this function first. Aggravators:
SSE/Streamable-HTTP transports, default bind `0.0.0.0` (port 8017), **zero authentication**,
and `path.parent.mkdir(parents=True, exist_ok=True)` enabling arbitrary directory creation.

**Why it's a strong test target:** the cleanest single-file path-traversal example in the list —
ideal for validating the Rule line's `path-join-no-realpath` pattern and path-tampering
detection. Clone: `git clone https://github.com/haris-musa/excel-mcp-server.git` (checkout `<= 0.1.7`).

---

## 6. `appsecco/vulnerable-mcp-servers-lab` (intentional training lab)

- **Repo:** https://github.com/appsecco/vulnerable-mcp-servers-lab
- **Already integrated** in this project as a submodule: `detection/examples/vulnerable-mcp-servers-lab`.

Deliberately vulnerable MCP server implementations (incl. a "Filesystem Workspace Actions"
server with naive path joining and unsandboxed code execution) used as a **known-truth regression
suite**. Not CVE-tracked, but valuable because the vulnerabilities are intentional and labeled,
making it a ground-truth benchmark for scoring detector accuracy.

---

## Related references (non-Python or research)

Kept separate from the main list because they are not Python *MCP servers*, but they inform the
threat model this system detects:

- **Invariant Labs "Tool Poisoning Attacks"** (MCP03:2025) — indirect prompt injection via tool
  name/description/schema. Repro: [`invariantlabs-ai/mcp-injection-experiments`](https://github.com/invariantlabs-ai/mcp-injection-experiments).
  **MCPTox** academic benchmark (arXiv 2508.14925) — 493 malicious tools; this project already
  validates against it (`detection/examples/benchmarks/mcptox`).
- **CVE-2025-49596 — MCP Inspector** — RCE from missing auth between client and proxy (TypeScript tooling, not Python).
- **CVE-2026-67430 — MCP Ruby SDK** — DoS via unbounded sessions (Ruby, not Python).
- **CVE-2025-61765 — python-socket.io** — pickle deserialization RCE (Python, but a transport
  library rather than an MCP server itself; relevant to multi-server broker deployments).
- **OWASP MCP Top 10** and the CSA `ModelContextProtocol-Security/vulnerability-db` (OSV-MCPS schema)
  are useful ongoing sources for new Python MCP server CVEs.

---

## Sources

- GitHub Advisory Database — [CVE-2025-63604](https://github.com/advisories/ghsa-fxw5-f8vf-f238) · [GHSA-5cgr-j3jf-jw3v](https://github.com/advisories/GHSA-5cgr-j3jf-jw3v) · [GHSA-9xwc-hfwc-8w59](https://github.com/advisories/GHSA-9xwc-hfwc-8w59) · [GHSA-vjqx-cfc4-9h6v](https://github.com/advisories/GHSA-vjqx-cfc4-9h6v) · [GHSA-rj5c-58rq-j5g5](https://github.com/advisories/GHSA-rj5c-58rq-j5g5) · [GHSA-j98m-w3xp-9f56](https://github.com/advisories/GHSA-j98m-w3xp-9f56)
- PraisonAI advisory — [GHSA-9mqq-jqxf-grvw](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-9mqq-jqxf-grvw)
- PyPA advisory database — [PYSEC-2026-331 (excel-mcp-server)](https://github.com/pypa/advisory-database/blob/main/vulns/excel-mcp-server/PYSEC-2026-331.yaml)
- The Hacker News — [Three Flaws in Anthropic MCP Git Server](https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html)
- Invariant Labs — [MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- MCPTox research — https://arxiv.org/abs/2508.14925
