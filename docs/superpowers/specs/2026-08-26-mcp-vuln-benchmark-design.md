# MCP 漏洞检测 Benchmark（v5）设计

- 日期：2026-08-26
- 状态：待评审
- 范围：为 mcp-sec-audit v5.0 建立一个 20 项、已知漏洞的 MCP 源码 benchmark，用于对检测能力做 P / R / F1 打分。

## 1. 目标与成功标准

**目标**：给 v5 系统一个可复现、可分层打分的检测能力基准，回答「这个系统对已知 MCP 漏洞的检出率和误报率是多少」。

**成功标准**：
1. `cargo run -- bench --manifest benchmark/manifest.toml` 一条命令跑完 20 项、产出机器可读的指标（JSON）+ 人类可读表格（Markdown）。
2. 20 项全部锁定在**漏洞态 commit**，用 SSH 克隆，可离线重跑（clone 结果本地缓存）。
3. 对每条 finding 能给出 TP / FP / unconfirmed 三分类，并给出 **optimistic / pessimistic** 两个 precision。
4. 指标可按 **语言桶 / 凭据层级（evidence_tier）/ 漏洞类别（CWE）** 分层看。
5. 评分对「行号漂移」有明确容差（±N 可配，默认 5）。

## 2. 已敲定的决策（来自需求对话）

| 决策点 | 取值 |
|---|---|
| 用途 | 检测能力打分（P / R / F1） |
| 语料配比 | 10 Python / 4 TypeScript / 2 JavaScript / 4 Rust = 20 |
| 语料存储 | clone 脚本 + 锁 commit；源码 clone 到 `.gitignore` 的 `benchmark/corpus/`，不入库 |
| 凭据底线 | CVE / GHSA / RUSTSEC 正式条目 + 公开 issue / 厂商 writeup，每条标注 `evidence_tier` |
| 命中判定 | **只认 sink 行**，±N 容差（N 可配，默认 5） |
| 误报口径 | 三分类 TP / FP / unconfirmed，报告给乐观+悲观两个 precision |

## 3. 现状与约束（已核实的代码事实）

- v5 主体在 `rust/`（workspace：`mcp-sec-audit-cli` + `mcp-sec-audit-core`）。
- CLI 用 clap 子命令（`rust/crates/mcp-sec-audit-cli/src/main.rs:22`），已有 `Batch(BatchArgs)` 子命令走 `batch::run(config)`，并为 batch 单独建 tokio runtime。
- 批量编排在 `rust/crates/mcp-sec-audit-core/src/batch/`（`orchestrator.rs` + `governor.rs` + `learning_bus.rs` + `summary.rs`）。
- 批量配置 `[[batch.repo]]` 支持 `name`/`path` + 任意嵌套字段覆盖（`batch/config.rs`），且 `scan.targets` 默认取 repo path、可被 per-repo 覆盖、`scan.languages` 可 per-repo 覆盖。**这让我们能把同一个 monorepo 的 Python 与 TypeScript 两个 item 各自作用域化。**
- 报告 JSON 顶层键：`facts / rule_results / taint_results / agent_results / codeql_results / codeql_raw_sarif / model_candidates / fused_findings / summary / config_snapshot / evolution`。
- **关键**：`FusedFinding`（`model/static_result.rs:171`）**没有** `file`/`line`，只有 `evidence: Vec<String>`（形如 `path:line:snippet`）和 `related_*_result_ids`。
  - 但 `RuleAnalysisResult.file/line`、`TaintAnalysisResult.sink_id/sink_kind`（无独立 line，靠 `evidence`）、`CodeqlAnalysisResult.locations: Vec<Location>` 都带明确 `file`+`line`。
  - 因此 sink 行对齐要从**原始逐行结果**取，而不是从 fused 裸拼。

## 4. 方案选择：新增 Rust `bench` 子命令（方案 A）

- 新增 `Command::Bench` 子命令（`bench --manifest <path>`），放 CLI。
- core 新增 `bench/` 模块：`manifest.rs`（schema + 加载）、`scorer.rs`（sink 行对齐 + 三分类 + 指标）、`report.rs`（JSON + Markdown）。
- 复用 `batch::run` 跑检测：`bench` 把 manifest 里的每个 item 翻译成一个 `[[batch.repo]]`（含 `scan.targets`/`scan.languages` 作用域覆盖 + 指向 `benchmark/corpus/<slug>`），写一份临时 batch TOML，交给现有 `batch::run`，然后读每仓的 report JSON 打分。
- 不引入 Python / 外部二进制。scorer 与报告 schema 的耦合是内部契约，可接受。

## 5. 语料与目录结构

```
benchmark/
  manifest.toml            # 20 个 item：SSH URL + commit + 语言 + 作用域
  ground-truth.toml        # 每条漏洞：sink 行 + CWE + 类别 + tier + 证据引用
  fetch.sh                 # 读 manifest，SSH clone + checkout 漏洞 commit
  corpus/                  # gitignore；clone 结果（不入库）
    <slug>/                # 每个 item 一个目录
  bench_results/           # gitignore；跑批输出
    <timestamp>/metrics.json
    <timestamp>/metrics.md
    <timestamp>/<slug>/report.json   # 复用 batch 的输出布局
```

- `fetch.sh` 用 `git@github.com:owner/repo.git`（用户要求 SSH，已确认本机 `git@github.com` 认证通过），`git clone` 后 `git -C <slug> checkout <commit>`。
- 同一仓库多 item 时按 `(repo, commit)` 去重：`modelcontextprotocol/servers` 只 clone 一次，Python item 作用域 `src/git`，TypeScript item 作用域 `src/filesystem`。

## 6. manifest schema

```toml
[[repo]]
slug         = "servers-git-py"
url          = "git@github.com:modelcontextprotocol/servers.git"
commit       = "<vulnerable-commit-sha>"   # 落地时用 git ls-remote/tags 核实锁死
language     = "python"                     # python | typescript | javascript | rust
scan_targets = ["src/git"]                  # 相对 clone 根的路径（可选，默认整仓）
evidence_tier = "cve"                        # cve | issue | synthetic
vulns        = ["CVE-2025-68144", "CVE-2025-68143"]  # 引 ground-truth 的 key
```

- `scan_targets` 直接映射为 batch repo 的 `scan.targets`；`language` 映射为 `scan.languages`。

## 7. ground-truth schema

每条漏洞一个 key（如 `CVE-2025-68144`）：

```toml
["CVE-2025-68144"]
repo_slug      = "servers-git-py"
language       = "python"
cwe            = "CWE-88"           # 或 "CWE-22" 等
category       = "command_execution" # 对齐 v5 category 词汇表，用于类别分层
severity       = "high"
evidence_tier  = "cve"
sink_line      = 123                # 唯一危险汇聚点行号
sink_file      = "src/git/server.py"
source_urls    = ["https://github.com/advisories/GHSA-9xwc-hfwc-8w59"]
known_clean    = []                 # 已人工确认「干净」的 file:line 区（可选，判 FP 用）
```

- `sink_file` 相对 repo 根；`sink_line` 是 sink 表达式所在行。
- 一条 taint 漏洞只标 **sink 行**（对齐「只认 sink 行」决策）。
- `known_clean` 用于 FP 三分类：finding 落在 `known_clean` 区 → FP；否则 → unconfirmed。

## 8. 打分逻辑

### 8.1 收集 finding 的 sink 行

对每个 item 的 report JSON，取所有候选行集合（`file + line`）：

1. 遍历 `fused_findings`，用 `related_taint_result_ids` 回连 `taint_results` 的 `evidence` 首行（`path:line:snippet`）取 line；
2. `related_rule_result_ids` 回连 `rule_results.file/line`；
3. `related_codeql_result_ids` 回连 `codeql_results.locations[].file/line`；
4. 仍无行号的 fused finding，解析其 `evidence` 字符串中的 `file:line`。

最终每个 finding 产出一组 `(file, line)`，与 ground truth 的 `sink_file` 做路径后缀匹配 + `|line - sink_line| <= N`。

### 8.2 三分类

- **TP**：存在一条 ground-truth 漏洞，其 sink 行被至少一条 finding 命中。
- **FP**：finding 未命中任何 ground-truth，且落在该 item 的 `known_clean` 区。
- **unconfirmed**：finding 未命中 ground-truth，也不在 `known_clean` 区（真实仓库的未披露真漏洞）。

### 8.3 指标

- `recall = TP / |ground_truth|`（漏报 = 未命中的 ground-truth 条目）。
- `precision_pessimistic = TP / (TP + FP + unconfirmed)`（把所有未标注当误报）。
- `precision_optimistic = TP / (TP + FP)`（把 unconfirmed 全当真阳性）。
- 分层：按 `language`、`evidence_tier`、`category` 各出一组 P/R/F1；整体一组。
- 每条未命中的 ground-truth 在报告中列出为 **miss**，附最近一条 finding 的行距，便于诊断。

## 9. 报告输出

- `metrics.json`：机器可读，含每 item 的 TP/FP/unconfirmed、per-layer 指标、未命中清单。
- `metrics.md`：表格（总体 + 语言桶 + tier + category），顶部给 optimistic/pessimistic 两个 precision。
- 每 item 的检测报告复用现有 batch 输出（report JSON + markdown）。

## 10. 测试

- `manifest.rs` 单元测试：schema 反序列化、`(repo, commit)` 去重、作用域覆盖生成。
- `scorer.rs` 单元测试：用 fixture JSON 覆盖——sink 行精确命中、±N 内命中、行距超限、file 后缀匹配、FP vs unconfirmed 分流、related-id 回连 vs evidence 解析回退。
- 端到端冒烟：1 个 Python item（sqlite-mcp，体积小）走 `bench --manifest` 全流程，断言 metrics.json 可解析且字段完整。

## 11. 待办 / 落地前校验（实现计划第一步）

1. 用 `git ls-remote` / tags 逐一核实 20 个 item 的 `commit`（漏洞态 SHA），把 §5 候选池里的「三角定位」变成「锁死的 SHA」。
2. 确认每条 ground-truth 的 `sink_file`/`sink_line` 在该 commit 的源码里真实存在，并把行号调准。
3. 确认 `modelcontextprotocol/servers` 在选定 commit 上 `src/git`（Python）与 `src/filesystem`（TS）同时存在、语言归属正确。

## 12. 风险与诚实声明

- Rust 桶 3/4 是 issue 级（无 CVE），TS/Python 全是真 CVE——benchmark 的强度在不同语言桶间不平衡，必须在报告里显式按 `evidence_tier` 分层，禁止用「单一大 P/R/F1」掩盖这一点。
- `serverless/serverless` 是超大 monorepo，`scan_targets = ["packages/mcp"]` 必须生效，否则扫描时间/噪声不可控。
- 候选池里的 pin 版本来自安全镜像/厂商 writeup 三角定位，GitHub 页面在本环境不可直接抓取；未核实前不得视为已锁定。
