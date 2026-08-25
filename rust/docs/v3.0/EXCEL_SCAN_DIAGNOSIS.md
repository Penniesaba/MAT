# Excel MCP Server 扫描诊断与修复计划

**日期:** 2026-08-20
**目标:** `haris-musa/excel-mcp-server` @ `v0.1.7`(CVE-2026-40576 —— `get_excel_path()` 路径穿越)
**扫描命令:** `cargo run -- ../test-targets/configs/excel-mcp-server-config.toml`
**被分析的报告:** `rust/docs/result/excel/20260820-155240.md`

---

## 1. 结果与预期

已知漏洞是教科书式的 **CWE-22 路径穿越**,位于 `src/excel_mcp/server.py:74-93`
(`get_excel_path`):`os.path.isabs()` 对绝对路径不加校验直接放行,而
`os.path.join(EXCEL_FILES_PATH, filename)` 接受 `../`。约 25 个 `@mcp.tool()` 处理器
全部调用它,文件随后通过 `openpyxl.load_workbook(...)` 打开。

预期:rule + taint + CodeQL 三条线都应各自独立命中该 sink。
实际扫描输出:

```
- Rule Results:   3   (path_traversal 落在 __main__.py:13  ← 错误位置)
- Taint Results:  0   ← 漏报
- CodeQL Results: 0   ← 漏报
- Agent Results:  0   (该线被禁用)
- Fused Findings: 0
```

以下四个相互独立的根因解释了这一结果。每条都附有证据与具体修复方案。

---

## 2. 根因

### RC-1 — Taint 一无所获:`openpyxl.load_workbook` 未被识别为 sink

**证据**

该仓库从不调用 `open()`、`Path.read_text` 或 `Path.write_text` —— 这些是 taint 线
唯一认识的文件 sink(`static_analysis/facts/python/sinks.rs`)。它只通过第三方封装
打开文件:

```
$ grep -rn "load_workbook" src/ | wc -l          → 20+ 处调用
$ grep -rn "open(\|read_text\|write_text" src/    → (无任何内建文件打开调用)
```

`sinks.rs` 中的 `SINK_RULES` 列出了 `open`、`Path.read_text/write_text`、`pickle.load`、
`requests.get` 等 —— 但**没有任何针对 `load_workbook`、`read_excel`、`to_excel`、
`DataFrame.to_csv` 等条目**。因此 taint 引擎没有任何 sink 可追踪入口参数,即便数据流
正是它要检测的那类,也会返回零条发现。

**修复(小改动,高价值)**

为常见表格/数据框 I/O 封装新增 `file_read`/`file_write` 的 SinkRule:

```rust
// sinks.rs — 追加到 SINK_RULES
SinkRule {
    patterns: &["load_workbook", "read_excel", "read_csv", "read_table", "read_json"],
    category: "file_read",
    severity: Severity::Medium,
    reason: "Spreadsheet/dataframe read opens an attacker-influenceable path",
    confidence: Confidence::High,
},
SinkRule {
    patterns: &["to_excel", "to_csv", "DataFrame.to_excel", "DataFrame.to_csv", "save"],
    category: "file_write",
    severity: Severity::Medium,
    reason: "Spreadsheet/dataframe write modifies an attacker-influenceable path",
    confidence: Confidence::High,
},
```

然后重跑:taint 应能追踪 `filepath`(工具参数)→ `get_excel_path` →
`load_workbook(filepath)`,并在约 25 处调用点产生 `file_read` 发现。

### RC-2 — CodeQL 一无所获:默认查询包不把 `load_workbook` 建模为 sink

**证据**

CodeQL 本身运行正常。用固定版本的查询包(`codeql/python-queries@1.8.7`,
存在于 `~/.codeql/packages`)手动复现:

```
$ codeql database create /tmp/excel-db --language=python \
    --source-root=test-targets/excel-mcp-server          → 成功(29 个模块)
$ codeql database analyze /tmp/excel-db codeql/python-queries@1.8.7 \
    --format=sarif-latest --output=/tmp/excel-results.sarif   → 0 条结果
```

标准 `py/path-injection` 查询把 `open()`、`os.remove`、`shutil.copy` 等建模为 sink,
但**不把 `openpyxl.load_workbook` 当作文件读** —— 它不识别这个第三方库调用。因此该
穿越对标准 CodeQL 不可见。这是*模型覆盖缺口*,而非流水线崩溃。

**叠加的隐藏 bug**

`pipeline.rs` 只保存 `codeql_output.results`,而**丢弃了 `codeql_output.diagnostics`
和 `raw_sarif`**:

```rust
// pipeline.rs (run_static_scan_with_progress)
Ok(StaticAnalysisResult {
    ...
    codeql_results: codeql_output.results,   // diagnostics + raw_sarif 被丢弃
    ...
})
```

如果建库或分析步骤失败(缺少 extractor、查询包无法解析、网络被阻断),错误被吞掉,
并表现为一条静默的 "CodeQL Results: 0"。
**修复:** 把 `diagnostics`(可选 `raw_sarif`)带入 `StaticAnalysisResult`,并在 markdown
报告中渲染一节 "CodeQL Diagnostics"。

**修复(中等)**

分两部分:
1. 在结果与报告中呈现 CodeQL diagnostics(让失败不再静默)。
2. 新增自定义 CodeQL model/query,把 `openpyxl.load_workbook`(以及
   `pandas.read_excel`/`to_excel`)当作文件 I/O sink —— 可以在
   `static_analysis/codeql/queries/mcp-python/` 加一小段 `.ql`,或使用 models-as-data
   扩展,使标准数据流能到达它们。(或者接受「库封装的文件 I/O 由 rule/taint 线覆盖」,
   让 CodeQL 仅作第二意见。)

### RC-3 — Rule 线报错位置:`..` 关键词匹配到了省略号

**证据**

`path_traversal` 能力(`rules/languages/keywords.toml`)使用关键词模式 `..`,它通过
**朴素子串搜索**匹配(`rule/mod.rs` → `match_keyword_indicator` →
`haystack.find(&needle)`)。任意两个连续点号都会命中 —— 包括字符串字面量里的 `...`:

```python
# __main__.py:13
print("\nShutting down server...")     # "..." 含 "..",且字符串字面量未被 mask_python 掩码
```

规则引擎每个 capability 只输出**一条**结果,其 `primary` 是按 `(file, line, matched_text)`
排序后的*第一条*匹配。由于 `__main__.py` 排在 `server.py` 之前,这个省略号误报成为
头条位置,而 `server.py:93` 真正的 `os.path.join(...)` 被埋进了 `evidence` 列表。

**修复(中等)**

- 从 `path_traversal` 规则中移除/转义 `..` 关键词(作为关键词它过于宽泛);改用
  `os.path.join` / `Path(` / 需要点号后带斜杠的正则,如 `\.\./`。
- 在 `mask_python` 中同样掩码单行字符串字面量(当前是*跳过但保留*),使字符串内的
  省略号/`..` 不再匹配。
- 在 `rule/mod.rs` 中,`primary` 应选最*具体*(最长)的匹配,而非字典序第一个文件;
  或改为每个文件各输出一条结果,而不是每个 capability 一条。

### RC-4 — Agent 线无法读取目标文件(路径错配)—— **已修复**

**证据**

agent 线的核心机制本身没问题。直接验证过:

```
$ claude -p "Read src/excel_mcp/server.py and ..." --max-turns 3 --output-format text
    → 能正确读取文件并作答(非交互,stdin=/dev/null)
```

问题在路径解析。`DiscoveredFile.path` **相对于扫描进程的 CWD**(例如
`../test-targets/excel-mcp-server/src/excel_mcp/server.py`),但 agent 子进程以
`working_dir = target_root`(第一个文件的*父目录*)启动。在子进程内部,这些相对路径
不再解析成功,所以 agent 打不开它被要求审计的文件。

**修复(本次会话已实现)**

`static_analysis/agent/mod.rs` 现通过新增的 `absolute_path()` 辅助函数(优先
canonicalize,失败则回退为拼接当前目录),将每个文件路径(以及 `target_root`)规范化为
绝对路径;`agent/prompt.rs` 的措辞也由 `relative/path:LINE` 改为 `path:LINE`
(「使用 Files 一节中列出的精确路径」)。构建通过,19 个 agent 单测全绿。

---

## 3. 修复计划(按优先级)

| # | 修复 | 文件 | 工作量 | 收益 |
|---|------|------|--------|------|
| P1 | 新增 `load_workbook`/`read_excel`/`to_excel` 文件 sink | `facts/python/sinks.rs` | 极小 | Taint 线立即命中 CVE-2026-40576(~25 处) |
| P2 | 在报告中呈现 CodeQL diagnostics + raw_sarif | `pipeline.rs`、`model/static_result.rs`、`reporting.rs` | 小 | 失败不再静默;「0 结果」变得可信 |
| P3 | 修复 `..` 规则模式 + 掩码字符串字面量 + primary 选择 | `rules/languages/keywords.toml`、`rule/mod.rs` | 中 | 消除误报;纠正头条位置 |
| P4 | 为 `openpyxl.load_workbook` 建自定义 CodeQL 模型 | `codeql/queries/mcp-python/` | 中 | CodeQL 独立确认该穿越 |
| P5 | **已完成** — agent 路径规范化 | `agent/mod.rs`、`agent/prompt.rs` | 完成 | Agent 线可读文件并产出发现 |

**建议顺序:** 先做 P1 + P2(改动小,立即使扫描产生预期发现、并让「0」可信),再做 P3,
最后 P4。

---

## 4. 完成 P1+P2 后的预期结果

用同一配置重跑应得到:

- **Rule:** `path_traversal` 锚定在 `server.py:93`(`os.path.join`)—— 需待 P3。
- **Taint:** 约 25 条 `file_read` 发现,从 `@mcp.tool()` 参数经 `get_excel_path`
  流入 `load_workbook`。
- **CodeQL:** 可见的 diagnostic 轨迹(或经 P4 后,在 `load_workbook` 调用处产生
  `py/path-injection` 风格发现)。
- **Agent:** 带绝对 `path:LINE` 位置的发现(把 `[static.agent].enabled = true`
  设为 true 即可触发;单次 `claude -p` 调用,最多 80 个文件)。
- **Fusion:** 上述线路相互印证后,`fused_findings` 应在 `server.py:74-93` 浮现一条
  已确认的路径穿越发现。
