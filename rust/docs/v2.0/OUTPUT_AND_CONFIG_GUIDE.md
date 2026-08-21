# mcp-sec-audit 输出文件与配置字段详解

本文档解释程序输出报告文件的每一行/每个字段，以及配置文件中几个关键字段的含义与实现原理。所有代码引用均以 `rust/` 为根目录。

---

## 0. 报告文件是如何命名的

`[report]` 段决定输出：

```toml
[report]
output = "/tmp/python-report1"
formats = ["markdown"]
```

实现位置：`crates/mcp-sec-audit-cli/src/main.rs:184-217` 的 `write_report_files`。

最终文件名为 `output + "." + 扩展名`，扩展名由 `crates/mcp-sec-audit-core/src/reporting.rs:26-33` 决定：

| format | 扩展名 | 实际输出文件 |
|--------|--------|--------------|
| `json` | `.json` | `/tmp/python-report1.json` |
| `markdown` | `.md` | `/tmp/python-report1.md` |
| `jsonl` | `.jsonl` | `/tmp/python-report1.jsonl` |

#### `<timestamp>` 占位符

`output` 支持 `<timestamp>` 占位符：写入时会被替换为当前 **UTC 时间 `YYYYMMDD-HHMMSS`**（如 `20260815-171234`）。

```toml
[report]
output = "/home/xiao/Project/mcp-sec-audit/rust/docs/<timestamp>"
formats = ["markdown"]
```

→ 生成 `/home/xiao/Project/mcp-sec-audit/rust/docs/20260815-171234.md`。

实现位置：`crates/mcp-sec-audit-core/src/reporting.rs` 的 `resolve_output_path`。它在 `write_report_files` 循环**之前**解析一次，保证 `md`/`json`/`jsonl` 多个格式落在同一个秒、共用同一时间戳。

> 注意：`/tmp` 下实际存在的是 `/tmp/python-report1.json`（47KB），它是一次 `formats = ["json"]` 运行的结果；当前 `python-config.toml` 已改为 `formats = ["markdown"]`，再跑一次会生成 `/tmp/python-report1.md`。

程序共有三种渲染器，都在 `reporting.rs`：
- `render_json`（`reporting.rs:114`）：`serde_json::to_string_pretty` 输出美化 JSON。
- `render_markdown`（`reporting.rs:182`）：逐行拼 Markdown。
- `render_jsonl`（`reporting.rs:118`）：每行一条 `{event, data}` 记录。

---

## 1. 输出报告文件逐字段/逐行含义

报告的整体结构是 `StaticAnalysisResult`（`crates/mcp-sec-audit-core/src/model/static_result.rs:172-182`），共 8 个顶层字段：

```rust
pub struct StaticAnalysisResult {
    pub facts: Vec<Fact>,                    // 事实（AST 提取的底层数据）
    pub rule_results: Vec<RuleAnalysisResult>,    // 规则线结果
    pub taint_results: Vec<TaintAnalysisResult>,  // 污点线结果
    pub agent_results: Vec<AgentAnalysisResult>,  // Agent 线结果
    pub codeql_results: Vec<CodeqlAnalysisResult>,// CodeQL 线结果
    pub fused_findings: Vec<FusedFinding>,   // 融合后的最终发现
    pub summary: StaticAnalysisSummary,      // 汇总统计
    pub config_snapshot: ConfigSnapshot,     // 本次运行配置快照
}
```

下面按 JSON 输出（`/tmp/python-report1.json`）的实际顺序逐段解释。

### 1.1 `facts` — 事实列表

这是 `[static].save_facts = true` 时保留的 AST 提取产物，是后续规则/污点分析的输入。每条 fact 都有一个 `type` 标签（`model/facts.rs:69-81` 的 `#[serde(tag = "type")]`）和一组公共字段 `id` / `file` / `line` / `extractor`。

**公共字段：**

| 字段 | 含义 |
|------|------|
| `type` | fact 类型（import/function/call/assign/entrypoint/source/sink/dataflow/…） |
| `id` | 全局唯一标识，编码了类型+文件+行号 |
| `file` | 所属文件路径 |
| `line` | 起始行号 |
| `extractor` | 生成它的提取器名（如 `rust_python_ast_phase7`、`rust_taint_phase10_11`） |

**各类型特有字段（`model/facts.rs`）：**

- **`import`**（`ImportFact`，facts.rs:99）：`module`（被导入模块）、`imported_name`（导入的符号）、`alias`（别名，如 `import subprocess as sp` 里的 `sp`）、`kind`（`import_as`/`from_import` 等）。示例里 `"subprocess"` 的 alias 是 `"sp"`。

- **`function`**（`FunctionFact`，facts.rs:84）：`name`、`qualified_name`、`end_line`、`params`（`{name, annotation, default}` 数组）、`decorators`（如 `["mcp.tool()"]`）、`docstring`、`return_type`、`enclosing_class`。

- **`entrypoint`**（`EntryPointFact`，facts.rs:110）：标记 MCP 工具入口。`kind`（`mcp_tool`）、`name`（工具名）、`function_id`、`evidence`（如 `{kind:"decorator", text:"mcp.tool()"}`）、`params`（入参名列表）、`confidence`。

- **`call`**（`CallFact`，facts.rs:122）：一次函数调用。`caller`（所在函数 id）、`callee`（被调名）、`normalized_callee`（解析后的规范名，如 `runner` → `subprocess.run`）、`column`/`end_line`、`snippet`（源码片段）、`args`（位置参数 `{index,expr,kind}`）、`kwargs`、`resolution`（别名解析信息 `{import_alias, confidence}`）。

- **`assign`**（`AssignFact`，facts.rs:161）：一次赋值。`function_id`、`target`（左值，如 `runner`）、`value`（右值，可能是 AST dump 字符串）、`snippet`。

- **`source`**（`SourceFact`，facts.rs:151）：污点源（通常来自 MCP 工具参数）。`kind`（如 `mcp_tool_parameter`）、`function_id`、`name`、`confidence`。

- **`sink`**（`SinkFact`，facts.rs:137）：危险汇聚点。`call_id`（对应 call）、`category`（如 `command_execution`/`network_request`）、`rule_id`、`sink_name`、`severity_base`、`reason`、`conditions`、`confidence`。

- **`dataflow`**（`DataFlowFact`，facts.rs:171）：污点分析产生的数据流记录。`source_id`、`sink_id`、`path`（路径步骤）、`confidence`。它是 taint 线运行后追加进 facts 的。

### 1.2 `rule_results` — 规则线结果

每个元素是 `RuleAnalysisResult`（static_result.rs:32-45）：

| 字段 | 含义 |
|------|------|
| `result_id` | 如 `rule-result:file_read:1` |
| `rule_id` / `category` | 命中的能力名（如 `file_read`、`network_request`） |
| `owasp_mcp` | 预留，恒 `null` |
| `file` / `line` | 首个命中位置 |
| `matched_text` | 匹配到的文本（如 `"open("`） |
| `evidence` | 所有命中点的 `file:line:text` 列表 |
| `severity` | 严重度（`low`/`medium`/`high`/`critical`） |
| `confidence` | 置信度（`low`/`medium`/`high`） |
| `recommendation` | 建议，规则线目前恒 `null` |
| `related_facts_exist` | 是否有相关 fact（当前恒 `false`） |

### 1.3 `taint_results` — 污点线结果

每个元素是 `TaintAnalysisResult`（static_result.rs:48-61）：

| 字段 | 含义 |
|------|------|
| `result_id` | 如 `taint:source:...:sink:...` |
| `source_id` / `sink_id` | 源/汇的 fact id |
| `source_kind` | 如 `mcp_tool_parameter` |
| `entrypoint_id` | 关联的入口 id（如 `entry:server.py:fetch_url`） |
| `sink_kind` | 如 `network_request` |
| `call_chain` | 跨函数调用链 |
| `dataflow_path` | 数据流路径的代码片段 |
| `evidence` | 路径步骤摘要 |
| `taint_confidence` | 置信度 |
| `entrypoint_is_mcp` | 源是否来自 MCP 入口 |
| `backward_trace_found_root` | 是否回溯到根（源） |

示例报告里 `call_chain`/`dataflow_path`/`evidence` 都为空数组，是因为该 fixture 是直接 source→sink 单跳，未产生跨函数路径步骤。

### 1.4 `agent_results` — Agent（LLM）线结果

每个元素是 `AgentAnalysisResult`（static_result.rs:64-79）：

| 字段 | 含义 |
|------|------|
| `result_id` | 如 `agent:claude:0` |
| `agent_id` | provider 名（`claude`） |
| `prompt_profile` | 使用的 prompt 模板名 |
| `model_provider` | 模型提供方 |
| `input_scope` | 输入给 Agent 分析的文件列表 |
| `candidate_title` | 发现标题 |
| `affected_locations` | 受影响位置（`file:line` 列表） |
| `reasoning_summary` | 推理摘要 |
| `evidence_snippets` | 证据代码片段 |
| `related_rule_result_ids` / `related_taint_result_ids` | 关联的其它线结果（当前空） |
| `confidence` | 置信度 |
| `verification_status` | 校验状态（`uncorroborated`） |
| `limitations` | 限制说明 |

### 1.5 `codeql_results` — CodeQL 线结果

每个元素是 `CodeqlAnalysisResult`（static_result.rs:83-104）：`rule_id`、`rule_name`、`message`、`severity`、`locations`、`dataflow_path` 等。CodeQL 现已正常产出结果（如 `mcp/tool-parameter-to-sink`），其中 `dataflow_path` 是结构化路径（`DataFlowPath`），含 `steps`（每个 step 有 `location.file`/`location.line` 和可选 `snippet`），对应 SARIF 的 `codeFlows`（`parser.rs` 的 `parse_code_flows` 解析）。

### 1.6 `fused_findings` — 融合后的最终发现

每个元素是 `FusedFinding`（static_result.rs:131-150）：

| 字段 | 含义 |
|------|------|
| `finding_id` | UUID |
| `title` | 标题（来自优先级最高的子结果，见 merger.rs:60-81） |
| `category` | 类别（组内多数投票，merger.rs:83-101） |
| `severity` | 组内最大严重度 |
| `confidence` | 加权置信度（见 fusion 章节） |
| `status` | `potential`（固定） |
| `supported_by` | 支持该发现的线条：`["rule"]`/`["taint"]`/`["agent"]`/`["codeql"]` 的组合 |
| `related_*_result_ids` | 融合进来的各线子结果 id |
| `evidence` | 去重后的证据并集 |
| `call_chain` / `dataflow_path` | 来自 taint（或 codeql）的路径 |
| `recommendation` | 建议 |
| `conflict_notes` | 冲突说明（如 `severity mismatch`、`category mismatch`） |

示例中第一条 `open(` 的 `supported_by` 只有 `["rule"]`，且 `conflict_notes` 记录了 `severity mismatch` 和 `category mismatch` —— 说明 rule 线的 `file_read` 与 `network_request` 两个结果被按行临近/类别归并进同一组后产生了冲突。

### 1.7 `summary` — 汇总

`StaticAnalysisSummary`（static_result.rs:152-164）：

| 字段 | 含义 |
|------|------|
| `target` | 扫描目标 |
| `fact_count` | 事实数（51） |
| `rule_result_count` | 规则线结果数（2） |
| `taint_result_count` | 污点线结果数（2） |
| `agent_result_count` | Agent 结果数（5） |
| `codeql_result_count` | CodeQL 结果数（0） |
| `codeql_fused_count` | 被融合的 CodeQL 数（0） |
| `fused_finding_count` | 融合发现数（5） |
| `highest_severity` | 最高严重度（`high`） |
| `risk_level` | 风险等级（`high`） |

### 1.8 `config_snapshot` — 配置快照

记录本次运行实际使用的完整 `RuntimeConfig` 和 `rulebook_paths`，方便审计报告复现。

---

### 1.9 Markdown 输出的"每行"含义

若 `formats = ["markdown"]`，`render_markdown`（reporting.rs:182-282）逐行输出如下结构：

```markdown
# Static Analysis Summary — ../test-targets/python-mcp-server
                        ← 空行
- Risk Level: high
- Facts: 51
- Fused Findings: 5
- Rule Results: 2
- Taint Results: 2
- Agent Results: 5
- CodeQL Results: 2
- Highest Severity: "high"

## Facts               ← 仅 include_facts 时；按类型计数，如 "- function: 7"
- function: 7
- import: 5
...

## Fused Findings      ← 仅 include_fused_results 时
- **<标题>** [high/medium] — <category>
  - Supported by: taint, agent
  - Dataflow path: server.py:73 → server.py:84 → … → server.py:86   ← 若有路径
  - Recommendation: ...

## Raw Rule Results    ← 仅 include_raw_rule_results 时
- `file_read` at server.py:8

## Raw Taint Results
- `taint:...`: mcp_tool_parameter -> network_request

## Raw Agent Results
- `claude`: <标题> (high)

## Raw CodeQL Results
- `rule_id` at file:line — message
  - Dataflow path: server.py:73 → … → server.py:86   ← 若 codeFlows 有路径
```

各段是否输出由 `[report]` 的 `include_*` 布尔开关控制（reporting.rs:62-73 的 `MarkdownRenderOptions`）。当前 `python-config.toml` 只开 `include_fused_results`、`include_raw_rule_results`、`include_raw_taint_results`、`include_facts`，关闭了 agent/codeql 两个原始段。

---

## 2. `scan.exclude` 字段

### 含义

`[scan].exclude` 是一个字符串数组，列出要**跳过**的**目录名或路径段名**。命中的文件/目录不会被扫描。

```toml
[scan]
exclude = ["__pycache__", ".venv", ".mypy_cache"]
```

默认值（config.rs:298-303）：`["node_modules", "target", ".venv", "dist"]`。

### 实现原理

核心是**按路径段（path component）的精确字符串匹配**，而非前缀或通配匹配。

实现位置：`crates/mcp-sec-audit-core/src/static_analysis/discovery.rs`。

`is_excluded`（discovery.rs:102-111）：

```rust
pub fn is_excluded(path: &Path, excludes: &[String]) -> bool {
    if excludes.is_empty() { return false; }
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        excludes.iter().any(|exclude| value == exclude.as_str())
    })
}
```

即：把路径拆成一个个段，只要**任意一段**与 exclude 里的某个字符串**完全相等**，就判定为排除。例如 `src/node_modules/pkg/index.js` 含 `node_modules` 段，被排除；而 `src/node_modules_like/index.js` 的段是 `node_modules_like`，与 `node_modules` 不相等，**不会被排除**（discovery.rs:229-238 的测试专门验证了这点）。

应用点有两处（discovery.rs:113-168）：

1. **目录级剪枝** `walk_directory`（discovery.rs:120-147）：遍历目录时先 `is_excluded(directory)`，命中则整棵子树直接 `return`（不递归），并 `skipped_paths += 1`。对每个子条目也先 `is_excluded(&path)`，命中则 `continue`。
2. **文件级过滤** `discover_file`（discovery.rs:152-168）：`is_excluded(path)` 命中返回 `None`；否则按扩展名 `detect_language`（discovery.rs:47-57）识别语言，再检查语言是否在 `languages` 白名单内。

整体入口 `discover_files`（discovery.rs:59-100）遍历每个 target，若 target 是目录则 `walk_directory`，是文件则 `discover_file`，最终返回 `DiscoverySummary { scanned_targets, discovered_files, skipped_paths }`。

**关键点**：exclude 匹配的是**目录/文件名本身**（路径的某个段），与文件类型、语言无关；它是纯字符串相等比较，不支持 glob 或正则。

---

## 3. `static.taint.max_depth` 与 `entrypoint_required`

### 含义

```toml
[static.taint]
max_depth = 8
entrypoint_required = true
```

配置定义（config.rs:57-68），默认 `max_depth = 8`（config.rs:323-325）、`entrypoint_required = true`。

- **`max_depth`**：污点传播 BFS 的**最大搜索深度**（最多走多少条边/跳）。
- **`entrypoint_required`**：是否**只**从 MCP 入口函数产生的 source 开始正向追踪。`true` = 只看入口源；`false` = 放宽到所有 source。

### 实现原理

实现在 `crates/mcp-sec-audit-core/src/static_analysis/taint/propagation.rs`。

**`max_depth` —— BFS 深度上限：**

`propagate`（propagation.rs:77-210）用一个队列做广度优先搜索，每个队列项 `BfsItem` 携带 `depth`（propagation.rs:27-34）。两处使用深度：

1. 出队时（propagation.rs:100-102）：
   ```rust
   if item.depth >= config.max_depth {
       continue;   // 达到深度上限，不再展开
   }
   ```
2. 入队时（propagation.rs:196-205）：
   ```rust
   if item.depth + 1 < config.max_depth {
       queue.push_back(BfsItem { depth: item.depth + 1, ... });
   }
   ```

起始节点的 `depth = 0`（propagation.rs:94）。所以 `max_depth = 8` 表示从 source/sink 出发最多沿图走 8 跳；`max_depth = 0` 则一步都不走，返回空（propagation.rs:543-549 的测试验证了 `max_depth=0` 找不到任何路径）。测试 `max_depth_limits_propagation` 见 propagation.rs:543。

**`entrypoint_required` —— 源节点的过滤：**

正向传播的起点由 `find_source_start_nodes`（propagation.rs:217-244）决定：

```rust
fn find_source_start_nodes(graph: &Graph, entrypoint_required: bool) -> Vec<String> {
    graph.nodes.iter().filter_map(|(id, node)| {
        if let Node::Source { function_id, .. } = node {
            if entrypoint_required {
                // 只保留「所属函数是某 entrypoint 的函数」的 source
                let is_ep = graph.entrypoint_to_function
                    .values()
                    .any(|ep_func_id| ep_func_id == function_id);
                if is_ep { Some(id.clone()) } else { None }
            } else {
                Some(id.clone())   // 放宽：所有 source 都是起点
            }
        } else { None }
    }).collect()
}
```

`graph.entrypoint_to_function` 映射（`entry:...` → `python:...`）在建图阶段由 `EntryPointFact` 填充（builder.rs:57-62）。测试 `entrypoint_required_filters_non_entrypoint_sources`（propagation.rs:552-574）验证：`entrypoint_required = true` 时，不属于任何入口函数的 source 不会产生路径。

**完整调用链：**

`taint/mod.rs:run`（taint/mod.rs:15-28）→ 提取 facts → `run_taint_analysis`（taint/mod.rs:34-53）→ `builder::build_graph` 建图 → `propagation::propagate_both`（propagation.rs:59-71，按 `forward`/`backward` 开关分别跑正向/反向）→ `result::build_taint_results` 与 `build_dataflow_facts` 转成结果。

补充：`forward`/`backward` 控制方向；两者都开时结果去重（`deduplicate_paths`，propagation.rs:397-410）。反向传播的起点是所有 Sink（`find_sink_start_nodes`，propagation.rs:247-261），不受 `entrypoint_required` 影响。

---

## 4. `fusion` 段所有字段

### 字段清单与默认值

配置定义（config.rs:112-132），默认值（config.rs:245-258）：

```toml
[fusion]
enabled = true                       # 是否启用融合
require_confirmed_by = 1             # 一个发现至少需要几条线支持
boost_when_multiple_lines_agree = true  # 多线一致时 +0.1 置信度
agent_only_as_advisory = true        # 纯 Agent 发现封顶 medium
line_proximity = 5                   # 行临近窗口
rule_weight = 3                      # 规则线权重
taint_weight = 2                     # 污点线权重
agent_weight = 1                     # Agent 线权重
codeql_weight = 4                    # CodeQL 线权重
```

融合流水线分三步（`fusion/mod.rs:16-39`）：`matcher::match_results`（分组）→ `scorer::score_groups`（过滤+打分）→ `merger::merge_groups`（生成 FusedFinding）。

### 5.1 `enabled`

`false` 时 `run`（fusion/mod.rs:23-25）直接返回空 `Vec`，不融合。

### 5.2 `line_proximity` — 行临近窗口

用于分组（matcher）第一阶段，实现在 `fusion/matcher.rs`。

`match_results`（matcher.rs:100-275）先把四种结果统一成 `Matchable`（file/line/category/kind）。注意 taint 结果没有 file/line 字段，是从 `sink_id` 里解析出来的（matcher.rs:130-143，`parse_file_from_id` / `parse_line_from_id`，行号解析不到时为 0）；agent 从 `affected_locations` 第一个位置解析（matcher.rs:147-159）。

**两阶段贪心分组：**

- **Stage 1 临近匹配**（matcher.rs:184-203）：`can_join_group_proximity`（matcher.rs:319-331）判定 —— 同文件 且 `|line差| <= line_proximity`。agent 没有 category，**只能**靠这一阶段入组。
- **Stage 2 类别匹配**（matcher.rs:205-233）：Stage 1 落单的条目，若 `can_join_group_category`（matcher.rs:335-342）成立（同文件 + 同 category）则并入。agent（category 为 None）跳过，保持 solo。
- 始终匹配不到的条目会成为**单元素组**，不会被丢弃（matcher.rs:186-190）。

`line_proximity = 5` 意味着：两条不同线的结果若在同一文件、行号差 ≤ 5，就被认为指向同一处代码。

### 5.3 `require_confirmed_by` — 最少支持线条数

用于过滤，实现在 `fusion/scorer.rs:71-79`：

```rust
if group.line_count() < config.require_confirmed_by {
    return None;   // 过滤掉
}
```

`line_count()`（matcher.rs:29-44）统计该组里有几条非空线（rule/taint/agent/codeql，0–4）。

`require_confirmed_by = 1` 是最低严格度：单线发现也能通过。设为 2 表示至少两条线同时支持才保留（scorer.rs:274-285 的测试验证 `=2` 时 solo 组被过滤）。

### 5.4 三个权重 `rule_weight` / `taint_weight` / `agent_weight` / `codeql_weight`

用于计算组的加权置信度，实现在 `fusion/scorer.rs:80-105`：

```rust
// 置信度数值化（scorer.rs:24-30）：
//   High = 0.8, Medium = 0.6, Low = 0.4
// CodeQL 无 confidence 字段，固定按 Medium = 0.6（scorer.rs:34）

for r in &group.rule_results {
    weighted_sum += rule_weight * confidence_value(&r.confidence);
    weight_sum    += rule_weight;
}
// taint 用 t.taint_confidence，agent 用 a.confidence，codeql 用固定 0.6
let mut raw = weighted_sum / weight_sum;
```

即 `raw = Σ(weight × confidence) / Σ(weight)`。默认 `4:3:2:1` 反映各线的可信度排序（架构文档 `STATIC_ANALYSIS_ARCHITECTURE.md:296`）：CodeQL 权重最高（深度语义分析），Agent 最低（LLM 输出不确定）。

例如默认配置下 rule=High + taint=Medium：`raw = (3×0.8 + 2×0.6)/(3+2) = 0.72`（scorer.rs:242-256 的测试）。

### 5.5 `boost_when_multiple_lines_agree` — 多线一致加成

实现在 `fusion/scorer.rs:107-110`：

```rust
if config.boost_when_multiple_lines_agree && group.line_count() >= 2 {
    raw = (raw + 0.1).min(1.0);   // 至少两条线同意 → +0.1，封顶 1.0
}
```

鼓励多线互相印证：一个发现同时被 rule+taint 支持，置信度比单线高 0.1。

### 5.6 `agent_only_as_advisory` — 纯 Agent 封顶

实现在 `fusion/scorer.rs:112-118`：

```rust
if config.agent_only_as_advisory
    && group.line_count() == 1      // 只有一条线
    && !group.agent_results.is_empty()  // 且这条线是 agent
{
    raw = raw.min(0.6);             // 封顶 0.6（即最高 Medium）
}
```

含义：LLM 单独给出的发现不可全信，置信度上限压到 `medium`（数值 0.6 → `raw_to_confidence` 落在 Medium 区间）。scorer.rs:259-271 的测试验证纯 agent High 被压到 Medium。

### 5.7 打分后的结果转化

- **置信度** `raw_to_confidence`（scorer.rs:37-45）：`raw ≥ 0.7 → High`，`≥ 0.5 → Medium`，否则 `Low`。
- **严重度** `group_max_severity`（scorer.rs:132-161）：取组内最大严重度；rule/codeql 用自身 `severity`，taint/agent 无 severity 字段，用 `taint_confidence`/`confidence` 映射（High→High、Medium→Medium、Low→Low，scorer.rs:163-177）。

### 5.8 融合输出

`merger::merge_groups`（fusion/merger.rs:16-58）把每个 `ScoredGroup` 生成一个 `FusedFinding`，字段拼装规则见本文件第 1.6 节。标题优先级（merger.rs:60-81）：rule 的 `matched_text` → codeql 的 `rule_name`/`message` → agent 的 `candidate_title` → `taint: source → sink`。类别为多数投票（merger.rs:83-101），证据为去重并集（merger.rs:103-133），冲突记录到 `conflict_notes`（merger.rs:168-209，检测 severity 与 category 的不一致）。

---

## 附：字段 → 源码速查表

| 配置字段 | 解析位置 | 消费位置（实现逻辑） |
|----------|----------|----------------------|
| `scan.exclude` | config.rs:25, 298 | discovery.rs:102-168 |
| `scan.targets` / `scan.languages` | config.rs:23-27 | discovery.rs:59-100, 170-192 |
| `static.rule.enabled` / `rule_paths` | config.rs:48-51 | rule/mod.rs:28-45 |
| `static.taint.enabled/forward/backward` | config.rs:58-62 | taint/mod.rs:15-53, propagation.rs:59-71 |
| `static.taint.max_depth` | config.rs:64, 323 | propagation.rs:100, 196 |
| `static.taint.entrypoint_required` | config.rs:66 | propagation.rs:217-244 |
| `static.codeql.enabled` | config.rs:86-87 | codeql/mod.rs |
| `static.codeql.binary` | config.rs:90-91, 98-100 | codeql/provider.rs（`CliCodeqlProvider::new`） |
| `static.codeql.query_pack_path` / `timeout_seconds` / `extra_args` | config.rs:88-95 | codeql/mod.rs, codeql/provider.rs |
| `fusion.enabled` | config.rs:115 | fusion/mod.rs:23 |
| `fusion.line_proximity` | config.rs:122, 351 | fusion/matcher.rs:319-331 |
| `fusion.require_confirmed_by` | config.rs:117, 347 | fusion/scorer.rs:76 |
| `fusion.*_weight` | config.rs:124-131, 355-369 | fusion/scorer.rs:84-99 |
| `fusion.boost_when_multiple_lines_agree` | config.rs:119 | fusion/scorer.rs:108 |
| `fusion.agent_only_as_advisory` | config.rs:121 | fusion/scorer.rs:113 |
| `report.formats/output/include_*` | config.rs:136-151 | cli/main.rs:184-217, reporting.rs |
