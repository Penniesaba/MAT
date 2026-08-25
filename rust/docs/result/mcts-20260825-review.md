# MCTS examples 静态分析运行成果评审报告

> **评审对象**：`mcts-20260825-190058.json` / `.md`（2026-08-25 19:00:58 运行）
> **扫描目标**：`test-targets/MCTS/examples`（14 个 py/ts/rs 源文件；2 个 `.go`、1 个 `.json` 按配置跳过）
> **评审性质**：客观评审——同时指出有效部分与缺陷，结论不替代逐条人工复核。

---

## 一、总体结论

检测主链路（rule + taint + codeql）在**有意构造的漏洞目标**上能够正确命中，三线印证机制在真实漏洞上是有效的；但本轮输出的可信度与可用性被四个问题明显拉低：

1. **agent 线完全失效**（配置 `enabled=true` 但产出 0 条，进化/裁决循环全部为 0）；
2. **融合层过度合并与分类错乱**（`conflict_notes` 记录了类别冲突，却仍在错误类别上输出 High 结论）；
3. **规则关键词误报**（`description` → tool_poisoning、`process.env` → data_exfiltration 等）；
4. **严重度虚高**（单一弱关键词也打 High，风险等级被整体拉成 `high`）。

**结论：本轮结果可作为"引擎连通性验证"参考，但不宜直接作为安全结论引用；建议先整改 R1–R5 再复跑。**

---

## 二、运行概况

| 项 | 值 |
|---|---|
| 目标 | `../test-targets/MCTS/examples` |
| 语言 | python / typescript / rust |
| Facts | 193 |
| Rule 结果 | 8 |
| Taint 结果 | 8 |
| **Agent 结果** | **0** |
| CodeQL 结果 | 5（全部 python） |
| Fused 结果 | 8 |
| 风险等级 | **high**（最高严重度 high） |

关键配置：`rule`+`taint`+`codeql`+`agent` 均 `enabled=true`；`taint.entrypoint_required=false`；`fusion.require_confirmed_by=1`、`line_proximity=5`、权重 `rule=3 / taint=2 / agent=1 / codeql=4`。

进化/裁决状态（`evolution`）：`adjudicated=0`、`promoted=0`、`promoted_count=0`、`b0_count=0`、`b_still_ambiguous=0`、`rolled_back=false` —— 整条自洽裁决链本轮**一次都未触发**。

---

## 三、有效部分（客观肯定）

1. **`vulnerable-mcp-server` 三处真实漏洞全部命中**，且 rule/taint/codeql 互相印证：
   - `read_file(path) → Path(path).read_text()`（任意文件读取 + 路径穿越，line 14）✅
   - `get_env(name) → os.environ.get(name)`（环境变量/凭据访问，line 36）✅
   - `run_shell(command) → subprocess.check_output(..., shell=True)`（任意命令执行，line 43）✅
2. **`behavioral-fixtures/python_mismatch` 的"描述与实现不符"夹具被正确识破**：文档自称"只读目录列举"，实际 `open(path, "w")` 任意写入 —— 被 `file_write`（rule + codeql `tool-param-to-file-write` + taint `list_files:path → file_write`）三线命中。
3. **CodeQL 给出精确的 `file:line → file:line` 数据流路径**（如 `tools.py:9 → tools.py:11`），可复核性强。
4. **facts 抽取有效**：193 条（含 14 个 `mcp_tool`、9 个 `mcp_tool_parameter` 及 imports/sinks），说明语义抽取层在正常工作。

---

## 四、需要整改的问题（按严重度排序）

### R1 · agent 线完全失效（P0）

**现象**：`static.agent.enabled=true`、`provider=claude`，但 `agent_result_count=0`，且 `evolution` 中裁决/晋升全部为 0。整个 Plan-2 自洽裁决机制在本轮**零参与**。

**根因推断**：agent 子进程以 `claude -p <prompt> --max-turns N --output-format text` 调用，解析器 `parse_agent_output` 要求 stdout 里出现 `{"findings": [...]}`（或 ```json 围栏）。若 claude 返回的是纯文本、或 findings 缺少精确 `file:LINE` 位置，会被整体丢弃，最终解析为 0 条而不报错（空结果静默通过）。

**影响**：四线里唯一"语义/LLM 判断"这条线没有产出，融合层因此没有任何需要裁决的歧义（`b0_count=0`），进化循环空转。

**整改方向**：用 `logging.level=debug` + `log_file` 落盘重跑，抓 agent 子进程的 stdout/stderr；或单独渲染一次 prompt 喂给 `claude -p` 看真实输出格式，确认是"无发现"还是"输出格式不被解析器接受"。

---

### R2 · 融合层过度合并与分类错乱（P0）

**现象 A（吞并）**：融合项 `open(` → `file_write` 把 **file_read + file_write + command_execution** 三种 sink 并成了一个 High 结论。其 `conflict_notes` 明写 `category mismatch: file_read, file_write, command_execution`，但最终仍只输出 `file_write` —— `run_shell(...shell=True)` 这条**命令执行信号被吞进 file_write 项**，独立身份丢失。

**现象 B（错分）**：`process.env` → `data_exfiltration`（High）。`legacy.ts:30` 只是 `Object.keys(process.env)` 列环境变量名，与"数据外泄"无关；且同一行同时命中 `data_exfiltration` 与 `env_access` 两个类别，融合未消解冲突。

**根因**：`line_proximity=5` 把 `python_mismatch/server.py` 第 9 行附近的多个 sink 与不同 tool 的 taint 结果跨类别聚类；融合在类别冲突时仍"选一个"输出，未降级为 ambiguous 交给裁决。

**整改方向**：聚类改为**按 sink 类别 + 精确行号**；类别冲突时应标记为 ambiguous 触发裁决，或按证据权重选多数而非单一胜出。

---

### R3 · 规则关键词误报（P1）

| 误报 | 命中处 | 说明 |
|---|---|---|
| `description` → tool_poisoning (High) | 5 个文件 | 全部是普通 tool 的 `description` 字段，**纯误报** |
| `process.env` → data_exfiltration (High) | legacy.ts:30 | 仅列环境变量名 |
| `open(` → file_read | python_mismatch:9 | 实际是 `open(path,"w")` 写模式，被关键词判成"读" |
| `Path(` → path_traversal (High) | 2 个文件 | `pathlib.Path` 是极常见写法，关键词过宽（此处碰巧有 codeql 佐证） |
| `Command::new` → command_execution (High) | rust-mcp-rmcp:12 | 硬编码 `"sh"`，无用户输入，属能力探测而非漏洞 |

**根因**：keyword 匹配只做子串命中，不判断语义（`open(` 不看模式、`description` 不看上下文、`Command::new` 不看参数是否可控）。

**整改方向**：keyword 升格为"关键词 + 上下文约束"（如 `open(` 需带 `r`/`w` 模式判定；`description` 排除 tool-schema 字段；命令执行需命令来源可追踪到用户输入）。

---

### R4 · 污点退化自环 + 真实链路漏追踪（P1）

**现象 A（退化自环）**：8 条 taint 中 4 条是 `source_kind == sink_kind` 的无效自环：`network_request → network_request` ×2、`env_var → env_access` ×2，来源均为 `model:call`（把 sink 本身当 source）。`server.ts:37` 那条 `entrypoint_is_mcp=false`、`backward_trace_found_root=false`，仍被上报（`entrypoint_required=false` 放宽所致）。

**现象 B（漏追踪）**：`single-tool-agent-server` 的 `SALES_API_TOKEN`（`os.environ.get`）→ `requests.post` 的真实凭据外泄链路**没有被连成一条数据流**，只得到两条互不相连的自环，token 到外部 URL 的实际流动在数据流层面丢失。

**值得肯定**：另外 4 条是高质量的 `mcp_tool_parameter → sink`（`read_file→file_read`、`get_env→env_access`、`run_shell→command_execution`、`list_files→file_write`）。

**整改方向**：过滤 `source_kind == sink_kind` 的自环；对 `model:call` 源在 `entrypoint_required=false` 时降权或剔除；修复跨 sink 的数据流拼接（source 与 sink 的 kind 建模需区分 HTTP 动词与调用本身）。

---

### R5 · CodeQL 语言覆盖不全 + 类别错标（P1）

**现象 A（覆盖不全）**：5 条结果**全部是 python**。`server.ts:22` 的 `readFileSync(path)` 路径穿越（真实漏洞）只被 rule 关键词抓，CodeQL 零命中；Rust 同样 0 条。

**现象 B（类别错标）**：`mcp/tool-parameter-to-sink` 的 `category` 被标为 `command_execution`，但其 message 是泛化的 "dangerous sink"，且实际 sink 是 `open(path,"w")` 文件写入。

**现象 C**：5 条 CodeQL 结果 `verification_status` 全部 `uncorroborated`；`codeql_fused_count=2`（5 条被压进 2 个融合项，丢失了独立展示）。

**整改方向**：排查 TS/Rust 数据库是否成功构建（尤其 memory 中记录的 Rust 抽取器 macro 坑）；修正 codeql 结果到 category 的映射；让 codeql 结果在报告中可独立列出。

---

### R6 · 严重度虚高（P2）

`severity_from_weight` 规则为 `weight>=20 → High`，而 `data_exfiltration/tool_poisoning/command_execution/network_request` 权重均为 25，于是**单一弱关键词命中也打 High**。造成 "High 严重度 + Medium 置信度" 泛滥，风险等级被整体拉成 `high`。

**整改方向**：严重度分级引入证据强度（命中的线数、是否有数据流、是否有用户输入可达性）；弱关键词命中降级为 Low/Medium。

---

### R7 · 无修复建议 + facts 未关联（P2）

- 所有 finding 的 `recommendation` 均为 `null` —— 只有检测结论，无可执行修复指引。
- 所有 rule result 的 `related_facts_exist=false`，193 条 facts 与 rule 结果**零关联**，facts 抽取的语义信息没有被下游消费。

**整改方向**：finding 生成时附带 remediation 建议；rule 结果关联对应 facts（函数、参数、sink）作为证据链。

---

## 五、需要优化的地方

- **O1 融合聚类**：`line_proximity=5` 过宽，跨行跨类别合并；改为按 sink 类别 + 精确行号聚类，类别冲突时降级为 ambiguous。
- **O2 规则引擎**：keyword 加模式/上下文判断；降低 `description`/`Path(`/`Command::new` 这类泛化关键词的权重或加前置条件。
- **O3 污点**：过滤 source/sink 同 kind 自环；修复跨 sink 数据流拼接（token → 外部 URL 应成一条链）；`model:call` 源降权。
- **O4 CodeQL**：修正 result→category 映射；排查 TS/Rust 抽取；让 codeql 原始结果可独立列出。
- **O5 分级**：严重度引入证据强度；弱证据降级。
- **O6 产出**：finding 附 remediation；facts 关联到 rule 结果。
- **O7 配置与可观测性**：`rule_paths` 里 `rules/mcp` 当前是空目录（实际只加载了 `rules/languages/keywords.toml`），需补 MCP 专属规则或移除该路径；agent 日志建议 `log_file` 落盘以便诊断。

---

## 六、建议下一步（行动清单）

1. **P0**：定位 agent 0 结果根因（`log_file` 落盘重跑，抓 agent stdout/stderr），确认是"无发现"还是"输出格式不被解析"。
2. **P0**：修复融合层——按 sink 类别 + 行号聚类，类别冲突降级为 ambiguous，禁止吞并。
3. **P1**：清理规则关键词误报（`description`/`process.env`/`Path(`/`open(` 无模式/`Command::new`）。
4. **P1**：污点过滤自环、修复跨 sink 数据流；排查 CodeQL TS/Rust 抽取。
5. **P2**：严重度分级引入证据强度；finding 附 remediation、关联 facts。
6. 复跑后用本报告"有效部分/误报清单"做回归对照。

---

*报告生成：Claude Code · 2026-08-25 · 基于 `mcts-20260825-190058` 运行产物与 `rust/` 源码核对。*
