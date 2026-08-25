# 以自洽裁决为核心的自主进化方案（详细设计）

- 日期：2026-08-24
- 范围：四线自主进化（taint / rule / codeql / prompt）
- 前身：`SELF_EVOLUTION_DESIGN_20260824.md`（方案 D）
- 本版要点：**扁平化**（拒绝多层）、**明确进化因子 vs 模糊进化因子**、**自洽裁决为核心 + 输入预处理 + 输出后处理**

---

## 0. 设计原则（回应你对方案 D 的三点不满）

你对方案 D 的核心批评，我提炼成三条设计约束，本方案严格遵循：

| 你的批评 | 本方案的回应 |
|---|---|
| 层太多，顶层失误会级联压垮底层 | **三段扁平结构**：预处理 → 裁决 → 后处理。只有"裁决"一个 LLM 中心，前后两段都是**纯函数式确定性代码**，不会"失误"。没有深度依赖链，不存在"顶层输出喂给底层再喂给更底层"。 |
| 阶段1/阶段2 对比应区分明确/模糊进化因子 | **明确因子**（可纯计算）不经过 agent，直接由代码决定；**模糊因子**（需语义判断）才交给 agent。两类因子**并行**，互不依赖。 |
| 以自洽裁决为主，agent 要有输入预处理和输出后处理 | **自洽裁决（Self-Consistent Adjudication）是唯一 agent 中心，通过 claude code CLI（headless 子进程）执行，而非直连 LLM API**，外包两段确定性处理：输入预处理保证"垃圾进"被拦截，输出后处理保证"垃圾出"被拦截。 |

**关键设计哲学**：能算的不要问 agent（省钱、可复现、零失误）；必须问 agent 的（经 claude code CLI 执行），用**输入预处理 + 自洽投票 + 输出接地**三道保险把它包住。这样 agent 失误的影响面被压缩到最小，且永远不会"带崩"确定性部分。

---

## 1. 核心概念：明确进化因子 vs 模糊进化因子

### 1.1 定义

"进化因子" = 从**阶段 1（基线）与阶段 2（学习后）的对比**中提取的、决定"这次学习该不该保留"的信号。

| | 明确进化因子 | 模糊进化因子 |
|---|---|---|
| **英文** | Deterministic Evolution Factor | Fuzzy / Ambiguous Evolution Factor |
| **本质** | 纯集合/规则运算，**有唯一真值**，可复现 | 需语义推理，**无唯一真值**，依赖对代码的理解 |
| **谁来判** | 确定性代码（无 LLM） | 自洽裁决 agent（LLM） |
| **失误成本** | 零（不会失误） | 有，但被预处理/后处理兜住 |
| **举例** | 见 §1.2 | 见 §1.3 |

### 1.2 明确进化因子（举例说明）

这些是 `validate.rs::migrate()` 已经能算出来的集合运算，**它们就是明确的**，永远不需要问 LLM：

| 因子 | 计算方式 | 含义 | 进化动作 |
|---|---|---|---|
| `b1` | `p1_b_only ∩ p2_agreed` | agent 阶段1独报，阶段2 标准线通过学习**补上了** → agent 说得对 | **确认收益** → 对应模型 corroboration+1 |
| `a1` | `p1_a_only ∩ p2_agreed` | 标准线阶段1独报，阶段2 agent **补上了** → 标准线对 | 确认（记证据） |
| `b2` | `p2_a_only − p1_a_only` | 阶段2 **新增**标准线独报 → 学进去的东西**制造了新误报** | **污染** → 对应模型 pollution+1 / 回退 |
| `a2` | `p1_a_only ∩ p2_a_only` | 标准线两阶段都独报 → 标准线**在报误报** | **抑制** → 生成负向抑制模型 |
| `dedup` | candidate ∈ 现有 catalog? | 候选已在目录里 | 直接跳过（无新可学） |
| `G1` | PackageRule Hot/Warm/Cold | sink 候选是否被包规则/命名前缀支持 | Hot/Warm 放行，Cold 丢 b0 |
| `G2` | MadSink / TaintModel / SemanticOnly | 候选能否编码为标准线组件 | 可编码→学，不可编码→b0 |

**举例**（MCTS 那次真实数据）：
- `a2=2`：有 2 条标准线误报（`server.py:15` 和 `server.ts:37` 的 `network_request→network_request` 自环，是 taint 把 HTTP 动词 `post` 当 source 又当 sink 的误报）。**这是明确因子**——它数学上就是"标准线两阶段都在重复报同一位置"，不需要任何语义判断，直接生成抑制规则"该位置别再报"。
- `b1=0 a1=0 b2=0`：本次没有确认也没有污染，**这也是明确因子**——三个计数都是零，意味着"这次学习既没证明有益也没证明有害"，这个事实本身就能确定。

### 1.3 模糊进化因子（举例说明）

这些是明确因子**无法判定**的残差，才需要语义判断：

| 因子 | 为什么模糊 | 需要 agent 判什么 |
|---|---|---|
| `still_ambiguous`（阶段1、2 都 agent 独报） | agent 两次都报，但标准线始终没跟——**可能是 agent 幻觉，也可能是标准线盲区** | 这条是真漏洞吗？从 MCP 参数可达吗？ |
| `b0`（semantic-only / cold） | 无法编码成 sink/source/sanitizer，但可能是真实语义漏洞 | 能抽象成一条可复用规则吗？category 是什么？ |
| `b1/a1` 的"确认" | 双线**可能同时错**（共用同一份被污染的包规则） | 这条"确认"是不是假确认？ |
| 候选 category 赋值 | agent 把 `delete_range` 归为 `file_delete`，但语义上它是"删单元格"不是"删文件" | category 语义是否正确？ |

**举例**（MCTS 真实 `still_ambiguous=2`）：
- `main.rs:10 run_tool`：`Command::new(cmd).spawn()` —— 是真命令执行，但 agent 自己都说"run_tool 从未被 call_tool 调用，是 fixture 不是暴露路径"。**到底该不该学？这是模糊的**——它需要判断"不可达的 sink 是否值得建模"。
- `server.ts:22 read_config`：`fs.readFileSync(path)` —— agent 说"完全可达的任意文件读取"。**该不该学成 file_read sink？这也是模糊的**——需要确认可达性。

这两条就是交给自洽裁决的典型输入。

---

## 2. 总体架构（扁平三段式）

```
                      ┌────────────────────────────────────────┐
                      │  明确进化因子（确定性，无 LLM，零失误）    │
                      │  = 输入预处理 Input Preprocessing        │
                      │    · 去噪 / 过滤 / 归因 / 富化 / 结构化   │
                      └────────────────────────────────────────┘
                                       │ 结构化「证据包」
                                       ▼
                      ┌────────────────────────────────────────┐
                      │  模糊进化因子（唯一 LLM 中心）           │
                      │  = 自洽裁决 Self-Consistent Adjudication │
                      │    · 多条独立推理链 + 多数投票            │
                      └────────────────────────────────────────┘
                                       │ 结构化「裁决结果」
                                       ▼
                      ┌────────────────────────────────────────┐
                      │  明确进化因子（确定性，无 LLM，零失误）    │
                      │  = 输出后处理 Output Post-processing     │
                      │    · schema 校验 / 接地核验 / 自洽核验     │
                      │    · 置信阈值 / 归一化 / 确定性兜底        │
                      └────────────────────────────────────────┘
                                       │
                                       ▼
                      进化执行 promote / retire / rollback / suppress
                                      （确定性）
```

**为什么这样不会"顶层失误级联"**：
1. 预处理和后处理是**纯函数**（同一输入永远同一输出），它们没有"失误"概念，只有"规则对不对"（规则可单测）。
2. 唯一的 LLM 在**中间**，它的失误（幻觉）会被后处理的地核验 + 自洽投票拦截；即使漏网，也只会影响"模糊因子"这一小撮残差，**明确因子（b1/a1/b2/a2/dedup）照常正确执行**。
3. 三段之间是**单向数据流**，不存在"A 的输出错误导致 B 的输出错误再导致 C"的深度链——每段只依赖上一段的**结构化数据**，不依赖上一段的**正确性判断**。

---

## 3. 输入预处理（明确因子段 ①）

**目的**：把喂给 agent 的输入做到"**最小、最干净、最结构化**"，从源头避免"垃圾进 → 垃圾出"。

### 3.1 去噪与过滤（Noise Filtering）

**做什么**：确定性代码先吃掉所有明确因子，**只把模糊残差**递给 agent。

```
输入：阶段1/阶段2 的 diff（b1/a1/a2/b2/b0/still_ambiguous）
  ├─ b1/a1  → 确定性记账（corroboration+1），不进 agent
  ├─ b2     → 确定性记账（pollution+1）+ 可能回退，不进 agent
  ├─ a2     → 确定性生成抑制规则，不进 agent
  ├─ dedup  → 直接丢弃，不进 agent
  └─ still_ambiguous + b0  → 【唯一进 agent 的模糊残差】
```

**举例**：MCTS 一次运行产 `b1=0 a1=0 a2=2 b2=0 b0=4 still_ambiguous=2`。预处理后，agent 只收到 **4+2=6 条**，而不是全部 finding。`a2=2` 的两条噪声被确定性代码直接转成抑制规则，**不浪费 agent 一个 token**。

### 3.2 归因与上下文富化（Attribution & Context Enrichment）

**术语解释**：**归因（Credit Assignment）** = 回答"这条 finding 是哪条模型贡献的"。富化 = 给每条待裁决项附上判断所需的全部证据。

**做什么**：对每条 still_ambiguous / b0，反查出它的**证据包（Evidence Packet）**：

```json
{
  "item_id": "still_ambiguous:server.ts:22",
  "file": "bench/multi-file-ts-server/server.ts",
  "line": 22,
  "finding_text": "read_config 将 client 控制的 path 直接传给 fs.readFileSync(path)",
  "category_claim": "file_read",
  "call_chain": ["call_tool(read_config)", "read_config(path)", "fs.readFileSync(path)"],
  "source_kind": "mcp_tool_parameter",
  "matched_rule": "ts/path-traversal",
  "matched_package_rule": null,
  "agent_confidence": "high",
  "snippet": "text: fs.readFileSync(path, 'utf-8')",
  "related_models": ["fs.readFileSync"]   // ← 归因结果：这条 finding 关联哪个候选模型
}
```

**归因的确定性实现**（难点，但可纯计算）：
- taint finding 的 `sink_id` 形如 `sink:file_read:server.ts:22`，其 sink 名（`fs.readFileSync`）就是 `pattern`，直接反查目录即可精确归因。
- codeql finding 用 `related_rule_ids` / dataflow 末节点反查。
- agent finding 用 `affected_locations` + `related_*_ids` 近似归因。

### 3.3 结构化（Structuring）

**做什么**：把证据包统一成 **JSON Schema**，让 agent 输入格式稳定（这是"后处理能做 schema 校验"的前提）。

```json
{
  "task": "adjudicate_evolution_candidates",
  "items": [ { /* 证据包，如上 */ } ]
}
```

**为什么重要**：结构化输入 → agent 可以输出结构化结果 → 后处理才能机械校验。非结构化文本无法自动核验。

---

## 4. 自洽裁决（模糊因子段 · 唯一 agent 中心）

### 4.0 调用方式：claude code CLI（headless 子进程，非直连 LLM API）

**关键整改**：自洽裁决**不直接调用 LLM API**，而是**复用现有 agent 线的 `CliAgentProvider`**，以 headless 子进程方式调用 **claude code CLI**（`claude` 二进制）。

现有基础设施（`agent/provider.rs`）已经实现了这个能力，无需新造：

```
CliAgentProvider::run(&AgentRunConfig {
    provider_binary: "claude",           // claude code CLI
    prompt: "<裁决 prompt>",
    max_turns: N,
    // is_agent_cli("claude") == true → 自动注入：
    //   claude -p "<prompt>" --max-turns N --output-format text
    ...
})
```

**为什么用 claude code CLI 而非直连 LLM**：
1. **agentic 能力**：claude code CLI 自带工具调用 / 推理循环，裁决"可达性""可抽象性"这类需要读代码、查调用链的问题，比单次 LLM 补全强得多。
2. **统一管线**：与现有 agent 线（阶段 1 的 B 线、L2/L3 解释 pass）走同一 `CliAgentProvider`，复用超时、stderr 捕获、exit code 处理。
3. **结构化输出**：裁决阶段把 `--output-format` 从 `text` 改为 `json`（或 `stream-json`），拿到可被后处理段 schema 校验的机器可读结果。

**自洽（Self-Consistency）的落地**：对同一批待裁决项，用 claude CLI 独立跑 **N=3 次**（每次新起一个子进程），对每次的 JSON 结果做多数投票。claude CLI 无 `temperature` 参数，其非确定性由**多次独立子进程 + 投票**来对冲（这正是"自洽裁决"名称的由来）。

### 4.1 术语：自洽性（Self-Consistency）

**定义**：对同一个问题，让 LLM **独立生成多条推理链**，然后**取多数一致答案**。源于 LLM 研究里的 Self-Consistency（Wang et al., 2022）。

**原理**：LLM 采样有随机性，单次回答可能错；但"正确答案"通常会在多条采样里**反复出现**，而"错误答案"往往是**发散**的。多数投票能把单次错误率显著压下去。

**举例**：对 `read_config` 是否任意文件读取这个问题，独立问 3 次：
- 第 1 次：是，可达（理由：直接传 path，无校验）
- 第 2 次：是，可达（理由：无 base-dir join）
- 第 3 次：是，可达（理由：返回内容进模型上下文）
- → **3:0 一致**，高置信采纳。

若某次问出了"否"（理由：可能文件在 config 目录内），则 **2:1 分裂** → 视为"不确定"，降级处理（进入跨运行累积，不立即 promote）。

### 4.2 裁决问题设计（三类窄问题）

agent 不做开放式"审一下"，而是**逐条回答三个封闭问题**（每个都有确定的答案空间）：

| 问题 | 答案空间 | 目的 |
|---|---|---|
| Q1 真实性：这条是真实安全漏洞吗？ | `true/false` | 过滤 agent 幻觉 |
| Q2 可达性：能从 MCP tool 参数到达该 sink 吗？ | `reachable/unreachable/unknown` | 区分真漏洞 vs 死代码 |
| Q3 可表达性：能抽象成可复用规则/模型吗？ | 结构化 `{kind, category, pattern}` 或 `not_abstractable` | 决定学成什么形态（sink/rule/prompt） |

### 4.3 裁决 prompt 骨架（示意）

```
你是进化裁决器。对下面每条候选，独立判断，输出严格 JSON，不要解释：
{ "item_id": "...", "is_real": true/false,
  "reachable": "reachable|unreachable|unknown",
  "abstractable": {"kind":"sink|rule|prompt", "category":"...", "pattern":"..."} | null,
  "confidence": "high|medium|low", "reason": "一句话" }
```

**关键**：要求输出**严格 JSON**（可 schema 校验），且每条独立（便于多轮投票对齐）。

---

## 5. 输出后处理（明确因子段 ②）

**目的**：不盲信 agent 输出，用确定性规则拦截"垃圾出"。

### 5.1 Schema 校验（Schema Validation）

- agent 输出必须是合法 JSON 且字段齐全、枚举合法（如 `reachable` 只能取三值）。
- 不合法 → **重试一次**；仍不合法 → 该条降级为"不确定"，不进 promote。

### 5.2 接地核验（Grounding / 归谬）

**术语解释**：**接地（Grounding）** = 检查 LLM 的结论是否能被**硬事实**支持。LLM 常见的错误是"编造理由"，接地就是拿它的理由去对硬事实。

**做什么**：
- 若 agent 说 `reachable=true`，但该候选**没有**从 source 到 sink 的 dataflow 路径（call_chain 断了）→ 标记 `grounding_mismatch`，降级。
- 若 agent 说 `abstractable.pattern = "X.Y"`，但 `X.Y` 在目标代码里**从未被调用**（call facts 里查不到）→ 判为幻觉，拒绝。

**举例**：agent 若把 `main.rs:10 run_tool` 判为 `reachable=true`，但归因数据里 `run_tool` 的 `call_chain` 是空的（`call_tool` 的 match arm 为空、`register_tools` 是 no-op）→ 接地核验发现矛盾 → 拒绝"可达"，采纳"unreachable"（这正是真实裁决的正确结论）。

### 5.3 自洽核验（Consistency Check / 多数投票）

- 同一候选跑 N=3 次，取多数。
- `3:0` → 采纳；`2:1` → 降级"不确定"（进跨运行累积）；`1:2` 或 `0:3` → 拒绝/淘汰方向。
- 投票分裂的候选**绝不立即 promote**（这是"自洽裁决为主"的安全底线）。

### 5.4 置信阈值与确定性兜底

- agent 自评 `confidence=low` 的裁决 → 不直接采纳，转跨运行累积。
- 自洽核验仍"不确定"的 → **确定性兜底**：回落到明确因子——若该候选与 a2 模式相似则抑制，否则归档"待观察"，**绝不让"不确定"变成"promote"**。

---

## 6. 进化执行（确定性）

裁决通过后，按**类型**执行，全部是确定性写入：

| 裁决结果 | 进化动作 | 写入目标 |
|---|---|---|
| `is_real && reachable && abstractable.kind=sink` | promote 为新 sink 模型 | `learned/` |
| `is_real && abstractable.kind=source/sanitizer` | promote 为新 source/sanitizer | `learned/` |
| `is_real && reachable && abstractable.kind=rule` | promote 为新 rule capability | learned rulebook |
| `is_real && abstractable.kind=prompt`（无法编码的语义漏洞） | 追加 prompt 提示 | `learned-prompt.md` |
| `!is_real`（幻觉） | 丢弃 | — |
| `is_real && unreachable` | 归档"死代码候选"，不建模 | `learned/archive/` |
| `2:1 不确定` | 进跨运行累积，暂不 promote | pending 状态 |

**明确因子驱动的执行**（与裁决并行，不依赖裁决）：
- `b1/a1` → 对应模型 `corroboration_count+1`（累积升 confidence）。
- `b2` → 对应模型 `pollution_count+1`，超阈值回退。
- `a2` → 写入抑制规则，下一轮压制该位置。

---

## 7. 端到端数据流示例（走一遍）

以 MCTS 那轮真实数据为例，展示一条 still_ambiguous 如何走完三段：

**输入**（阶段1/2 diff 后）：`still_ambiguous` 含 `server.ts:22 read_config`。

**① 预处理（明确）**：
- 去噪：`a2=2` 的两条 `network_request` 自环被确定性转抑制，不进 agent。
- 归因：反查 `server.ts:22` → sink `fs.readFileSync`（file_read），附 call_chain + snippet。
- 结构化：打包成 JSON 证据包。

**② 自洽裁决（模糊）**：
- 跑 3 次，问 Q1/Q2/Q3。
- 结果：3 次都 `is_real=true, reachable=reachable, abstractable={kind:sink, category:file_read, pattern:fs.readFileSync}`。

**③ 后处理（明确）**：
- schema 校验：合法 JSON ✅
- 接地核验：call_chain `call_tool→read_config→fs.readFileSync` 连通 ✅；`fs.readFileSync` 在 call facts 里存在 ✅
- 自洽核验：3:0 ✅
- 阈值：confidence=high ✅

**④ 执行**：promote `fs.readFileSync → file_read` sink 到 `learned/`，`corroboration_count=1`。

下一轮再扫同类目标时，这条 sink 已被 `load_catalog()` 载入，标准线能直接命中 `read_config`，`b1` 会 +1 → 模型升 medium/high。**这就是"能力随次数提升"的完整闭环**，且全程无人工。

---

## 8. 与旧方案的关系（吸收而非丢弃）

| 旧方案组件 | 本方案去留 |
|---|---|
| 方案 A 的跨运行置信度累积 | ✅ 保留为"执行段"的记账（corroboration/pollution/last_seen） |
| 方案 A 的归因 | ✅ 保留为"预处理段"的 §3.2 |
| 方案 B 的 fitness | ⚠️ 降级为**可选退化护栏**（不硬卡，只观测趋势），不进主链路 |
| 方案 C 的 agent 裁决 | ✅ **升级为核心**（自洽裁决），但套了预处理+后处理 |
| 方案 D 的 L1 差分 | ✅ 保留为"明确因子"来源（§1.2） |

**关键变化**：不再是 5 层串行，而是 **明确因子（差分/去噪/归因/记账）与模糊因子（自洽裁决）并行 + 一个扁平三段**。

---

## 9. 分期落地

| 期 | 内容 | 产出 |
|---|---|---|
| **一** | 修明确因子基座：`promoted` 语义、`delete`→file_delete、file_read/write 双向过计数、learned 模型加生命周期字段 | 明确因子（b1/a1/a2/b2/dedup）可信、a2 变干净 |
| **二** | 预处理段：归因 `evidence.rs` + 去噪 + 结构化证据包 | 能反查 finding→model，喂给 agent 的是干净证据包 |
| **三** | 自洽裁决 + 后处理：窄问题 prompt、多轮投票、schema/接地/自洽核验 | 模糊因子（still_ambiguous/b0）零人工闭环 |
| **四** | 执行段：promote/retire/suppress + 跨运行累积 + 四线写入 + 可选退化护栏 | 完整自主进化，能力随次数可观测提升 |

---

## 10. 待确认决策点

1. **投票轮数 N**：建议 3（成本/可靠性平衡），是否接受？（claude CLI 无 temperature 参数，非确定性靠多次独立子进程 + 多数投票对冲）
2. **投票分裂（2:1）的处理**：建议"降级为不确定 + 进跨运行累积"，而不是直接丢弃——是否同意？
3. **接地核验的严格度**：`reachable=true` 但无 dataflow 路径，是"降级"还是"硬拒绝"？
4. **归因的覆盖范围**：一期只对 taint 线做精确归因，agent/codeql 线用近似归因，是否可接受？
5. **不可达候选（unreachable）**：归档到 `learned/archive/` 还是直接丢弃？（归档保留审计，但会占空间）

---

*本方案为设计稿，确认上述决策点后进入实现计划（writing-plans）。*
