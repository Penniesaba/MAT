# 自主进化机制设计文档

- 日期：2026-08-24
- 范围：无需人工干预的自主进化闭环（taint / rule / codeql / prompt 四线，全四线范围）
- 关联：`RUN_EVALUATION_20260824-143601.md`、`SELF_CHECK_AND_TEST_PLAN.md`
- 状态：设计讨论稿（待确认后进入实现计划）

---

## 0. 摘要

现有系统已经跑通**两阶段差分进化**（阶段1 基线 → G1/G2 门控 agent 候选 → 阶段2 进化 catalog 重跑 → `migrate()` 得 `b1/a1/a2/b2/b0/still_ambiguous` → `b2>b1` 回退否则 promote），且 `learned_dir` 具备**跨运行持久化**（`load_catalog()` 每轮 merge 回 base catalog）。

但当前**不构成"自主进化"**，四个硬伤：

1. `b0`（semantic-only / cold）与 `still_ambiguous` 仍需人工裁决（L3）。
2. `promote` 无质量门槛，`promoted` 字段只是 `!rolled_back`（语义误导），learned 模型一律 `confidence=low`。
3. learned 模型**从不跨运行累积证据**——没有"多次 corroboration 提升置信度 / 制造噪声降级 / 长期无效淘汰"的生命周期，因此"能力随测试次数提升"无法成立。
4. 无负向学习（`a2` 噪声没被学成抑制）、无 fitness 指标证明能力真的变强。

本文先梳理自主进化的**核心挑战**与**技术难点**，再给出四个候选方案及各自的具体实现与优缺点，最后给出推荐与分期建议。

---

## 1. 现状盘点（代码级基线）

### 1.1 已跑通的机制

| 环节 | 位置 | 说明 |
|---|---|---|
| 两阶段编排 | `pipeline.rs:152-259, 338-522` | 阶段1 跑 rule/taint/agent/codeql；阶段2 用进化 catalog 重跑 taint+codeql+agent(验证 prompt) |
| G1 信号门控 | `learning.rs::gate_sink_candidate` | sink 走 PackageRule（Hot/Warm/Cold）；source/sanitizer 直接放行 |
| G2 可表达性门控 | `diff.rs::classify_candidate` | MadSink / TaintModel / SemanticOnly |
| 差分分区 | `diff.rs::diff_lines` | c(agreed) / a(a_only) / b(b_only) 三集合 |
| 迁移校验 | `validate.rs::migrate` | 产出 `b1/a1/a2/b2/b0/still_ambiguous` |
| 回退判定 | `validate.rs::should_rollback` | `b2 > b1` |
| 可逆进化抽象 | `component.rs` | `Component` trait（Codeql/Taint/Rule/Agent 四线统一 `evolve/promote/rollback`） |
| 跨运行持久化 | `facts/pipeline.rs::load_catalog` | 每轮把 `learned_dir` 的 TOML merge 回 base catalog |

### 1.2 差分标签语义

| 标签 | 含义 | 现状用途 |
|---|---|---|
| `b1` | agent 独报 → 阶段2 标准线补上（agent 对，且已学进标准线） | 确认收益 |
| `a1` | 标准线独报 → 阶段2 agent 补上（标准线对，agent 确认） | 确认 |
| `a2` | 标准线独报 → 阶段2 仍独报（标准线误报） | **被忽略** |
| `b2` | 阶段2 新增标准线独报（学进的东西制造了新误报） | 触发回退 |
| `b0` | 无法编码的语义漏洞 / 无信号 Cold sink | **丢人工** |
| `still_ambiguous` | 阶段1、2 都 agent 独报 | **丢人工** |

---

## 2. 核心挑战（自主进化的本质难题）

### 挑战 1：无监督真相问题（Ground-truth-free）

安全扫描器没有"标准答案"。判定一个候选 sink/source 模型"对不对"没有梯度、没有 loss、没有标注标签。这是所有自主进化系统的第一性难题：**用什么当"对的信号"？**

- 现系统用"多线差分"当信号（`b1/a1` = 对，`b2` = 错）。这是合理的近似，但它是**间接**的：它衡量的是"多线是否一致"，不是"是否真的是漏洞"。
- 风险：多线**同时**错时（例如 taint 和 codeql 共用同一份被污染的 package 规则），差分会给出错误的"确认"。

### 挑战 2：自我强化与回声室（Echo chamber / self-poisoning）

自主进化 = 输出（learned 模型）回喂输入（下一轮 catalog）。这是闭环，闭环里**错误会复利放大**：

- 一条坏 sink 被 promote → 下一轮它制造新 finding → 新 finding 若又被差分"确认" → 坏模型被进一步巩固。
- 这就是现有 `b2` 回退机制存在的理由，但 `b2 > b1` 是**单次、粗粒度**的护栏，挡不住"慢速污染"——每轮只污染一点点、不触发回退，累积几十轮后系统就废了。

### 挑战 3：归因难题（Credit assignment）

一个 fused finding 可能是 taint + codeql + agent 三条线共同贡献的。当它"被确认"时，**功劳归谁**？当它"是误报"时，**罪责归谁**？

- 现有差分在 `file + line` 空间做匹配，而 learned 模型在 `pattern` 空间（如 `openpyxl.load_workbook`）。两个空间之间**没有反查链路**：你无法从一条 finding 回答"它是哪条 learned 模型贡献的"。
- 没有归因，就无法逐条给模型记证据，置信度累积就是空谈。

### 挑战 4：样本稀疏与冷启动（Sparse evidence / cold start）

单次运行对一个候选只有一次观测。早期证据极少：

- 一条候选第一次出现，`confidence=low` 是合理的，但**永远 low** 就意味着永远不被信任、等于没学。
- 冷启动期误学风险高：碰巧一次 corroboration 就可能把坏候选抬上去。需要"升级谨慎、降级灵敏"的非对称阈值。

### 挑战 5：记忆 vs 泛化（Memorization vs generalization）

现有 learned 模型是**库特定名**（`openpyxl.load_workbook → file_read`）。换一个库（`xlsxwriter`）就失效。

- 真正的"能力提升"应该是**语义泛化**（学到"读工作簿"这个概念，而非某个库的某个函数名），但泛化难、易误报。
- 反过来，若只学库特定名，learned 目录会无限膨胀（一个库一个文件），且跨库复用率为零。

### 挑战 6：退化与漂移（Regression & drift）

- 能力可能**不升反降**：加模型会同时增加真阳性和假阳性，净收益未必为正。
- 目标漂移：某条模型针对的 fixture 不再出现（或被测目标变了），模型就"悬空"——既不复现也不污染，长期占位。

### 挑战 7：模型膨胀与清理（Model bloat / lifecycle）

只增不减的进化必然爆炸：

- learned 目录无限增长 → 加载变慢、匹配变慢、误报面扩大。
- 必须有**淘汰**（retire）：连续 N 轮无效、或制造过 K 次污染、或被更强的模型取代的，要删除或降级归档。

### 挑战 8：可逆性与安全性（Reversibility & safety）

- 进化错了必须能**精确回退**（不只是回退到"上一轮"，而是能定位到"哪一条模型、哪一次进化"）。
- 必须有**审计链**：每条 learned 模型的完整来龙去脉（何时学的、证据是什么、谁确认的、现在什么置信度），否则无法定位问题。

---

## 3. 技术难点（代码级的具体障碍）

| # | 难点 | 现状 | 后果 |
|---|---|---|---|
| D1 | finding→model 归因链路缺失 | 差分在 `file+line`，模型在 `pattern`，无连通 | 无法逐条记证据（挑战 3 的直接障碍） |
| D2 | 差分可信度受 taint 噪声污染 | `a2` 里混着"真误报"（file_read/file_write 双向过计数）和"半真半假" | `a2` 不能直接当"标准线误报"的干净信号 |
| D3 | learned 生命周期状态机缺失 | 只有静态 `confidence` 字段，无 `corroboration_count/pollution_count/last_seen` | 无法累积、无法淘汰（挑战 4/7） |
| D4 | 四线进化可表达性不对等 | sink/source/sanitizer 好表达为模型；"语义漏洞""能力暴露"这类 b0 不好表达 | b0 永远卡人工 |
| D5 | 跨运行状态格式 + 幂等/并发 | learned TOML 是 append 式单文件；无版本、无去重合并 | 多轮写同一模型会重复/覆盖冲突 |
| D6 | promote/rollback 语义名不副实 | `promoted = !rolled_back`（`pipeline.rs:532`）；`learned_dir` 未配时 promote 是 no-op 却报成功 | 报告"进化成功"但实际没写 |
| D7 | 缺少 fitness 度量 | 无 recall/precision 趋势，无法证明"变强" | 能力提升无法量化、无法对外证明 |

---

## 4. 候选方案

以下四个方案解决同一问题的不同侧面。它们不是互斥的——方案 D 是对前三个的编排组合。

---

### 方案 A：差分 + 跨运行置信度累积（状态机）

**核心思想**：保留现有差分当"单次采样"，叠加一条**逐模型的生命周期状态机**，让每条 learned 模型记住自己的历史表现。这是唯一能直接兑现"能力随测试次数逐步提升"的机制。

**具体实现**：

1. **扩展 learned 模型格式**（`learning.rs` 的 TOML 序列化 + `models.rs` 的 `SinkModel/SourceModel/SanitizerModel`）：
   ```toml
   [[sinks]]
   language = "python"
   category = "file_read"
   patterns = ["openpyxl.load_workbook"]
   confidence = "medium"            # 由累积证据驱动，不再是写死 low
   corroboration_count = 3          # 新增：被差分确认的次数
   pollution_count = 1              # 新增：制造 b2 污染的次数
   last_seen_run = 20260824         # 新增：最近一次触发的 run id
   source = "learned"
   learned_from = "scan-xxx/claude"
   ```

2. **新增归因模块**（新文件 `evidence.rs`，核心难点 D1）：
   - 建立 `finding → model` 反查：一条 taint finding 的 `sink_name`（如 `openpyxl.load_workbook`）→ 匹配到贡献它的 learned sink pattern。
   - 归因规则：taint finding 的 `sink_id` 含 sink 名，agent/codeql finding 的 `related_*_ids` 反查。**先只对 taint 线做精确归因**（taint 的 sink 名是确定的），agent/codeql 线用"同位置 + 同 category"近似归因。

3. **生命周期状态机**（`lifecycle.rs`）：
   ```
   staged(low)
     │ 本轮被 corroboration（归因到它且差分 b1/a1）
     ▼
   medium ── 再次 corroboration ──▶ high
     │
     │ 本轮被归因到 b2 污染
     ▼
   downgrade ── 再犯或 pollution≥2 ──▶ retire（删除）
   ```
   非对称阈值：**升级要 ≥2 次 corroboration，降级 1 次污染即生效**（冷启动防误学）。

4. **pipeline 接线**（`pipeline.rs` migrate 之后）：
   - 每轮算完 `migrate()` → 把 `b1/a1/b2` 的 finding 归因到具体模型 → 逐条回写 evidence → 持久化到 `learned_dir`。
   - `promote` 从"无门槛全收"改为"按累积证据逐条升/降/淘汰"，并修正 `promoted` 字段语义（改为"本轮实际 promote 了几条、retire 了几条"）。

5. **负向学习**（复用 a2，难点 D2）：
   - `a2`（标准线误报）→ 归因后生成**抑制模型**（suppression），记"该 sink 在这些位置是误报"，下一轮压制。需要先修 D2（taint 双向过计数），否则 a2 是脏信号。

**优点**：
- 逐条粒度，避免"好坏候选一起蒙混"。
- 复用现有差分，**不引入真值维护成本**。
- 真正实现"每次变强"：成熟模型 confidence 递增，噪声模型被淘汰。

**缺点 / 风险**：
- 冷启动误学风险（靠非对称阈值 + 升级门槛缓解）。
- D1 归因链要从零做，是最大工程量点。
- 状态漂移需 `last_seen_run` 老化机制。

---

### 方案 B：基准集 fitness 门控（进化策略式）

**核心思想**：维护一组**已知真值**的 fixture（excel CVE-2026-40576、MCTS `vulnerable-*`），每轮用基准集算 recall/precision，**指标提升才采纳本轮进化**。类似进化策略（evolution strategy）里"用 fitness 决定保留/丢弃"。

**具体实现**：

1. **ground-truth 标注文件**（新文件，如 `benchmark/ground-truth.json`）：
   ```json
   [
     {"target": "excel-mcp-server", "vuln": "path_traversal",
      "file": "src/excel_mcp/workbook.py", "line": 23, "reachable": true},
     {"target": "MCTS/examples/vulnerable-mcp-server", "vuln": "path_traversal",
      "file": "server.py", "line": 14, "reachable": true}
   ]
   ```

2. **fitness 计算**（新文件 `benchmark.rs`，或复用 `report` 模块）：
   - `recall = 命中的真值 finding 数 / 真值总数`
   - `precision = 真阳性 / 总报出`（真值外的报出暂按"未标"计，或用 agent 二次裁决粗标）

3. **门控接线**：`pipeline.rs` promote 分支改为：
   ```
   采纳本轮进化 iff Δfitness > 0（recall 提升且 precision 不降）
   否则 rollback
   ```

4. **报告增加能力趋势小节**：每轮 append `run_id, recall, precision, learned_count, retired_count` 到 `benchmark/history.csv`，形成趋势线。

**优点**：
- **最客观、可量化、可复现**：能明确说"recall 0.71 → 0.80"，可接 CI 回归。
- 防退化能力强：指标硬卡，比 `b2 > b1` 严格。

**缺点 / 风险**：
- **要持续维护真值标注**（成本）。
- **过拟合基准集**：只对这几个 fixture 变强（刷榜），对新目标无提升。缓解：fixture 集要多样 + 定期扩充。
- **整轮粒度**：只能判"整轮好坏"，无法逐条判模型（好候选 + 坏候选一起 promote 可能被指标持平掩盖）。
- **运行成本**：每轮多跑一遍基准集。

---

### 方案 C：agent 自洽对抗验证（LLM-as-judge）

**核心思想**：把"判定对错"这件事也交给 agent——用**第二个 agent（或同一 agent 的窄问题二次 pass）做对抗裁决**，对 b0 和 still_ambiguous 自动闭环。本质是把"人工 L3 裁决"替换成"agent 裁决 + 多轮投票 + 置信阈值"。

**具体实现**：

1. **窄问题裁决 prompt**（复用现有 `agent::run_with_prompt` + L2/L3 解释 pass 的机制，`pipeline.rs:480-502`）：
   - 对每条 `still_ambiguous`，用窄 prompt 问："这条是否是真的、且从 MCP tool 参数可达？给出是/否 + 一句话理由 + 置信度。"
   - 对每条 `b0`（semantic-only），用窄 prompt 问："这条语义漏洞能否抽象成一条可复用的检测规则？如果能，给出规则的 pattern/category。"

2. **多轮投票**（解决非确定性，见评估里的 Agent 4→3）：
   - 同一裁决问题跑 2~3 次，取多数票；票数一致才自动采纳，否则维持"不确定"进入跨运行累积。

3. **b0 → 规则自动编码**：
   - agent 裁决后，把可抽象的 b0 转成 `RuleComponent::capabilities`（`component.rs` 已预留 `RuleComponent.evolve` 但未接线），写入 learned rulebook。
   - 不可抽象的 b0（如"capability over-exposure"这类无 sink 语义的）→ 转成 `PromptComponent::prompt_extra`（把这类漏洞的识别提示追加到下一轮 agent prompt），实现"四线"里 rule + prompt 线的进化。

4. **置信阈值**：agent 自评 confidence < 阈值（如 medium）的裁决不自动采纳，转跨运行累积。

**优点**：
- 直接消灭"人工场景"，且能激活 rule / prompt 两条线的进化（呼应"全四线"范围）。
- 复用现有 agent 能力，不需要新真值。

**缺点 / 风险**：
- **自评不可靠**：agent 会高估自己（LLM 校准差），阈值要保守。
- **成本**：多轮投票 + 二次裁决 = token 成本成倍。
- **回声室风险加剧**：用 agent 验证 agent 的产出，错上加错的概率不是零，需要差分做底层约束。

---

### 方案 D：分层信任综合（推荐组合）

**核心思想**：不单选一个，而是**分层**——每一层解决一类问题，层层递进，前面的层是后面层的输入。

**具体实现**（分层架构）：

```
L1 差分信号层（已有，修正语义）
   └─ 产出 b1/a1/a2/b2 的"单次观测"
        ├─ b1/a1 确认、b2 污染、a2 误报（修 D2 后变干净）
        ▼
L2 归因层（新增，方案 A 的 evidence.rs）
   └─ finding → model 反查，把差分观测归到具体模型
        ▼
L3 生命周期层（新增，方案 A 的 lifecycle.rs）
   └─ 逐模型累积 corroboration/pollution → 升/降/淘汰
        ▼
L4 自洽裁决层（方案 C）
   └─ 只对 L3 仍"不确定"的（still_ambiguous / b0）用 agent 窄问题裁决 + 多轮投票
        ├─ 可抽象 b0 → rule capability
        └─ 不可抽象 b0 → prompt_extra
        ▼
L5 fitness 护栏层（方案 B，轻量版）
   └─ 只用基准集做"退化检测"（Δfitness < 阈值才回退），不硬卡逐条 promote
        ▼
promote / retire（写 learned_dir，带完整审计链）
```

**优点**：
- 各层职责单一，可独立测试、独立演进。
- 差分（L1）做底层约束，防止 agent 裁决（L4）失控；fitness（L5）做最后护栏，防止整轮退化。
- 直接覆盖全部四个硬伤 + 全部"全四线"范围。

**缺点 / 风险**：
- 工程量最大（但可分期，见 §6）。
- 层间接口要一次设计好，否则返工。

---

## 5. 方案对比矩阵

| 维度 | A 状态机 | B fitness | C agent 裁决 | D 分层综合 |
|---|---|---|---|---|
| 判定粒度 | 逐条模型 | 整轮 | 逐条 finding | **逐条（最优）** |
| 能否"每次变强" | ✅ | 部分（刷榜风险） | 部分 | ✅ |
| 消灭人工场景 | 部分（b0/still 仍存） | 否 | ✅ | ✅ |
| 需维护真值 | 否 | **是** | 否 | 轻量（仅退化护栏） |
| 激活四线 | 仅 taint | 仅 taint | taint+rule+prompt | 全部 |
| 防自我污染 | 中（状态机） | 强（指标硬卡） | 弱（需差分兜底） | **强（多层）** |
| 工程量 | 中 | 中 | 中 | 大（可分期） |
| 主要风险 | 冷启动误学、归因难 | 过拟合、归因不细 | 自评不可靠、成本 | 层间接口复杂度 |

---

## 6. 推荐与分期落地建议

**推荐方案 D（分层信任综合）**，分三期落地，每期都有独立可验证的产出：

### 第一期：修基座（先让"进化"名副其实）
- 修 D6：`promoted` 字段语义（改为"本轮 promote N 条 / retire M 条"，空 delta 报 `nothing to promote`）。
- 修 D3 起步：learned 模型格式加 `corroboration_count/pollution_count/last_seen_run` 字段，向后兼容。
- 修 D2：`delete` 前缀 → file_delete 误报（P1-A）、file_read/file_write 双向过计数（P1-B）——**这是 a2 变干净的前提**。
- **产出**：一次运行后，报告里的进化小节真实可信；a2 成为可用信号。

### 第二期：归因 + 生命周期（方案 A 落地，核心价值）
- 新增 `evidence.rs`（D1 归因）+ `lifecycle.rs`（升/降/淘汰）。
- 接入 pipeline，逐条回写证据。
- 负向学习：a2 → 抑制模型。
- **产出**：同一 fixture 连续扫描 N 轮，能观察到 learned 模型 confidence 递增、噪声模型被淘汰——**"能力随次数提升"第一次可被观测**。

### 第三期：去人工 + 四线 + 护栏（方案 C + B 轻量）
- agent 窄问题裁决 + 多轮投票，自动闭环 still_ambiguous / b0。
- b0 → rule capability / prompt_extra，激活 rule + prompt 线。
- 轻量基准集退化护栏 + 能力趋势报告。
- **产出**：零人工介入的完整进化闭环 + 可量化的能力趋势线。

---

## 7. 待确认决策点

1. **基准集是否纳入第一期**：需要先维护 MCTS + excel 的 ground-truth 标注，才能有 fitness 护栏。是否值得？
2. **升级/降级阈值**：建议"升 high 需 ≥2 次 corroboration、1 次污染即降级"，是否需要更保守（≥3）？
3. **agent 裁决的温度/轮数**：为对抗非确定性，多轮投票建议 2~3 轮，固定 temperature=0，是否接受 token 成本？
4. **负向学习的粒度**：抑制是"位置级"（file+line）还是"pattern 级"（整个 sink 名）？位置级精确但不可泛化，pattern 级泛化但可能误伤真阳性。
5. **淘汰后是否归档**：retire 的模型是物理删除，还是移到 `learned/archive/` 保留审计？

---

*本文档为设计讨论稿，确认上述决策点后进入实现计划（writing-plans）。*
