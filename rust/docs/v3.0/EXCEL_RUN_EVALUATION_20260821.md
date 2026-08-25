# Excel MCP Server 运行结果评审(20260821-124759)

> **评审对象**:`rust/docs/result/excel/20260821-124759.md`(对 `excel-mcp-server @ v0.1.7` 的一次完整扫描)
> **目的**:诚恳评价这次运行的**质量**——哪些工作正常、哪些是噪声/误报/缺陷、需要怎么改。
> 本文不粉饰:数字好看(289 条 taint 命中、8 条 fused),但**信号质量很差**,大量误报与冗余稀释了
> 真正的发现。
>
> **配套文档**:`ARCHITECTURE.md`(新架构)、`EXCEL_MCP_SERVER_TEST_PLAN.md`(测试方案)、
> `EXCEL_SCAN_DIAGNOSIS.md`(重构前漏报根因)。

**日期:** 2026-08-21

---

## 目录

- [1. 运行概览](#1-运行概览)
- [2. 亮点:哪些工作正常](#2-亮点哪些工作正常)
- [3. 问题清单(按严重度)](#3-问题清单按严重度)
- [4. 对测试方案的纠正](#4-对测试方案的纠正)
- [5. 改进建议(可落地)](#5-改进建议可落地)
- [6. 结论](#6-结论)

---

## 1. 运行概览

| 指标 | 值 | 一句话评价 |
|---|---|---|
| Risk Level | **high** | ⚠️ 被误报顶高,不反映真实风险 |
| Facts | 1985 | 正常 |
| **Rule Results** | **3** | ❌ 3 条全为误报/误标 |
| **Taint Results** | **289** | ⚠️ 大量噪声 + 冗余,真阳性被稀释 |
| **Agent Results** | 5 | ✅ 高质量,但类别缺失 + 1 条丢失 |
| **CodeQL Results** | 2 | ✅ 真实路径穿越 + 完整 dataflow |
| Fused Findings | 8 | ⚠️ 8 条中约 3 条是误报,4 条 agent 类别 unknown |

Facts 构成:`assign 396 / call 600 / dataflow 497 / entrypoint 25 / function 77 / import 173 /
sink 106 / source 111`。entrypoint=25 与 25 个 `@mcp.tool()` 精确对应,提取器工作正常。

**一句话结论**:新架构的五条能力(语义推断、双引擎、agent 三角色、门控+回灌+持久化、融合)都**确实跑起来了**,
真实 CVE 被 CodeQL + agent 命中;但 **rule 与 taint 两条确定性线贡献的是噪声而非信号**,导致最终
8 条 fused finding 里近一半是误报。这是「召回高、精度低」的典型状态。

---

## 2. 亮点:哪些工作正常

1. **CodeQL 独立命中真实路径穿越**(2 条)——这是本次最有价值的确定性命中:
   - `mcp/tool-param-to-path-traversal` @ `workbook.py:23` 与 `workbook.py:66`,二者都是 `path = Path(filepath)`;
   - 完整 dataflow 路径从 `server.py:97`(工具参数)→ `get_excel_path`(`server.py:74/85`,正是 CVE 缺陷点)
     → `workbook.py` 的 `Path(...)` sink。证据链完整、可追溯。
2. **agent 三角色产出 5 条高质量语义发现**,其中:
   - 「Arbitrary file read/write via absolute-path and `../` traversal bypass in get_excel_path」——直接命中 CVE 根因;
   - 其余 4 条(未鉴权 0.0.0.0 暴露、存储型公式注入、公式校验可绕过、透视表组合爆炸 DoS)是
     rule/taint/CodeQL **永远抓不到**的语义漏洞,验证了 agent 的独特价值。
3. **语义推断确实抓到 `openpyxl.load_workbook` → `file_read`**(重构的头号目标),只是被噪声淹没(见 P0-1)。
4. **自进化闭环跑通**:`models/learned/` 落盘 2 个模型文件:
   - `learned-openpyxl_load_workbook.toml`(file_read)、`learned-openpyxl_workbook_Workbook_save.toml`(file_write);
   - 证明 agent 提出模型 → 门控 → 冷持久化全链路可用。
5. **可观测性生效**:CodeQL 的 0/命中不再静默(有 2 条结果 + 完整路径),agent/learned 有迹可查。

---

## 3. 问题清单(按严重度)

### P0-1 · 语义推断层 3 的 `get` → `network_request` 大规模误报

**证据**:289 条 taint 结果里,前 ~40 条(以及末尾大量)都是
`mcp_tool_parameter → network_request`,sink 全落在 `server.py:107/269/283/306/336/363/386/402/419/435/448/461/474/493/520/545/574/608/626/644/662...`
——即**每个 tool handler 里那句 `full_path = get_excel_path(filepath)`** 被误判成网络请求 sink。

**根因**(`infer.rs` 层 3):

```rust
const NAME_PREFIX_CATEGORY: &[(&str, &str)] = &[
    ("get", "network_request"),   // ← 罪魁祸首
    ...
];
```

`get_excel_path`、`get_workbook_info`、`get_merged_ranges` 等**本地辅助函数**名字以 `get` 开头、首个参数
`filepath` 含 `path`(`ARG_PATH_HINTS`),于是被 `infer_by_name` 判成 `network_request`。两点错误叠加:
- `get` 是**全代码最高频的前缀之一**,「get 一个文件」几乎从不是网络请求;
- `infer_by_name` **没有 module 限定守卫**——它对裸函数名(不含 `.`/`::`)也触发。对比 `learning.rs`
  的温回灌有 `if !c.name.contains('.') && !c.name.contains("::") { continue; }` 守卫,`infer_by_name` 缺失。

**后果**:openpyxl 是纯文件库,本目标**任何** `network_request` 都是定义性误报。这一条直接灌进
~40+ 噪声,并顶高 `Risk Level = high`。

### P0-2 · rule 线 3 条结果全为误报/误标

| rule 结果 | 位置 | 真相 |
|---|---|---|
| `data_exfiltration` | `server.py:69` | `host=os.environ.get("FASTMCP_HOST","0.0.0.0")` 的**正常配置读取**,非数据外带 |
| `env_access` | `server.py:69` | 同上,读取环境变量本身不是漏洞 |
| `path_traversal` | `__main__.py:13` | `print("\nShutting down server...")` 的省略号 `...` 被关键词 `..` 命中(RC-3 未修) |

**后果**:rule 线对真实 `os.path.join`(`server.py:93`)贡献 **0 真阳性**,反而产出 3 条误报。
两个独立根因:
1. `env_access`/`data_exfiltration` 能力**盲目标记所有 `os.environ` 读取**,不区分「读敏感凭证」与「读 host/port 配置」;
2. `path_traversal` 能力的 `".."` 关键词过宽(RC-3),且 `rule` 每个 capability 只报排序后的第一条匹配
   (`__main__.py` 字典序在 `server.py` 前),把真命中 `os.path.join` 埋进 evidence。

### P1-3 · taint 结果爆炸(289 条)且无聚合去重

**证据**:同一 tool handler 的每个参数 × 每个 sink 都独立成一条:
- `delete_range` 的 `filepath/sheet_name/start_cell/end_cell/shift_direction` 各自 × `file_read/file_write/file_delete` 产生十余条;
- 同一 `openpyxl.load_workbook` 调用点同时出现 `sink:inferred:` **和** `sink:learned:` 两条(温回灌把层 2 已经推断出的 sink 又学了一遍)。

**后果**:fusion 最终只塌缩出 1 条 taint finding,但报告仍**全量 dump 289 条**,淹没真阳性、不可读。
温回灌的 `sink:learned` 与层 2 的 `sink:inferred` **重复**(见 §5 建议 5)。

### P1-4 · agent 发现类别 `unknown` + 1 条丢失

**证据**:8 条 fused 里有 4 条 agent finding 的 category 是 `unknown`:
- 「Stored formula injection」「Formula safety validation bypassable」「Pivot table combinatorial explosion」「Arbitrary file read/write」都无法映射到 `category.rs` 的 17 个规范类别。
- 第 5 条「Unauthenticated network exposure: server binds 0.0.0.0 with no auth」**没有出现在 fused findings 里**(被丢弃)。

**根因**:agent 的语义漏洞类别(tool poisoning、capability over-exposure、DoS、auth bypass、formula injection)
不在 `CANONICAL_CATEGORIES` 里,所以无法归类、无法按类别与其它线印证;「unknown」还让 agent finding
看起来比实际更不可信。

### P2-5 · fusion 标题与类别不一致

fused finding 标题是 `taint: mcp_tool_parameter → network_request`,但 category 却标 `file_read`。
标题取自 source→sink 字符串(被噪声 sink 污染),类别取自另一个字段,二者对不上,进一步降低可信度。

### P2-6 · learned 溯源是硬编码占位

`learned_from = "scan/agent"`——`pipeline.rs` 把 scan_id/agent_id **硬编码**为 `"scan"`/`"agent"`,
并非真实的扫描 ID/时间戳。架构宣称的「可追溯自进化」目前是**假的溯源**:无法回溯到「哪次扫描、哪个证据」。

### P2-7 · 报告可读性

289 条 taint raw + 106 条 sink + 497 条 dataflow 全量 dump,报告 340 行、绝大多数是重复噪声,
没有「去重/折叠/按 sink 聚合」的呈现。

---

## 4. 对测试方案的纠正

我在 `EXCEL_MCP_SERVER_TEST_PLAN.md` §2/§7 里判断「CodeQL 对本 CVE 预期 **0** 命中」——**这个判断错了**。
实际运行 CodeQL 命中 **2 条**真实路径穿越:

- 原因是我假设该仓库「无内建 `open()`/`Path()` 文件 sink」,但实际 `workbook.py:23` 与 `:66` 各有一句
  `path = Path(filepath)`,正好落在 `ToolParamToPathTraversal.ql` 的 `pathlib.Path` sink 上;
- 且 dataflow 路径**精确穿过** `get_excel_path` 的 `isabs`/`os.path.join` 缺陷点,证据质量极高。

**应修正测试方案**:
- §2 矩阵 CodeQL 行:由「0 条(对本 CVE)」改为「**2 条真实命中**(经 `pathlib.Path` sink,带完整 dataflow)」;
- §7 第 1 条:删除「CodeQL 对本 CVE 预期 0 命中」,改为「CodeQL 能命中经 `Path()`/`open()` 的路径穿越;
  但**经 `openpyxl.load_workbook` 直接打开**的第三方封装路径仍依赖 MaD 注入(2.26.2 下被禁)」。

(此纠正基于本次实测,非推测。)

---

## 5. 改进建议(可落地)

按「投入产出比」排序:

| # | 建议 | 涉及文件 | 收益 |
|---|---|---|---|
| 1 | **删除/收紧层 3 的 `get`→`network_request`**。`get` 太泛,改为 `download/upload/fetch/post/put` 等明确网络动词,或删除 `get` | `infer.rs::NAME_PREFIX_CATEGORY` | 立即消除 ~40+ 条 network_request FP |
| 2 | **层 3 增加 module 限定守卫**:只对含 `.`/`::` 的调用触发,跳过本地裸函数名(对齐 `learning.rs` 的 bare-name 守卫) | `infer.rs::infer_by_name` | 消除 `get_excel_path`/`get_workbook_info` 等本地函数误判 |
| 3 | **收紧 rule 的 `env_access`/`data_exfiltration`**:不盲目标记 `os.environ.get`,只对含 `key/token/secret/password` 等敏感键名触发;并修 `path_traversal` 的 `".."` 关键词(RC-3) | `rules/languages/keywords.toml`、`rule/mod.rs` | rule 线从 0/3 提升到真阳性 |
| 4 | **taint 结果聚合**:按 `(entrypoint, sink_category, sink_call_id)` 聚合,去掉「每参数一条」的爆炸;报告里折叠展示 | `taint/result.rs`、`reporting.rs` | 报告从 340 行降到可读;precision 显著提升 |
| 5 | **温回灌去重**:门控前跳过已被层 2 推断覆盖的候选(不重复学 `openpyxl.load_workbook`) | `learning.rs` / `pipeline.rs` | 消除 `sink:inferred` 与 `sink:learned` 重复 |
| 6 | **扩充语义类别词表**:加入 `tool_poisoning`(已有)、`capability_overexposure`、`denial_of_service`、`authentication_bypass`、`formula_injection` 等,并让 agent prompt 使用这些词 | `category.rs`、`agent/prompt.rs` | agent finding 可分类、可印证、不再 `unknown` |
| 7 | **learned 溯源用真实 ID**:`candidate_to_sink_model` 传入真实 scan 时间戳/ID | `pipeline.rs`、`learning.rs` | 溯源不再是占位符 |
| 8 | **修正测试方案预期**(§4) | `EXCEL_MCP_SERVER_TEST_PLAN.md` | 文档与实测一致 |

其中 **1–3 是「精度救火」**,直接决定「8 条 fused 里 3 条误报」能否降到 0;**4–5 是「可读性/去重」**;
**6–8 是「收尾」**。建议先做 1–3。

---

## 6. 结论

这次运行是**「架构能力验证成功、输出质量验证失败」**:

- ✅ **能力面**:语义推断、双引擎、agent 三角色、门控+温回灌+冷持久化、融合、可观测性——五条全链路都真实跑通,
  真实 CVE 被 CodeQL(2 条完整 dataflow)与 agent(直接命中根因)独立发现。
- ❌ **质量面**:rule 线 3 条全为误报;taint 线 289 条里约半数是被 `get`→`network_request` 灌出的误报、
  其余是参数粒度爆炸与 inferred/learned 重复;最终 8 条 fused 里约 3 条是误报、4 条 agent 类别 unknown。

**下一步最重要的一件事**:修 `infer.rs` 的 `get`→`network_request` 过度泛化 + 层 3 裸函数名守卫(§5 的 #1/#2)。
这两处改动小、立竿见影,能把 taint 从「289 条噪声」拉回「~25 条真 file_read/file_write」,让这次评审里的
「头号成功信号(语义推断抓到 load_workbook)」真正浮出水面,而不是被噪声淹没。

---

*本文与 `EXCEL_SCAN_DIAGNOSIS.md` 呼应:后者记录了重构前「taint 0 命中、rule 报错位置、CodeQL 0 命中、
agent 读不到文件」四根因;本文则记录了重构后「能力都跑通,但精度被层 3 泛化 + rule 误报拖垮」的新问题。*
