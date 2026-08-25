# 静态分析线通用性设计:为什么「无限补 QL 文件」不是答案

> **本文定位**:这是高于 `CODEQL_MASTER_PLAN.md`(怎么把 CodeQL 做全)和
> `IMPROVEMENT_PLAN.md`(怎么修 Rust 线准确性)的**战略层文档**,回答一个更根本的问题:
>
> > 修完 excel-mcp-server 这一单次漏报之后,换一个目标,CodeQL / Taint 两条线是不是照样漏?
> > 通用性到底从哪里来?CodeQL 的办法难道就是不断补 `.ql` 文件吗?
>
> **结论先行**:不断补 QL 文件是**最低效、最不可能收敛**的那条路。真正的通用性来自三层结构
> (通用引擎 / 语义 sink 类 / 模型数据) + 「有界分类学 vs 无界 sink 清单」的正确切分 +
> 三个抓手(语义化 sink 推断、sink 目录数据化、agent 反馈回路)。下文逐层展开。

**日期:** 2026-08-20
**触发背景:** excel-mcp-server 扫描(见 `EXCEL_SCAN_DIAGNOSIS.md`)中,`Taint = 0`、
`CodeQL = 0`,根因是 `openpyxl.load_workbook` 未被任何一条线建模为文件读取 sink。
**相关文档:** `EXCEL_SCAN_DIAGNOSIS.md`(单次漏报的根因),`CODEQL_MASTER_PLAN.md`(CodeQL 战术),
`IMPROVEMENT_PLAN.md`(Rust 线战术)。

---

## 目录

- [1. 问题陈述:漏报是结构性的,不是 bug](#1-问题陈述漏报是结构性的不是-bug)
- [2. 认知纠偏:CodeQL 的通用性分三层,只有一层需要「补」](#2-认知纠偏codeql-的通用性分三层只有一层需要补)
  - [2.1 L3 模型数据详解](#21-l3-模型数据详解)
- [3. 关键切分:有界的分类学 vs 无界的 sink 清单](#3-关键切分有界的分类学-vs-无界的-sink-清单)
- [4. 现状盘点:四条线各自的通用性短板](#4-现状盘点四条线各自的通用性短板)
- [5. 三个抓手:让确定性引擎的网一次性撒大](#5-三个抓手让确定性引擎的网一次性撒大)
  - [5.1 抓手① 语义化 sink 推断(三层置信度)](#51-抓手--语义化-sink-推断三层置信度)
  - [5.2 抓手② sink 目录数据化(models-as-data)](#52-抓手--sink-目录数据化models-as-data)
  - [5.3 抓手③ agent 作为通用层 + 反馈回路](#53-抓手--agent-作为通用层--反馈回路)
  - [5.4 自进化:冷、温、热三档进化机制](#54-自进化冷温热三档进化机制)
- [6. 与现有代码 / 文档的对接点](#6-与现有代码--文档的对接点)
- [7. 落地顺序与里程碑](#7-落地顺序与里程碑)
- [8. 预期效果与仍然存在的局限](#8-预期效果与仍然存在的局限)
- [9. 结论](#9-结论)

---

## 1. 问题陈述:漏报是结构性的,不是 bug

excel-mcp-server 的扫描暴露了一个让人不安的事实:四条线里,规则 / Taint / CodeQL 都是
**「给定一个 sink 名字清单,在源码里找这些名字」**。区别只是:

| 线 | 找 sink 的方式 | 认识 `load_workbook` 吗? |
|---|---|---|
| Rule | `rules/languages/keywords.toml` 里手写的关键词 | 不认识(只有 `os.path.join` / `Path(` / `..`) |
| Taint | `facts/python/sinks.rs` 里的 `SINK_RULES` | **不认识**(只有 `open` / `read_text` / `write_text` / `subprocess.*`…) |
| CodeQL | 标准套件 + 自定义 `.ql` 里的 sink 类 | **不认识**(`py/path-injection` 没把 `openpyxl` 建模进文件读) |
| Agent | LLM 阅读源码后推理 | **认识**(它能推理「读文件 = 路径穿越风险」) |

注意最后一行:唯一「认识」`load_workbook` 的,是那条不靠清单的 agent 线。这就是整个问题的答案
的钥匙——**通用性只能来自「不靠穷举名字」的那一层**。

换句话说:当 Taint / CodeQL 的 sink 清单里没有 `load_workbook` 时,它们返回 0,不是它们跑挂了,
而是**它们的模型里根本不存在这个函数**。这不是某一次可以「补一下」的 bug,而是
「名字穷举式检测」这一类方法论的**结构性局限**:

> 只要你还在枚举「具体函数名」,你就永远会漏掉清单外的那一个。清单是无界的。

---

## 2. 认知纠偏:CodeQL 的通用性分三层,只有一层需要「补」

先把「CodeQL 是不是靠补 QL 文件」这个问题讲准。CodeQL 的通用性其实分三层,绝大多数人只看到
了第三层:

| 层                                 | 是什么                                                                                                                   | 换一个新库要不要补?                 | 通用性贡献       |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------- | -------------------------- | ----------- |
| **L1 数据流 / 污点引擎**                 | 给定一个 sink,自动追踪任意源头到它的路径:跨函数、跨文件、处理别名、字段访问、净化函数                                                                        | **不用**,完全通用                | 🔴 最高       |
| **L2 语义 sink 类**                  | 抽象类,如 Python 的 `FileSystemAccess`、`RemoteFlowSource`、`CommandExecution`。查询针对的是「文件系统访问」这个**语义**,而不是 `open()` 这个**函数名** | 不用                         | 🔴 高        |
| **L3 模型数据 (models-as-data, MaD)** | 把**具体库函数**映射到语义类的一行 **YAML 数据**,例如「`openpyxl.load_workbook` 的第 0 个参数是文件读 sink」。由 GitHub 集中维护,随 `codeql/python-all` 分发 | **要**,但这是加**一行数据**,不是写一个查询 | 🟡 低(但必须持续) |

所以准确的说法是:

- **CodeQL 不是「每发现一个漏洞就写一个 .ql」。** 它是「把通用性下沉到 L1/L2 引擎和语义类,
  只把『具体库函数 → 语义类』这一层做成可增量追加的数据」。追踪本身(L1)是完全通用的。
- 「补 QL 文件」这个词混淆了两件事:**补查询(每漏洞一条)** 和 **补模型(每库函数一行数据)**。
  CodeQL 的做法是后者,而且把后者做成了可扩展的数据文件,而非散落的代码。

**但结论不变**,必须诚实承认:**即便用 MaD,L3 仍然是一份需要长期维护的清单。** 静态分析的本质
决定了「给定 sink 才能追踪」——引擎再强,也得先知道「追踪到哪里」。所以通用性**不能只靠
CodeQL**,这正是本文第 5 节要解决的。

> 补充:CodeQL 还有一个「库内追踪」的优势值得点明——如果目标项目里 `load_workbook` 是**它自己
> 写的**(而非第三方库),CodeQL 能顺着调用链追踪到它最终调用的 `io.open`,从而间接命中。但对
> **source-only 审计**(只审计 MCP server 源码、不审计 openpyxl 库本身),第三方库内部是黑盒,
> 这一步走不通,于是又回到了「需要 L3 模型」的老问题。这是所有 source-only 静态分析的共同天花板。

### 2.1 L3 模型数据详解

上表里「L3 模型数据」这一行最容易绕晕,单独展开讲清楚。

#### 2.1.1 L3 要解决的「断点」

L1 引擎和 L2 语义类是通用的,但这两层之间有一个**接不上的地方**:

- L1 引擎会追踪「数据从 A 流到 B」,但它**不知道 B 是谁**;
- L2 语义类定义了「什么叫『文件读取』」,但它**只认识抽象概念,不认识具体函数**;
- 引擎不可能知道 `openpyxl.load_workbook` 这个函数是干嘛的——它只是一个名字。

所以中间需要**一张表**,把「具体函数名」翻译成「语义类」。这张表,就是 L3。

> 类比:引擎是一个能听懂「帮我找危险文件操作」的侦探,但他不认识全世界的每个函数。你需要
> 给他一本**词典**:`openpyxl.load_workbook` = 文件读取、`os.system` = 命令执行、
> `pickle.load` = 反序列化…… L3 就是这本词典。

#### 2.1.2 具体到 excel-mcp-server 这件事

`load_workbook(filepath)` 为什么漏报?就是因为**词典里没有这一条**:

```
没有 L3 模型时:
  引擎: "我从 @mcp.tool() 参数追踪到了 load_workbook(...) 的调用"
  引擎: "但 load_workbook 是危险操作吗? 词典里查不到 → 跳过"   ← 漏报!

有了 L3 模型(加一行数据)后:
  词典: "load_workbook 的第 0 个参数 = 文件读 sink"
  引擎: "我追踪到了 load_workbook,词典说它是文件读 → 命中!"     ← 命中
```

**关键点:引擎本身一行都不用改。** 你只是往词典里加了一条词条,追踪逻辑是现成的、通用的。

#### 2.1.3 「一行数据」到底长什么样

CodeQL 的 MaD 就是一份 YAML,每加一个函数就是加**一条数组**。以文件读 sink 为例,大致长这样
(字段名随版本略有差异,但结构稳定):

```yaml
extensions:
  - addsTo:
      pack: codeql/python-all          # 追加到哪个标准库
      extensible: sinkModel            # 追加到「sink 词典」
    data:
      # [模块,      函数,             哪个参数,        语义类别,            来源]
      - ["os",       "system",         "Argument[0]",   "command-injection", "manual"]
      - ["subprocess", "run",          "Argument[0]",   "command-injection", "manual"]
      - ["openpyxl", "load_workbook",  "Argument[0]",   "file-read",        "manual"]  # ← 这一行就是「补模型」
```

看最后一行,它说了三件事:

1. **哪个函数** → `openpyxl.load_workbook`;
2. **哪个参数危险** → `Argument[0]`(第 0 个参数,即 `filepath`);
3. **属于哪类危险** → `file-read`(文件读)。

就这么一行。对比一下:如果走「补 QL 文件」的路,你得写一个完整的查询文件(定义 source、
定义 sink 类、配置污点追踪、写 select……几十行)。而 MaD 只需要**一行数据**。

#### 2.1.4 上表那几列的含义(「要」「🟡 低」「必须持续」)

| 列 | 含义 |
|---|---|
| **「要」** | 换一个没建过模型的新库,确实**还得补**。它没有彻底消灭「补」,只是把「补」的成本从「写查询」降到了「加一行数据」 |
| **「🟡 低」** | 它**不贡献新的通用能力**。L1/L2 才是通用性的来源,L3 只是「喂数据」。引擎强不强、能不能跨函数追踪,跟 L3 无关 |
| **「必须持续」** | 但它**不能停**。因为库是无穷的,词典永远是「不完整但一直在补」的状态。GitHub 每天都在追着新库补模型 |

所以 L3 的定位是:**它不聪明,但它便宜、且必须一直做。** 这也是为什么本文第 5 节说「通用性
不能只靠 CodeQL」——如果把宝全押在「不断补词典」上,就陷入了「永远在追库、永远追不完」的境地。

#### 2.1.5 一句话:本项目已经有一个「手搓版 MaD」

`facts/python/sinks.rs` 里的 `SINK_RULES`,**本质就是一张 L3 词典**,只是它:

- 用 **Rust 代码**存,而不是 YAML;
- 只有「精确函数名」一种匹配,没有包名归类 / 命名模式;
- 没接到 agent 反馈回路上(所以永远靠人补)。

CodeQL 的 MaD 和 `sinks.rs` 的 `SINK_RULES` 是**同一件事的两种实现**,区别只是:MaD 是数据
文件(改一行就能扩展)、`SINK_RULES` 是硬编码代码(要重新编译)。这也正是第 5.2 节「抓手②
sink 目录数据化」要做的事:把自己的 `SINK_RULES` 也做成 YAML 数据,让它和 CodeQL 的 MaD 一样
「加一行就扩展」——这样 Taint / CodeQL / 未来的 agent 回填就能共享同一份词典。

---

## 3. 关键切分:有界的分类学 vs 无界的 sink 清单

这是理解整个问题最有用的一刀。把「我们要检测什么」拆成两层:

### 3.1 有界的一层:漏洞分类学(taxonomy)

MCP server 的攻击面是**有限、且早已被穷举**的。OWASP MCP Top 10、MCPTox、以及本项目 agent
提示词里的 7 类(见 `agent/prompt.rs` 的「MCP Vulnerability Taxonomy」)已经覆盖:

| 类别 | 类别 id(与 rule 词表对齐) | 危险动作的「语义」 |
|---|---|---|
| 命令注入 | `command_execution` | 参数流入 shell / 子进程 |
| 代码执行 | `dynamic_execution` | 参数流入 `eval` / `exec` / `Command::new` |
| 文件读取(敏感泄露) | `file_read` | 参数决定读哪个文件 |
| 文件写入 / 删除 | `file_write` | 参数决定写 / 删哪个文件 |
| 路径穿越 | `path_traversal` | 参数拼进路径且未做 realpath / 前缀校验 |
| SSRF / 外发 | `network_request` / `data_exfiltration` | 参数决定访问哪个 URL |
| SQL 注入 | `database_injection` | 参数拼进 SQL 字符串 |
| 反序列化 | `deserialization` | 参数流入 `pickle` / `yaml` / `bincode` |
| Prompt 注入 | `prompt_injection` | 参数拼进 prompt / 模板 |
| 工具投毒 / 能力过曝 | `tool_poisoning` / `capability_overexposure` | 描述与实现不符 / 暴露过多工具 |

**这一层是稳定的、可以写死的。** 它决定了「有几条检测线、报告里怎么归类、fusion 怎么交叉印证」。
十年内它都不会大改。

### 3.2 无界的一层:具体 sink 清单(sink inventory)

每一个类别下面,落到具体语言、具体库,是**无穷无尽**的:

- `file_read` 的 sink 可以是 `open`、`Path.read_text`、`openpyxl.load_workbook`、
  `pandas.read_excel`、`csv.reader`、`json.load`、`yaml.safe_load`、`PIL.Image.open`、……
- `command_execution` 的 sink 可以是 `os.system`、`subprocess.run`、`os.popen`、
  `sh.Command`、`fabric.Connection.run`、……

**这一层永远列不完。** 而 Taint 线的 `SINK_RULES`、CodeQL 的 L3 模型、Rule 线的关键词表,
本质都是在枚举这一层。

### 3.3 由此推出的三条设计原则

1. **把「分类学」和「sink 清单」解耦。** 分类学写死在代码里(因为它有界、稳定);sink 清单
   做成数据(因为它无界、要持续追加)。
2. **确定性引擎(rule / taint / codeql)负责在「已知 sink 清单」内做到高精度、高速度、可印证;
   不要指望它们独自覆盖全清单。**
3. **通用性由「语义化 sink 推断 + agent 反馈回路」承担,而不是靠把清单补全。**

---

## 4. 现状盘点:四条线各自的通用性短板

对照第 3 节的切分,看本项目四条线现在各自卡在哪:

### 4.1 Rule 线(关键词 / 正则)

- **位置:** `rules/languages/keywords.toml` + `static_analysis/rule/mod.rs`(`match_keyword_indicator`)。
- **现状:** 纯文本子串匹配(`haystack.find(&needle)`),对「sink 清单」的枚举方式是**最脆弱的**
  ——连 `use std::{fs, io}` 这种 import 别名都解析不了(见 `IMPROVEMENT_PLAN.md` Task 3)。
- **通用性短板:** 它既没有数据流(不知道参数是否可控),也没有别名解析,命中即误报风险高
  (`EXCEL_SCAN_DIAGNOSIS.md` RC-3 的 `..` 匹配到省略号就是典型)。
- **定位:** 它的价值不是「通用」,而是「快 + 兜底」——在没有任何模型的情况下,用正则先扫出
  可疑区域,交给更精确的线确认。**不要试图让它变通用,它天生不是干这个的。**

### 4.2 Taint 线(内建污点追踪)

- **位置:** `static_analysis/taint/` + `static_analysis/facts/python/sinks.rs`(`SINK_RULES`)。
- **现状:** 有一个真正的数据流引擎(forward/backward、max_depth、entrypoint_required),但
  **source/sink 都是名字清单**。sink 清单只覆盖了内建函数(`open` / `subprocess.*` /
  `eval` / `pickle.load` / `requests.get`…),对第三方库的封装函数(`load_workbook` /
  `read_excel` / `to_excel` / `to_csv`)一无所知。
- **通用性短板:** 引擎是通用的,**瓶颈 100% 在 sink 清单**。`EXCEL_SCAN_DIAGNOSIS.md` 的
  RC-1 就是:引擎完全有能力追踪 `filepath → get_excel_path → load_workbook(filepath)`,但
  因为 `load_workbook` 不在清单里,它没有「追踪到哪里」的目标。
- **定位:** 这是**最值得升级**的一条线——引擎通用、只差一个「语义化的 sink 识别」,见 5.1。

### 4.3 CodeQL 线

- **位置:** `static_analysis/codeql/`(`queries.rs` 引用 `codeql/python-queries@1.8.7` 标准
  套件 + 自定义 MCP 查询目录)。
- **现状:** 有工业级 L1/L2 引擎(见 `CODEQL_MASTER_PLAN.md` Part 1 的内建 taint vs CodeQL
  对比),但**只用了标准套件里「GitHub 已经建好模型」的那部分**。`load_workbook` 这类库封装
  函数不在标准套件模型里 → `py/path-injection` 返回 0。
- **通用性短板:** 和 Taint 线**同一个病根**——L3 模型数据没跟上。区别是 CodeQL 的 L3 是
  MaD(YAML),理论上比 `sinks.rs` 好扩展;但本项目**还没接上「自定义模型扩展」这条路**,
  而是打算靠「再写几条 `.ql` 查询」(`CODEQL_MASTER_PLAN.md` Part 6 的查询矩阵)。
- **定位:** CodeQL 应定位成**高精度的第二意见**,而不是主力召回。它的价值在「命中就基本可信 +
  带完整数据流路径」;它的召回天然受限于「谁为这个库建了模型」。

### 4.4 Agent 线(LLM)

- **位置:** `static_analysis/agent/`(`mod.rs` + `prompt.rs`)。
- **现状:** 唯一不靠 sink 清单的线。prompt 明确要求「优先找**非平凡模式匹配**能抓住的语义
  风险」(`agent/prompt.rs` 第 76-82 行)。它靠**推理**而不是**枚举**,所以「认识」`load_workbook`。
- **通用性短板:** 慢、贵、且结果有不确定性(LLM 可能漏、可能幻觉行号)。prompt 里为此加了
  「重新读文件确认行号」的约束,但仍是概率性的。
- **定位:** **这是全系统的通用性来源。** 见 5.3,核心是把它从「一次性审计」升级成「反哺目录的
  持续学习者」。

> **一句话总结现状:** 四条线里,三条确定性线共享同一个瓶颈(名字清单),一条概率线(agent)
> 没有这个瓶颈但不可靠。要系统性解决通用性,就必须:(a) 让确定性线从「名字清单」升级到
> 「语义识别」;(b) 把 agent 的推理能力「固化」成可复用的 sink 清单。

---

## 5. 三个抓手:让确定性引擎的网一次性撒大

按性价比从高到低。三个抓手相互配合,缺一个都不完整。

### 5.1 抓手① 语义化 sink 推断(三层置信度)

**核心思想:** 不要按「精确函数名」枚举 sink,改成**三层识别,置信度递减**:

```
┌─────────────────────────────────────────────────────────────┐
│ 第 1 层:精确名   —— 现有 SINK_RULES / MaD,高置信,命中即报     │
│         例:open / subprocess.run / pickle.load                │
├─────────────────────────────────────────────────────────────┤
│ 第 2 层:包名归类 —— 新加,中置信,把一类库整体识别为 sink         │
│         例:from openpyxl import ... → 文件读写                 │
│             import subprocess → 命令执行                      │
│             import requests/httpx/socket → 网络               │
│             import pickle/yaml/dill → 反序列化                │
├─────────────────────────────────────────────────────────────┤
│ 第 3 层:命名模式 —— 新加,低置信,交给 fusion / agent 印证        │
│         例:函数名匹配 ^(load|read|open|save|write|dump|exec|   │
│             run|get|post|delete|remove|unlink|rmdir)          │
│             + 「第 1 个参数是路径/命令/URL」的启发式            │
└─────────────────────────────────────────────────────────────┘
```

#### 5.1.1 第 2 层(包名归类)的设计

这是**性价比最高**的一层:一行 `import` 就能把成百上千个函数一次性覆盖,而不用逐函数枚举。

按 Python 包名归类(JS/TS/Rust 可建同构的表):

| 包 / 模块 | 归类类别 | 依据 |
|---|---|---|
| `openpyxl`、`pandas`、`xlrd`、`xlsxwriter`、`csv` | `file_read` / `file_write` | 表格 / 数据框库,`load_*`/`read_*` 读、`save`/`to_*` 写 |
| `subprocess`、`os`(部分)、`sh`、`fabric`、`pexpect` | `command_execution` | 子进程 / shell |
| `requests`、`httpx`、`urllib`、`aiohttp`、`socket`、`websockets` | `network_request` | 网络 I/O |
| `pickle`、`dill`、`marshal`、`yaml`、`joblib` | `deserialization` | 反序列化 |
| `eval` / `exec`(builtins)、`ast.literal_eval`(低) | `dynamic_execution` | 动态执行 |
| `jinja2`、`mako`、`string.Template` | `template_injection` | 模板渲染 |

**实现要点:** 对 Python,`import openpyxl` 或 `from openpyxl import load_workbook` 都能被
现有的 import 解析(或一个轻量正则)抓到。抓到包名 → 查上表 → 得到类别 → 把这个模块下所有
「函数调用」都标记为候选 sink(读/写再按函数名前缀细分,见 5.1.2)。

> 注意:**包名归类是「包 → 类别」的映射,不是「函数 → 类别」。** 它比精确名粗,但比命名模式
> 可靠,因为它利用了「这个库是干什么的」这个稳定的语义事实。

#### 5.1.2 第 3 层(命名模式)的设计

当包名不在表里、精确名也不命中时,用**函数名 + 参数位置**的弱启发式兜底:

- 函数名正则:`^(load|read|open|save|write|dump|exec|run|eval|get|post|delete|remove|unlink|rmdir|fetch|download|upload)`
  (前缀匹配,`load_workbook`、`read_excel`、`fetch_url` 都能命中);
- 参数位置启发式:第 1 个参数是 `str` 类型名(或参数名含 `path`/`file`/`url`/`cmd`/`command`);
- 置信度:**Low**,绝不单独出报告,必须由 fusion 的「多线印证」或 agent 确认后才提升。

**这一层解决的是「未来出现一个我们完全没听说过的库」的场景**——它不会精确命中,但会把
「可疑调用点」喂给 agent 和 fusion,而不是像现在这样直接漏掉。

#### 5.1.3 置信度如何流入 fusion

三层识别产出不同 `confidence` 的 `SinkFact`,fusion 的 `require_confirmed_by` 和权重
(见 `config.rs` 的 fusion 段:`rule_weight=3` / `taint_weight=2` / `codeql_weight=4` /
`agent_weight=1`)天然能消费:

- 第 1 层(精确名)→ 高置信,单线即可报告;
- 第 2 层(包名)→ 中置信,需另一条线印证;
- 第 3 层(命名模式)→ 低置信,**仅作 agent 的候选线索**,不独立报告。

### 5.2 抓手② sink 目录数据化(models-as-data)

**核心思想:** 把 `SINK_RULES` 从 Rust 硬编码,改成一份可扩展的 YAML/TOML 数据文件。
这就是把 CodeQL 的 MaD(L3)做法搬到本项目来。

#### 5.2.1 为什么要数据化

现在 `sinks.rs` 里加一个 sink 要改 Rust 代码、重新编译、重新发布。这带来两个后果:

1. **补覆盖 = 改代码**,门槛高,用户 / 客户无法自己加;
2. **sink 清单和代码耦合**,无法做「运行期加载用户自定义 sink」。

数据化之后,「补覆盖 = 加一行 YAML」,和 CodeQL 的 MaD 一致,而且:

- 用户可以针对**自己的私有库**写模型;
- 可以按语言 / 按目标拆分 sink 目录文件(而非一份巨型 `SINK_RULES`);
- agent 反馈回路(5.3)可以**直接写这个 YAML**,不需要改代码。

#### 5.2.2 目标 schema(示例)

```yaml
# sinks/python/openpyxl.yaml  —— 一个库一个文件,可增量追加
version: 1
language: python
sinks:
  - name: openpyxl.load_workbook
    category: file_read          # 与 rule/fusion 共享的类别词表
    argument: 0                  # 哪个参数是「用户可控路径」
    severity: medium
    confidence: high
    source: manual               # manual | learned | package
    package: openpyxl            # 供 5.1 第 2 层包名归类使用
  - name: openpyxl.load_workbook
    category: file_write
    argument: 0
    severity: medium
    confidence: medium
    source: manual               # 写模式(取决于 read_only/write_only 参数,降置信)
```

**关键设计:** `category` 必须和 `rules/languages/keywords.toml`、fusion 的类别词表**完全一致**
(这正是 `CODEQL_MASTER_PLAN.md` Part 4 问题 #4 强调的耦合点)。否则 Taint 报的 `file_read`
和 CodeQL 报的 `py/path-injection` 又对不上,融合失效。

#### 5.2.3 加载与合并

- **内建目录**(随二进制发布)+ **用户目录**(从配置 `rule_paths` / 新增 `sink_paths` 加载);
- 运行时合并:用户目录覆盖 / 追加内建目录;
- 保留 `source` 字段(`manual` / `learned` / `package`)用于溯源,报告里能说清「这条 sink 是
  谁加的、为什么可信」。

### 5.3 抓手③ agent 作为通用层 + 反馈回路

**核心思想:** agent 是**唯一能泛化到任意代码**的线;但一次性的 LLM 审计不可靠、不持久。所以
要把它从「一次性审计」升级成「**持续学习者**:每发现一个未知 sink,就把它固化进目录」,
让工具**每扫一次就自动变强一点**,而不是等人类去补 QL 文件。

#### 5.3.1 数据流

```
                 ┌─────────────── 扫描 ───────────────┐
                 │                                     │
   target ──► 确定性线(rule/taint/codeql) 命中已知 sink │
                 │                                     │
                 │    ┌──────────── 未命中的可疑点 ────┐ │
                 ▼    ▼                                │
              agent 线:阅读源码,推理出「未知库函数 X   │
              是文件读 sink,且参数可控 → 路径穿越」     │
                 │                                     │
                 ▼                                     │
         解析 agent 输出,提取「新 sink 候选」           │
        (callee 名 + 类别 + 参数位置 + 置信度)          │
                 │                                     │
                 ├─► 立即作为本次扫描的一条 agent 发现   │
                 │                                     │
                 ▼                                     │
         写入 sink 目录(带 source: learned)            │
         下次扫描时,确定性线就能命中这个新 sink         │
                 └─────────────────────────────────────┘
```

#### 5.3.2 「learned」条目的治理(重要,否则目录被污染)

LLM 可能幻觉,所以「learned」条目不能直接当高置信 sink 用:

1. **低置信入库:** 带 `source: learned`、`confidence: low`,且记录 `learned_from`(哪次扫描、
   哪个 agent、原始证据片段);
2. **需多线印证才提升:** 只有后续扫描里被 fusion 的 `require_confirmed_by` 印证,或被人
   审阅确认后,才升级成 `confidence: high`、`source: manual`;
3. **可回滚:** learned 目录单独存放,可一键清空 / 批量审阅,不污染手写目录。

#### 5.3.3 这一步为什么是关键

回到最初的问题:「换一个目标,是不是又因为 QL 查询包没覆盖而漏报?」有了反馈回路之后,答案是:

> 换一个目标,如果它用了一个**新**的库封装,确定性线仍然会漏——**但 agent 会抓住它,并把这个
> 库函数写进目录**。于是下一个用同一库的目标,确定性线就不会漏了。漏报从「永久性」变成
> 「一次性」。

这就是把「不断补 QL 文件」这个**人力劳动**,改造成「agent 自动补目录」这个**系统机制**的区别。

### 5.4 自进化:冷、温、热三档进化机制

5.3 的反馈回路是「**冷**」进化——学到的东西**下次运行**才生效。本节回答一个更进一步的问题:
能不能**自进化**(无人参与、自动补字典),甚至**「热」进化**(本次运行内就生效)?

**直接回答:** 能自进化,也能「本次运行内就受益」;但「热」有一个工程边界,务实形态是
「**温**」进化。

#### 5.4.1 三档进化速度

| 档 | 生效时机 | 改动量 | 收益 | 依赖 |
|---|---|---|---|---|
| **冷 (cross-run)** | 下次运行 | 小(5.3 已设计) | agent 发现的新 sink 持久化,后续目标受益 | M5a |
| **温 (intra-run,单轮回跑)** | **本次运行内** | 中(需 5.4.2 的关键重构) | agent 本轮发现的新 sink 立刻回灌、重跑全部引擎(含 CodeQL 缓存库重跑),本轮 fusion 就吃到 | M5b |
| **热 (streaming 逐 sink 注入)** | 本次运行内、边跑边注入 | 大 | 比「温」只多省一点 wall-clock,收益边际递减 | 通常不需要 |

**结论:** 用户想要的「不用等下一次运行就能享受进化效果」,**「温」进化就完全能做到**,而且
不需要「热」那种流式复杂度。「热」更多是标签,不是必要工程。

#### 5.4.2 「温」进化的关键:一次事实提取 + 可重跑的 sink 应用

「温」进化之所以便宜,依赖一个通用重构:把每个引擎都拆成「**一次性的事实提取**」与
「**可重跑的模型应用**」两步——

1. **事实提取(fact extraction)**:解析源码,产出 `Sink`/`Call`/`Dataflow` 等 facts。这一步
   **跑一次就缓存**,和 sink 清单无关。
2. **sink 应用(sink matching)**:拿着 sink 清单去 facts 上匹配,再跑数据流。这一步的
   **输入是 sink 清单,输出是命中**。

只要做到「sink 清单是第二步的*输入参数*、而非编译进第一步」,「加一个新 sink」就等于
「用更新后的清单再跑一遍第二步」,成本极低:

- **taint 线**:进程内 BFS,重跑第二步几乎免费 → **温进化友好**;
- **rule 线**:关键词匹配,重跑几乎免费 → **温进化友好**;
- **codeql 线**:数据库在首次建库时**一次生成并缓存**;重跑只需在缓存库上重跑 `analyze`
  (成本远低于重建)。所以 CodeQL 也**参与温进化**——回灌后重跑 `analyze`,用扩展后的 MaD
  模型包再次分析同一份缓存库。

#### 5.4.3 管线顺序改造:2-phase 而非多轮

现状是 agent 最后跑。要让「温」进化成立,管线要改成 2-phase:

```
Phase 1: rule / taint / codeql 用「现有字典」跑一遍(基线)
Phase 2: agent 读源码,推理出「新 sink 候选」+ 置信度
Phase 3: 把通过门控的新 sink 回灌进字典,重跑 rule / taint / codeql
         (codeql 用缓存库重跑 analyze + 扩展 MaD,不重建库)
Phase 4: fusion(此时能看到「rule/taint 靠新 sink 命中」与「agent 发现」的交叉印证)
Phase 5: 把通过门控的新 sink 持久化到 learned 目录(冷进化,给下次运行)
```

为什么是 2-phase 而非多轮迭代?因为 agent 已经**读完了所有源码**,它能说出的新 sink 是
**有限的、一次性的**;重跑第二步只会让「已知新 sink 的数据流更完整」,不会「再发现更新的
sink」。所以**一轮温回跑就收敛了**,多轮迭代收益递减、纯属浪费。

#### 5.4.4 自进化的最大风险:污染 + 门控

温/热进化的风险是:agent 幻觉出一个「假 sink」,立刻回灌 → 本轮 taint 就在这个假 sink 上
产生一批误报。这比冷进化更危险(冷进化至少下轮还有机会被人看到、纠正)。

所以「回灌」必须过一道**门控(gate)**,核心原则:**不信任单一来源,要求「昂贵信号(agent)」
与「便宜信号(5.1 启发式)」互相印证。**

| 新 sink 的信号来源 | 门控判定 | 结果 |
|---|---|---|
| agent 说它是 sink,且 5.1 第 2 层(包名归类)**也**把它归到同一类别 | 双信号一致 | **hot 激活**(本轮直接回灌,高置信) |
| agent 说它是 sink,但包名不在归类表、只有 5.1 第 3 层(命名模式)弱命中 | 单信号 + 弱印证 | **warm 参与**(本轮回灌但标 low,只作 fusion 的弱权重线索) |
| agent 说它是 sink,但 5.1 各层都不支持 | 只有 agent 一家之言 | **cold 入库**(只写 learned 目录,下轮再验证,本轮不回灌) |

> 这里有个优美的闭环:**5.1 的便宜启发式,恰好成了 agent 的「验证器」。** 启发式单独看太粗
> (会误报),agent 单独看太贵太慢(会幻觉);两者互相印证,既能热激活,又能挡住幻觉。

#### 5.4.5 收敛性与上界

- 单轮温回跑必然终止(见 5.4.3);
- learned 目录会**单调增长但有上界**——上界是「你扫描过的所有目标里出现过的 sink 集合」;
- 为防止无限膨胀,需要**去重 + 定期剪枝**:同一 sink 从多个来源(manual / package / learned)
  命中时合并置信度;长期未被任何目标用到的 learned 条目可降权或归档。

#### 5.4.6 「最终非常先进完善的字典」的诚实判断

自进化能做到的是:**字典收敛到「你的扫描语料所覆盖的 sink 全集」**。也就是说:

- 对你**实际会扫的那类 MCP server**(Python/JS/Rust、常用库),字典会越来越全、越来越好用;
- 但它**不是**「全世界所有 Python sink 的完备字典」——一个你从没扫过、agent 也从没见过的
  深奥库,字典里不会有,而且 agent 大概率也还会漏(自进化**继承了 agent 的漏报率**)。

所以自进化**必须**和 5.1 的启发式兜底并存:启发式是「不依赖 agent、但更粗」的第二只眼,它保证
「agent 漏掉的」不至于完全漏掉。**自进化 + 启发式**,才构成完整的通用性。

#### 5.4.7 广义化:字典不只是 sink

「字典」其实包含三类模型,自进化机制对三者**同样适用**:

| 模型 | 是什么 | 自进化的例子 |
|---|---|---|
| **sink** | 危险汇聚点 | agent 发现 `load_workbook` 是文件读 |
| **source** | 用户可控入口 | agent 发现某 MCP 框架用 `server.tool("x", fn)` 注册(而非 `@mcp.tool()`),把这种注册式写进 source 识别 |
| **sanitizer** | 净化函数 | agent 发现 `is_safe_path` 做了 realpath 校验,写进净化函数,后续 taint 在此截断、减少误报 |

真正「先进」的字典,是**三类模型都被自进化持续打磨**,而不仅是一张越来越长的 sink 名单。

---

## 6. 与现有代码 / 文档的对接点

这一节说明本战略落在**哪些文件**上,以及它和两份既有计划的关系。

### 6.1 需要改动 / 新增的代码位置

| 抓手 | 涉及文件 | 动作 |
|---|---|---|
| ① 语义化 sink 推断 | `static_analysis/facts/python/sinks.rs`(及 `facts/rust/sinks.rs`、`facts/js/…`) | 把「精确名匹配」升级为「精确名 + 包名归类 + 命名模式」三层;新增 `infer_sink_by_package()`、`infer_sink_by_name()` |
| ① 置信度分流 | `static_analysis/taint/` 结果模型、`fusion/matcher.rs` | `SinkFact` 增加 `confidence_tier`;fusion 按 tier 决定是否需多线印证 |
| ② sink 目录数据化 | 新增 `sinks/*.yaml`(或复用 `rules/` 目录约定);`static_analysis/facts/*/sinks.rs` 改为「加载 YAML + 内建兜底」 | 把 `SINK_RULES` 迁移成数据;新增加载 / 合并逻辑 |
| ② 配置入口 | `config.rs`(`RuntimeConfig`) | 新增 `sink_paths`(可选),与 `rule_paths` 平行 |
| ③ agent 反馈回路 | `static_analysis/agent/parser.rs`(已有解析 agent 输出)、新增 `sink_learning.rs` | 从 agent 输出提取「新 sink 候选」→ 写 learned 目录 → 下次加载 |
| ③ learned 治理 | 新增 `sinks/learned/`(独立目录) | 低置信入库、可审阅、可回滚 |

### 6.2 与 `CODEQL_MASTER_PLAN.md` 的关系(战略 vs 战术)

`CODEQL_MASTER_PLAN.md` 是一份**优秀的战术文档**,但它隐含的假设是「把 CodeQL 做全 = 多写
查询」,Part 6 的查询矩阵本质上还是在**枚举 sink / 攻击面**。本战略文档要补的一层是:

- **战术上**:按 `CODEQL_MASTER_PLAN.md` 把 source/sink/sanitizer 三件套做对、补类别对齐
  (Part 4 问题 #1–#10)——这些都对,继续做;
- **战略上**:不要把所有希望押在「写完查询矩阵」上。查询矩阵是**有界的**(就那 9 类),写完了
  还有「每个库的 L3 模型」这个**无界**问题。所以 CodeQL 的定位应是「高精度第二意见」,而通用性
  由 5.1 的语义化推断(它也同时喂给 Taint 线)和 5.3 的 agent 反馈回路承担。

**一句话:把 CodeQL 从「主力召回」降级为「高精度印证」,把召回主力让给「语义化 sink 推断 +
agent」。** 这样 CodeQL 补模型的压力就小了——它漏的,别的线会兜住。

### 6.3 与 `IMPROVEMENT_PLAN.md` 的关系

`IMPROVEMENT_PLAN.md` 里 Task 3(rule 线 import 别名解析)、Task 8(sink reason 按库分级)
其实是本战略 5.1「语义化识别」的**局部特例**——它们在 Rust 线上实现了「别名解析」和
「按库分级」。本战略是它们的**推广**:不只做 Rust、不只做别名,而是把「名字清单 → 语义识别」
这条原则贯彻到所有语言、所有 sink。

---

## 7. 落地顺序与里程碑

按「先用最小的改动把召回救活,再逐步升级通用性」排序:

| 里程碑 | 内容 | 对应抓手 | 工作量 | 交付判据 |
|---|---|---|---|---|
| **M1** | 补 `load_workbook`/`read_excel`/`to_excel` 等文件 sink(一次性) | —(救火) | 极小 | excel-mcp-server 的 Taint 线从 0 → ~25 条 |
| **M2** | 呈现 CodeQL diagnostics(失败不再静默) | —(透明化) | 小 | `CodeQL Results: 0` 变得可信,有 diagnostic 轨迹 |
| **M3** | sink 目录数据化:`SINK_RULES` → YAML,加 `sink_paths` 配置 | ② | 中 | 加 sink 无需改 Rust 代码;用户可自定义 sink |
| **M4** | 语义化 sink 推断:精确名 + 包名归类 + 命名模式三层 | ① | 中 | 未建模的库(如 `openpyxl`)靠 `import` 归类自动命中 |
| **M5a** | agent 反馈回路 + learned 目录治理(冷进化) | ③ | 大 | agent 发现的新 sink 自动入库,下次扫描确定性线命中 |
| **M5b** | 温进化:事实提取缓存 + 单轮回灌 + fusion 后置 + 门控 | ③ | 中 | 本轮内 agent 发现的新 sink 立刻回灌,本轮 fusion 即受益 |

**依赖关系:** M3 是 M4/M5a/M5b 的地基(sink 必须是数据才能被推断结果写入 / 被 agent 回填);
M4 和 M5a/M5b 可以并行;M1/M2 独立、可立即做。

> **建议起点:** M1 + M2 立刻做(改动小、立竿见影,见 `EXCEL_SCAN_DIAGNOSIS.md` 的 P1/P2);
> 然后 M3 → M4 → M5a → M5b 逐步升级。M3 完成后,「补覆盖」就从「改 Rust 代码」变成「加一行 YAML」,
> 这是通用性工程的第一个质变点。

---

## 8. 预期效果与仍然存在的局限

### 8.1 达成 M1–M5 之后的预期

| 场景 | 现在的表现 | M1–M5 之后的表现 |
|---|---|---|
| 已知库(openpyxl / pandas / requests…) | 漏报(不在清单) | 包名归类自动命中(第 2 层) |
| 见过一次的库 | 永久漏报 | agent 发现 → 温进化本轮回灌命中,或冷进化下次命中 |
| 完全未知、命名古怪的库 | 永久漏报 | 命名模式(第 3 层)给低置信候选,喂给 agent 兜底 |
| 换一个新目标 | 大面积漏报,工具「没用」 | 漏报收敛到「个别深奥库」,且由 agent 兜底 |

### 8.2 诚实地说:仍然存在的局限

必须说清,避免过度承诺:

1. **agent 线仍有概率性。** 它是通用性的来源,但 LLM 会漏、会幻觉。反馈回路靠「低置信入库 +
   多线印证」缓解,但无法根除。
2. **source-only 的硬天花板仍在。** 第三方库内部是黑盒,引擎无法穿透;我们只能「推断」库的
   语义(包名 / 命名),推断可能错。
3. **「语义识别」永远到不了 100% 召回。** 这是所有静态分析的本质,连 CodeQL 官方也承认
   (L3 模型永远在追库的更新)。工程目标不是 100%,而是「**每单位维护成本下的最大召回 + 对
   漏报的透明呈现**」。
4. **融合仍可能错。** 语义推断的低置信候选如果融合阈值没调好,可能制造新误报。M4 落地时
   需要配套「误报率回归测试」。
5. **自进化可能污染字典。** 温/热回灌若门控不严,agent 幻觉会固化进 learned 目录并持续误报。
   需 5.4.4 的门控 + 5.4.5 的剪枝(见 5.4 节)。

**所以「自动化工具就没用处」这个担忧,正确的回应不是「我们做到不误不漏」,而是:**
把「漏报是永久的、静默的」改造成「漏报是**一次性的**(agent 会记住)、**可见的**(diagnostics
透明化)」。这才是通用性工程能兑现的、诚实的承诺。

---

## 9. 结论

回到最初的问题:

> CodeQL 和 Taint 线没有通用性,补完这次换一个目标还是漏,这个自动化工具是不是没用了?
> CodeQL 解决这个问题的方法就是不断补 QL 文件吗?

**分三层回答:**

1. **「不断补 QL 文件」是最笨的那条路,但不是唯一的路。** CodeQL 真正的通用性在 L1 引擎 +
   L2 语义类,「补」的只是 L3 模型数据——而且应做成 MaD 数据,不是散落查询。
2. **通用性的根本解是「把确定性引擎从名字清单升级成语义识别」**(抓手①②),配合
   「agent 作为通用层 + 反馈回路」(抓手③)。前者让网一次性撒大,后者让网**越用越大**。
3. **「完全通用」是不存在的,但「越用越通用」是可达的。** 把漏报从「永久 + 静默」改造成
   「一次性 + 可见」,就是本工具通用性工程的终点目标。

**一句话落地方向:** 先 M1/M2 救火,再 M3 把 sink 数据化(第一个质变点),然后 M4 语义推断、
M5 agent 反馈回路。三个抓手全部落地后,「换一个目标照样大面积漏报」会收敛成「个别深奥库
漏一次,agent 记住,下次不再漏」。

---

*本文档是「分析线通用性」这一战略的唯一事实来源;具体任务拆解见 `CODEQL_MASTER_PLAN.md`
(CodeQL 战术)和 `IMPROVEMENT_PLAN.md`(Rust 线战术),单次漏报根因见
`EXCEL_SCAN_DIAGNOSIS.md`。*
