# 新一代架构:模型驱动 · 双引擎 · 自进化

> **本文定位**:这是 mcp-sec-audit 静态分析子系统的**新架构规格书**——回答「管线该如何重构」,
> 而不是「为什么」(为什么见 `GENERALITY_STRATEGY.md`)。它把四条分析线从「各跑各的、按名字
> 穷举」重构成「**一个共享的、会进化的模型目录,驱动两个深度引擎(CodeQL + 内建 Taint),
> 由一个语义推理引擎(agent)不断补充与验证**」的五阶段管线。
>
> **设计目标(你的原则)**:充分发挥 CodeQL 与 agent 的强大能力,在扫描一个**陌生的 MCP server
> 仓库**时,尽可能多地找到源码级漏洞。
>
> **相关文档**:`GENERALITY_STRATEGY.md`(战略/原理)、`CODEQL_MASTER_PLAN.md`(CodeQL 战术)、
> `IMPROVEMENT_PLAN.md`(Rust 线战术)、`EXCEL_SCAN_DIAGNOSIS.md`(单次漏报根因)。

**日期:** 2026-08-20

---

## 目录

- [1. 为什么需要重构](#1-为什么需要重构)
- [2. 架构总览](#2-架构总览)
- [3. 设计原则](#3-设计原则)
- [4. 新管线:五阶段](#4-新管线五阶段)
  - [阶段一 侦察](#阶段一--侦察-recon)
  - [阶段二 建模](#阶段二--建模-model-assembly)
  - [阶段三 深挖](#阶段三--深挖-deep-analysis)
  - [阶段四 语义验证](#阶段四--语义验证-agent)
  - [阶段五 进化与融合](#阶段五--进化与融合-evolution--fusion)
- [5. 核心组件规格](#5-核心组件规格)
  - [5.1 模型目录(单一事实来源)](#51-模型目录单一事实来源)
  - [5.2 语义推断引擎](#52-语义推断引擎)
  - [5.3 双引擎:CodeQL 与内建 Taint](#53-双引擎codeql-与内建-taint)
  - [5.4 agent 语义推理层](#54-agent-语义推理层)
  - [5.5 门控与自进化](#55-门控与自进化)
  - [5.6 融合与置信度分级](#56-融合与置信度分级)
- [6. 端到端数据流](#6-端到端数据流)
- [7. 与现有代码的映射](#7-与现有代码的映射)
- [8. 落地路径与里程碑](#8-落地路径与里程碑)
- [9. 验收标准(陌生仓库上的召回)](#9-验收标准陌生仓库上的召回)
- [10. 结论](#10-结论)

---

## 1. 为什么需要重构

当前管线是一条**线性的、彼此无交流**的流水线:

```
discover → rule → taint → codeql → agent → fusion
```

它的三个结构性问题,决定了对陌生仓库必然大面积漏报(详见 `GENERALITY_STRATEGY.md`):

| # | 结构性问题 | 后果 |
|---|---|---|
| 1 | 四条线各自维护**自己的**「危险名字清单」,互不共享 | 同一个 `load_workbook`,Taint 不认识、CodeQL 不认识、只有 agent 认识;且补一次要改多处 |
| 2 | 管线**一次性、无反馈**:agent 最后跑,它发现的新知识无法反哺前面的线 | 漏报是「永久性」的,本轮发现、下轮才(可能)生效 |
| 3 | CodeQL 只跑「标准套件里已建模的部分」,agent 只做「一次性扫描」 | 两个最强技术都没被用满:CodeQL 的深度数据流被模型覆盖拖累,agent 的泛化能力没有被固化 |
| 4 | 各线在做什么、为何得出该结论完全不可见 | 结果不可信、「0 结果」无法解释、工具自身无法调试 |

**重构的实质**:把「四条线 + 各自清单」改成「**一个共享模型目录 + 两个深度引擎 + 一个会进化
的语义推理引擎 + 一套贯穿全程的可观测日志**」,并让管线从「线性一次跑」变成「**建模 → 深挖 →
验证 → 回灌**」的闭环。

---

## 2. 架构总览

```
                         ┌───────────────────────────────────────────┐
                         │           模型目录 (Model Catalog)          │
                         │  sink / source / sanitizer 三类模型        │
                         │  manual + package + learned 三种来源        │
                         │  编译为:内建规则 + CodeQL MaD 模型包        │
                         └──────────────┬────────────────────────────┘
                                        │ 读取 & 写回(进化)
        ┌───────────────────────────────┴───────────────────────────────┐
        │                                                                 │
   ┌────▼─────┐   ┌────▼─────┐   ┌────▼──────────┐   ┌────▼──────────┐   ┌────▼─────────┐
   │ ① 侦察    │   │ ② 建模    │   │ ③ 深挖         │   │ ④ 语义验证     │   │ ⑤ 进化与融合  │
   │ Recon    │──►│ Model    │──►│ Deep Analysis │──►│ Agent         │──►│ Evolution &  │
   │ rule 快扫 │   │ Assembly │   │ CodeQL + Taint│   │ 验证/发现/推理 │   │ Fusion       │
   │ 包清单    │   │ 语义推断  │   │  双引擎并行    │   │               │   │ 门控+回灌+持久化│
   └──────────┘   └──────────┘   └───────────────┘   └───────────────┘   └──────────────┘
        ▲                                                                        │
        └──────────────────── 温回灌(本轮生效)/ 冷持久化(下轮生效) ────────────────┘
```

**一句话概括:** 不再「四条线各跑各的」,而是「**一份会进化的模型目录,驱动两个深度引擎,由一个
语义推理引擎不断补充与验证**」。

---

## 3. 设计原则

由你的目标(陌生仓库 + 最大化漏报召回)直接推出四条原则:

### 原则 1:把 CodeQL 用到极致(它是精度与深度的金标准)

CodeQL 的价值在**深度**——字段敏感、流敏感、上下文敏感、跨函数跨文件、自带净化函数模型、
带完整 `codeFlows` 路径证据。要「用满」它,意味着:

- **跑全**:不只跑 `codeql/python-queries` 一个套件,而是 `codeql/python-queries` +
  `codeql/python-security-and-quality` + `codeql/javascript-queries` 等全部标准安全套件;
- **补全**:写满 MCP 攻击面的自定义查询矩阵(命令注入 / 代码执行 / 文件读写 / SSRF / SQL /
  反序列化 / 路径穿越 / 模板注入 / prompt 注入 / 资源外带,见 `CODEQL_MASTER_PLAN.md` Part 6);
- **喂模型**:让 CodeQL 能追踪到第三方库封装——把模型目录**编译成 CodeQL MaD 模型包**,使
  `load_workbook` 这类函数被建模为文件读 sink(见 5.1 / 5.3);
- **吃证据**:用 CodeQL 的 `codeFlows`(完整污点路径)给 finding 提供最高可信度的证据。

**CodeQL 的弱点是模型覆盖,而不是能力。** 重构的任务是把它的模型覆盖缺口,用「语义推断 + agent」
补上,而不是把 CodeQL 降级。

### 原则 2:把 agent 用到极致(它是泛化与语义的唯一来源)

agent 是唯一「不靠清单、靠推理」的引擎。要「用满」它,意味着把它的角色从「第五个扫描器」升级成
**三个角色**:

1. **发现者(discover)**:从陌生源码里推理出「哪些库函数是危险 sink / 入口 source / 净化
   sanitizer」——这是其他引擎做不到的泛化;
2. **验证者(verifier)**:对深挖引擎的候选 finding 做「证伪」——它有全局语义,能看出「这个
   参数其实在上游被校验了」这类假阳性;
3. **语义审计者(reasoner)**:抓数据流永远抓不到的语义漏洞(工具投毒、能力过曝、鉴权绕过、
   prompt 注入、描述与实现不符)。

### 原则 3:一份模型目录,所有引擎共用(消除「各维护各的清单」)

sink / source / sanitizer 三种「模型」是**单一事实来源**,统一存放在数据化的模型目录里,并
**编译成两种形态**:

- **内建规则**(给 rule / 内建 taint 用);
- **CodeQL MaD 模型包**(给 CodeQL 用)。

任何一处新增模型,两条引擎同时受益。这就是「充分发挥 CodeQL + agent」和「消除漏报」的结合点。

### 原则 4:闭环进化(漏报从「永久」变「一次性」)

管线必须有**反馈回路**:agent 发现的新模型 → 门控 → 回灌 → 本轮(温)或下轮(冷)生效。
陌生仓库的第一个目标会漏一些,但**它漏掉的东西会被记住**,第二个目标就少漏一点。

### 原则 5:可观测性——日志是重构的关键

一套会自进化、双引擎并行的管线,**只有每一步都可观测才可信**。日志不是事后补的调试工具,
而是与模型目录、双引擎同级的**一等公民**:

- **可解释**:「0 结果」永远伴随原因(没入口?没模型?引擎跳过?),绝不再静默;
- **可审计**:自进化回填的每一条模型,都能回溯到「哪次扫描、哪条日志、哪个证据」;
- **可调试**:漏报时,日志直接指出是「模型缺口 / 引擎缺口 / 解析缺口」;
- **可配置**:力度由 `[logging]` 配置控制,默认 info,排障时 trace。

具体见 5.7。

---

## 4. 新管线:五阶段

下面逐阶段说明。关键变化是:**阶段②「建模」被提升为一等公民**,它把「这个目标导入了哪些库」
翻译成「这个目标该用哪些模型」,从而让后面所有深挖都跑在**为目标定制的模型集**上,而非一份
全局通用清单。

### 阶段① 侦察 (Recon)

**目标:** 秒级完成,产出「这个仓库长什么样」的三样东西,供后续所有阶段使用。

| 产出 | 内容 | 用途 |
|---|---|---|
| **可疑点地图** | rule 线(关键词/正则)扫出的候选调用点 + 锚点 | 给 agent 和深挖引擎当「优先看哪里」的线索;它本身不产出最终结论 |
| **包清单 (import inventory)** | 解析 import/use/require,列出用到的所有库 | 喂给阶段②语义推断,判断哪些库是危险类别 |
| **入口清单** | 识别 MCP 入口(装饰器式 `@mcp.tool()` + 注册式 `server.tool("x", fn)` + 各种框架变体) | 作为 taint/CodeQL 的 source;也是 agent 的重点阅读范围 |

**改动:** 现状 rule 线已经能做「可疑点地图」的一部分;新增「包清单提取」和「入口识别」两个
轻量解析器(可用现有 `facts/` 的 import 解析 + `CODEQL_MASTER_PLAN.md` 阶段 1 的注册式 source
识别思路)。

### 阶段② 建模 (Model Assembly)

**目标:** 产出「**目标专属模型集**」——比全局目录更全,因为它针对这个目标实际导入的库做了
语义推断。

```
全局模型目录(manual + learned)
        │
        │  合并
        ▼
┌─────────────────────────────┐
│ 语义推断(见 5.2)            │
│  · 包名归类:  import openpyxl │
│    → 其 load*/save* 是文件读写│
│  · 命名模式:  load_*/read_*   │
│    + 参数含 path/url/cmd      │
└─────────────┬───────────────┘
              │
              ▼
   目标专属模型集(target-specific model set)
   = 全局目录 ∪ 语义推断出的候选模型(带置信度)
              │
     编译成两种形态(见 5.1):
     ├─► 内建规则(rule/taint 用)
     └─► CodeQL MaD 模型包(codeql 用)
```

**这是重构后最重要的新增阶段。** 它让「陌生的 `openpyxl`」在阶段③就被建模为文件读写,
而不是像现在这样等到 agent(阶段④)才发现、下轮(阶段⑤冷)才生效。

### 阶段③ 深挖 (Deep Analysis)

**目标:** 用阶段②产出的模型集,跑两个深度数据流引擎,**并行**:

| 引擎 | 干什么 | 产出 | 支持语言 |
|---|---|---|---|
| **CodeQL** | 建库 → 跑全部标准套件 + 自定义 MCP 查询 + 目标专属 MaD 模型包 | 高精度发现 + `codeFlows` 完整污点路径 | python / js / ts |
| **内建 Taint** | 用目标专属模型集跑 forward/backward 污点 | 发现 + 内建 dataflow 路径 | 全语言(含 rust) |

**二者关系(为什么是双引擎):**

- CodeQL **深但覆盖窄**:字段/流/上下文敏感、自带净化模型、路径证据强,但只支持 python/js/ts,
  且受模型覆盖限制;
- 内建 Taint **浅但覆盖广**:支持所有语言、永远可用(CodeQL 没装 / 不支持 Rust 时兜底),
  重跑便宜(可温回灌)。

两者并行,互为补充;对同一 sink,双引擎都命中 = 最高可信度。

### 阶段④ 语义验证 (Agent)

**目标:** agent 扮演三角色(见原则 2),产出**两类结果**:

```
agent 输入 = 阶段①的可疑点地图 + 阶段②的模型集 + 阶段③的候选 finding
              │
              ▼
        ┌─────────────────────────────┐
        │ 角色 1 验证者:证伪候选 finding │──► 剔除假阳性
        │ 角色 2 发现者:提出新模型       │──► 进入门控(阶段⑤)
        │ 角色 3 审计者:语义漏洞         │──► 直接作为 agent finding
        └─────────────────────────────┘
```

**prompt 需要相应升级**(见 5.4):不再只是「找漏洞」,还要「**输出你发现的新 sink/source/
sanitizer 模型,附证据与置信度**」。

### 阶段⑤ 进化与融合 (Evolution & Fusion)

**目标:** 把阶段④的新知识「用起来 + 存起来」,并给出最终结论。

```
agent 提出的新模型
        │
        ▼
   门控(gate,见 5.5):交叉印证,分 hot / warm / cold
        │
        ├─► hot/warm:回灌进模型集,重跑全部引擎 rule + 内建 taint + codeql
        │             (codeql 用缓存库重跑 analyze + 扩展 MaD,不重建库)
        │
        ▼
   fusion:四条线 + 回灌后的结果,按类别 + 行号邻近 + 置信度分级交叉印证
        │
        ├─► 最终 finding(带 supported_by、数据流路径、置信度)
        │
        ▼
   冷持久化:通过门控的新模型写入 learned 目录(下轮生效)
```

**关键约束**:温回灌**重跑全部引擎**——rule / 内建 taint 几乎免费;CodeQL 靠「数据库缓存 +
重跑 analyze」实现(首次建库一次、后续只重跑分析,成本远低于重建库)。这确保 agent 本轮发现的
新模型,**本轮**就在 CodeQL 上生效。

---

## 5. 核心组件规格

### 5.1 模型目录(单一事实来源)

三类模型统一存放在数据文件里,每个模型带 `source`(来源)与 `confidence`(置信度):

```yaml
# models/python/openpyxl.yaml  —— 一个库一个文件
version: 1
language: python
models:
  - kind: sink                 # sink | source | sanitizer
    name: openpyxl.load_workbook
    category: file_read        # 与 rule/fusion 共享的类别词表
    argument: 0                # 危险参数位置
    severity: medium
    confidence: high
    source: manual             # manual | package | learned
    learned_from: null         # learned 来源的溯源(哪次扫描/哪个 agent/证据)
  - kind: source
    name: mcp_registration     # 识别 server.tool("x", fn) 注册式入口
    pattern: "server.tool"
    category: entrypoint
    confidence: high
    source: manual
  - kind: sanitizer
    name: is_safe_path         # 做了 realpath 校验的净化函数
    category: path_traversal
    confidence: medium
    source: learned
    learned_from: "scan-20260820/excel/agent#3"
```

**编译为两种形态:**

1. **内建规则**:给 rule / 内建 taint 加载;
2. **CodeQL MaD 模型包**:由 `sink` 模型生成 MaD YAML(见 `GENERALITY_STRATEGY.md` 2.1.3),
   用 `--model-packs` 或自定义扩展喂给 CodeQL,使标准数据流能到达第三方封装。

**目录结构:**

```
models/
├── python/
│   ├── openpyxl.yaml
│   ├── subprocess.yaml
│   └── ...
├── javascript/
├── rust/
└── learned/          # agent 回填的模型,单独存放,可审阅/回滚
```

### 5.2 语义推断引擎

在阶段②,把「包清单」翻译成「候选模型」。三层识别、置信度递减(详见 `GENERALITY_STRATEGY.md`
5.1):

| 层 | 机制 | 置信度 | 例子 |
|---|---|---|---|
| 1 精确名 | 模型目录里已有的精确条目 | high | `subprocess.run` |
| 2 包名归类 | `import openpyxl` → 该库 `load*`/`save*` 是文件读写 | medium | `load_workbook` |
| 3 命名模式 | 函数名 `^(load\|read\|save\|exec\|run\|fetch\|...)` + 参数含 `path/url/cmd` | low | 任意 `load_x(path)` |

**关键:** 语义推断的产物带 `source: package`,与 `manual` / `learned` 区分;第 3 层的 low 候选
**不独立报告**,只作 agent 的线索和门控的印证信号。

### 5.3 双引擎:CodeQL 与内建 Taint

**CodeQL 的「用满」清单**(对应 `CODEQL_MASTER_PLAN.md` 各阶段):

1. **建库 + 全量套件**:`codeql/python-queries`、`codeql/python-security-and-quality`、
   `codeql/javascript-queries` 全部跑,不挑子集;
2. **自定义 MCP 查询矩阵**:9 类攻击面 × 2 语言(python/js),每条查询用标准
   `TaintTracking` 骨架,定义 source(装饰器 + 注册式)/ sink / sanitizer;
3. **MaD 模型扩展**:阶段②产出的 `sink` 模型编译成 MaD,让标准 `py/path-injection`、
   `py/command-injection` 等查询也能命中第三方封装;
4. **路径证据**:`parser.rs` 解析 `codeFlows`,把完整污点路径写进 finding 的 `dataflow_path`;
5. **诊断透明**:`pipeline.rs` 不再丢弃 `diagnostics` / `raw_sarif`,失败/跳过显式呈现;
6. **数据库缓存 + 温重跑**:数据库建一次并缓存;agent 回灌新模型后,用扩展 MaD 在缓存库上
   重跑 `analyze`,让 CodeQL **本轮**就吃到新模型(不重建库)。

**内建 Taint 的定位:** 全语言兜底(CodeQL 不支持的语言如 Rust 也由它覆盖)。它是 CodeQL 的
「浅但永远可用」的搭档,不是替代品。

### 5.4 agent 语义推理层

agent 的 prompt 从「找漏洞」升级为「**审计 + 建模**」三任务(见 `agent/prompt.rs` 现有模板,
需扩展):

1. **验证**:对阶段③的候选 finding 给出「confirmed / refuted / uncertain」,附理由;
2. **建模**:输出发现的新模型,结构化字段 = `{ kind, name, category, argument, confidence,
   evidence_snippets }`;
3. **审计**:输出数据流抓不到的语义漏洞(工具投毒、能力过曝、鉴权绕过、prompt 注入等)。

**解析**:`agent/parser.rs` 扩展,从 agent 输出里同时提取 `findings` 和 `model_candidates`。

### 5.5 门控与自进化

温回灌的风险是 agent 幻觉 → 假模型 → 本轮误报。门控原则(详见 `GENERALITY_STRATEGY.md`
5.4.4):**不信任单一来源,要求「昂贵信号(agent)」与「便宜信号(语义推断)」互相印证。**

| agent 提出新 sink 的信号 | 门控判定 | 结果 |
|---|---|---|
| agent 说它是 sink,且包名归类(第 2 层)也归到同一类别 | 双信号一致 | **hot**:本轮回灌、高置信 |
| agent 说它是 sink,只有命名模式(第 3 层)弱命中 | 单信号 + 弱印证 | **warm**:本轮回灌但 low,仅作 fusion 弱权重 |
| agent 说它是 sink,但语义推断各层都不支持 | 只有 agent 一家之言 | **cold**:只写 learned,下轮再验证,本轮不回灌 |

**自进化三档**(详见 `GENERALITY_STRATEGY.md` 5.4):

- **冷**:新模型持久化 → 下轮生效;
- **温**:新模型回灌 → 重跑全部引擎(rule/taint/codeql,后者用缓存库)→ 本轮 fusion 即受益;
- **热**:流式逐 sink 注入 —— 收益边际递减,一般不需要。

### 5.6 融合与置信度分级

fusion 从「行号邻近 + 类别对齐」升级为「**置信度分级 + 多线印证**」:

| 置信度层级 | 条件 | 报告呈现 |
|---|---|---|
| **confirmed** | 两条深度引擎(CodeQL + Taint)命中,或一条深度引擎 + agent 确认 | 最高,直接给出 |
| **probable** | 一条深度引擎命中,无反驳 | 给出,标 medium |
| **suspicious** | 仅语义推断(第 2/3 层)或仅 agent 命中 | 列出但标 low,提示需人工复核 |

需要**先修一个前置 bug**(见 `IMPROVEMENT_PLAN.md` P0-1):fusion 现在按「整串路径精确比较」,
必须改成 **basename 归一化 + 类别对齐**,否则不同线对同一漏洞报的路径不一致,永远融合不起来。

### 5.7 日志与可观测性(重构的关键)

**为什么是关键:** 一套「会自进化、双引擎并行」的管线,只有每一步都可观测才可信。日志不是事后
补的调试工具,而是与模型目录、双引擎**同级的一等公民**——它是整个重构里最基础、最该先做的部分
(见里程碑 R0)。

**技术选型:** Rust `tracing`(结构化、分级、span)+ `tracing-subscriber`(终端渲染)。

**配置(`[logging]`):**

```toml
[logging]
level = "info"              # trace | debug | info | warn | error
format = "compact"          # full | compact | pretty | json
ansi = true                 # 终端彩色
show_timestamps = true
show_progress = true        # 五阶段进度 + 每文件进度
log_file = null             # 可选,如 "logs/audit.log"

# 按组件细调力度(默认继承 [logging].level)
[logging.scopes]
pipeline = "info"
rule = "debug"
taint = "debug"
codeql = "trace"            # 记录 codeql 子进程完整命令 + 耗时
agent = "debug"
fusion = "debug"
learning = "trace"          # 记录每条门控判定与模型回灌
```

**每阶段的关键日志:**

| 阶段 | 关键日志 |
|---|---|
| ① 侦察 | 发现文件数、按语言分布、包清单(导入了哪些库)、入口点数量、rule 快扫命中数 + 耗时 |
| ② 建模 | 每条语义推断决策(如「`openpyxl.load_workbook` → `file_read`(包名层, medium)」)、模型集大小(推断前/后) |
| ③ 深挖 | CodeQL:完整 `database create`/`analyze` 命令、模块数、逐查询结果数、耗时;Taint:source/sink 数、逐 sink 命中路径数、追踪深度 |
| ④ agent | prompt 字节数/文件数、provider 命令、超时、解析结果(findings + model_candidates 计数) |
| ⑤ 进化 | 每条门控判定(「hot/warm/cold:`X` 因为 …」)、回灌触发、重跑触发、fusion 分组数、learned 目录写入 |

**终端体验:**

- 阶段级进度 + 每阶段结束的计数摘要(如「[③ 深挖] CodeQL 命中 12, Taint 命中 34, 耗时 41s」);
- 任何「跳过 / 丢弃 / 0 结果」都显式打一条带原因的日志(如「CodeQL skipped: 无支持语言」);
- 排障时 `level = "trace"` + `codeql = "trace"`,能看到引擎原始命令与每步判定。

**四条铁律:**

1. **绝不静默**:任何「0 结果 / 跳过 / 丢弃」必须伴随原因;
2. **决策必留痕**:每条语义推断、门控判定、模型回灌都有 trace 日志 + 溯源;
3. **计数必上报**:每阶段把「处理多少、命中多少、耗时多少」写成结构化字段;
4. **可追溯自进化**:learned 目录的每一条模型,都能从日志回溯到「哪次扫描、哪个证据」。

---

## 6. 端到端数据流

```
目标仓库
   │
   ▼
[① 侦察] rule 快扫 ──► 可疑点地图
          import 解析 ──► 包清单 ──────────────┐
          入口识别 ──► 入口清单                  │
   │                                            │
   ▼                                            │
[② 建模] 全局模型目录 + 语义推断(包清单) ◄────────┘
   │       → 目标专属模型集
   │       → 编译为 内建规则 + CodeQL MaD
   │
   ▼
[③ 深挖] ┌─ CodeQL:全量套件 + MCP 查询 + MaD ──► 高精度 finding + codeFlows
          └─ 内建 Taint:目标模型集前/后向 ──────► finding + dataflow
   │
   ▼
[④ agent] 验证候选 + 提出新模型 + 语义审计 ──────► 剔除 FP + 新模型候选 + 语义 finding
   │
   ▼
[⑤ 进化] 门控(agent × 语义推断)───────────────► hot/warm 回灌 → 重跑 rule+taint+codeql
   │                                              cold → learned 目录
   ▼
fusion(置信度分级 + 多线印证)─────────────────► 最终报告(带 supported_by / 路径 / 置信度)
```

---

## 7. 与现有代码的映射

| 新架构组件 | 现有代码 | 动作 |
|---|---|---|
| 阶段① 包清单 / 入口识别 | `static_analysis/facts/`(import 解析)+ 新增 | 抽出一个轻量 `recon` 模块 |
| 阶段② 模型目录 | 新增 `models/*.yaml` | 迁移 `facts/*/sinks.rs` 的 `SINK_RULES` 为数据;新增加载/合并 |
| 阶段② 语义推断 | `facts/*/sinks.rs` | 新增 `infer_sink_by_package()` / `infer_sink_by_name()` |
| 阶段② 编译 MaD | 新增 `codeql/models.rs` | 把模型目录编译成 CodeQL MaD 模型包 |
| 阶段③ CodeQL | `static_analysis/codeql/`(`queries.rs`/`provider.rs`/`parser.rs`) | 跑全量套件 + 自定义查询矩阵 + MaD 扩展 + 解析 `codeFlows` + 数据库缓存以支持温重跑 |
| 阶段③ 内建 Taint | `static_analysis/taint/` | 改为「读模型目录」而非硬编码 sink |
| 阶段④ agent | `static_analysis/agent/`(`prompt.rs`/`parser.rs`) | prompt 升级三任务;parser 提取 `model_candidates` |
| 阶段⑤ 门控/回灌 | 新增 `sink_learning.rs` | 门控判定 + learned 目录读写 |
| 阶段⑤ fusion | `static_analysis/fusion/matcher.rs` | basename 归一化 + 类别对齐 + 置信度分级 |
| 管线编排 | `static_analysis/pipeline.rs` | 从线性改成五阶段 + 温回灌循环;保留 diagnostics |
| 日志与可观测性 | `cli/src/main.rs` + 新增 `logging.rs` | 接入 `tracing`/`tracing-subscriber`;`[logging]` 配置;每组件 `span`/`instrument` |

---

## 8. 落地路径与里程碑

按「先把基础打好,再逐级点亮能力」排序(继承 `GENERALITY_STRATEGY.md` 第 7 节并落地到本架构):

| 里程碑 | 内容 | 交付判据 |
|---|---|---|
| **R0** | 日志与可观测性基础:结构化日志 + `[logging]` 配置 + 每阶段/组件日志(贯穿全程) | 终端可见五阶段进度;每条「0」/跳过/门控判定都有 trace 日志 |
| **R1** | 融合前置修复:basename 归一化 + 类别对齐 + CodeQL diagnostics 透明 | `rule+taint+codeql` 能交叉印证;`0` 结果不再静默 |
| **R2** | 模型目录数据化:迁移 `SINK_RULES` → YAML,加 `models/` 加载 | 加模型无需改 Rust;三类模型统一 schema |
| **R3** | 阶段①+②:包清单 + 语义推断(三层识别)→ 目标专属模型集 | 未建模库靠 `import` 归类自动命中 |
| **R4** | 阶段③ CodeQL 用满:全量套件 + MCP 查询矩阵 + MaD 扩展 | CodeQL 命中第三方封装(如 `load_workbook`) |
| **R5** | 阶段④ agent 三角色 + 阶段⑤ 门控 + 温回灌(rule/taint/codeql)+ 冷持久化 | agent 发现的新模型本轮(含 CodeQL 重跑)/下轮生效,且无幻觉污染 |

**依赖关系:** R0 贯穿全程、先于其他;R1 → R2 → R3 → (R4、R5 可并行)→ 全链路验收。

---

## 9. 验收标准(陌生仓库上的召回)

用一个**全新的、未建模的** MCP server 仓库(含第三方库封装 + 多种漏洞)做验收:

1. **召回**:已知漏洞清单 100% 被至少一条线命中;其中第三方库封装型漏洞(如 `load_workbook`)
   靠语义推断或 agent 发现命中,而非靠事先手工补模型;
2. **多线印证**:至少 50% 的 confirmed finding 由两条以上线支撑(`supported_by` 含 2+ 来源);
3. **证据质量**:CodeQL 命中的 finding 带完整 `codeFlows` 路径;内建 taint 命中带 dataflow 路径;
4. **进化生效**:同一仓库连扫两次,第二次比第一次多命中(温/冷进化生效),且 learned 目录有新条目;
5. **无污染**:门控挡住 agent 幻觉——不出现「假 sink 导致的一批误报」;`cargo test` 全绿;
6. **可观测**:`[logging]` 下五阶段进度、每阶段计数、CodeQL 命令与耗时、每条门控判定、每条 learned 回填都能在终端看到;不存在静默的「0 结果」。

---

## 10. 结论

新架构把 mcp-sec-audit 的静态分析从「四条线各扫各的」升级成「**模型驱动 · 双引擎 · 自进化**」:

- **模型驱动**:一份会进化的模型目录(sink/source/sanitizer)是单一事实来源,编译成内建规则 +
  CodeQL MaD,让所有引擎共享同一份知识;
- **双引擎**:CodeQL(深度、精度、路径证据)与内建 Taint(全语言、永远可用、可热更新)并行,
  各自把强项用到极致;
- **自进化**:agent 从「扫描器」升级成「发现者 + 验证者 + 审计者」,它发现的新模型经门控后
  温回灌(本轮生效)与冷持久化(下轮生效),让漏报从「永久」变「一次性」。

**对一个陌生 MCP server 仓库,它的行为是:** 先快速摸清仓库导入了什么、入口在哪;据此装配一份
比全局目录更全的目标专属模型集;再让 CodeQL 和内建 Taint 双引擎并行深挖;然后 agent 验证候选、
发现遗漏、审计语义;最后门控回灌、融合分级、持久化进化。**每一步都在为「多找到一个漏洞」服务,
而漏掉的东西会被记住,下一次少漏一点。**

---

*本文档是新架构的唯一事实来源;战术任务见 `CODEQL_MASTER_PLAN.md`(CodeQL)、`IMPROVEMENT_PLAN.md`
(Rust 线),原理与取舍见 `GENERALITY_STRATEGY.md`。*
