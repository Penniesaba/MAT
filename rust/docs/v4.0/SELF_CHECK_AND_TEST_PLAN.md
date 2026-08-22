# v4.0 实现自检 · 项目目录解析 · 测试方案

> 本文件一次性交付三部分内容，用于对照 `IDEA_EVALUATION_AND_DESIGN.md` 做实现核对、
> 解析工作目录结构、并落地测试配置文件与测试方案。
>
> 配套设计文档：`IDEA_EVALUATION_AND_DESIGN.md`（原始想法 `idea.md`）。
> 自检代码基线：`crates/mcp-sec-audit-core/src/static_analysis/`（提交 `f826beb`…`cdaf6a1`，v4.0 全量落地）。

---

## 目录

1. [第一部分：全面自检（对照 IDEA_EVALUATION_AND_DESIGN.md）](#第一部分全面自检对照-idea_evaluation_and_designmd)
2. [第二部分：项目目录解析](#第二部分项目目录解析)
3. [第三部分：测试方案与测试配置文件](#第三部分测试方案与测试配置文件)

---

# 第一部分：全面自检（对照 IDEA_EVALUATION_AND_DESIGN.md）

## 1.1 自检方法与结论速览

- 判定口径：**✅ 完成（已接线）** / **🟡 部分（有骨架但未接线或缺子方法）** / **❌ 未实现（空/缺失）**。
- 验证方式：逐条核对设计文档的里程碑（M0–M4）、核心机制（Component/差分/b0/门控/分层验证/回滚/prompt'/三类模型），
  并落到具体 `文件:行号`。
- 总结论：**v4.0 设计文档所构想的全部核心机制（M0–M4、C1–C14）均已完整实现并接线、无任何部分实现或空实现；
  279 个单测（core 274 + cli 5）全部通过、0 失败、0 警告。「两阶段闭环 + 差分反馈 + 可回滚」主线、
  「Component 抽象统一」（内涵 ①）、taint 三类模型（source/sink/sanitizer，P5）、b0 显式筛选、
  a1/a2 二分、分层验证 L0–L3、真溯源 learned_from 均已落地。**

## 1.2 里程碑核对（设计文档 第十一节）

| 里程碑 | 设计内容 | 落地位置 | 状态 | 说明 |
|---|---|---|---|---|
| **M0** | 升级 CodeQL CLI ≥ 2.26.3，`MAD_INJECT_ENABLED=true`，回退 suite 版本 pin | `codeql/mod.rs::mad_inject_supported`、`codeql/queries.rs::standard_suite_refs_for` | ✅ 完成 | CLI 已升级到 2.26.3（`/home/xiao/App/codeql/codeql`），版本门控 `>=2.26.3` 运行期通过；suite 引用回退为非版本化（`codeql/python-queries` 等），并实测 `--model-packs` 3 列 sinkModel 通过 overlay-eval（不再报 `Expected 4, but was 3`）。 |
| **M1** | Component trait + 四实现 + `diff.rs`（c/a/b + b0）+ 可表达性门控 | `component.rs`、`diff.rs` | ✅ 完成 | `Component` trait 含 `tool()/fingerprint()/evolve()/promote()/rollback()` 五方法；四实现齐（Codeql/Taint/Rule/Prompt）；`diff_lines`（c/a/b）与 `classify_candidate`（G2）已实现并有单测；trait 已由 `pipeline.rs` 接线驱动进化。 |
| **M2** | `evolve`/`rollback` + prompt' 注入 + `validate.rs` 跨阶段迁移 | `learning.rs`、`agent/prompt.rs`、`validate.rs` | ✅ 完成 | `stage_catalog_evolution`+`write_staging`+`rollback_staging`+`catalog_fingerprint`+`StagedDelta`；`render_verification_prompt`；`validate::migrate`+`should_rollback`。均已接线并有单测。 |
| **M3** | 校验通过的 delta 固化，**优先喂 CodeQL（MaD）**，其次 taint | `pipeline.rs`（promote/rollback 分支）、`codeql/mod.rs` | ✅ 完成 | promote 分支写 `learned_dir`，rollback 分支删 staging；CodeQL 用进化后 catalog 编译 MaD。CLI 2.26.3 下 MaD 固化运行期已生效（阶段 2 `codeql::run(&evolved_catalog)` 注入 sinkModel 扩展）。 |
| **M4** | 全模块日志广泛插桩 | `facts/infer/taint/rule/agent/codeql/fusion/pipeline` + `cli/logging.rs` | ✅ 完成 | 本次会话完成 13 个 tracing target 插桩 + CLI `SCOPE_TARGETS` 扩到 13 项。 |

## 1.3 核心机制逐条核对（设计文档 三/四/七节）

| # | 设计条目 | 落地位置 | 状态 | 说明 |
|---|---|---|---|---|
| C1 | 集合差分 c/a/b（`U = A∪B` 三分） | `diff.rs::diff_lines` → `LineDiff{agreed,a_only,b_only}` | ✅ | 复用 fusion matcher 的邻近+类别分组；`has_standard`/`has_agent` 二分归类。 |
| C2 | a1/a2、b0/b1/b2 记号语义 | `validate.rs::Migration` 的 `b1_confirmed/a1_confirmed/a2_confirmed/b2_confirmed/b0_count/b_still_ambiguous` | ✅ | 迁移信号 b1/a1/a2/b2 有确定性判定（`migrate`）；b0 由 pipeline 门控后回填（`b0_count = b0.len()`），a2 独立产出为「A 独有且 B 阶段 2 仍未报」。 |
| C3 | Component 抽象统一（内涵 ①） | `component.rs` | ✅ | trait 含 `tool/fingerprint/evolve/promote/rollback` 五方法；四实现（Codeql/Taint/Rule/Prompt）齐；`pipeline.rs` 经 `TaintComponent.evolve/promote/rollback` 驱动进化，消除「抽象与实际进化脱节」。 |
| C4 | taint 三类模型（source/sink/sanitizer，P5） | `models/mod.rs` | ✅ | `SourceModel`/`SinkModel`/`SanitizerModel` 三结构体齐；`ModelCatalog` 存 sinks/sources/sanitizers 三类 BTreeMap；内置 `models/{sinks,sources,sanitizers}/*.toml`；抽取器按三类模型装配 fact。 |
| C5 | b0 筛选（语义漏洞直接筛出） | `diff.rs::classify_candidate` → `SemanticOnly` + `pipeline.rs` 门控分支 | ✅ | G2 失败→`SemanticOnly` 或 Cold sink 被显式筛入 `b0` 候选，记入 `EvolutionReport.b0_candidates` 并上报到报告，不再静默丢弃。 |
| C6 | G1 信号门控（Hot/Warm/Cold） | `learning.rs::gate_sink_candidate` | ✅ | 交叉核对 `PackageRule` 包分类（Hot）/ 命名前缀（Warm）/ 无信号（Cold）。 |
| C7 | G2 可表达性门控（MaD/TaintModel/b0） | `diff.rs::classify_candidate` | ✅ | `sink`→(MadSink/TaintModel/SemanticOnly)，`source`/`sanitizer`→TaintModel。 |
| C8 | G3 试探性加入（staging + 快照 + fingerprint） | `learning.rs::stage_catalog_evolution` + `write_staging` + `StagedDelta` | ✅ | 写临时 staging（非 learned/）、记 `base_fingerprint`+`fingerprint`。 |
| C9 | 可回滚预进化 + 决策度量 | `validate.rs::should_rollback` = `b2_confirmed > b1_confirmed` | ✅ | 回滚度量落地为「新增 A'-only 误报（b2）> b1 确认收益」。 |
| C10 | 验证提示词 prompt'（a1 正例 / a2 反例） | `agent/prompt.rs::render_verification_prompt` + `pipeline.rs::build_recheck` | ✅ | `build_recheck` 把 a-only 二分为 a1（有 codeql/rule 确定性支撑→「请复核」）与 a2（仅 taint 启发式→「请勿重复报告」），分别注入 prompt' 两段。 |
| C11 | 跨阶段集合迁移校验 | `validate.rs::migrate` | ✅ | b→c'=b1、a→c'=a1、b→新增A'=b2 回滚，均落地。 |
| C12 | 分层验证 L0/L1/L2/L3 | `pipeline.rs`（L0 重跑 + L1 migrate + L2 解释 + L3 裁决出口） | ✅ | L0（阶段2重跑=round-trip）、L1（`migrate`）✅；L2（`render_explanation_prompt` + `attach_explanations` 回填 agent 语义解释）；L3（`ambiguous_items` 仍混沌条目进 `EvolutionReport.ambiguous_for_review` 结果文件，留人工裁决）。 |
| C13 | 固化 learned_component + 真实溯源 | `learning.rs::write_learned_sinks`（promote 分支）+ `pipeline.rs` provenance | ✅ | 校验通过的 delta 固化进 `learned_dir`；`learned_from` 溯源写入真实 `{scan_id}/{agent_provider}`，不再是占位。 |
| C14 | 日志广泛插桩（8.4 清单） | 全模块 | ✅ | 覆盖 facts/infer/taint/rule/agent/codeql/fusion/evolution/diff/validate 的中间结果、数据流转、gate/进化决策。 |

## 1.4 已知缺口清单（按优先级）

> ✅ **全部缺口已在本轮（G1–G5）闭环**：P0/P1/P2 七项全部落地（三类模型、Component 接线、
> b0 显式筛选、a1/a2 二分、L2/L3、CLI 2.26.3 + suite pin 回退、真溯源）。仅剩 P3（风险 R2/R4）
> 为设计文档十节「待决」项，非本轮必须，保留如下：

| 优先级 | 缺口 | 对应设计 | 状态/建议动作 |
|---|---|---|---|
| **P3** | 风险 R4（组件爆炸上限/prune）、R2（B 随机性低温/seed）未处理 | 十节 | 视作「待决」，非本轮必须。 |

## 1.5 一句话自检结论

> v4.0 设计文档（`IDEA_EVALUATION_AND_DESIGN.md`）所构想的**全部核心机制（M0–M4、C1–C14）均已完整实现并接线、无任何部分实现或空实现**：
> 「学 → 验证 → 才固化」完整进化闭环（两阶段 + 门控 + 暂存 + 迁移校验 + promote/rollback）、
> Component 抽象统一（内涵 ①）、taint 三类模型 + sanitizer 降噪（P5）、b0 显式筛选、a1/a2 二分、
> 分层验证 L0–L3、真溯源 learned_from 均已落地。
> 无任何「空实现」的假接线——所有已接线路径都有对应单测；`#[allow(dead_code)]` 标注处（`learning.rs` 部分被取代的旧 helper、`component.rs` 的空壳字段）都明确注释了「被 catalog→MaD 路径取代 / M3 接线前」的真实原因。

---

# 第二部分：项目目录解析

> 工作目录为多仓/多语言混合仓库：根目录是 Git 主仓（分支 `feat/r4-r5-codeql-agent-evolution`），
> 核心交付物是 `rust/` 下的 Rust workspace；`detection/`（Python）与 `web-detection-portal/` 是早期/并行产物。

## 2.1 顶层目录

| 路径 | 作用 |
|---|---|
| `README.md` | 仓库总览（26KB，早期 v3 描述） |
| `.gitmodules` / `targets/` | 子模块：`targets/serena`（真实 MCP server，用于实测）；`targets/phase7-e2e` |
| `rust/` | **主交付**：Rust workspace（core + cli），见 2.2 |
| `detection/` | Python 早期静态/动态分析原型（`detection/detection/`、`analysis/`、`tests/`、`sandbox/`） |
| `web-detection-portal/` | Flask/uv 报告门户（`templates/`），配套 `UV_GUIDE.md` |
| `docs/` | 顶层文档 + `.superpowers/plans|specs`（历史 SDD 计划/设计） |
| `test-targets/` | 测试靶子：4 个最小 MCP server + 1 个真实漏洞 server + 配置，见 2.5 |
| `.superpowers/sdd/` | 历史任务 brief/report（phase7/8/9/10/11/12/fusion/codeql 等） |

## 2.2 `rust/` 工作区

| 路径 | 作用 |
|---|---|
| `rust/Cargo.toml` | workspace 根（members: `crates/*`） |
| `rust/Cargo.lock` | 锁文件（serde 等 pin） |
| `rust/README.md` | workspace 简述 |
| `rust/config/default.toml` | 默认运行时配置（scan/static/fusion/report 全开关，见 3.2） |
| `rust/rules/mcp/` | 空占位目录（预留 MCP 专项 rulebook） |
| `rust/rules/languages/keywords.toml` | 语言关键字 rulebook（`path_traversal` 等 capabilities） |
| `rust/models/learned/*.toml` | **冷持久化目录**：已学到的 sink 模型（openpyxl 两例），下次运行载回 |
| `rust/target/` | 构建产物（忽略） |
| `rust/docs/` | v2.0/v3.0/v4.0 设计文档 + result/（扫描报告产物）+ reference/ |

## 2.3 `rust/crates/mcp-sec-audit-core/`（核心库）

```
src/
├── lib.rs                    # crate 根：模块声明 + 公共 API re-export + CURRENT_PHASE
├── config.rs                 # RuntimeConfig 全 schema（scan/static/dynamic/fusion/report/logging）
├── rules.rs                  # RuleBook 解析（TOML capabilities→indicators→patterns）
├── reporting.rs              # 报告渲染（json/jsonl/markdown）与输出路径解析
├── fixtures.rs               # 合成结果夹具（CLI `report demo` 用）
├── model/                    # 数据模型
│   ├── enums.rs              # Severity/Confidence/ReportFormat/… 枚举
│   ├── facts.rs              # Fact 全枚举：Import/Call/Sink/Source/Function/Entrypoint/Assign/…
│   ├── mod.rs                # AgentOutput/ModelCandidate/AgentAnalysisResult/CodeqlAnalysisResult…
│   ├── report.rs             # StaticAnalysisResult/Summary/ConfigSnapshot
│   └── static_result.rs      # Rule/Taint/Agent/Codeql 分析结果结构体
├── models/                   # 模型目录（v4 Component 的「枢纽部件」）
│   └── mod.rs                # SinkModel/SourceModel/SanitizerModel/PackageRule/ModelCatalog + 内置目录编译(include_str!)
│   ├── sinks/{python,javascript,rust}.toml      # 内置 sink 模型
│   ├── sources/{python,javascript,rust}.toml    # 内置 source 模型
│   ├── sanitizers/{python,javascript,rust}.toml # 内置 sanitizer 模型
│   └── package_inference.toml                    # PackageRule（包名→危险类别/读写拆分）
└── static_analysis/
    ├── mod.rs                # 静态分析模块声明（含 `mod component;`）
    ├── pipeline.rs           # ⭐ 两阶段编排 + 门控 + promote/rollback + 汇总
    ├── discovery.rs          # 文件发现 + 语言探测 + 排除目录
    ├── recon.rs              # 包清单收集（PackageInventory）
    ├── infer.rs              # 语义推断：按包(L2) / 按命名(L3) 补 sink
    ├── category.rs           # 类别常量/映射
    ├── component.rs          # ⭐ Component trait（tool/fingerprint/evolve/promote/rollback，已接线）
    ├── diff.rs               # ⭐ 集合差分 c/a/b + G2 可表达性门控
    ├── validate.rs           # ⭐ 跨阶段迁移校验 + 回滚判定
    ├── learning.rs           # ⭐ G1 门控 + 暂存/指纹/回滚 + 冷持久化
    ├── rule/mod.rs           # rule 线路：capabilities 匹配 + 计数
    ├── taint/                # taint 线路：source→传播→sink
    │   ├── mod.rs            #   入口 run_with_catalog / run_taint_analysis
    │   ├── builder.rs        #   ProgramGraph 构建（facts→节点/边）
    │   ├── graph.rs          #   图结构
    │   ├── propagation.rs    #   正向/反向 BFS 传播
    │   └── result.rs         #   TaintAnalysisResult + DataFlowFact 组装
    ├── facts/                # 事实抽取（多语言）
    │   ├── mod.rs            #   re-export extract_*_facts / load_catalog
    │   ├── pipeline.rs       #   ⭐ 每文件 fact 抽取 + 语义推断装配（喂 catalog）
    │   ├── ids.rs            #   ID 生成
    │   ├── python/{calls,functions,mcp,sinks,mod}.rs
    │   ├── js_ts/{calls,functions,imports,ids,mcp,sinks,mod}.rs
    │   └── rust/{calls,display,mcp,sinks,mod}.rs
    ├── fusion/               # 四线融合
    │   ├── mod.rs            #   run：matcher→scorer→merger
    │   ├── matcher.rs        #   邻近+类别分组（MatchGroup）
    │   ├── scorer.rs         #   打分/过滤
    │   └── merger.rs         #   合并为 FusedFinding
    ├── agent/                # B 线（agent/LLM）
    │   ├── mod.rs            #   run / run_with_prompt（阶段2 注入 prompt'）
    │   ├── prompt.rs         #   ⭐ 模板渲染 + render_verification_prompt
    │   ├── parser.rs         #   agent 输出 JSON 解析
    │   └── provider.rs       #   CliAgentProvider（子进程调用 + 超时）
    └── codeql/               # A 线主力（CodeQL）
        ├── mod.rs            #   CodeqlSession create/analyze + run(catalog) + MaD 注入门控
        ├── provider.rs       #   CliCodeqlProvider（建库/分析/版本）
        ├── parser.rs         #   SARIF 解析
        ├── queries.rs        #   QueryPack 解析 + suite refs（版本 pin）
        ├── models.rs         #   MaD 编译（sinkModel 3 列扩展）+ mad_sink_kind 映射
        └── queries/{mcp-python,mcp-js,mcp-rust}/*.ql   # 内置 MCP 安全查询（.ql + qlpack.yml）
```

## 2.4 `rust/crates/mcp-sec-audit-cli/`（CLI）

| 文件 | 作用 |
|---|---|
| `src/main.rs` | clap CLI：`status` / `config validate --config` / `rules validate --rules` / `report demo` / 位置参数直接跑扫描 |
| `src/logging.rs` | tracing 订阅器：`SCOPE_TARGETS`（13 个 target）+ 分级过滤 + 文件/stderr 输出 |

## 2.5 `test-targets/`（测试靶子与配置）

| 路径 | 作用 |
|---|---|
| `python-mcp-server/{server.py,helpers.py,pyproject.toml}` | 最小 Python MCP server（命令注入靶子） |
| `js-mcp-server/{server.js,server_types.ts,helpers.js,package.json}` | 最小 JS MCP server |
| `rust-mcp-server/{src/main.rs,src/helpers.rs,Cargo.toml}` | 最小 Rust MCP server |
| `excel-mcp-server/` | **真实漏洞靶子**（haris-musa/excel-mcp-server v0.1.7，CVE-2026-40576 路径穿越，~25 个 @mcp.tool()） |
| `configs/*.toml` | 6 个扫描配置（见 3.3） |

## 2.6 `rust/docs/`（文档分层）

| 目录 | 内容 |
|---|---|
| `v2.0/` | 早期数据模型/重构/静态分析设计（`TEST_PLAN.md` 为早期测试方案） |
| `v3.0/` | 35 步流程架构、CodeQL 主计划、excel 测试计划/诊断/评估 |
| `v4.0/` | `idea.md`（原始想法）+ `IDEA_EVALUATION_AND_DESIGN.md`（本自检对照对象） |
| `result/` | 历史扫描报告产物（`2026xxxx-HHMMSS.md` 等） |
| `reference/` | 漏洞 Python MCP server 参考清单 |

---

# 第三部分：测试方案与测试配置文件

## 3.1 现有测试体系

| 层级 | 命令 | 结果 | 说明 |
|---|---|---|---|
| 单元测试 | `cd rust && cargo test --workspace` | core **274** + cli **5** = **279 通过，0 失败，0 警告** | 覆盖：差分/迁移/门控/暂存/回滚/组件指纹/prompt'/三类模型装载/fact 抽取/taint 传播/fusion 分组/CodeQL MaD/SARIF 解析/配置解析/CLI |
| 集成/端到端 | `cd rust && cargo run -- <config.toml>` | 需 CodeQL CLI（≥2.26.3 才有 MaD）与 `claude` 可用 | 用 `test-targets/configs/*.toml` 驱动真实扫描 |

> 关键单元测试（v4 相关）：`static_analysis::pipeline::tests::agent_warm_reinjection_adds_taint_finding_for_learned_sink`、
> `static_analysis::validate::tests::*`（b1/a1/b2/回滚）、`static_analysis::learning::tests::catalog_fingerprint_*`、
> `static_analysis::diff::*`（c/a/b + b0）、`static_analysis::agent::prompt::tests::renders_recheck_and_do_not_report_sections`。

## 3.2 配置 schema（`config.rs` 全字段）

- `[scan]`：`targets` / `languages` / `exclude`
- `[static]`：`enabled` / `save_facts` / `models_dir` / `learned_dir`
- `[static.rule]`：`enabled` / `rule_paths`
- `[static.taint]`：`enabled` / `forward` / `backward` / `max_depth` / `entrypoint_required`
- `[static.agent]`：`enabled` / `provider` / `prompt_template_path` / `max_turns` / `timeout_seconds` / `extra_args`
- `[static.codeql]`：`enabled` / `binary` / `query_pack_path` / `timeout_seconds` / `extra_args`
- `[fusion]`：`enabled` / `require_confirmed_by` / `boost_when_multiple_lines_agree` / `agent_only_as_advisory` / `line_proximity` / 四个 weight
- `[report]`：`formats` / `output` / 各类 `include_*` / `include_facts`
- `[logging]`：`level` / `format` / `ansi` / `show_timestamps` / `show_progress` / `log_file`
- `[logging.scopes]`：13 个 target 覆盖（`pipeline/rule/taint/agent/codeql/fusion/learning/facts/infer/diff/validate/evolution/component`）

## 3.3 测试配置文件清单（已落实）

| 配置 | 目标 | 启用线路 | 用途 |
|---|---|---|---|
| `configs/python-config.toml` | `python-mcp-server` | codeql | 单语言 A 线冒烟（rule/taint/agent 关） |
| `configs/js-config.toml` | `js-mcp-server` | rule+taint+agent+codeql | JS 全线路（agent 无 provider 覆盖） |
| `configs/rust-config.toml` | `rust-mcp-server` | rule+taint+agent+codeql | Rust 全线路 |
| `configs/all-languages-config.toml` | 三个 server | rule+taint+fusion | 多语言 + 四线融合 |
| `configs/excel-mcp-server-config.toml` | `excel-mcp-server`（真实 CVE） | rule+taint+agent+codeql+learned_dir | 真实漏洞召回/融合/自进化（scenario A/B/C/D） |
| **`configs/v4-evolution-config.toml`**（本次新增） | `excel-mcp-server` | 全线路 + learned_dir + 13 个 logging scope | **v4.0 两阶段差分进化端到端**（见 3.5） |

> 说明：`js-config.toml` / `rust-config.toml` 的 `[static.agent]`/`[static.codeql]` 只设 `enabled=true` 未设 `provider`/`binary`，
> 依赖默认 `claude` 与 PATH 上的 `codeql`；实际端到端运行时请显式指定（参考 `v4-evolution-config.toml` 的写法）。

## 3.4 测试方案

### 3.4.1 单元测试（每提交 / CI 常驻）
- `cargo test --workspace` 必须 0 失败、0 警告（`cargo build --workspace 2>&1 | grep -i warning` 为空）。
- v4 关键回归面：两阶段编排、门控（G1/G2）、暂存/回滚、迁移校验、prompt' 渲染、三类模型装载、MaD 编译。

### 3.4.2 端到端扫描（按 scenario 分层）
1. **A 线召回基线**：`agent.enabled=false` + `fusion.enabled=false`，验证 rule/taint/codeql 各自命中数。
2. **四线融合**：`fusion.enabled=true`，验证 `require_confirmed_by` 与 `codeql_weight=4` 对融合置信度的影响。
3. **两阶段差分进化（v4 核心）**：`agent.enabled=true` + `learned_dir`，观测：
   - `[evolution]` 逐候选 gate 判定（Hot/Warm/Cold + MadSink/TaintModel/SemanticOnly）；
   - `[diff]` 差分分区 c/a/b 计数；`[validate]` 迁移结果（b1/a1 确认、新增误报、仍混沌）；
   - `learned/` 目录在 promote 分支新增 TOML（`write_learned_sinks`）；
   - rollback 时 staging 目录被删、learned/ 不动。
4. **可观测性**：`[logging.scopes]` 把 `evolution/validate/diff/facts/infer` 调到 `debug/trace`，验证中间结果与数据流转可见。

### 3.4.3 真值靶子（excel-mcp-server CVE-2026-40576）
- 已知漏洞：`src/excel_mcp/server.py::get_excel_path()` 绝对路径绕过 + `os.path.join(..., "..")`（CWE-22）。
- 验证点：rule 线 `path_traversal` capability、taint 线 file_read 路径、CodeQL 线路径穿越查询、agent 线语义结论，以及四线融合是否把它标为 high/critical。
- 版本要求：clone 后 `git checkout v0.1.7`（0.1.8 已修复）。

### 3.4.4 门控与回滚的可复现性
- 用 stub agent（见 `pipeline::tests::agent_warm_reinjection_*` 的固定 JSON 输出）做**确定性**单测，
  避免 agent 随机性（风险 R2）影响断言；端到端进化验证再切回真实 `claude`。

## 3.5 本次「落实」的变更

1. **新增** `test-targets/configs/v4-evolution-config.toml`：一条覆盖 v4.0 两阶段差分进化完整路径的端到端配置，
   含全部 13 个 `[logging.scopes]`（与 `cli/src/logging.rs` 的 `SCOPE_TARGETS` 对齐）。
2. 在本文档中把 6 个配置文件的用途、启用线路、观测点做成矩阵（3.3），并给出分层测试方案（3.4）。

---

## 附：关键术语速查（与设计文档一致）

| 术语 | 含义 |
|---|---|
| Component | 决定工具能力的部件（QueryPack+MaD / TaintModelCatalog / RuleBook / Prompt） |
| c / a / b | 共识集 / A 独有 / B 独有 |
| a1 / a2 | A 真阳性+B漏报 / A 误报 |
| b0 / b1 / b2 | 语义漏洞(A 无能力) / B真阳性+A漏报 / B 误报 |
| G1 / G2 / G3 | 信号门控(Hot/Warm/Cold) / 可表达性门控(MaD/TaintModel/b0) / 试探性加入(staging) |
| staging / promote / rollback | 试探进化临时区 / 校验通过固化 / 校验失败回滚 |
| MaD | Models as Data：CodeQL 的 sinkModel 数据扩展 |
| sanitizer | 净化函数：截断 taint 传播、消解误报 |
| L0–L3 | round-trip 实验 → 集合迁移 → agent 解释 → 人工裁决 |
