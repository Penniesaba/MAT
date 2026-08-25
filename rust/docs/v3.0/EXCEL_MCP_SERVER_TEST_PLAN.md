# Excel MCP Server 测试方案

> **目的**:用真实世界的漏洞目标 `haris-musa/excel-mcp-server`(CVE-2026-40576 路径穿越)
> 验证 2026-08-20 架构重构后的四条分析线 + 自进化闭环是否按预期工作,并给出**可复现、可验收**
> 的测试步骤与预期结果。
>
> **配套文档**:`ARCHITECTURE.md`(新架构详解)、`EXCEL_SCAN_DIAGNOSIS.md`(重构前该目标漏报的根因)。
>
> **配置文件**:`test-targets/configs/excel-mcp-server-config.toml`(已按本方案完善)。

---

## 目录

- [1. 被测对象与已知漏洞](#1-被测对象与已知漏洞)
- [2. 检测能力矩阵(每条线预期命中什么)](#2-检测能力矩阵每条线预期命中什么)
- [3. 环境前置](#3-环境前置)
- [4. 测试场景(分场景、可验收)](#4-测试场景分场景可验收)
- [5. 配置文件逐段说明](#5-配置文件逐段说明)
- [6. 验收标准汇总](#6-验收标准汇总)
- [7. 已知边界与预期差异(诚实清单)](#7-已知边界与预期差异诚实清单)

---

## 1. 被测对象与已知漏洞

| 项 | 值 |
|---|---|
| 仓库 | `haris-musa/excel-mcp-server`(PyPI 包 `excel-mcp-server`) |
| 版本 | `v0.1.7`(当前 checkout `f0c0ecd`,含漏洞;0.1.8 已修复) |
| 语言 | Python(14 个 `.py` 文件) |
| 漏洞 | **CVE-2026-40576**(GHSA-j98m-w3xp-9f56, PYSEC-2026-331) |
| 类型 | CWE-22 路径穿越 |
| 位置 | `src/excel_mcp/server.py:74-93` `get_excel_path()` |
| 触发点 | ~25 个 `@mcp.tool()` 处理器全部经 `get_excel_path` 打开文件 |

**漏洞代码**(`server.py:74-93`):

```python
def get_excel_path(filename: str) -> str:
    if os.path.isabs(filename):          # 缺陷①:绝对路径不校验,直接放行
        return filename
    if EXCEL_FILES_PATH is None:
        raise ValueError(...)
    return os.path.join(EXCEL_FILES_PATH, filename)   # 缺陷②:未校验 "../"
```

两个缺陷:绝对路径绕过 `os.path.isabs()` + `os.path.join(..., "..")` 未做规范化/白名单校验。
文件随后经 `openpyxl.load_workbook(...)`(32 处调用)打开,任意路径可读。**加重因素**:无鉴权、
默认绑定 `0.0.0.0`。

---

## 2. 检测能力矩阵(每条线预期命中什么)

这是本测试方案的核心——**先明确每条线「应该」产出什么**,再逐场景验证。真实预期(基于代码,非乐观假设):

| 分析线 | 对该 CVE 的预期 | 机制 | 状态 |
|---|---|---|---|
| **rule** | 命中 `path_traversal`,但锚点被 `..` 误报污染 | `rules/languages/keywords.toml` 的 `path_traversal` 能力含 `".."` 关键词 | ⚠️ 已知 FP(RC-3) |
| **taint** | 命中 ~25 条 `file_read` | **语义推断层 2**:`openpyxl.load_workbook` 经 `openpyxl` 包归类 → `file_read` | ✅ 重构核心能力 |
| **codeql** | **0 条**(对本 CVE) | MaD 注入在 2.26.2 被禁 + 该仓库无 `open()`/`Path()` 内建文件 sink | ⚠️ 预期 0,见 §7 |
| **agent** | 语义发现路径穿越 + 提出 `openpyxl.load_workbook` → `file_read` 模型 | 三角色 prompt + `model_candidates` 解析 | ✅(需启用) |
| **fusion** | 把 rule/taint 交叉印证为 fused finding | basename 归一化 + 类别对齐 | ✅(需启用) |

> **头号成功信号**:重构前该目标 taint = **0 条**(`load_workbook` 未被建模,见
> `EXCEL_SCAN_DIAGNOSIS.md` RC-1);重构后 taint 应靠语义推断**自动命中 ~25 条 `file_read`**。
> 这验证了「模型驱动 + 语义推断」的核心价值,**无需为 openpyxl 手工补任何 sink 模型**。

---

## 3. 环境前置

| 依赖 | 要求 | 验证命令 |
|---|---|---|
| Rust 工具链 | 1.88+ | `cargo --version` |
| CodeQL CLI | 2.26.2(或更高) | `/home/xiao/App/codeql/codeql/codeql --version` |
| Claude CLI(仅 agent 场景) | 在 PATH 上 | `claude --version` |
| 测试目标 | `test-targets/excel-mcp-server` @ v0.1.7 | `git -C test-targets/excel-mcp-server describe --tags` → `v0.1.7` |

**首次准备**(目标已 clone 到 v0.1.7,一般无需重跑):

```bash
cd test-targets
git clone https://github.com/haris-musa/excel-mcp-server.git
cd excel-mcp-server
git checkout v0.1.7      # 或 git log --oneline 挑 f51340e 之前的提交
```

**运行入口**(从 `rust/` 目录;配置文件是位置参数,不是 `scan static` 子命令):

```bash
cd rust
cargo run -- ../test-targets/configs/excel-mcp-server-config.toml
```

---

## 4. 测试场景(分场景、可验收)

场景 A/B/C/D 通过**修改配置文件里的开关**切换(见 §5),不必改代码。

### 场景 A · 基线召回(rule + taint + codeql,关 agent 与 fusion)

**目的**:验证三条确定性分析线,尤其是语义推断对 `load_workbook` 的自动召回。

**配置**:`[static.agent].enabled = false`,`[fusion].enabled = false`。

**命令**:`cargo run -- ../test-targets/configs/excel-mcp-server-config.toml`

**预期**:
1. `Taint Results > 0`,且存在 `sink_kind == "file_read"`、`sink_name` 含 `openpyxl.load_workbook` 的结果;
2. `Rule Results > 0`,含 `path_traversal` 类别(但注意 §7 的 `..` FP);
3. `CodeQL Results` 可见为 0,且 `codeql_diagnostics` 无「skip」——它**成功运行**但无命中(§7);
4. `Fused Findings == 0`(fusion 关闭)。

**验收判据**:
- ✅ taint 命中 `file_read` 且 `sink_name` 含 `load_workbook` —— 语义推断生效;
- ✅ 报告里能区分「CodeQL 跑通了但 0 命中」与「CodeQL 被跳过」。

### 场景 B · 多线印证(fusion 开启)

**目的**:验证 basename 归一化 + 类别对齐让 rule/taint 交叉印证。

**配置**:`[fusion].enabled = true`,`require_confirmed_by = 1`。

**预期**:`fused_findings` 非空,且至少存在一条 `supported_by` 含 `taint` 的 `file_read` fused finding
(带完整 dataflow 路径);`summary.fused_finding_count > 0`。

**验收判据**:
- ✅ 存在 `supported_by` 含 2 条线的 finding(rule + taint 经 basename 归一化后按邻近/类别印证);
- ✅ `summary.codeql_fused_count` 语义正确(CodeQL 0 命中时为 0)。

### 场景 C · 自进化闭环(agent + 门控 + 温回灌 + 冷持久化)

**目的**:验证 agent 三角色 → 门控 → 温回灌 → 冷持久化的完整闭环。

**配置**:`[static.agent].enabled = true`(`provider = "claude"`),`[static].learned_dir = "models/learned"`,
`[static.taint].enabled = true`,`[fusion].enabled = true`。

**命令**:连续扫两次。

**预期(第一次)**:
1. `Agent Results` 非空 —— agent 语义发现路径穿越(带绝对 `path:LINE` 位置);
2. `model_candidates` 非空 —— agent 提出 `openpyxl.load_workbook` → `file_read`(或其它 sink);
3. 日志可见门控判定(见场景 D);
4. `models/learned/` 下出现 `learned-*.toml` 文件(仅 hot/warm 通过门控者)。

**预期(第二次)**:
1. 启动日志可见「loaded extra sink models」—— learned 模型被 `load_models_dir` 重新载入;
2. 第二次 `fused_finding_count >= 第一次`(进化生效;即便对本目标语义推断已覆盖 load_workbook,
   learned 模型仍以 `source = "learned"` 形态叠加,验证冷持久化通路而非依赖它召回)。

**验收判据**:
- ✅ `models/learned/` 有内容,且 `learned_from` 字段非空(可溯源);
- ✅ 第二次扫描日志显示 learned 目录被加载;
- ✅ agent 输出被正确解析出 `model_candidates`(不被幻觉污染——cold 候选不落盘)。

> **注意**:agent 会真实调用 `claude -p`,耗时/成本较高。快速回归时把 `[static.agent].enabled = false`
> 即可跳过。想只验证「温回灌 + 冷持久化」通路、不跑真实 agent 时,可参考
> `pipeline.rs` 的 `agent_warm_reinjection_adds_taint_finding_for_learned_sink` 单测(用 stub agent)。

### 场景 D · 可观测性(logging 分级)

**目的**:验证「绝不静默、决策留痕、计数上报」的铁律。

**配置**:`[logging]` 节(见 §5),先 `level = "info"`,排障时改 `codeql = "trace"` / `learning = "trace"`。

**预期**:
1. 终端可见五阶段进度(`rule → taint → agent → codeql → fusion`);
2. CodeQL 的「0 命中」伴随原因(本目标为「成功运行但标准/自定义查询未命中第三方封装」,而非静默);
3. 语义推断计数:`inferred_sinks` 与 `packages` 日志可见(验证 openpyxl 被识别);
4. `learning = "trace"` 时可见门控判定与 `hot_warm` 计数。

**验收判据**:不存在「某条线静默返回 0」;每条 0/跳过都有日志或 diagnostic 说明原因。

### 场景 E · 回归(cargo test)

**命令**:`cargo test`

**预期**:238 全绿(234 core + 4 cli)。新增语义推断、门控、温回灌、CodeQL MaD、SARIF 解析等单测全部通过。

---

## 5. 配置文件逐段说明

配置文件已完善为 `test-targets/configs/excel-mcp-server-config.toml`,逐段说明:

```toml
[scan]
targets = ["../test-targets/excel-mcp-server"]   # 从 rust/ 目录的相对路径
languages = ["python"]                            # 该目标只有 Python
exclude = ["__pycache__", ".venv", ".mypy_cache", ".pytest_cache", ".git"]

[static]
enabled = true
save_facts = true
# models_dir = "models/custom"                    # 可选:额外手工模型目录
learned_dir = "models/learned"                    # 冷持久化目录(场景 C)
```

`learned_dir` 是自进化闭环的关键:门控通过的 agent 模型以 `learned-*.toml` 写到这里,下轮被
`load_models_dir` 载入。`models_dir` 与它共用同一加载 seam(手工模型),按需开启。

```toml
[static.rule]
enabled = true
rule_paths = ["rules/mcp", "rules/languages"]     # path_traversal 能力在 rules/languages

[static.taint]
enabled = true                                    # 必须开:语义推断在 taint 线的事实提取里执行
forward = true
backward = true
max_depth = 8
entrypoint_required = true

[static.agent]
enabled = true                                    # 场景 C 用;快速回归改 false
provider = "claude"
max_turns = 30
timeout_seconds = 600

[static.codeql]
enabled = true
binary = "/home/xiao/App/codeql/codeql/codeql"     # 绝对路径,避免 PATH 歧义
timeout_seconds = 1200
```

`[static.taint].enabled` 必须为 true——阶段①包清单 + 阶段②语义推断在 `taint::run` 的事实提取里执行
(见 `ARCHITECTURE.md` §4/§11),关闭 taint 则无事实、无推断、无 sink。

```toml
[fusion]
enabled = true                                    # 场景 B/C 用
require_confirmed_by = 1                          # 至少 1 条线印证即可(演示用;严格可调 2)
boost_when_multiple_lines_agree = true
agent_only_as_advisory = true                     # agent 单线命中 → 顶多 medium
line_proximity = 5                                # 行号邻近阈值
rule_weight = 3
taint_weight = 2
agent_weight = 1
codeql_weight = 4                                 # CodeQL 权重最高(精度金标准)

[logging]
level = "info"                                    # 默认 info;排障改 debug/trace
format = "compact"
ansi = true
show_timestamps = true
show_progress = true
# log_file = "logs/audit.log"                     # 可选:重定向到文件

[logging.scopes]                                  # 按组件细调
pipeline = "info"
codeql = "debug"                                  # 建库/分析命令 + 耗时
learning = "trace"                                # 门控判定 + 回灌 + 持久化
```

`[logging.scopes]` 的键对应 `pipeline/rule/taint/agent/codeql/fusion/learning` 七个组件
(见 `cli/src/logging.rs` 的 `SCOPE_TARGETS`)。

```toml
[report]
output = "/home/xiao/Project/mcp-sec-audit/rust/docs/result/excel/<timestamp>"  # <timestamp> 会被替换
formats = ["markdown"]
include_fused_results = true
include_raw_rule_results = true
include_raw_taint_results = true
include_raw_agent_results = true
include_raw_codeql_results = true
include_facts = true                             # 打开:直接看 Sink/Import/Call 事实,验证语义推断
```

`<timestamp>` 占位符由 `resolve_output_path` 替换为 `YYYYMMDD-HHMMSS`(见 `reporting.rs`),所以
保留它即可,每次运行生成带时间戳的报告文件。

---

## 6. 验收标准汇总

| # | 标准 | 场景 | 通过条件 |
|---|---|---|---|
| 1 | 语义推断召回 | A | taint 命中 `file_read` 且 sink 含 `openpyxl.load_workbook`(从 0 → ~25) |
| 2 | 多线印证 | B | 存在 `supported_by` 含 2 条线的 fused finding |
| 3 | agent 三角色 | C | `agent_results` + `model_candidates` 非空且被正确解析 |
| 4 | 门控 + 冷持久化 | C | `models/learned/` 有 `learned-*.toml`,二次扫描载入 |
| 5 | 可观测性 | D | 无静默 0;CodeQL 0 命中带原因;推断/门控计数可见 |
| 6 | 回归 | E | `cargo test` 238 全绿 |

---

## 7. 已知边界与预期差异(诚实清单)

本测试方案**不粉饰**以下预期差异,它们来自真实代码状态,验收时必须知晓:

1. **CodeQL 对本 CVE 预期 0 命中**——不是故障,是**模型覆盖缺口**:
   - 自定义查询 `ToolParamToPathTraversal.ql` 的 sink 只有 `open()` / `pathlib.Path()`,不含
     `openpyxl.load_workbook`;
   - 标准 `py/path-injection` 也不建模第三方库封装;
   - MaD 注入本可补上这个缺口,但 CLI 2.26.2 的 `--model-packs` bug 使 `MAD_INJECT_ENABLED = false`
     (见 `ARCHITECTURE.md` §11)。升 2.26.3+ 后翻转开关,CodeQL 才能独立命中。**现阶段该 CVE 的
     CodeQL 覆盖由内建 taint 的语义推断兜底。**
2. **rule 线 `..` 关键词误报**(RC-3):`path_traversal` 能力的 `".."` 会命中 `__main__.py` 里字符串
   省略号 `...`,可能把头条位置顶成误报。这是已识别、未修复的已知问题,不影响 taint 的 file_read 召回。
3. **taint 与 rule 类别不同**:taint 报 `file_read`(load_workbook 打开文件),rule 报 `path_traversal`
   (`os.path.join`)。二者是「同一漏洞的两个侧面」,但**类别不同、行号不同**,fusion 可能把它们分为
   两个组(而非合并成一个「路径穿越 + 任意读」的复合 finding)。验收时以「taint 命中 file_read」为
   主信号,不强行要求 rule 与 taint 合并为同一条。
4. **语义推断与 agent 对 load_workbook 存在重叠**:openpyxl 已被层 2 包归类覆盖,agent 再提
   `load_workbook → file_read` 属「冗余印证」而非「唯一来源」。agent 的**独特价值**在语义漏洞
   (如 `isabs` 绝对路径绕过的设计缺陷)与未建模库的新模型,验收时关注这两类而非重复的 load_workbook。
5. **agent 是真实外部进程**:耗时/成本不可控,超时(`timeout_seconds = 600`)会在 finding 上标注
   `limitations`。快速迭代时关闭 agent。

---

*本方案与 `EXCEL_SCAN_DIAGNOSIS.md` 呼应:后者记录了重构前该目标的四条漏报根因,本方案则用同一目标
验收重构后的修复效果。头号信号是「taint 从 0 → ~25 file_read」,它不依赖手工补模型,而是语义推断的产物。*
