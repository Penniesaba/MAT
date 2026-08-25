# CodeQL 方案完善计划 + 从零精通指南

> 目标:把 mcp-sec-audit 的 CodeQL 分析线做到尽可能完美,让 CodeQL 成为四条分析线
> (Rule / Taint / Agent / CodeQL)里可信度最高、最工业级的一条。
> 本文同时是一份面向 CodeQL 新手的教程 —— 结合本项目的真实场景、真实查询、真实测试
> 目标,把原理、用法、流程和"你应该知道的一切"讲清楚。

---

## 目录

- [Part 0 · 现状盘点:我们的 CodeQL 长什么样](#part-0--现状盘点我们的-codeql-长什么样)
- [Part 1 · CodeQL 原理(从零理解它为什么强)](#part-1--codeql-原理从零理解它为什么强)
- [Part 2 · CodeQL 工作流程与上手(可复制的命令)](#part-2--codeql-工作流程与上手可复制的命令)
- [Part 3 · QL 语言速成(用本项目的查询当教材)](#part-3--ql-语言速成用本项目的查询当教材)
- [Part 4 · 诊断:现有 CodeQL 方案的 10 个问题](#part-4--诊断现有-codeql-方案的-10-个问题)
- [Part 5 · 完善计划(分阶段、可验收)](#part-5--完善计划分阶段可验收)
- [Part 6 · 查询矩阵:我们要写哪些查询](#part-6--查询矩阵我们要写哪些查询)
- [Part 7 · 验收标准与里程碑](#part-7--验收标准与里程碑)
- [附录 · 学习资源](#附录--学习资源)

---

## Part 0 · 现状盘点:我们的 CodeQL 长什么样

先看清我们**已经有什么**,才知道要补什么。本项目 CodeQL 线由 4 个 Rust 文件 + 1 个查询目录组成:

```
crates/mcp-sec-audit-core/src/static_analysis/codeql/
├── mod.rs          # 入口:过滤语言 → 建库 → 跑查询 → 解析 SARIF
├── provider.rs     # 封装 `codeql` CLI(建库/分析)
├── queries.rs      # QueryPack:内置查询 + 标准套件引用
├── parser.rs       # SARIF → CodeqlAnalysisResult
└── queries/mcp/
    ├── qlpack.yml              # 查询包声明(依赖 codeql/python-all)
    ├── ToolParameterToSink.ql  # MCP 工具参数 → 危险 sink
    ├── PromptInjection.ql      # MCP prompt 参数 → LLM API 调用
    └── ResourceToNetwork.ql    # MCP resource 数据 → 外发网络
```

**关键事实(已经核实):**

1. **CodeQL CLI 已安装**:`/home/xiao/App/codeql/codeql/codeql`,版本 **2.26.2**,在 PATH 上。
2. **支持语言**:`SUPPORTED_LANGUAGES = ["python", "javascript", "typescript"]`(`mod.rs:17`)。Rust 不是 CodeQL 一等语言,所以 Rust 目标会直接 "skipped"。
3. **内置查询包**(`queries.rs` 的 `QueryPack::default()`):
   - 3 条 `.ql` 查询(上面那 3 条,**全是 Python**);
   - `suite_refs = ["codeql/python-queries", "codeql/javascript-queries"]` —— 即除了自定义查询,还会引用 GitHub 官方的**标准安全套件**。
4. **运行逻辑**(`provider.rs:134`):对"内置 + 非 Python"的数据库会**跳过那 3 条 MCP 查询**(因为它们是 Python 专用),但标准套件引用仍然按语言加上。所以:
   - Python 目标 = 3 条 MCP 查询 + `codeql/python-queries` 标准套件;
   - JS/TS 目标 = `codeql/javascript-queries` 标准套件(**没有 MCP 专属查询**);
   - Rust 目标 = 直接 skipped。
5. **融合(fusion)如何消费 CodeQL 结果**(`matcher.rs:175` + `merger.rs:94`):CodeQL 结果的"类别"直接取 `rule_id`(例如 `py/cmd-injection` 或 `mcp/tool-parameter-to-sink`)。**这个 id 和 rule/taint 的类别词表(`command_execution`/`file_write`)不一致**,所以 CodeQL 结果只能靠**行号邻近(stage 1)** 融合,几乎无法靠**类别(stage 2)** 和 rule/taint 交叉印证。

这第 5 点,和 agent 的 "category 缺失" 是同一个病根:三条"智能"线里,只有 rule/taint 共用一套类别词表,agent 和 codeql 各自为政。**这是本次完善计划要重点解决的。**

---

## Part 1 · CodeQL 原理(从零理解它为什么强)

### 1.1 一句话本质

CodeQL 不是一个"扫描器",而是一个**「把源码编译成关系数据库,再用声明式逻辑语言(QL)去查询这个数据库」的系统**。它由两部分组成:

1. **提取器(extractor)** —— 把源码解析成抽象语法树/数据流,存进一个关系数据库(CodeQL database)。
2. **QL 语言 + 标准库** —— 你在 QL 里写"我要找所有从 A 流到 B 的数据",它在数据库上求值。

> 类比:普通 grep 是"在文本里找字符串";CodeQL 是"先建一个能理解代码结构的数据库,再写 SQL 式的逻辑查询"。所以它能看到 grep 永远看不到的东西:**跨函数、跨文件的污点流、别名、字段访问、净化函数**。

### 1.2 为什么它比我们的内建 taint 强(这是关键)

我们项目里有两条 taint 能力:内建的 summary-based taint(在 `taint/` 目录),和 CodeQL 自带的 taint tracking。对比:

| 能力 | 内建 taint | CodeQL |
|---|---|---|
| 字段敏感(field-sensitive) | ❌ 变量是整名字符串 | ✅ `a.b.c` 和 `a.b.d` 精确区分 |
| 流敏感(flow-sensitive) | ❌ 不看语句顺序 | ✅ 值随时间变化被精确跟踪 |
| 上下文敏感(context-sensitive) | ❌ 一个函数一个节点 | ✅ 调用点上下文(1-CFA 级别) |
| 跨函数/跨文件 | 部分(靠摘要) | ✅ 完整、精确 |
| 净化函数(sanitizer) | ❌ 完全没有 | ✅ 可定义 `isSanitizer` |
| 别名追踪 | 弱 | ✅ API Graphs 自动处理 `import x as y` |

**结论:与其费劲把内建 BFS 升级成 CodeQL 级引擎(基本不可能),不如把精力投到"写好 CodeQL 查询"上 —— 工业级 taint 是白送的。** 内建 taint 的定位是"没装 CodeQL 时的降级方案",不是主力。

### 1.3 核心概念清单(先背下来)

| 术语 | 含义 |
|---|---|
| **Database** | 源码编译后的关系数据库,CodeQL 分析的对象 |
| **Query (.ql)** | 你写的查询,`select` 输出结果 |
| **Library (.qll)** | 可复用的查询代码,`import` 进来 |
| **Query suite (.qls)** | 一批查询的集合(一个文件列多个查询) |
| **Query pack (qlpack.yml)** | 打包查询 + 声明依赖,可分发/下载 |
| **SARIF** | 结果的标准交换格式(JSON),我们的 parser 读的就是它 |
| **DataFlow** | 值跟踪(变量到变量) |
| **TaintTracking** | 污点跟踪(比 DataFlow 更宽松,默认透传字符串拼接等) |
| **API Graphs** | 从"模块导入"到"成员调用"的图,自动处理别名 |
| **Sanitizer** | 净化函数,告诉引擎"流到这里就断了" |

### 1.4 QL 是什么语言

QL 是**声明式、面向逻辑**的语言,风格接近 SQL 和 Datalog:

- 你不写"怎么找",你写"**满足什么条件**的东西是我要找的";
- 支持**递归**和**传递闭包**(`+`/`*`),这是数据流分析的核心;
- 结果通过 `select` 输出。

一个最小的 Python 查询:

```ql
import python

from Function f
where f.getName() = "main"
select f, "找到 main 函数"
```

---

## Part 2 · CodeQL 工作流程与上手(可复制的命令)

你机器上 CodeQL 2.26.2 已装好。下面是完整流程,每一步都能在**本仓库**直接跑。

### 2.1 检查环境

```bash
codeql --version
codeql resolve qlpacks        # 看已安装/可见的查询包
codeql resolve languages      # 看支持的提取语言
```

### 2.2 第一步:创建数据库

```bash
cd /home/xiao/Project/mcp-sec-audit

codeql database create /tmp/db-python \
  --language=python \
  --source-root=test-targets/python-mcp-server \
  --overwrite
```

- `--language=python` 决定用哪个提取器;
- `--source-root` 是源码根目录;
- 建库会先"build"(纯 Python 项目通常无需额外构建命令)。

JS/TS 同理:`--language=javascript`(CodeQL 把 TS 归到 javascript 提取器)。

### 2.3 第二步:运行查询

单条查询分析(输出 SARIF):

```bash
codeql database analyze /tmp/db-python \
  crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp/ToolParameterToSink.ql \
  --format=sarif-latest \
  --output=/tmp/out.sarif
```

交互式调试(不产出 SARIF,快速看结果):

```bash
codeql query run \
  crates/mcp-sec-audit-core/src/static_analysis/codeql/queries/mcp/ToolParameterToSink.ql \
  --database=/tmp/db-python
```

### 2.4 第三步:看结果

SARIF 是 JSON。本项目 `parser.rs` 解析的字段主要是:

- `runs[].tool.driver.rules[]` → 查询的元信息(id/name/默认严重级)
- `runs[].results[]` → 每条命中,含 `ruleId`、`message.text`、`locations[]`、`codeFlows[]`(数据流路径)、`level`

你也可以用官方工具把 SARIF 转成更好读的格式,或直接在 VSCode CodeQL 扩展里看。

### 2.5 推荐:装 VSCode CodeQL 扩展(写查询必备)

用 VSCode 打开本仓库,装官方 **CodeQL** 扩展。好处:

- 语法高亮、自动补全、跳转定义;
- 选中一个查询 → "CodeQL: Run Query on Selected Database" 交互式看结果;
- 结果里能**逐节点看数据流路径**,这是调试 taint 查询最直观的方式。

> 这是 CodeQL 开发者的标准工作流,强烈建议写查询阶段全程用它。

---

## Part 3 · QL 语言速成(用本项目的查询当教材)

### 3.1 基本语法三件套

**predicate(谓词/函数):**

```ql
predicate isInteresting(Function f) {
  f.getName() = "run_shell" or
  f.getName() = "fetch_url"
}
```

**class(定义一组满足条件的实体):**

```ql
class DangerousSink extends DataFlow::Node {
  DangerousSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("os").getMember("system").getACall()
    |
      this = call.getArg(0)
    )
  }
}
```

**查询主体(from-where-select):**

```ql
from McpToolToSinkFlow::PathNode source, McpToolToSinkFlow::PathNode sink
where McpToolToSinkFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "污点从 $@ 流到了危险 sink。", source.getNode(), "用户输入"
```

### 3.2 数据流分析的标准骨架(最重要)

一条 taint 查询的固定套路是"定义 source / sink / (可选) sanitizer,然后跑 flowPath":

```ql
import python
import semmle.python.dataflow.new.TaintTracking

// 1. source:什么算"用户可控输入"
class MySource extends DataFlow::Node { MySource() { ... } }

// 2. sink:什么算"危险汇聚点"
class MySink extends DataFlow::Node { MySink() { ... } }

// 3. (可选)净化函数:流过这些就洗白了
class MySanitizer extends DataFlow::Node { MySanitizer() { ... } }

// 4. 配置 + 启动全局污点追踪
module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof MySource }
  predicate isSink(DataFlow::Node n)   { n instanceof MySink }
  predicate isSanitizer(DataFlow::Node n) { n instanceof MySanitizer }
}
module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "污点路径命中"
```

> `DataFlow::ConfigSig`(精确值流)vs `TaintTracking::Global`(污点流):污点流更宽松,默认把"字符串拼接""容器展开"等都视为透传,更适合安全审计(宁可多报不可漏报)。**我们用 TaintTracking。**

### 3.3 API Graphs:自动处理别名

`API::moduleImport("subprocess")` 返回"import 了 subprocess 的那个模块对象",`.getMember("run")` 取它的 `run` 成员,`.getACall()` 取所有对它的调用。**它自动处理 `import subprocess as sp` 这种别名**(只要后续用 `sp.run` 而不是 `runner = sp.run; runner()` 这种二次赋值)。

### 3.4 逐行精读 ToolParameterToSink.ql

我们把仓库里真实的 `ToolParameterToSink.ql` 拆开讲(编号对应原文件):

```ql
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
```

引入 Python 提取器 + 新版数据流/污点/ApiGraphs 标准库。

```ql
class McpToolEntrypoint extends DataFlow::Node {
  McpToolEntrypoint() {
    exists(Function f |
      f.getADecorator().(Call).getFunc().(Attribute).getObject().(Name).getId() = "mcp" and
      f.getADecorator().(Call).getFunc().(Attribute).getName() = "tool" and
      this = DataFlow::parameterNode(f.getArg(0))
    )
  }
}
```

翻译成人话:**找"被 `@mcp.tool()` 装饰的函数",它的第一个参数就是污点源**。

- `f.getADecorator()` —— 函数的装饰器;
- `.(Call)` —— 这个装饰器是一个调用 `@mcp.tool(...)`;
- `.getFunc().(Attribute)` —— 调用的是 `mcp.tool` 这个属性访问;
- `.getObject().(Name).getId() = "mcp"` —— 属性访问的对象是个**名为 `mcp`** 的变量;
- `.getName() = "tool"` —— 属性名是 `tool`;
- `f.getArg(0)` —— 被装饰函数的第 1 个参数。

**这段就是问题的核心**(见 Part 4):它只认 `@mcp.tool()` 且对象必须字面叫 `mcp`,完全认不出 `server.tool("name", handler)` 这种注册式写法。

```ql
class DangerousSink extends DataFlow::Node {
  DangerousSink() {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("os").getMember("system").getACall() or
      call = API::moduleImport("subprocess").getMember("run").getACall() or
      ...
      call = API::builtin("eval").getACall() or
      call = API::moduleImport("builtins").getMember("open").getACall()
    |
      this = call.getArg(0)
    )
  }
}
```

定义危险 sink:`os.system` / `subprocess.run/Popen/call` / `os.popen` / `eval` / `exec` / `pickle.loads` / `open` 的第一个参数。

```ql
module McpToolToSinkConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof McpToolEntrypoint }
  predicate isSink(DataFlow::Node sink) { sink instanceof DangerousSink }
}
module McpToolToSinkFlow = TaintTracking::Global<McpToolToSinkConfig>;
import McpToolToSinkFlow::PathGraph

from McpToolToSinkFlow::PathNode source, McpToolToSinkFlow::PathNode sink
where McpToolToSinkFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "MCP tool parameter flows from $@ to a dangerous sink without sanitization.",
  source.getNode(), "user input"
```

配好 source/sink,启动全局污点追踪,把每条 `source → sink` 的路径作为结果输出。

---

## Part 4 · 诊断:现有 CodeQL 方案的 10 个问题

按严重程度排序,每条都给证据和"为什么是问题"。

| # | 问题 | 证据 / 后果 | 严重度 |
|---|---|---|---|
| 1 | **source 只认装饰器 `@mcp.tool()`,且对象必须叫 `mcp`** | `getObject().(Name).getId() = "mcp"`;认不出 `server.tool("x", handler)`(我们 JS 测试目标就是这种)、认不出 `fastmcp.tool()`、认不出别的变量名 | 🔴 高 |
| 2 | **`parameterNode(f.getArg(0))` 假设第 1 个参数就是输入** | 认不出 `request/context` 对象、命名参数、`**kwargs` 里的真实输入 | 🔴 高 |
| 3 | **无 sanitizer 模型** | 三条查询都没定义 `isSanitizer`;`is_safe_url`/`normalize_path` 这类"看似校验"的函数会误报,`shlex.quote`/`os.path.realpath` 这类真净化也不识别 | 🔴 高 |
| 4 | **类别不对齐融合** | CodeQL 结果的 category = `rule_id`(如 `mcp/tool-parameter-to-sink`),和 rule/taint 的 `command_execution`/`file_write` 词表不一致 → 只能靠行号邻近融合,无法靠类别交叉印证 | 🔴 高 |
| 5 | **3 条查询纯 Python,JS/TS 没有 MCP 专属查询** | `queries.rs` 的 builtin 只有 Python;`provider.rs:134` 对非 Python 跳过内置查询 → JS 目标只剩标准套件,没有"工具参数→危险 sink"这类 MCP 专属检测 | 🟡 中 |
| 6 | **`open` 作为 sink 过宽** | 任何 `open()` 都算危险 sink,不区分读(`"r"`)和写(`"w"`),也没限定是"文件路径参数可控" | 🟡 中 |
| 7 | **查询类别矩阵不全** | 缺 SSRF(tool→network)、SQL 注入、path traversal、模板注入/SSTI、文件写入、prompt 模板注入 | 🟡 中 |
| 8 | **`target_root` 推导脆弱** | `mod.rs:71` 用 `discovered_files.first().parent()` 当 source-root,多文件/多目录时不对 | 🟢 低 |
| 9 | **别名二次赋值漏检** | `runner = sp.run; runner(...)` 这种"赋值别名"API Graphs 不自动跟踪 → run_shell 这条可能漏 | 🟢 低 |
| 10 | **metadata 未回填** | `parser.rs` 的 `CodeqlMetadata { query_source, languages }` 标注了 `#[allow(dead_code)]`,没写进结果 → 无法溯源 | 🟢 低 |

**一个必须先纠正的认知**:之前我评估说"JS/TS 跑 CodeQL 是零查询"——**这不准确**。JS/TS 会跑到 `codeql/javascript-queries` 标准套件(如果该 pack 已下载),只是**没有 MCP 专属查询**。真正的问题是 #5:我们的项目特色(MCP 攻击面)在 JS/TS 上完全缺失。

---

## Part 5 · 完善计划(分阶段、可验收)

按依赖关系排序,每阶段都有**可运行的验收命令**。

### 阶段 0 · 环境基线(半天)

**目标**:确认 CLI + 官方查询包齐全,能对 python-mcp-server 跑出结果。

1. 确认 CLI:`codeql --version`(预期 2.26.2 ✅)
2. 下载标准查询包(如果 resolve qlpacks 里没有):
   ```bash
   codeql pack download codeql/python-queries codeql/javascript-queries
   ```
3. 冒烟测试:对 `test-targets/python-mcp-server` 建库 + 跑内置 3 条查询,记录基线结果数。

**验收**:`codeql database analyze` 能产出非空 SARIF,且 `ToolParameterToSink.ql` 至少命中 `run_shell`。

### 阶段 1 · 修复并强化现有 3 条 Python 查询(1–2 天)

**目标**:把 source/sink/sanitizer 三件套做对,并给查询打上类别标签。

1. **修 source(问题 #1/#2)**:
   - 同时支持装饰器(`@mcp.tool()` / `@fastmcp.tool()` / 任意 `.tool()` 装饰器)和注册式(`mcp.tool("name", fn)` / `server.tool(...)`)。
   - 用「装饰器名以 `tool` 结尾」代替「对象名必须是 `mcp`」。
   - 对注册式,把 handler 函数的**所有**参数(而非第 1 个)当作源。
2. **精化 sink(问题 #6)**:
   - 把 `open` 拆成 file-read / file-write 两条,读模式检查 `getArg(1)` 是否含 `"w"`/`"a"`。
   - 补 `os.system`、`subprocess.*(shell=True)`、`eval/exec`、`pickle.loads`、`tempfile`、`shutil` 等。
3. **加 sanitizer(问题 #3)**:
   ```ql
   class Sanitizer extends DataFlow::Node {
     Sanitizer() {
       this = API::moduleImport("shlex").getMember("quote").getACall().getReturn() or
       this = API::moduleImport("os").getMember("path").getMember("realpath").getACall().getReturn()
       // 参数化查询、URL 白名单等按场景补
     }
   }
   predicate isSanitizer(DataFlow::Node n) { n instanceof Sanitizer }
   ```
4. **加 `@tags` 类别标签(问题 #4 的前半)**:
   ```ql
   /**
    * @name MCP tool parameter to command-execution sink
    * @id mcp/tool-param-to-command-exec
    * @tags security mcp command-execution
    */
   ```
   用 `@tags` 携带**和 rule 词表一致的类别**,供 parser 提取。

**验收**:`run_shell`(含 `runner = sp.run` 别名)被命中;`read_log` 的 `open` 能区分读写;加了 `shlex.quote` 的样本不再误报。

### 阶段 2 · 补齐 Python MCP 查询矩阵(2–3 天)

**目标**:按 Part 6 的查询矩阵,补全 Python 侧所有 MCP 攻击面,每条用 `server.py` 对应漏洞验收。

新增查询(每条都是同一个 ConfigSig 骨架,只换 source/sink):

| 新查询 | source | sink | 验收样本 |
|---|---|---|---|
| `ToolParamToNetwork`(SSRF) | tool 参数 | `requests.get/post`、`httpx`、`urllib`、`aiohttp`、`socket` | `fetch_url` |
| `ToolParamToFileWrite` | tool 参数 | `open(w/a)`、`shutil.move/copy`、`os.remove` | 新增样本 |
| `ToolParamToSql` | tool 参数 | `cursor.execute`、`conn.execute`、ORM raw | 新增样本 |
| `ToolParamToTemplate`(SSTI) | tool 参数 | `jinja2.Template.render`、`render_template_string`、f-string → render | 新增样本 |
| `PathTraversal` | tool 参数(路径类) | `open`/`Path` 且无 `realpath`/前缀校验 | `read_log` |
| `PromptTemplateInjection` | tool 参数 | 拼进 prompt/模板再喂 LLM | 与 PromptInjection 合并 |

**验收**:`python-mcp-server` 的 `run_shell`/`read_log`/`fetch_url` 分别命中对应查询,且与 rule/taint 行号邻近能融合。

### 阶段 3 · JS/TS 查询(2–3 天)

**目标**:把 MCP 攻击面覆盖到 JS/TS,用 `js-mcp-server` 验收。

1. 新建 `queries/mcp-js/qlpack.yml`,依赖 `codeql/javascript-all`:
   ```yaml
   name: mcp-sec-audit/mcp-js-queries
   version: 0.0.0
   dependencies:
     codeql/javascript-all: "*"
   ```
2. 写 JS 查询,重点解决**注册式 source**(这是 JS/TS 的主流写法):
   ```ql
   import javascript
   import semmle.javascript.dataflow.new.TaintTracking

   class ServerToolRegistration extends DataFlow::CallNode {
     ServerToolRegistration() {
       this.getCalleeName() = "tool" and
       this.getReceiver().toString() = "server"   // server.tool("x", handler)
     }
   }
   // source = 第二个参数(handler)的所有形参
   ```
3. JS sink:`child_process.exec/spawn`、`eval`、`Function()`、`fs.writeFileSync`、`fetch`、`axios`、SQL(`.query(` 但需精化)。

**验收**:`js-mcp-server` 的 `db_query`(eval/exec)和 `export_file`(fs.writeFileSync 跨文件)被命中。

### 阶段 4 · Rust 侧改造,把结果正确接入 fusion(1–2 天)

**目标**:解决 #4/#5/#8/#10,让 CodeQL 结果真正参与交叉印证。

1. **`queries.rs`**:按语言组织查询包(如 `queries/mcp-python/` + `queries/mcp-js/`),删掉"非 Python 跳过内置查询"的硬编码,改为"按数据库语言选对应查询目录"。
2. **`parser.rs`**:
   - 从 SARIF 的 `rule.tags` 提取类别,映射到共享词表(`command-execution` → `command_execution` 等);
   - 把 `CodeqlMetadata { query_source, languages }` 真正写进结果(去掉 `dead_code`);
   - `rule_id` 保留原始值,新增 `category` 字段。
3. **`mod.rs`**:`target_root` 改为从 `scan.targets` 推导,而非 `first().parent()`。
4. **fusion**:让 CodeQL 结果的 category 用新映射后的 `category`(而非 `rule_id`),使 stage-2 类别匹配能生效。

**验收**:`python-mcp-server` 上,CodeQL 的 `command-execution` 命中与 rule/taint 的 `command_execution` 能靠**类别**融合,报告里出现 `rule + taint + codeql` 三重印证。

### 阶段 5 · 验收与回归(1 天)

**目标**:全链路验证 + 不破坏现有四条线。

1. `cargo test` 全绿(现有 186 个测试 + 新增 CodeQL 相关测试)。
2. 三个测试目标各跑一遍:
   - `python-mcp-server`:3 条漏洞各命中对应查询,且三重/双重印证;
   - `js-mcp-server`:eval/exec/file-write 命中 JS 查询;
   - `rust-mcp-server`:确认 "CodeQL skipped" 诊断正常(不报错)。
3. 记录 `Fused Findings` 里出现 `codeql` 支撑的条目数。

---

## Part 6 · 查询矩阵:我们要写哪些查询

这是"完美 CodeQL"的最终蓝图。横轴是 MCP 攻击面(和 agent 提示词里的 7 类 + 通用 sink 对齐),纵轴是语言。✅=已有,⬜=待写。

| 攻击面 | 类别(与 rule 对齐) | Python | JS/TS |
|---|---|---|---|
| 命令注入 | `command_execution` | ✅(需修) | ⬜ |
| 代码执行 | `dynamic_execution` | ✅(eval/exec) | ⬜ |
| 文件读取(敏感泄露) | `file_read` | ⬜ | ⬜ |
| 文件写入/删除 | `file_write` | ⬜ | ⬜ |
| SSRF | `network_request` | ⬜ | ⬜ |
| SQL 注入 | `database_injection` | ⬜ | ⬜ |
| 反序列化 | `deserialization` | ✅(pickle) | ⬜ |
| 路径穿越 | `path_traversal`(新类别) | ⬜ | ⬜ |
| 模板注入/SSTI | `template_injection`(新类别) | ⬜ | ⬜ |
| Prompt 注入 | `prompt_injection`(新类别) | ✅(需修) | ⬜ |
| 资源外带 | `data_exfiltration`(新类别) | ✅(需修) | ⬜ |

> 注意:上表里新类别(`path_traversal`/`template_injection`/`prompt_injection`/`data_exfiltration`)需要**同时**补进 `rules/languages/keywords.toml` 和 fusion 的类别词表,否则 CodeQL 报出来也没法交叉印证。这是"整个系统一起改"的关键耦合点。

---

## Part 7 · 验收标准与里程碑

### 里程碑

| 里程碑 | 交付物 | 完成判据 |
|---|---|---|
| M0 | 环境基线 | `codeql database analyze` 对 python 目标产出非空 SARIF |
| M1 | 3 条 Python 查询强化 | source 支持装饰+注册,sanitizer 生效,`@tags` 带类别 |
| M2 | Python 查询矩阵完整 | 9 类攻击面全覆盖,`server.py` 3 条漏洞全命中 |
| M3 | JS/TS 查询 | `js-mcp-server` eval/exec/file-write 命中 |
| M4 | fusion 接入正确 | CodeQL 靠类别融合,出现 rule+taint+codeql 三重印证 |
| M5 | 回归通过 | `cargo test` 全绿 + 三目标 E2E 通过 |

### 全局验收标准(最终)

1. **覆盖**:Python 9 类攻击面、JS/TS 至少 6 类(命令/代码执行、文件写、SSRF、SQL、prompt 注入、反序列化)。
2. **正确**:每个 query 有对应测试样本,无样本命中率 0(不空报),有样本命中率 100%(不漏报)。
3. **融合**:CodeQL 结果能靠**类别**与 rule/taint 交叉印证,报告里 `supported_by` 出现 `codeql`。
4. **不回归**:`cargo test` 全绿;Rule/Taint/Agent 三条线行为不变。
5. **可维护**:每条查询有 `@id` + `@name` + `@tags` + 注释说明"检测什么、样本在哪"。

---

## 附录 · 学习资源

按优先级:

1. **官方文档** https://codeql.github.com/docs/ —— 入门 + 语言参考 + 各语言手册(必读)
2. **QL 语言参考** https://codeql.github.com/docs/ql-language-reference/ —— 查语法
3. **Python 数据流** https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/
4. **JS 数据流** https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-javascript-and-typescript/
5. **API Graphs 教程** https://codeql.github.com/docs/codeql-language-guides/using-api-graphs-in-python/
6. **GitHub Security Lab 博客** https://securitylab.github.com/ —— 大量真实漏洞的 CodeQL 建模案例(最有价值)
7. **CodeQL 官方查询库**(`codeql/python-queries` 下载后本地看)—— 最好的查询范例,直接 `import` 它的库、抄它的写法。

> 学习路径建议:**先跑通 Part 2 的冒烟测试 → 用 VSCode 扩展交互式改 `ToolParameterToSink.ql` 看数据流 → 照抄 GitHub Security Lab 的 SSRF/SQL 建模案例 → 再动手写 M1–M3 的查询。** 不要一上来就写新查询,先把"改一个 sink、跑一次、看路径"这个循环练熟。

---

*本文档是 CodeQL 完善计划的唯一事实来源;执行时按 M0→M5 顺序推进,每完成一个里程碑更新本文件对应小节。*
