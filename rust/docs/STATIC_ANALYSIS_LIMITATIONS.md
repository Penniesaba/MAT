	# 静态分析系统问题与不足分析

> 分析对象：`test-targets/configs/python-config.toml` 扫描 `python-mcp-server` 的实际运行结果
> 生成日期：2026-08-14
> 结论性质：基于代码阅读 + 实测运行结果 + 命令验证，非推测

---

## 1. 运行结果快照

一次典型运行（`cargo run --release ../test-targets/configs/python-config.toml`）的摘要：

| 线路 | 结果数 | 说明 |
|---|---|---|
| Rule | 2 | 模式匹配 |
| Taint | 2 | 源→汇数据流 |
| Agent | 5~6（**每次不同**） | Claude LLM 语义分析 |
| CodeQL | **2** | 已修复（见 §3），产出带完整数据流路径的 findings |
| Fused | 4~6（**每次不同**） | 融合结果 |

三次运行中 `Agent` 分别为 6/5/6 条、`Fused` 分别为 6/5/4 条——结果**不可复现**。

---

## 2. 为什么四条线路发现的问题不一样

四条线路用了**完全不同的检测机制**，天然命中不同的问题：

| 线路 | 机制 | 特点 |
|---|---|---|
| **rule** | 规则模式匹配（近似 grep） | 最浅，只看文本是否命中规则库里的固定模式，无语义、无数据流 |
| **taint** | 源→汇数据流追踪 | 真正的数据流，但只对"配置里定义的源/汇对"生效 |
| **agent** | Claude LLM 语义分析 | 最深，读代码语义做推理，能发现前两者抓不到的问题 |
| **codeql** | 专业查询式数据流 | 补上跨过程深度污点，并产出完整数据流路径（见 §3） |

差异的本质原因：

1. **rule 只认"文本模式"**：`open(` 命中 `file_read`、某个 URL 函数命中 `network_request`，是正则级匹配，既不追踪参数流向也不理解上下文，找到的都是"看起来像"的东西。

2. **taint 只回答"参数流没流到 sink"这一个问题**：它要求 `entrypoint_required=true`（必须从 MCP tool 参数出发），所以 `fetch_url:url → network_request`、`run_shell:command → command_execution` 被抓到；但理解不了"`is_safe_url` 是个永远返回 True 的空校验器"这类语义问题。

3. **agent 是在"读代码、想漏洞"**：能抓出语义层问题——"SSRF via fetch_url（`is_safe_url` 恒为 True）"、"read_log 描述故意写成 'Read a log file' 掩盖任意文件读取（Tool Poisoning）"、"logging 服务器却暴露 shell 执行（Capability Over-Exposure）"——这些是 rule/taint 在机制上不可能发现的。

4. 四条线路本质是**互补**关系，CodeQL 补上深度跨过程污点这一环（已修复，见 §3）。

---

## 3. CodeQL 修复说明（曾为什么什么都发现不了）

**状态：✅ 已修复。** 现在 CodeQL 对 `python-mcp-server` 产出 2 条 finding（`mcp/tool-parameter-to-sink`），且每条都带完整的**数据流路径**（`codeFlows` 路径链，如 `server.py:73 → 84 → 85 → 50 → 55 → 86`），并作为对等线路参与四线融合。

**原结论（修复前）：CodeQL 不是"没发现问题"，是"没装上查询库 + 错误被静默吞掉"，0 是一个假阴性。** 下述根因链已全部修复。

### 修复内容（对照三个根因）

| 根因 | 修复 |
|---|---|
| 标准查询库没装 | 配置 `[static.codeql].binary` 指向含 qlpacks 的 CodeQL（`/home/xiao/codeql-home/codeql/codeql`），内置查询包 `qlpack.yml` 声明 `codeql/python-all` 依赖 |
| 内置 `.ql` 跑不起来 | 3 个查询改为 `@kind path-problem` + `import <Flow>::PathGraph` + 标准 6 列 select，产出完整路径链（原为 `@kind problem`，不产出 `codeFlows`） |
| 失败被静默吞掉 | `run_analysis` 检查 `exit_code`（非 0 直接 `bail!`）、把 SARIF 写到临时文件再读取（`--output=-` 在 2.25.6 下不输出 SARIF）、stderr 进入错误信息 |

### 根因 1（历史记录）：CodeQL 标准查询库根本没装

实测：

```bash
$ codeql resolve queries codeql/python-queries
A fatal error occurred: Query pack codeql/python-queries cannot be found.
```

CodeQL CLI 本身装了（2.26.2），但 `/home/xiao/App/codeql/codeql/` 下**没有 `qlpacks/` 目录**，`codeql resolve qlpacks` 只列出 `legacy-upgrades`。

而代码里 `codeql/queries.rs` 硬编码了两个 suite 引用：

```rust
suite_refs: vec!["codeql/python-queries", "codeql/javascript-queries"]
```

这两个 pack 都不存在，`codeql database analyze` 直接 fatal。

### 根因 2（历史记录）：内置的 3 个 `.ql` 文件也跑不起来

`ToolParameterToSink.ql` 开头就是 `import python` / `import semmle.python.dataflow...`，这些标准库模块同样没装。单个 `.ql` 虽能被识别为 "anonymous QL pack"，但一编译就因找不到 `python` 模块失败。

### 根因 3（历史记录，最严重）：失败被静默吞掉

`codeql/provider.rs` 的 `run_analysis`：

```rust
let _ = err.read_to_string(&mut stderr);   // stderr 被丢弃
let status = child.wait();
let exit_code = ...;
let _ = tx.send((stdout, stderr, exit_code)); // 只取 stdout
...
match rx.recv_timeout(timeout) {
    Ok((stdout, _stderr, _exit_code)) => Ok(stdout),  // exit_code 完全不管
    ...
}
```

`codeql database analyze` 失败后 stdout 为空，但函数只要进程没超时/没断开就返回 `Ok("")`。随后 `parse_sarif("")` 解析空串报错，错误被塞进 `diagnostics`——而 **diagnostics 根本没进 markdown 报告**。最终呈现为 "CodeQL Results: 0"，看起来像"没发现问题"，实际是"根本没跑成"。

---

## 4. 系统整体的不足与问题

1. **结果不可复现（非确定性）**：agent 真实调用 `claude -p <prompt>`（`agent/provider.rs`），LLM 输出天然不稳定。同一份代码三次运行 `Agent` 6/5/6 条、`Fused` 6/5/4 条——对安全审计是硬伤。

2. **"融合"名不副实，没有真正的交叉印证**：配置 `require_confirmed_by = 1`，意味着**任何一条线路单方面报的都算数**。报告里每条 Fused Finding 都只有 **一个** `Supported by`（rule/agent/taint 各自单飞），`boost_when_multiple_lines_agree` 从未触发。更明显的是：rule 报的 `network_request`(server.py:9) 和 taint 报的 `mcp_tool_parameter → network_request` 本质是同一个问题，却被拆成两条独立 finding——**matcher 没能把跨线路的同一问题关联起来**。当前 fusion 更像"汇总 + 贴标签"，而非"多线路互相印证置信度"。

3. **严重度(severity)与置信度(confidence)被混为一谈**：taint 和 agent 的结果结构里没有 severity 字段，`fusion/scorer.rs` 拿 confidence 硬映射成 severity（`taint_confidence_to_severity` / `confidence_to_severity`）。"我们有多确定"和"问题多严重"是两个正交维度，这里被合并，会误导排序与分级。

4. **四条线路四种数据结构**（`RuleAnalysisResult` / `TaintAnalysisResult` / `AgentAnalysisResult` / `CodeqlAnalysisResult` 各不相同），fusion 要写大量适配代码去对齐，这也是"关联不起来"的结构性原因。

5. **故障静默降级（不止 CodeQL）**：agent 的 `stderr`/`exit_code` 也标着 `#[allow(dead_code)]`"尚未在报告中呈现"；任何一条线路失败，用户看到的是"少了几条"而不是"这条线挂了"。

6. **rule 线路假阳性风险高**：纯模式匹配无语义，已出现 `open(` 被归类成 `network_request` 的错配（报告第一条 Fused Finding 标题是 `open(` 但类别是 `network_request`）。

---

## 5. 改进优先级建议

1. ~~**修 CodeQL 静默失败**~~ ✅ **已完成**（见 §3）：安装标准库、`run_analysis` 检查 `exit_code`（非 0 直接 `bail!`）、SARIF 写临时文件、stderr 进入错误信息均已落地，CodeQL 现已产出 2 条带数据流路径的 finding。

2. **让 fusion 真正交叉印证**：把 `require_confirmed_by` 默认提到 2，并修 matcher 让"rule 的 network_request"和"taint 的 network_request"能关联成一组。

3. **确定性**：agent 结果要么固定 model/seed、要么跑多次取交集，否则审计结论不可复现。

4. **分离 severity 与 confidence**：为 taint/agent 结果补独立 severity 字段，不再用 confidence 映射。

5. **线路失败必须显式告警**：任何线路报错/超时/空结果都应作为诊断信息进入最终报告，而不是静默降级。
