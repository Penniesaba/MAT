# Rust 静态分析结果改进计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复 Rust 静态分析本次运行暴露的准确性与融合（fusion）缺陷，使四条分析线能交叉印证、锚点精确、报告自洽。

**Architecture:** 问题集中在三个层面：规则线（纯文本匹配，无 import 别名解析、锚点落在 `use` 语句）、fact 提取（id 用文件父目录导致路径只剩 basename、方法链展平产生重复 sink、assign value 混入 AST Debug）、融合与报告（按原文路径精确比较导致永不合并、severity/confidence 混淆）。本计划按 P0→P2 优先级，每个任务独立可测、独立提交。

**Tech Stack:** Rust (edition 2024, `syn` 2 / `swc_core` / `rustpython-parser`)，`cargo test` 单测，`cargo run --release -- <config.toml>` 端到端。

**Spec:** 本计划依据对运行结果 `rust/docs/20260818-235257.md` 与 `20260818-235054.json` 的逐项核对，以及下述源码的实读定位。

---

## Global Constraints

- 工作区根：`rust/`（所有 `cargo` 命令从该目录运行；相对路径配置均基于该 cwd 解析）。
- 保持 fact id 的既有序列化格式稳定——改 id 会破坏 `ids.rs` 测试和已生成报告，除非任务明确要求。
- 不改变 `rust-config.toml` 的相对路径约定（`targets`/`rule_paths` 相对 cwd）。
- 每次改动后 `cargo test` 全绿；端到端用 `./target/release/mcp-sec-audit ../test-targets/configs/rust-config.toml` 验证。

---

## 根因总览（与结果对照）

| # | 观察到的现象（本次结果） | 根因 | 代码位置 |
|---|---|---|---|
| 1 | 9 个 fused finding 全部单线支撑，无任何 rule+taint/agent 交叉印证 | 规则锚点落在 `use` 语句 + 路径归一化不一致，融合按原文精确比较 | `rule/mod.rs` `mask_rust`；`facts/pipeline.rs` `root`；`fusion/matcher.rs` |
| 2 | `file_write` 规则线漏报，只靠 taint 兜底 | 规则关键字是 `std::fs::write`，源码是 `use std::{fs,io}` + `fs::write`，未做别名解析 | `rule/mod.rs` `match_keyword_indicator` |
| 3 | 8 个 sink 实际只有 4 个真实 sink，23 个 call 大量同语句中间态 | 方法链 `.arg().arg().output()` 被逐级展平，每级都触发 `check_sink` | `facts/rust/mod.rs` `check_sink` |
| 4 | markdown `[Medium]` 与 `Risk Level: high` 矛盾 | markdown 打印的是 `confidence`，summary 的 risk_level 由 `severity` 算出 | `reporting.rs:215` |
| 5 | `assign.value` 出现 `<Expr::Try {...}>`、`<Expr::Unsafe {...}>` | `expr_to_string` 对 `Try`/`Unsafe` 无匹配分支，落入 Debug 兜底 | `facts/rust/display.rs` |
| 6 | `dataflow.path` 恒为空，融合无 `Dataflow path` | `build_dataflow_facts` 写死 `file=""`，路径步骤未持久化/未输出 | `taint/result.rs` |
| 7 | deserialization reason 声称 RCE，对 `serde_json` 不实 | sink reason 套用通用模板，未按库分级 | `facts/rust/sinks.rs` |
| 8 | CodeQL 开启但返回 0 | CodeQL 不支持 Rust，管线未显式跳过 | `codeql/mod.rs` |

---

## P0-1：修复融合零交叉印证（锚点 + 路径归一化）

这是本次结果最核心的缺陷，分两个子任务，**二者都完成融合才会真正生效**（缺一不可，见下）。

### Task 1: 规则线屏蔽 `use`/`mod`/`extern crate` 语句，锚点落到真实调用

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/rule/mod.rs`（`mask_rust` 函数，约 200-270 行）

**Interfaces:**
- Consumes: 无（纯函数内改动）。
- Produces: `mask_rust` 的返回值——除注释/字符串外，`use`/`mod`/`extern crate` 语句也被空格掩码，行号不变。

**原因**：`command_execution` 的首命中是 `helpers.rs:6` 的 `use std::process::Command;`，而不是 `main.rs:33-36` 的真实 `Command::new(...).output()`。掩码 import 后，`command_execution` 只剩 `.output()` 命中，锚点变为 `main.rs:36`（真实 sink 附近），与 taint 的 `main.rs:33` 在 `line_proximity=5` 内，才能融合。

- [ ] **Step 1: 写失败测试** —— 在 `rule/mod.rs` 的 `#[cfg(test)] mod tests` 末尾加：

```rust
#[test]
fn rust_use_statement_is_not_matched_as_code() {
    let root = temp_dir("rule-rust-use");
    let file = root.join("main.rs");
    fs::write(
        &file,
        "use std::process::Command as ShellCmd;\nfn f() {\n    let o = ShellCmd::new(\"sh\").output();\n}\n",
    )
    .expect("write source");
    let rulebook = parse_rulebook_toml(
        r#"
        [[capabilities]]
        name = "command_execution"
        weight = 25.0
        base_confidence = 0.4
          [[capabilities.indicators]]
          languages = ["rust"]
          type = "keyword"
          patterns = ["std::process::Command", "Command::new", ".output()"]
        "#,
    )
    .expect("parse rules");
    let ctx = context_with_files(vec![DiscoveredFile {
        path: file,
        language: ScanLanguage::Rust,
    }]);

    let results = analyze_rule_line(&ctx, &rulebook).expect("analyze rules");
    assert_eq!(results.len(), 1);
    // 锚点应落在真实调用 .output() 的第 3 行，而非 use 语句的第 1 行
    assert_eq!(results[0].line, 3);
    assert!(!results[0].evidence.iter().any(|e| e.contains(":1:")));

    fs::remove_dir_all(root).expect("cleanup");
}
```

- [ ] **Step 2: 运行确认失败**：`cargo test -p mcp-sec-audit-core rule::tests::rust_use_statement_is_not_matched_as_code`。预期 FAIL（当前 `line == 1`，因为 `use` 语句被匹配）。

- [ ] **Step 3: 实现** —— 在 `mask_rust` 中，字符串/注释处理之外，新增对 `use`/`mod`/`extern crate` 项级语句的掩码。在 `mask_rust` 的 while 循环里、`b == b'"'` 分支之前插入：

```rust
} else if is_rust_item_keyword_at(bytes, i) {
    // use / mod / extern crate 项：掩码到行尾分号，保留换行。
    while i < n && bytes[i] != b';' && bytes[i] != b'\n' {
        out[i] = b' ';
        i += 1;
    }
    if i < n && bytes[i] == b';' {
        out[i] = b' ';
        i += 1;
    }
}
```

并在文件内新增辅助函数（`use`/`mod`/`extern crate` 在 Rust 中仅作为项级关键字出现，且必须是行首或 `{` 后，故可安全识别）：

```rust
fn is_rust_item_keyword_at(bytes: &[u8], i: usize) -> bool {
    let at_boundary = i == 0
        || bytes[i - 1] == b'\n'
        || bytes[i - 1] == b'{'
        || bytes[i - 1] == b' '
        || bytes[i - 1] == b'\t';
    if !at_boundary {
        return false;
    }
    ["use ", "mod ", "extern crate "]
        .iter()
        .any(|kw| bytes[i..].starts_with(kw.as_bytes()))
}
```

> 注意：多行 `use std::{ fs, io };` 会掩码到 `;` 或首个换行。`use std::{\n fs,\n io\n};` 场景下首个换行后 `fs,`/`io` 行不会被掩码，但 `fs,`/`io` 本身不含 `std::fs::write` 之类完整模式，风险可忽略；如需彻底，可跟踪到匹配 `;` 并保留所有换行——作为后续增强，不阻塞本任务。

- [ ] **Step 4: 运行确认通过**：同上测试命令，预期 PASS。再跑全量 `cargo test -p mcp-sec-audit-core`，确认既有 `python_*`/`js_*` 测试不受影响。

- [ ] **Step 5: 提交**：

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/rule/mod.rs
git commit -m "fix(rule): mask use/mod/extern-crate items so rule hits anchor to real code"
```

### Task 2: 融合按 basename 归一化文件，消除 fact 与 rule 的路径不一致

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/fusion/matcher.rs`（`can_join_group_proximity`、`can_join_group_category`，约 230-280 行）

**Interfaces:**
- Consumes: `Matchable.file`（rule 为完整 discovered 路径，taint 为 `sink_id` 里的 basename，agent/codeql 为首个 location）。
- Produces: `can_join_group_*` 的相等判断从「整串路径相等」变为「basename 相等」。

**原因**：`facts/pipeline.rs` 用 `root = file.path.parent()`（`src/main.rs` 的 parent 是 `src/`），导致 `make_sink_id` 产出 `sink:command_execution:main.rs:33`（basename）。而 rule 的 `file` 是完整路径 `../test-targets/rust-mcp-server/src/main.rs`。`matcher.rs` 的 `member.file == candidate.file` 永远为 false。用 basename 作匹配键即可打通（同一扫描内同 basename 不同目录的概率低，风险已接受并标注）。

- [ ] **Step 1: 写失败测试** —— 在 `matcher.rs` 的 `#[cfg(test)] mod tests` 加：

```rust
#[test]
fn matches_rule_full_path_with_taint_basename() {
    // rule 用完整路径，taint sink_id 只含 basename —— 应能融合
    let rules = vec![make_rule("r1", "proj/src/main.rs", 33, "cmd_inj", Confidence::High)];
    let taints = vec![make_taint("t1", "sink:command_execution:main.rs:36", "command_execution", Confidence::Medium)];
    let groups = match_results(rules, taints, vec![], vec![], 5);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].supported_by(), vec!["rule", "taint"]);
}
```

- [ ] **Step 2: 运行确认失败**：`cargo test -p mcp-sec-audit-core fusion::matcher::tests::matches_rule_full_path_with_taint_basename`。预期 FAIL（当前 2 个 solo 组）。

- [ ] **Step 3: 实现** —— 新增归一化辅助函数，并在两处比较里使用：

```rust
use std::path::Path;

/// 取文件身份键：优先 basename（`a/b/main.rs` → `main.rs`）。
/// 消除 rule（完整路径）与 fact-derived（basename）之间的路径不一致。
fn file_key(file: &str) -> &str {
    Path::new(file)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(file)
}
```

`can_join_group_proximity` 改为：

```rust
let member_key = file_key(&member.file);
let candidate_key = file_key(&candidate.file);
member_key == candidate_key
    && member.line.abs_diff(candidate.line) <= line_proximity
```

`can_join_group_category` 同理：

```rust
file_key(&member.file) == file_key(&candidate.file)
    && member.category == candidate.category
```

- [ ] **Step 4: 运行确认通过**：同上测试 + 全量 `cargo test -p mcp-sec-audit-core`。既有 `stage1_*`/`stage2_*` 测试里文件名本就一致（`a.py` vs `a.py`），basename 归一化不改变其行为。

- [ ] **Step 5: 提交**：

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/fusion/matcher.rs
git commit -m "fix(fusion): match results by basename to bridge rule/fact path mismatch"
```

### 端到端验证（P0-1 完成标志）

- [ ] 重跑 `./target/release/mcp-sec-audit ../test-targets/configs/rust-config.toml`，确认报告中 `command_execution`/`deserialization` 的 fused finding 出现 `Supported by: rule, taint`（或 rule+taint+agent），且总数从 9 下降到接近真实漏洞数（约 4-6）。

---

### Task 3: 规则线 import 别名解析（消除 `file_write` 盲区）

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/rule/mod.rs`（`collect_inputs` / `analyze_rule_line`）

**Interfaces:**
- Consumes: `RuleInput.text`（已掩码源码）、`indicator.patterns`（如 `std::fs::write`）。
- Produces: 对 Rust 文件额外生成的别名模式匹配——`use std::{fs, io}` 后，`fs::write` 命中 `file_write`。

**原因**：源码 `use std::{fs, io};` + `fs::write(&dest_path, ...)`。规则关键字是 `std::fs::write`，字面匹配不到 `fs::write`。sink 提取因有 `resolve_callee` 做了别名归一化所以能命中，规则线没有这层。

**设计取舍（二选一，推荐 B）：**

- **方案 A（补规则表）**：给 `rust` 的 `file_read`/`file_write`/`network_request` 直接补 `fs::read`、`fs::write`、`File::open` 等短形式。改动最小，但治标——`use foo as bar` 任意重命名仍会漏。
- **方案 B（推荐，别名展开）**：规则匹配前为每个 Rust 文件构建 `alias → 完整路径` 映射（解析 `use` 语句），把形如 `std::fs::write` 的模式展开成 `{alias}::write` 一并匹配。

- [ ] **Step 1: 写失败测试**（按方案 B）：

```rust
#[test]
fn rust_alias_import_matches_file_write() {
    let root = temp_dir("rule-rust-alias");
    let file = root.join("main.rs");
    fs::write(
        &file,
        "use std::{fs, io};\nfn f(p: &str) { fs::write(p, b\"x\"); }\n",
    )
    .expect("write source");
    let rulebook = parse_rulebook_toml(
        r#"
        [[capabilities]]
        name = "file_write"
        weight = 15.0
        base_confidence = 0.35
          [[capabilities.indicators]]
          languages = ["rust"]
          type = "keyword"
          patterns = ["std::fs::write", "File::create"]
        "#,
    )
    .expect("parse rules");
    let ctx = context_with_files(vec![DiscoveredFile {
        path: file,
        language: ScanLanguage::Rust,
    }]);
    let results = analyze_rule_line(&ctx, &rulebook).expect("analyze rules");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].rule_id, "file_write");
    assert_eq!(results[0].line, 2);
    fs::remove_dir_all(root).expect("cleanup");
}
```

- [ ] **Step 2: 运行确认失败**：`cargo test -p mcp-sec-audit-core rule::tests::rust_alias_import_matches_file_write`。预期 FAIL（当前无命中）。

- [ ] **Step 3: 实现**：在 `RuleInput` 增加 `aliases: Vec<(String, String)>`（别名→完整路径）。`collect_inputs` 里对 Rust 文件解析 `use` 语句填充别名（复用 `facts/rust/display.rs` 的 `use_tree_summary` 或写一个轻量解析）。`analyze_rule_line` 匹配 keyword 时，对每个 `pattern = "std::fs::write"`，若存在别名 `fs → std::fs`，额外构造 `fs::write` 一并 `find`。

   核心片段（在 `match_keyword_indicator` 调用前展开）：

```rust
fn expanded_patterns<'a>(patterns: &'a [String], aliases: &[(String, String)]) -> Vec<String> {
    let mut out = patterns.to_vec();
    for p in patterns {
        for (alias, full) in aliases {
            if let Some(tail) = p.strip_prefix(full) {
                out.push(format!("{alias}{tail}"));
            }
        }
    }
    out
}
```

- [ ] **Step 4: 运行确认通过**：同上测试 + 全量 `cargo test -p mcp-sec-audit-core`。

- [ ] **Step 5: 提交**：

```bash
git add crates/mcp-sec-audit-core/src/static_analysis/rule/mod.rs
git commit -m "feat(rule): expand keyword patterns through rust use-aliases"
```

> 后续增强（不阻塞）：把别名解析逻辑抽到 `facts/rust` 复用，避免 rule 与 sink 各写一套 `use` 解析。

---

### Task 4: sink/call 方法链展平去重

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/rust/mod.rs`（`check_sink` 与 call 提取处）

**原因**：`ShellCmd::new("sh").arg("-c").arg(&shell_cmd).output().map_err(...)` 一条语句被逐级（`.new` / `.new().arg` / …）展平成 5 个 sink + 6 个 call，全部同 `call_id:main.rs:33:0`。这污染 facts，也拖累融合去重。

- [ ] **Step 1: 写失败测试**：对 `extract_rust_facts` 传含单条方法链的源码，断言该语句只产生 **1 个** `Fact::Sink` 与 **1 个** `Fact::Call`（当前会产生多个）。

- [ ] **Step 2: 实现**：在调用链提取时，仅对外层/最完整的方法链 emit 一个 call 与一个 sink，按 `call_id`（`call:main.rs:33:0`）去重——若同一 `line:column` 已 emit 过 call/sink，跳过中间态。

- [ ] **Step 3: 端到端**：重跑后 `sink: 8` 应降到约 4-5，`call: 23` 明显下降。

---

### Task 5: 报告 severity 与 confidence 一致性

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/reporting.rs`（`render_markdown`，约 213-217 行）

**原因**：markdown 的 `[Medium]` 是 `finding.confidence`，而顶部 `Risk Level: high` 由 `severity` 算出，二者口径不一致，读者必然误解。

- [ ] **Step 1: 实现**：fused finding 行同时显式标注两者，例如：

```rust
lines.push(format!(
    "- **{}** [sev: {:?}, conf: {:?}] — {}",
    finding.title, finding.severity, finding.confidence, finding.category
));
```

- [ ] **Step 2: 确认**：`FusedFinding` 模型含 `severity` 与 `confidence` 字段（若缺失则先从 `ScoredGroup` 透传）。重跑报告，确认 `sev: high` 与 `Risk Level: high` 自洽。

> 说明：历史提交 `6f96096` 曾「drop subjective severity」，若产品上确实不想要 severity，则改为**移除 summary 的 `risk_level` 行**而不是显示 confidence 顶替，二选一需在实现时确认。

---

### Task 6: assign value 去 AST Debug，输出源码片段

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/rust/display.rs`（`expr_to_string`）

**原因**：`Expr::Try` / `Expr::Unsafe` 无匹配分支，落入 `_ => format!("<{expr:?}>")`，产出 `<Expr::Try { attrs: [], ...` 这类不可读转储。

- [ ] **Step 1: 实现**：为 `Expr::Try`、`Expr::Unsafe` 补分支：

```rust
Expr::Try(try_expr) => format!("{}?", expr_to_string(&try_expr.expr)),
Expr::Unsafe(unsafe_expr) => format!("unsafe {{ ... }}"),
```

（`Unsafe` 内容可后续用 `block` 内语句源码拼接，先给稳定占位，消除 Debug 噪声。）

- [ ] **Step 2: 确认**：重跑后 `assign.value` 不再出现 `<Expr::` 前缀。

---

### Task 7: taint 记录并输出 dataflow 路径

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/taint/result.rs`（`build_dataflow_facts`，约 40-70 行）

**原因**：跨函数传播正确（`load_config` 的 sink 落在 `helpers.rs:25`），但 `path` 步骤未持久化、`file` 写死 `""`，报告拿不出调用链。

- [ ] **Step 1: 实现**：`build_dataflow_facts` 的 `file` 从 `path.source_id`/`path.sink_id` 推导，`path` 用 `path.steps` 的 `snippet`/`name` 序列填充；`render_markdown` 已支持 `dataflow_path` 输出（`reporting.rs` 224-229 行），无需改渲染层，只需保证 `fused_finding.dataflow_path` 非空即可。

---

### Task 8: sink reason 按库分级 + unsafe 语义化

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/facts/rust/sinks.rs`

**原因**：`serde_json::from_str` 的 reason 写成 "can cause type-confusion or RCE"，对 `serde_json`（内存安全）不实；agent 线已正确纠偏。`unsafe {` 正则命中不判断块内是否真有未防护操作（本次 `copy_nonoverlapping` 实为 capacity==len 的安全用法，属过报）。

- [ ] **Step 1: 实现**：`deserialization` 按库拆 reason——`serde_json` → "safe format, still unvalidated schema"（Medium），`bincode`/`serde` 派生 → 保留 RCE 措辞（High）。unsafe 检测从正则 `unsafe\s*\{` 升级为：命中后检查块内是否含裸指针解引用/`transmute`/未初始化读写，无则降为 Low 或提示 "no unsafe operation detected"。

---

### Task 9: CodeQL 对 Rust 显式跳过

**Files:**
- Modify: `crates/mcp-sec-audit-core/src/static_analysis/codeql/mod.rs`（`run` 入口）

**原因**：Rust 不在 CodeQL 支持范围内，`enabled=true` 静默返回 0，误导。

- [ ] **Step 1: 实现**：`codeql::run` 开头检查目标语言集合，若不含 python/js/ts 则 `progress("CodeQL skipped: no supported language in target")` 并返回空，不改动结果结构。

---

## 执行顺序与依赖

1. **Task 1 + Task 2 必须成对落地**，融合才会从「9 个单线」收敛到「多线印证」。二者互不依赖，可并行。
2. **Task 3** 依赖 Task 1 的 `mask_rust` 改动（同一文件），必须紧随其后（R2）。
3. **Task 4/5/6** 相互独立，可并行。
4. **Task 7/8/9** 为质量增强，排最后。

## 完成后的验收标准

- [ ] 重跑 Rust 目标，`Fused Findings` 从 9 → 约 4-6，且 `command_execution`/`deserialization`/`file_write` 至少一项出现 `rule + taint` 或 `rule + taint + agent` 交叉印证。
- [ ] `Risk Level` 与各 finding 的 severity/confidence 口径一致。
- [ ] `assign.value` 无 `<Expr::` 前缀；`dataflow` 输出非空调用链。
- [ ] `cargo test` 全绿。
