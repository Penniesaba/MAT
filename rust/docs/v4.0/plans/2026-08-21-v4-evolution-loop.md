# v4.0 M2 进化闭环 实现计划

> **给执行者：** 必用子技能：superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务实现。步骤用复选框（`- [ ]`）跟踪。

**目标：** 落地 M2 的三大进化闭环核心机制——可回滚的 catalog 进化（staging + rollback）、验证提示词（prompt'）、跨阶段迁移校验。

**架构：** 三个纯函数、各自单测：(1) `learning.rs` 新增 `stage_catalog_evolution`，把门控后的 sink 候选转成可回滚的 `StagedDelta`（指纹 + staging 目录，rollback = 删 staging）；(2) `agent/prompt.rs` 新增 `render_verification_prompt`，注入 a1「请复核」/ a2「请勿重复报告」两段；(3) 新增 `validate.rs`，计算跨阶段集合迁移（哪些 b 独有被 A' 追上、哪些新 A' 独有是污染信号）+ `should_rollback` 决策。**本计划不重构 pipeline 成两阶段——那是 M3。**

**技术栈：** Rust（edition 2024，rust-version 1.88），workspace crate `mcp-sec-audit-core`，`anyhow`，`tracing`。

**规格：** `rust/docs/v4.0/IDEA_EVALUATION_AND_DESIGN.md`（§7.1 分层验证、§7.2 门控+试探性加入、§7.3 回滚机制、§7.4 验证提示词、§5.4 跨阶段集合迁移）。

## 全局约束

- Rust edition **2024**，`rust-version = "1.88"`。
- 代码在 `rust/crates/mcp-sec-audit-core/src/static_analysis/`。
- `serde` 固定 `=1.0.224` —— 不要 bump；不加新外部依赖（只用 std）。
- `ModelCatalog` 按语言键 `"python" | "javascript" | "rust"` 分组，用 `sinks_for_language` 访问。
- 沿用现有约定：内部用 `pub(crate)`，分类用 snake_case，`tracing` target 用 `mcp_sec_audit::*`。
- M1 的 `Component` trait 在本计划保持最小（tool + fingerprint）——进化直接操作 `ModelCatalog`，不在泛型 trait 上加方法（trait 的 `evolve/promote/rollback` 推迟到 M3 pipeline 真正在两阶段间替换 component 时再加）。

---

### 任务 1：可回滚的 catalog 进化（`learning.rs`）

为门控后的 sink 候选加 staging + 指纹 + rollback，使进化可试探性应用、可回退，且不碰 `learned/`。

**文件：**
- 修改：`rust/crates/mcp-sec-audit-core/src/static_analysis/learning.rs`

**接口：**
- 消费：`crate::models::{ModelCatalog, SinkModel}`、`crate::model::{ModelCandidate, Confidence, Severity}`。
- 产出：
  - `learning::StagedDelta { base_fingerprint: String, models: Vec<SinkModel>, fingerprint: String }`
  - `learning::catalog_fingerprint(&ModelCatalog) -> String`
  - `learning::stage_catalog_evolution(&ModelCatalog, &[ModelCandidate]) -> Option<StagedDelta>`
  - `learning::write_staging(&Path, &StagedDelta) -> anyhow::Result<()>`
  - `learning::rollback_staging(&Path) -> anyhow::Result<()>`

- [ ] **步骤 1：扩展 imports**

`learning.rs` 顶部 import 改成引入 `ModelCatalog` 和 `BTreeSet`：

```rust
use std::collections::BTreeSet;
use std::path::Path;

use crate::model::{Confidence, Fact, FactBase, ModelCandidate, Severity, SinkFact};
use crate::models::{ModelCatalog, rule_prefix, PackageRule, SinkModel};
```

- [ ] **步骤 2：写失败的测试**

追加到 `learning.rs` 现有 `#[cfg(test)] mod tests`：

```rust
    #[test]
    fn catalog_fingerprint_is_deterministic_and_content_sensitive() {
        let a = crate::models::default_catalog();
        let b = crate::models::default_catalog();
        assert_eq!(catalog_fingerprint(&a), catalog_fingerprint(&b));
        let mut extra = crate::models::default_catalog();
        extra.merge(crate::models::ModelCatalog::from_sinks(vec![SinkModel {
            language: "python".into(), category: "file_read".into(),
            severity: Severity::Medium, confidence: Confidence::Low,
            reason: "x".into(), patterns: vec!["novel.read".into()],
            source: None, learned_from: None,
        }]));
        assert_ne!(catalog_fingerprint(&a), catalog_fingerprint(&extra));
    }

    #[test]
    fn stage_dedups_existing_and_returns_none_when_noop() {
        let catalog = crate::models::default_catalog();
        // subprocess.run 已是内置 python sink —— staging 它是 no-op。
        let cand = cand_lang("subprocess.run", "command_execution", "python");
        assert!(stage_catalog_evolution(&catalog, &[cand]).is_none());
    }

    #[test]
    fn stage_builds_delta_for_new_sink() {
        let catalog = crate::models::default_catalog();
        let cand = cand_lang("brand_new.lib.read", "file_read", "python");
        let delta = stage_catalog_evolution(&catalog, &[cand]).expect("new sink stages");
        assert_eq!(delta.models.len(), 1);
        assert_eq!(delta.models[0].patterns, vec!["brand_new.lib.read"]);
        assert_eq!(delta.base_fingerprint, catalog_fingerprint(&catalog));
    }

    #[test]
    fn staging_roundtrips_and_rollback_removes_dir() {
        let catalog = crate::models::default_catalog();
        let cand = cand_lang("brand_new.lib.read", "file_read", "python");
        let delta = stage_catalog_evolution(&catalog, &[cand]).unwrap();
        let dir = std::env::temp_dir().join(format!("staging-test-{}", std::process::id()));
        write_staging(&dir, &delta).expect("write staging");
        assert!(dir.join("staged-brand_new_lib_read.toml").exists());
        rollback_staging(&dir).expect("rollback");
        assert!(!dir.exists());
    }
```

- [ ] **步骤 3：跑一下确认失败**

运行：`cargo test -p mcp-sec-audit-core learning::tests::catalog_fingerprint_is_deterministic_and_content_sensitive`
预期：FAIL（编译错误 —— `catalog_fingerprint`/`StagedDelta`/`stage_catalog_evolution` 未定义）。

- [ ] **步骤 4：实现**

把下面代码追加到 `learning.rs`（放在现有 `write_learned_sinks` 之后、`severity_str`/`confidence_str` 辅助函数之前，或任意模块作用域位置 —— 只要在 `#[cfg(test)]` 之上）：

```rust
/// 一次暂存（试探性、可回退）的 catalog 进化。`base_fingerprint` 是进化前的身份
/// （回退锚点）；`fingerprint` 标识 delta 本身。
pub(crate) struct StagedDelta {
    pub(crate) base_fingerprint: String,
    pub(crate) models: Vec<SinkModel>,
    pub(crate) fingerprint: String,
}

/// `ModelCatalog` 的确定性内容身份：排序后的 `language:category:pattern` 条目用 `|` 连接。
pub(crate) fn catalog_fingerprint(catalog: &ModelCatalog) -> String {
    let mut entries = Vec::new();
    for lang in ["python", "javascript", "rust"] {
        for m in catalog.sinks_for_language(lang) {
            for p in &m.patterns {
                entries.push(format!("{lang}:{}:{}", m.category, p));
            }
        }
    }
    entries.sort();
    entries.join("|")
}

/// 把门控后（Hot/Warm）的 sink 候选转成可回退的 `StagedDelta`，对现有 catalog 去重。
/// 没有新增时返回 `None`。G1 门控（`gate_sink_candidate`）与 G2 可表达性
/// （`diff::classify_candidate`）由调用方在更上游完成。
pub(crate) fn stage_catalog_evolution(
    catalog: &ModelCatalog,
    candidates: &[ModelCandidate],
) -> Option<StagedDelta> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for lang in ["python", "javascript", "rust"] {
        for m in catalog.sinks_for_language(lang) {
            for p in &m.patterns {
                seen.insert(format!("{lang}:{}:{}", m.category, p));
            }
        }
    }

    let mut models = Vec::new();
    for c in candidates {
        if c.kind != "sink" || c.name.trim().is_empty() || c.category.trim().is_empty() {
            continue;
        }
        let key = format!("{}:{}:{}", c.language, c.category, c.name);
        if seen.insert(key) {
            models.push(SinkModel {
                language: c.language.clone(),
                category: c.category.clone(),
                severity: Severity::Medium,
                confidence: c.confidence.clone(),
                reason: format!(
                    "staged sink: {} (evidence: {})",
                    c.category,
                    c.evidence_snippets.first().cloned().unwrap_or_default()
                ),
                patterns: vec![c.name.clone()],
                source: Some("learned-staged".to_string()),
                learned_from: None,
            });
        }
    }

    if models.is_empty() {
        return None;
    }
    let base_fingerprint = catalog_fingerprint(catalog);
    let mut fp = models
        .iter()
        .flat_map(|m| m.patterns.iter().map(|p| format!("{}:{}:{}", m.language, m.category, p)))
        .collect::<Vec<_>>();
    fp.sort();
    let fingerprint = fp.join("|");
    Some(StagedDelta { base_fingerprint, models, fingerprint })
}

/// 把暂存 delta 写到 staging 目录（不是 `learned/`），每个模型一个 TOML 文件。
pub(crate) fn write_staging(dir: &Path, delta: &StagedDelta) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (i, m) in delta.models.iter().enumerate() {
        let safe = m.patterns.first()
            .map(|p| p.replace(['.', ':', '/'], "_"))
            .unwrap_or_else(|| i.to_string());
        let text = format!(
            "[[sinks]]\nlanguage = {:?}\ncategory = {:?}\nseverity = {:?}\nconfidence = {:?}\nreason = {:?}\npatterns = {:?}\nsource = \"learned-staged\"\nlearned_from = {:?}\n",
            m.language, m.category, severity_str(&m.severity), confidence_str(&m.confidence),
            m.reason, m.patterns, m.learned_from.as_deref().unwrap_or("staged")
        );
        std::fs::write(dir.join(format!("staged-{safe}.toml")), text)?;
    }
    Ok(())
}

/// 回退一次暂存进化：删除 staging 目录。`learned/` 不动。
pub(crate) fn rollback_staging(dir: &Path) -> anyhow::Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}
```

- [ ] **步骤 5：跑 learning 测试**

运行：`cargo test -p mcp-sec-audit-core learning::tests`
预期：PASS（现有 + 4 个新）。

- [ ] **步骤 6：提交**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/learning.rs
git commit -m "feat(v4): add reversible catalog evolution (staging + rollback)"
```

---

### 任务 2：验证提示词（`agent/prompt.rs`）

加一个函数渲染 `prompt'` = 基础 prompt + a1「请复核」段 + a2「请勿重复报告」段。

**文件：**
- 修改：`rust/crates/mcp-sec-audit-core/src/static_analysis/agent/prompt.rs`

**接口：**
- 产出：
  - `prompt::PromptFinding { location: String, category: String, note: String }`
  - `prompt::render_verification_prompt(base: &str, recheck: &[PromptFinding], do_not_report: &[PromptFinding]) -> String`

- [ ] **步骤 1：写失败的测试**

追加到 `prompt.rs` 现有 `#[cfg(test)] mod tests`：

```rust
    #[test]
    fn renders_recheck_and_do_not_report_sections() {
        let base = "Role: auditor\n";
        let out = render_verification_prompt(
            base,
            &[PromptFinding { location: "a.py:10".into(), category: "command_execution".into(), note: "os.system(cmd)".into() }],
            &[PromptFinding { location: "b.py:20".into(), category: "network_request".into(), note: "get_excel_path is local".into() }],
        );
        assert!(out.contains("请重点复核"));
        assert!(out.contains("a.py:10"));
        assert!(out.contains("请勿重复报告"));
        assert!(out.contains("b.py:20"));
        assert!(out.starts_with(base));
    }

    #[test]
    fn empty_inputs_return_base_unchanged() {
        let base = "just the base\n";
        assert_eq!(render_verification_prompt(base, &[], &[]), base);
    }
```

- [ ] **步骤 2：跑一下确认失败**

运行：`cargo test -p mcp-sec-audit-core agent::prompt::tests::renders_recheck_and_do_not_report_sections`
预期：FAIL（编译错误 —— `render_verification_prompt`/`PromptFinding` 未定义）。

- [ ] **步骤 3：实现**

追加到 `prompt.rs`（模块作用域，`#[cfg(test)]` 之上）：

```rust
/// 注入验证提示词的一条 finding 引用。
pub(crate) struct PromptFinding {
    pub(crate) location: String, // "file:line"
    pub(crate) category: String,
    pub(crate) note: String,     // 证据，或「为什么可能是误报」
}

/// 渲染验证提示词（`prompt'`）：基础 prompt 加上两段标签——a1 项「请复核」（你可能漏了）
/// 和 a2 项「请勿重复报告」（这些疑似误报）。
pub(crate) fn render_verification_prompt(
    base: &str,
    recheck: &[PromptFinding],
    do_not_report: &[PromptFinding],
) -> String {
    let mut out = base.to_string();
    if !recheck.is_empty() {
        out.push_str("\n\n## 上一轮标准工具发现、但你可能遗漏的（请重点复核是否真实）\n");
        for f in recheck {
            out.push_str(&format!("- {} ({})：{}\n", f.location, f.category, f.note));
        }
    }
    if !do_not_report.is_empty() {
        out.push_str("\n## 上一轮标准工具报告、但疑似误报的（请勿重复报告）\n");
        for f in do_not_report {
            out.push_str(&format!("- {} ({})：{}\n", f.location, f.category, f.note));
        }
    }
    out
}
```

- [ ] **步骤 4：跑 prompt 测试**

运行：`cargo test -p mcp-sec-audit-core agent::prompt::tests`
预期：PASS（现有 + 2 个新）。

- [ ] **步骤 5：提交**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/agent/prompt.rs
git commit -m "feat(v4): add verification prompt rendering (a1/a2 injection)"
```

---

### 任务 3：跨阶段迁移校验（`validate.rs`）

新增 `validate` 模块，比较阶段 1 与阶段 2 的分区，产出迁移报告 + 回滚决策。

**文件：**
- 创建：`rust/crates/mcp-sec-audit-core/src/static_analysis/validate.rs`
- 修改：`rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs`（注册 `mod validate;`）

**接口：**
- 消费：`diff::{LineDiff, MatchGroup}`（经 `super::diff`）、`fusion::matcher::MatchGroup`。
- 产出：
  - `validate::FindingKey { file: String, line: u32 }`
  - `validate::Migration { b1_confirmed: usize, a1_confirmed: usize, new_a_only: usize, b_still_ambiguous: usize }`，带 `should_rollback(&self) -> bool`
  - `validate::migrate(&LineDiff, &LineDiff) -> Migration`

- [ ] **步骤 1：注册模块**

`rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs` 里，在 `mod taint;` 之后加 `mod validate;`：

```rust
mod rule;
mod taint;
mod validate;
```

- [ ] **步骤 2：写失败的测试**

创建 `rust/crates/mcp-sec-audit-core/src/static_analysis/validate.rs`：

```rust
//! 跨阶段迁移校验（v4.0 M2）：比较阶段 1 与阶段 2 的差分分区，确认哪些试探性进化
//! 是真实的（b1/a1）、哪些污染了标准线（新增 A'-only）。

use std::collections::BTreeSet;

use crate::model::{AgentAnalysisResult, CodeqlAnalysisResult, RuleAnalysisResult, TaintAnalysisResult};

use super::diff::{LineDiff, MatchGroup};

/// 跨阶段比较用的稳定 finding 身份（basename + 行号）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FindingKey {
    pub(crate) file: String, // basename
    pub(crate) line: u32,
}

/// 两个阶段比较的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Migration {
    /// b-only(阶段1) 现在 agreed(阶段2) → 进化后的标准线抓到了 → b1 确认。
    pub(crate) b1_confirmed: usize,
    /// a-only(阶段1) 现在 agreed(阶段2) → 进化后的 prompt 抓到了 → a1 确认。
    pub(crate) a1_confirmed: usize,
    /// 新增 A'-only（a-only(阶段2) \ a-only(阶段1)）→ 疑似 b2 污染。
    pub(crate) new_a_only: usize,
    /// b-only(阶段1) 仍是 b-only(阶段2) → 仍混沌（b0 或 b2，需人工）。
    pub(crate) b_still_ambiguous: usize,
}

impl Migration {
    /// 回退触发：新增噪声 > 确认收益。
    pub(crate) fn should_rollback(&self) -> bool {
        self.new_a_only > self.b1_confirmed
    }
}

fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string()
}

fn group_key(group: &MatchGroup) -> Option<FindingKey> {
    if let Some(c) = group.codeql_results.first()
        && let Some(loc) = c.locations.first()
    {
        return Some(FindingKey { file: basename(&loc.file), line: loc.line });
    }
    if let Some(r) = group.rule_results.first() {
        return Some(FindingKey { file: basename(&r.file), line: r.line });
    }
    if let Some(t) = group.taint_results.first() {
        let parts: Vec<&str> = t.sink_id.splitn(4, ':').collect();
        let file = parts.get(2).map(|s| basename(s)).unwrap_or_default();
        let line = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
        return Some(FindingKey { file, line });
    }
    if let Some(a) = group.agent_results.first()
        && let Some(first) = a.affected_locations.first()
        && let Some((file, line)) = first.rsplit_once(':')
    {
        return Some(FindingKey { file: basename(file), line: line.parse().ok().unwrap_or(0) });
    }
    None
}

fn key_set(groups: &[MatchGroup]) -> BTreeSet<FindingKey> {
    groups.iter().filter_map(group_key).collect()
}

/// 比较阶段 1 与阶段 2 的分区。
pub(crate) fn migrate(phase1: &LineDiff, phase2: &LineDiff) -> Migration {
    let p1_b = key_set(&phase1.b_only);
    let p1_a = key_set(&phase1.a_only);
    let p2_c = key_set(&phase2.agreed);
    let p2_a = key_set(&phase2.a_only);
    let p2_b = key_set(&phase2.b_only);

    Migration {
        b1_confirmed: p1_b.intersection(&p2_c).count(),
        a1_confirmed: p1_a.intersection(&p2_c).count(),
        new_a_only: p2_a.difference(&p1_a).count(),
        b_still_ambiguous: p1_b.intersection(&p2_b).count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Location, Severity};

    fn rule(file: &str, line: u32, category: &str) -> RuleAnalysisResult {
        RuleAnalysisResult {
            result_id: "r".into(), rule_id: "r".into(), category: category.into(),
            owasp_mcp: None, file: file.into(), line, matched_text: None, evidence: vec![],
            severity: Severity::Medium, confidence: Confidence::High,
            recommendation: None, related_facts_exist: false,
        }
    }
    fn codeql(file: &str, line: u32) -> CodeqlAnalysisResult {
        CodeqlAnalysisResult {
            result_id: "c".into(), rule_id: "py/cmd".into(), rule_name: "cmd".into(),
            category: "command_execution".into(), query_source: "built-in".into(),
            languages: vec!["python".into()], message: "m".into(), severity: Severity::High,
            locations: vec![Location { file: file.into(), line, column: None, message: None }],
            dataflow_path: None, sarif_snippet: None, related_rule_ids: vec![],
            related_taint_ids: vec![], related_agent_ids: vec![],
            verification_status: "uncorroborated".into(), limitations: vec![],
        }
    }
    fn agent(file: &str, line: u32) -> AgentAnalysisResult {
        AgentAnalysisResult {
            result_id: "a".into(), agent_id: "a".into(), prompt_profile: "p".into(),
            model_provider: None, input_scope: vec![],
            candidate_title: "t".into(), affected_locations: vec![format!("{file}:{line}")],
            reasoning_summary: String::new(), evidence_snippets: vec![],
            related_rule_result_ids: vec![], related_taint_result_ids: vec![],
            confidence: Confidence::Medium, verification_status: "uncorroborated".into(),
            limitations: vec![],
        }
    }
    fn group_rule(r: RuleAnalysisResult) -> MatchGroup {
        MatchGroup { rule_results: vec![r], taint_results: vec![], agent_results: vec![], codeql_results: vec![] }
    }
    fn group_codeql(c: CodeqlAnalysisResult) -> MatchGroup {
        MatchGroup { rule_results: vec![], taint_results: vec![], agent_results: vec![], codeql_results: vec![c] }
    }
    fn group_agent(a: AgentAnalysisResult) -> MatchGroup {
        MatchGroup { rule_results: vec![], taint_results: vec![], agent_results: vec![a], codeql_results: vec![] }
    }

    #[test]
    fn b_only_confirmed_when_agent_and_standard_agree_in_phase2() {
        // 阶段1：仅 agent 报 b.py:5。阶段2：codeql + agent 都报 b.py:5（agreed）。
        let p1 = LineDiff { agreed: vec![], a_only: vec![], b_only: vec![group_agent(agent("b.py", 5))] };
        let p2 = LineDiff {
            agreed: vec![MatchGroup { rule_results: vec![], taint_results: vec![], agent_results: vec![agent("b.py", 5)], codeql_results: vec![codeql("b.py", 5)] }],
            a_only: vec![], b_only: vec![],
        };
        let m = migrate(&p1, &p2);
        assert_eq!(m.b1_confirmed, 1);
        assert!(!m.should_rollback());
    }

    #[test]
    fn a_only_confirmed_when_agent_catches_it_in_phase2() {
        // 阶段1：仅 rule 报 a.py:10。阶段2：rule + agent 都报 a.py:10。
        let p1 = LineDiff { agreed: vec![], a_only: vec![group_rule(rule("a.py", 10, "file_read"))], b_only: vec![] };
        let p2 = LineDiff {
            agreed: vec![MatchGroup { rule_results: vec![rule("a.py", 10, "file_read")], taint_results: vec![], agent_results: vec![agent("a.py", 10)], codeql_results: vec![] }],
            a_only: vec![], b_only: vec![],
        };
        assert_eq!(migrate(&p1, &p2).a1_confirmed, 1);
    }

    #[test]
    fn new_a_only_findings_trigger_rollback() {
        // 阶段1：一个 a-only。阶段2：两个 a-only（一个新增）且无 b1 收益 → 回退。
        let p1 = LineDiff { agreed: vec![], a_only: vec![group_rule(rule("a.py", 10, "file_read"))], b_only: vec![] };
        let p2 = LineDiff {
            agreed: vec![],
            a_only: vec![group_rule(rule("a.py", 10, "file_read")), group_rule(rule("c.py", 99, "file_read"))],
            b_only: vec![],
        };
        let m = migrate(&p1, &p2);
        assert_eq!(m.new_a_only, 1);
        assert!(m.should_rollback());
    }

    #[test]
    fn still_b_only_is_ambiguous() {
        let p1 = LineDiff { agreed: vec![], a_only: vec![], b_only: vec![group_agent(agent("b.py", 5))] };
        let p2 = LineDiff { agreed: vec![], a_only: vec![], b_only: vec![group_agent(agent("b.py", 5))] };
        assert_eq!(migrate(&p1, &p2).b_still_ambiguous, 1);
    }
}
```

- [ ] **步骤 3：跑一下确认失败**

运行：`cargo test -p mcp-sec-audit-core validate::tests`
预期：FAIL（编译错误 —— `validate` 模块缺失）。

- [ ] **步骤 4：确认测试通过**

运行：`cargo test -p mcp-sec-audit-core validate::tests`
预期：PASS（4 个测试）。

- [ ] **步骤 5：跑完整 core 测试 + 构建**

运行：`cargo test -p mcp-sec-audit-core && cargo build -p mcp-sec-audit-core`
预期：PASS，0 警告（若 `Migration`/`migrate`/`FindingKey`/`StagedDelta` 相关项、`PromptFinding`、`render_verification_prompt`、`stage_catalog_evolution` 在测试外仍未被用，加 `#[allow(dead_code)]` 并注释「M3 接线」）。

- [ ] **步骤 6：提交**

```bash
git add rust/crates/mcp-sec-audit-core/src/static_analysis/validate.rs \
        rust/crates/mcp-sec-audit-core/src/static_analysis/mod.rs
git commit -m "feat(v4): add cross-stage migration validation with rollback decision"
```

---

## 自审记录

- **规格覆盖**：任务 1 ↔ §7.2 G3（试探性加入 staging + 指纹）+ §7.3（回滚）；任务 2 ↔ §7.4（prompt'）；任务 3 ↔ §5.4 + §7.1 L1（跨阶段迁移）。§7.2 的 G1/G2 门控由调用方（M3）在 `stage_catalog_evolution` 上游完成，与本计划声明的范围一致。
- **占位符**：无 —— 每个步骤都有具体代码和命令。
- **类型一致性**：`StagedDelta { base_fingerprint, models, fingerprint }`、`PromptFinding { location, category, note }`、`FindingKey { file, line }`、`Migration { b1_confirmed, a1_confirmed, new_a_only, b_still_ambiguous }` 各步骤一致。
- **刻意推迟**：两阶段 pipeline 编排（真正跑阶段 2、把进化后的 catalog 换回去重跑、门控接线）是 M3——本计划只落纯原语，使其可隔离单测。

---

## 执行交接

计划完成，保存于 `rust/docs/v4.0/plans/2026-08-21-v4-evolution-loop.md`。**等你审阅/批准后再实现。**
