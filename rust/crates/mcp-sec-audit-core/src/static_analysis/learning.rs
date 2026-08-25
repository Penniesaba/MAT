//! Gate for classifying agent-proposed sink candidates against cheap
//! semantic-inference heuristics.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::model::{Confidence, Fact, FactBase, ModelCandidate, Severity, SinkFact};
use crate::models::{
    ModelCatalog, PackageRule, SanitizerModel, SinkModel, SourceModel, rule_prefix,
};

use super::infer::{language_from_file, name_category};

/// Gating decision for an agent-proposed sink model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    Hot,
    Warm,
    Cold,
}

fn split_module_function(name: &str) -> Option<(&str, &str)> {
    name.rsplit_once('.')
        .filter(|(m, f)| !m.is_empty() && !f.is_empty())
}

/// Classify an agent-proposed sink by cross-checking it against the cheap
/// semantic-inference heuristics. `Hot` = layer-2 package classification
/// agrees on the same category; `Warm` = only the layer-3 naming prefix
/// matches; `Cold` = no inference support (agent-only, not re-injected).
pub fn gate_sink_candidate(candidate: &ModelCandidate, rules: &[PackageRule]) -> GateDecision {
    let package_agrees = split_module_function(&candidate.name).is_some_and(|(module, _)| {
        rules.iter().any(|r| {
            r.language == candidate.language
                && r.package == module
                && (r.category.as_deref() == Some(candidate.category.as_str())
                    || r.read_category.as_deref() == Some(candidate.category.as_str())
                    || r.write_category.as_deref() == Some(candidate.category.as_str()))
        })
    });
    if package_agrees {
        return GateDecision::Hot;
    }
    if name_category(&candidate.name) == Some(candidate.category.as_str()) {
        return GateDecision::Warm;
    }
    GateDecision::Cold
}

/// Match agent-proposed sink candidates against already-extracted call facts
/// and produce `Sink` facts for the matching calls (warm re-injection).
// 被两阶段编排（M3）取代：pipeline 现在把门控后的 sink 暂存进进化 catalog 并在阶段 2
// 重跑 taint，而不是把 sink 事实回注入 facts。保留供测试。
#[allow(dead_code)]
pub fn sink_candidates_to_sink_facts(facts: &[Fact], candidates: &[ModelCandidate]) -> Vec<Fact> {
    let mut out = Vec::new();
    for fact in facts {
        let Fact::Call(call) = fact else { continue };
        let callee = call.normalized_callee.as_deref().unwrap_or(&call.callee);
        for c in candidates {
            if c.kind != "sink" {
                continue;
            }
            if language_from_file(&call.base.file) != c.language {
                continue;
            }
            // Unqualified method names are too low-specificity to re-inject.
            if !c.name.contains('.') && !c.name.contains("::") {
                continue;
            }
            let hit = callee == c.name
                || callee.ends_with(&format!(".{}", c.name))
                || callee.ends_with(&format!("::{}", c.name));
            if !hit {
                continue;
            }
            out.push(Fact::Sink(SinkFact {
                base: FactBase {
                    id: format!("sink:learned:{}:{}", call.base.id, c.category),
                    file: call.base.file.clone(),
                    line: call.base.line,
                    extractor: "agent_model".to_string(),
                },
                call_id: call.base.id.clone(),
                category: c.category.clone(),
                rule_id: format!("{}.{}", rule_prefix(&c.language), c.category),
                sink_name: callee.to_string(),
                severity_base: Severity::Medium,
                reason: format!(
                    "learned sink from agent (warm re-injection): {}",
                    c.category
                ),
                conditions: Default::default(),
                confidence: c.confidence.clone(),
            }));
        }
    }
    out
}

/// Convert sink candidates to `SinkModel`s so R4's MaD compiler can turn them
/// into CodeQL model packs for the warm CodeQL re-run.
// 被 catalog→MaD 路径取代：阶段 2 用 `evolved_catalog` 直接喂 `codeql::run`，
// 由其内部 `write_model_pack_dir` 编译三类模型为 MaD（CLI ≥ 2.26.3 时注入）。
#[allow(dead_code)]
pub fn candidates_to_mad_sinks(candidates: &[ModelCandidate]) -> Vec<SinkModel> {
    candidates
        .iter()
        .filter(|c| c.kind == "sink")
        .map(|c| SinkModel {
            language: c.language.clone(),
            category: c.category.clone(),
            severity: Severity::Medium,
            confidence: c.confidence.clone(),
            reason: format!("learned sink (warm): {}", c.category),
            patterns: vec![c.name.clone()],
            source: Some("learned".to_string()),
            learned_from: None,
            corroboration_count: 0,
            pollution_count: 0,
            last_seen_run: None,
        })
        .collect()
}

/// Convert a gated sink candidate into a low-confidence `learned` sink model.
// 被两阶段编排（M3）取代：promote 分支直接写 `staged.models`。保留供测试。
#[allow(dead_code)]
pub fn candidate_to_sink_model(
    c: &ModelCandidate,
    scan_id: &str,
    agent_id: &str,
) -> Option<SinkModel> {
    if c.kind != "sink" || c.name.trim().is_empty() || c.category.trim().is_empty() {
        return None;
    }
    Some(SinkModel {
        language: c.language.clone(),
        category: c.category.clone(),
        severity: Severity::Medium,
        confidence: Confidence::Low,
        reason: format!(
            "learned sink: {} (evidence: {})",
            c.category,
            c.evidence_snippets.first().cloned().unwrap_or_default()
        ),
        patterns: vec![c.name.clone()],
        source: Some("learned".to_string()),
        learned_from: Some(format!("{scan_id}/{agent_id}")),
        corroboration_count: 0,
        pollution_count: 0,
        last_seen_run: None,
    })
}

/// Confidence ordering: High(2) > Medium(1) > Low(0). `Confidence` derives
/// only `PartialEq`, not `PartialOrd`, so we rank explicitly.
fn confidence_rank(c: &crate::Confidence) -> u8 {
    match c {
        crate::Confidence::High => 2,
        crate::Confidence::Medium => 1,
        crate::Confidence::Low => 0,
    }
}

fn sink_key(m: &SinkModel) -> String {
    let pat = m.patterns.first().cloned().unwrap_or_default();
    format!("{}:{}:{}", m.language, m.category, pat)
}

/// Merge new models into existing by (language, category, pattern): sum
/// corroboration/pollution counts; when new.last_seen_run is Some, use it
/// (lexical newer-than comparison deferred to Plan 4); existing models not in
/// `new` are preserved. Sorted by pattern for determinism.
pub fn merge_sink_models(existing: &[SinkModel], new: &[SinkModel]) -> Vec<SinkModel> {
    let mut map: BTreeMap<String, SinkModel> = BTreeMap::new();
    for m in existing {
        map.insert(sink_key(m), m.clone());
    }
    for m in new {
        let key = sink_key(m);
        map.entry(key)
            .and_modify(|e| {
                e.corroboration_count += m.corroboration_count;
                e.pollution_count += m.pollution_count;
                if m.last_seen_run.is_some() {
                    e.last_seen_run = m.last_seen_run.clone();
                }
                // 已有模型置信度取较高者（不因新来 low 而降级）
                if confidence_rank(&m.confidence) > confidence_rank(&e.confidence) {
                    e.confidence = m.confidence.clone();
                }
            })
            .or_insert_with(|| m.clone());
    }
    map.into_values().collect()
}

fn source_key(m: &SourceModel) -> String {
    let pat = m.patterns.first().cloned().unwrap_or_default();
    format!("{}:{}:{}", m.language, m.category, pat)
}

/// Merge new source models into existing by (language, category, pattern): sum
/// corroboration/pollution counts; when new.last_seen_run is Some, use it;
/// existing models not in `new` are preserved. Sorted by key for determinism.
pub fn merge_source_models(existing: &[SourceModel], new: &[SourceModel]) -> Vec<SourceModel> {
    let mut map: BTreeMap<String, SourceModel> = BTreeMap::new();
    for m in existing {
        map.insert(source_key(m), m.clone());
    }
    for m in new {
        map.entry(source_key(m))
            .and_modify(|e| {
                e.corroboration_count += m.corroboration_count;
                e.pollution_count += m.pollution_count;
                if m.last_seen_run.is_some() {
                    e.last_seen_run = m.last_seen_run.clone();
                }
            })
            .or_insert_with(|| m.clone());
    }
    map.into_values().collect()
}

fn sanitizer_key(m: &SanitizerModel) -> String {
    let pat = m.patterns.first().cloned().unwrap_or_default();
    format!("{}:{}:{}", m.language, pat, m.neutralizes.join(","))
}

/// Merge new sanitizer models into existing by (language, pattern, neutralizes):
/// sum corroboration/pollution counts; when new.last_seen_run is Some, use it;
/// existing models not in `new` are preserved. Sorted by key for determinism.
pub fn merge_sanitizer_models(
    existing: &[SanitizerModel],
    new: &[SanitizerModel],
) -> Vec<SanitizerModel> {
    let mut map: BTreeMap<String, SanitizerModel> = BTreeMap::new();
    for m in existing {
        map.insert(sanitizer_key(m), m.clone());
    }
    for m in new {
        map.entry(sanitizer_key(m))
            .and_modify(|e| {
                e.corroboration_count += m.corroboration_count;
                e.pollution_count += m.pollution_count;
                if m.last_seen_run.is_some() {
                    e.last_seen_run = m.last_seen_run.clone();
                }
            })
            .or_insert_with(|| m.clone());
    }
    map.into_values().collect()
}

/// Write `contents` to `path` atomically: write to a sibling temp file in the
/// same directory, then `fs::rename` over the target. A reader never observes
/// a partially-written file. The target's directory must already exist.
pub(crate) fn atomic_write(path: &Path, contents: &str) -> anyhow::Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Append learned models to a directory as one TOML file per model (sorted by
/// name for determinism). Creates the directory if absent.
pub fn write_learned_sinks(dir: &Path, models: &[SinkModel]) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (i, m) in models.iter().enumerate() {
        let safe = m
            .patterns
            .first()
            .map(|p| p.replace(['.', ':', '/'], "_"))
            .unwrap_or_else(|| i.to_string());
        let mut text = format!(
            "[[sinks]]\nlanguage = {:?}\ncategory = {:?}\nseverity = {:?}\nconfidence = {:?}\nreason = {:?}\npatterns = {:?}\nsource = \"learned\"\nlearned_from = {:?}\ncorroboration_count = {}\npollution_count = {}\n",
            m.language,
            m.category,
            severity_str(&m.severity),
            confidence_str(&m.confidence),
            m.reason,
            m.patterns,
            m.learned_from.as_deref().unwrap_or("unknown"),
            m.corroboration_count,
            m.pollution_count,
        );
        // Only emit the run marker when present — a missing key reloads as
        // `None` via `#[serde(default)]`, preserving the None-vs-Some distinction.
        if let Some(run) = &m.last_seen_run {
            text.push_str(&format!("last_seen_run = {:?}\n", run));
        }
        atomic_write(&dir.join(format!("learned-{safe}.toml")), &text)?;
    }
    Ok(())
}

/// Append learned source models to a directory as one TOML file per model.
pub fn write_learned_sources(dir: &Path, models: &[SourceModel]) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (i, m) in models.iter().enumerate() {
        let safe = m
            .patterns
            .first()
            .map(|p| p.replace(['.', ':', '/'], "_"))
            .unwrap_or_else(|| i.to_string());
        let mut text = format!(
            "[[sources]]\nlanguage = {:?}\ncategory = {:?}\npatterns = {:?}\nsource = \"learned\"\nlearned_from = {:?}\ncorroboration_count = {}\npollution_count = {}\n",
            m.language,
            m.category,
            m.patterns,
            m.learned_from.as_deref().unwrap_or("unknown"),
            m.corroboration_count,
            m.pollution_count,
        );
        // Only emit the run marker when present — a missing key reloads as
        // `None` via `#[serde(default)]`, preserving the None-vs-Some distinction.
        if let Some(run) = &m.last_seen_run {
            text.push_str(&format!("last_seen_run = {:?}\n", run));
        }
        atomic_write(&dir.join(format!("learned-{safe}.toml")), &text)?;
    }
    Ok(())
}

/// Append learned sanitizer models to a directory as one TOML file per model.
pub fn write_learned_sanitizers(dir: &Path, models: &[SanitizerModel]) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (i, m) in models.iter().enumerate() {
        let safe = m
            .patterns
            .first()
            .map(|p| p.replace(['.', ':', '/'], "_"))
            .unwrap_or_else(|| i.to_string());
        let mut text = format!(
            "[[sanitizers]]\nlanguage = {:?}\npatterns = {:?}\nneutralizes = {:?}\nsource = \"learned\"\nlearned_from = {:?}\ncorroboration_count = {}\npollution_count = {}\n",
            m.language,
            m.patterns,
            m.neutralizes,
            m.learned_from.as_deref().unwrap_or("unknown"),
            m.corroboration_count,
            m.pollution_count,
        );
        // Only emit the run marker when present — a missing key reloads as
        // `None` via `#[serde(default)]`, preserving the None-vs-Some distinction.
        if let Some(run) = &m.last_seen_run {
            text.push_str(&format!("last_seen_run = {:?}\n", run));
        }
        atomic_write(&dir.join(format!("learned-{safe}.toml")), &text)?;
    }
    Ok(())
}

/// 把校验通过的 delta 固化到 learned 目录（三类模型）。
#[allow(dead_code)]
pub(crate) fn write_learned_models(dir: &Path, delta: &StagedDelta) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    write_learned_sinks(dir, &delta.sinks)?;
    write_learned_sources(dir, &delta.sources)?;
    write_learned_sanitizers(dir, &delta.sanitizers)?;
    Ok(())
}

/// Accumulate rule capabilities into a learned-rulebook file (one
/// "- capability" per line). Reads the existing `- capability` lines, appends
/// any not-yet-present capabilities (dedup via BTreeSet), and writes the full
/// list back — so earlier runs' rules survive later runs.
pub fn write_learned_rules(dir: &Path, capabilities: &[String]) -> anyhow::Result<()> {
    if capabilities.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    let path = dir.join("learned-capabilities.txt");
    let mut existing: Vec<String> = if path.exists() {
        std::fs::read_to_string(&path)?
            .lines()
            .filter_map(|l| l.strip_prefix("- ").map(str::to_string))
            .collect()
    } else {
        Vec::new()
    };
    let mut seen: std::collections::BTreeSet<String> = existing.iter().cloned().collect();
    for c in capabilities {
        if seen.insert(c.clone()) {
            existing.push(c.clone());
        }
    }
    let text = existing
        .iter()
        .map(|c| format!("- {c}"))
        .collect::<Vec<_>>()
        .join("\n");
    atomic_write(&path, &text)?;
    Ok(())
}

/// Accumulate prompt-extra text into a learned-prompt file. Reads the existing
/// content and appends the new text (newline-separated when the file does not
/// already end in a newline), so earlier runs' prompt text survives later runs.
pub fn write_learned_prompt(dir: &Path, text: &str) -> anyhow::Result<()> {
    if text.trim().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    let path = dir.join("learned-prompt.md");
    let mut content = if path.exists() {
        std::fs::read_to_string(&path)?
    } else {
        String::new()
    };
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(text);
    atomic_write(&path, &content)?;
    Ok(())
}

// --- M2 可回滚 catalog 进化（staging + 指纹 + rollback）------------------
//
// 这些原语直到 M3 的两阶段编排才被 pipeline 接线：阶段 1 门控出的 sink 候选
// 经 `stage_catalog_evolution` 暂存，`write_staging` 落盘到 staging 目录（非
// `learned/`），阶段 2 用 `catalog_fingerprint` 作回退锚点，必要时
// `rollback_staging` 删除暂存。接线前仅由单元测试驱动，故逐项 `#[allow(dead_code)]`。

/// 一次暂存（试探性、可回退）的 catalog 进化。`base_fingerprint` 是进化前的身份
/// （回退锚点）；`fingerprint` 标识 delta 本身。
#[allow(dead_code)]
pub(crate) struct StagedDelta {
    pub(crate) base_fingerprint: String,
    pub(crate) sinks: Vec<SinkModel>,
    pub(crate) sources: Vec<SourceModel>,
    pub(crate) sanitizers: Vec<SanitizerModel>,
    pub(crate) fingerprint: String,
}

/// `ModelCatalog` 的确定性内容身份。为了日志可读，不再逐条打印
/// `language:category:pattern`，而是压缩成「三类模型数量 + 全量内容的稳定哈希」：
/// 数量给出可读摘要，哈希保留内容敏感性与确定性（任一模型变化都会改变指纹）。
#[allow(dead_code)]
pub(crate) fn catalog_fingerprint(catalog: &ModelCatalog) -> String {
    let mut entries = Vec::new();
    let mut sinks = 0usize;
    let mut sources = 0usize;
    let mut sanitizers = 0usize;
    for lang in ["python", "javascript", "rust"] {
        for m in catalog.sinks_for_language(lang) {
            sinks += m.patterns.len();
            for p in &m.patterns {
                entries.push(format!("sink:{lang}:{}:{}", m.category, p));
            }
        }
        for m in catalog.sources_for_language(lang) {
            sources += m.patterns.len();
            for p in &m.patterns {
                entries.push(format!("source:{lang}:{}:{}", m.category, p));
            }
        }
        for m in catalog.sanitizers_for_language(lang) {
            sanitizers += m.patterns.len();
            for p in &m.patterns {
                entries.push(format!(
                    "sanitizer:{lang}:{}:{}",
                    m.neutralizes.join(","),
                    p
                ));
            }
        }
    }
    entries.sort();
    format!(
        "sinks={sinks} sources={sources} sanitizers={sanitizers} #{}",
        stable_hash(&entries.join("|"))
    )
}

/// 稳定的非加密 64-bit 哈希（FNV-1a），16 进制输出。用于把指纹压成紧凑摘要，
/// 同时保持「确定性 + 内容敏感」——跨运行、跨 Rust 版本稳定。
pub(crate) fn stable_hash(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// 把门控后（Hot/Warm）的 sink 候选转成可回退的 `StagedDelta`，对现有 catalog 去重。
/// 没有新增时返回 `None`。G1 门控（`gate_sink_candidate`）与 G2 可表达性
/// （`diff::classify_candidate`）由调用方在更上游完成。
#[allow(dead_code)]
pub(crate) fn stage_catalog_evolution(
    catalog: &ModelCatalog,
    candidates: &[ModelCandidate],
) -> Option<StagedDelta> {
    let mut seen_sinks: BTreeSet<String> = BTreeSet::new();
    let mut seen_sources: BTreeSet<String> = BTreeSet::new();
    let mut seen_sanitizers: BTreeSet<String> = BTreeSet::new();
    for lang in ["python", "javascript", "rust"] {
        for m in catalog.sinks_for_language(lang) {
            for p in &m.patterns {
                seen_sinks.insert(format!("{lang}:{}:{}", m.category, p));
            }
        }
        for m in catalog.sources_for_language(lang) {
            for p in &m.patterns {
                seen_sources.insert(format!("{lang}:{}:{}", m.category, p));
            }
        }
        for m in catalog.sanitizers_for_language(lang) {
            for p in &m.patterns {
                seen_sanitizers.insert(format!("{lang}:{}:{}", m.neutralizes.join(","), p));
            }
        }
    }

    let mut sinks = Vec::new();
    let mut sources = Vec::new();
    let mut sanitizers = Vec::new();
    for c in candidates {
        if c.name.trim().is_empty() || c.category.trim().is_empty() {
            continue;
        }
        match c.kind.as_str() {
            "sink" => {
                let key = format!("{}:{}:{}", c.language, c.category, c.name);
                if seen_sinks.insert(key) {
                    sinks.push(SinkModel {
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
                        corroboration_count: 0,
                        pollution_count: 0,
                        last_seen_run: None,
                    });
                }
            }
            "source" => {
                let key = format!("{}:{}:{}", c.language, c.category, c.name);
                if seen_sources.insert(key) {
                    sources.push(SourceModel {
                        language: c.language.clone(),
                        category: c.category.clone(),
                        patterns: vec![c.name.clone()],
                        source: Some("learned-staged".to_string()),
                        learned_from: None,
                        corroboration_count: 0,
                        pollution_count: 0,
                        last_seen_run: None,
                    });
                }
            }
            "sanitizer" => {
                let key = format!("{}:{}:{}", c.language, c.category, c.name);
                if seen_sanitizers.insert(key) {
                    sanitizers.push(SanitizerModel {
                        language: c.language.clone(),
                        patterns: vec![c.name.clone()],
                        neutralizes: vec![c.category.clone()],
                        source: Some("learned-staged".to_string()),
                        learned_from: None,
                        corroboration_count: 0,
                        pollution_count: 0,
                        last_seen_run: None,
                    });
                }
            }
            _ => continue,
        }
    }

    if sinks.is_empty() && sources.is_empty() && sanitizers.is_empty() {
        return None;
    }
    let base_fingerprint = catalog_fingerprint(catalog);
    let mut fp = sinks
        .iter()
        .flat_map(|m| {
            m.patterns
                .iter()
                .map(|p| format!("sink:{}:{}:{}", m.language, m.category, p))
        })
        .chain(sources.iter().flat_map(|m| {
            m.patterns
                .iter()
                .map(|p| format!("source:{}:{}:{}", m.language, m.category, p))
        }))
        .chain(sanitizers.iter().flat_map(|m| {
            m.patterns
                .iter()
                .map(|p| format!("sanitizer:{}:{}:{}", m.language, m.neutralizes.join(","), p))
        }))
        .collect::<Vec<_>>();
    fp.sort();
    let fingerprint = fp.join("|");
    Some(StagedDelta {
        base_fingerprint,
        sinks,
        sources,
        sanitizers,
        fingerprint,
    })
}

/// 把暂存 delta 写到 staging 目录（不是 `learned/`），每个模型一个 TOML 文件。
#[allow(dead_code)]
pub(crate) fn write_staging(dir: &Path, delta: &StagedDelta) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (i, m) in delta.sinks.iter().enumerate() {
        let safe = m
            .patterns
            .first()
            .map(|p| p.replace(['.', ':', '/'], "_"))
            .unwrap_or_else(|| i.to_string());
        let text = format!(
            "[[sinks]]\nlanguage = {:?}\ncategory = {:?}\nseverity = {:?}\nconfidence = {:?}\nreason = {:?}\npatterns = {:?}\nsource = \"learned-staged\"\nlearned_from = {:?}\n",
            m.language,
            m.category,
            severity_str(&m.severity),
            confidence_str(&m.confidence),
            m.reason,
            m.patterns,
            m.learned_from.as_deref().unwrap_or("staged")
        );
        std::fs::write(dir.join(format!("staged-{safe}.toml")), text)?;
    }
    for (i, m) in delta.sources.iter().enumerate() {
        let safe = m
            .patterns
            .first()
            .map(|p| p.replace(['.', ':', '/'], "_"))
            .unwrap_or_else(|| i.to_string());
        let text = format!(
            "[[sources]]\nlanguage = {:?}\ncategory = {:?}\npatterns = {:?}\nsource = \"learned-staged\"\nlearned_from = {:?}\n",
            m.language,
            m.category,
            m.patterns,
            m.learned_from.as_deref().unwrap_or("staged")
        );
        std::fs::write(dir.join(format!("staged-{safe}.toml")), text)?;
    }
    for (i, m) in delta.sanitizers.iter().enumerate() {
        let safe = m
            .patterns
            .first()
            .map(|p| p.replace(['.', ':', '/'], "_"))
            .unwrap_or_else(|| i.to_string());
        let text = format!(
            "[[sanitizers]]\nlanguage = {:?}\npatterns = {:?}\nneutralizes = {:?}\nsource = \"learned-staged\"\nlearned_from = {:?}\n",
            m.language,
            m.patterns,
            m.neutralizes,
            m.learned_from.as_deref().unwrap_or("staged")
        );
        std::fs::write(dir.join(format!("staged-{safe}.toml")), text)?;
    }
    Ok(())
}

/// 回退一次暂存进化：删除 staging 目录。`learned/` 不动。
#[allow(dead_code)]
pub(crate) fn rollback_staging(dir: &Path) -> anyhow::Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}
fn confidence_str(c: &Confidence) -> &'static str {
    match c {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, ModelCandidate};
    use crate::models::default_package_rules;

    fn cand(name: &str, category: &str) -> ModelCandidate {
        cand_lang(name, category, "python")
    }

    fn cand_lang(name: &str, category: &str, language: &str) -> ModelCandidate {
        ModelCandidate {
            kind: "sink".into(),
            name: name.into(),
            category: category.into(),
            language: language.into(),
            argument: Some(0),
            confidence: Confidence::Medium,
            evidence_snippets: vec![],
        }
    }

    #[test]
    fn package_agreement_is_hot() {
        // openpyxl is a package rule with read_category=file_read.
        let d = gate_sink_candidate(
            &cand("openpyxl.load_workbook", "file_read"),
            &default_package_rules(),
        );
        assert_eq!(d, GateDecision::Hot);
    }

    #[test]
    fn name_prefix_only_is_warm() {
        // "load_config" matches the load→file_read naming prefix, but has no package rule.
        let d = gate_sink_candidate(&cand("load_config", "file_read"), &default_package_rules());
        assert_eq!(d, GateDecision::Warm);
    }

    #[test]
    fn no_inference_signal_is_cold() {
        let d = gate_sink_candidate(
            &cand("frobnicate_thing", "file_read"),
            &default_package_rules(),
        );
        assert_eq!(d, GateDecision::Cold);
    }

    #[test]
    fn category_mismatch_is_not_hot() {
        // openpyxl is file_read, but agent claims command_execution → no agreement.
        let d = gate_sink_candidate(
            &cand("openpyxl.load_workbook", "command_execution"),
            &default_package_rules(),
        );
        assert_ne!(d, GateDecision::Hot);
    }

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("learn-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn candidate_converts_to_learned_sink_model() {
        let m = candidate_to_sink_model(
            &cand("openpyxl.load_workbook", "file_read"),
            "scan-1",
            "claude",
        )
        .expect("sink candidate maps");
        assert_eq!(m.language, "python");
        assert_eq!(m.category, "file_read");
        assert_eq!(m.patterns, vec!["openpyxl.load_workbook"]);
        assert_eq!(m.confidence, Confidence::Low); // learned enters low
        assert_eq!(m.source.as_deref(), Some("learned"));
        assert_eq!(m.learned_from.as_deref(), Some("scan-1/claude"));
    }

    fn call_fact(id: &str, callee: &str) -> Fact {
        use crate::model::{CallArg, CallFact};
        Fact::Call(CallFact {
            base: FactBase {
                id: id.into(),
                file: "s.py".into(),
                line: 3,
                extractor: "t".into(),
            },
            caller: "f".into(),
            callee: callee.into(),
            normalized_callee: Some(callee.into()),
            column: None,
            end_line: None,
            snippet: format!("{callee}(x)"),
            args: vec![CallArg {
                index: 0,
                expr: "x".into(),
                kind: "positional".into(),
            }],
            kwargs: Default::default(),
            resolution: None,
        })
    }

    #[test]
    fn warm_candidates_become_sink_facts_for_matching_calls() {
        let facts = vec![
            call_fact("call:1", "openpyxl.load_workbook"),
            call_fact("call:2", "unrelated.thing"),
        ];
        let cands = vec![cand("openpyxl.load_workbook", "file_read")];
        let new = sink_candidates_to_sink_facts(&facts, &cands);
        assert_eq!(new.len(), 1);
        if let Fact::Sink(s) = &new[0] {
            assert_eq!(s.sink_name, "openpyxl.load_workbook");
            assert_eq!(s.category, "file_read");
            assert_eq!(s.confidence, Confidence::Medium);
        } else {
            panic!("expected Sink");
        }
    }

    #[test]
    fn wrong_language_candidate_is_not_reinjected() {
        // A "rust" candidate must not match a Python (`s.py`) call.
        let facts = vec![call_fact("call:1", "foo.read")];
        let cands = vec![cand_lang("foo.read", "file_read", "rust")];
        let new = sink_candidates_to_sink_facts(&facts, &cands);
        assert!(new.is_empty(), "expected no re-injection across languages");
    }

    #[test]
    fn bare_name_candidate_is_not_reinjected() {
        // A bare, unqualified method name is too low-specificity to re-inject.
        let facts = vec![call_fact("call:1", "threading.Thread.run")];
        let cands = vec![cand("run", "command_execution")];
        let new = sink_candidates_to_sink_facts(&facts, &cands);
        assert!(
            new.is_empty(),
            "expected no re-injection for a bare method name"
        );
    }

    #[test]
    fn write_learned_sinks_roundtrips() {
        let dir = tmp_dir("write");
        let m = candidate_to_sink_model(
            &cand("openpyxl.load_workbook", "file_read"),
            "scan-1",
            "claude",
        )
        .unwrap();
        write_learned_sinks(&dir, &[m]).expect("write");
        let loaded = crate::models::load_models_dir(&dir).expect("load");
        assert_eq!(loaded.sink_count(), 1);
        assert!(loaded.sinks_for_language("python")[0].source.as_deref() == Some("learned"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_learned_sinks_preserves_last_seen_run_none_vs_some() {
        // None must not roundtrip as Some("none"): the key is omitted, so
        // #[serde(default)] maps it back to None.
        let dir_none = tmp_dir("write-none");
        let mut m_none = candidate_to_sink_model(
            &cand("openpyxl.load_workbook", "file_read"),
            "scan-1",
            "claude",
        )
        .unwrap();
        m_none.last_seen_run = None;
        write_learned_sinks(&dir_none, &[m_none]).expect("write none");
        let loaded_none = crate::models::load_models_dir(&dir_none).expect("load none");
        assert_eq!(loaded_none.sinks_for_language("python")[0].last_seen_run, None);
        std::fs::remove_dir_all(&dir_none).ok();

        // A Some run marker is emitted and reloads verbatim.
        let dir_some = tmp_dir("write-some");
        let mut m_some = candidate_to_sink_model(
            &cand("openpyxl.load_workbook", "file_read"),
            "scan-1",
            "claude",
        )
        .unwrap();
        m_some.last_seen_run = Some("20260824".to_string());
        write_learned_sinks(&dir_some, &[m_some]).expect("write some");
        let loaded_some = crate::models::load_models_dir(&dir_some).expect("load some");
        assert_eq!(
            loaded_some.sinks_for_language("python")[0].last_seen_run.as_deref(),
            Some("20260824")
        );
        std::fs::remove_dir_all(&dir_some).ok();
    }

    #[test]
    fn catalog_fingerprint_is_deterministic_and_content_sensitive() {
        let a = crate::models::default_catalog();
        let b = crate::models::default_catalog();
        assert_eq!(catalog_fingerprint(&a), catalog_fingerprint(&b));
        let mut extra = crate::models::default_catalog();
        extra.merge(crate::models::ModelCatalog::from_sinks(vec![SinkModel {
            language: "python".into(),
            category: "file_read".into(),
            severity: Severity::Medium,
            confidence: Confidence::Low,
            reason: "x".into(),
            patterns: vec!["novel.read".into()],
            source: None,
            learned_from: None,
            corroboration_count: 0,
            pollution_count: 0,
            last_seen_run: None,
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
        assert_eq!(delta.sinks.len(), 1);
        assert_eq!(delta.sinks[0].patterns, vec!["brand_new.lib.read"]);
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

    #[test]
    fn write_learned_rules_appends_capabilities() {
        let dir = std::env::temp_dir().join(format!("learn-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_learned_rules(&dir, &["path_traversal".into()]).expect("write");
        let content =
            std::fs::read_to_string(dir.join("learned-capabilities.txt")).expect("read");
        assert!(content.contains("- path_traversal"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_learned_prompt_writes_text() {
        let dir = std::env::temp_dir().join(format!("learn-prompt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_learned_prompt(&dir, "## recheck capability over-exposure\n").expect("write");
        let content = std::fs::read_to_string(dir.join("learned-prompt.md")).expect("read");
        assert!(content.contains("capability over-exposure"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_learned_rules_accumulates_across_calls() {
        let dir = std::env::temp_dir().join(format!("learn-rules-acc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_learned_rules(&dir, &["path_traversal".into()]).expect("w1");
        write_learned_rules(
            &dir,
            &["command_execution".into(), "path_traversal".into()],
        )
        .expect("w2");
        let content = std::fs::read_to_string(dir.join("learned-capabilities.txt")).expect("read");
        assert!(content.contains("- path_traversal"));
        assert!(content.contains("- command_execution"));
        // dedup: path_traversal 不重复
        assert_eq!(content.matches("- path_traversal").count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_learned_prompt_accumulates_across_calls() {
        let dir = std::env::temp_dir().join(format!("learn-prompt-acc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // First block written without a trailing newline, exercising the
        // newline-separator path on the second append.
        write_learned_prompt(&dir, "## first block").expect("p1");
        write_learned_prompt(&dir, "## second block").expect("p2");
        let content = std::fs::read_to_string(dir.join("learned-prompt.md")).expect("read");
        assert!(content.contains("## first block"));
        assert!(content.contains("## second block"));
        // Both blocks are joined by a newline (not concatenated).
        assert!(content.contains("## first block\n## second block"));
        std::fs::remove_dir_all(&dir).ok();
    }

    // Realistic caller pattern: pipeline.rs builds `rules`/`prompt_extra`
    // fresh per run from that run's adjudication promotions, so each run only
    // passes its own newly-promoted capabilities. Prior runs must not be lost
    // (this is the cross-run accumulation the brief targets; the disjoint
    // writes make the overwrite behavior observable, unlike the brief's test
    // which passes both sets in the second call).
    #[test]
    fn write_learned_rules_preserves_prior_run_capabilities() {
        let dir = std::env::temp_dir().join(format!("learn-rules-crossrun-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_learned_rules(&dir, &["path_traversal".into()]).expect("run1");
        write_learned_rules(&dir, &["command_execution".into()]).expect("run2");
        let content = std::fs::read_to_string(dir.join("learned-capabilities.txt")).expect("read");
        assert!(content.contains("- path_traversal"));
        assert!(content.contains("- command_execution"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_learned_prompt_preserves_prior_run_text() {
        let dir = std::env::temp_dir().join(format!("learn-prompt-crossrun-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_learned_prompt(&dir, "## block one").expect("run1");
        write_learned_prompt(&dir, "## block two").expect("run2");
        let content = std::fs::read_to_string(dir.join("learned-prompt.md")).expect("read");
        assert!(content.contains("block one"));
        assert!(content.contains("block two"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn merge_sink_models_preserves_existing_evidence() {
        let existing = SinkModel {
            language: "python".into(), category: "file_read".into(),
            severity: crate::Severity::Medium, confidence: crate::Confidence::Medium,
            reason: "t".into(), patterns: vec!["openpyxl.load_workbook".into()],
            source: Some("learned".into()), learned_from: None,
            corroboration_count: 2, pollution_count: 0, last_seen_run: Some("20260821".into()),
        };
        let new = SinkModel {
            language: "python".into(), category: "file_read".into(),
            severity: crate::Severity::Medium, confidence: crate::Confidence::Low,
            reason: "t".into(), patterns: vec!["openpyxl.load_workbook".into()],
            source: Some("learned".into()), learned_from: Some("adjudication".into()),
            corroboration_count: 1, pollution_count: 0, last_seen_run: None,
        };
        let merged = merge_sink_models(&[existing.clone()], &[new]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].corroboration_count, 3); // 2 + 1
        assert_eq!(merged[0].confidence, crate::Confidence::Medium); // existing preserved
    }

    #[test]
    fn merge_source_models_preserves_evidence() {
        let existing = SourceModel {
            language: "python".into(), category: "env_var".into(), patterns: vec!["os.environ".into()],
            source: Some("learned".into()), learned_from: None,
            corroboration_count: 2, pollution_count: 1, last_seen_run: Some("20260821".into()),
        };
        let new = SourceModel {
            language: "python".into(), category: "env_var".into(), patterns: vec!["os.environ".into()],
            source: Some("learned".into()), learned_from: Some("adjudication".into()),
            corroboration_count: 1, pollution_count: 0, last_seen_run: None,
        };
        let merged = merge_source_models(&[existing], &[new]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].corroboration_count, 3);
        assert_eq!(merged[0].pollution_count, 1);
    }

    #[test]
    fn merge_source_models_keeps_existing_not_in_new_and_newer_run() {
        let existing = vec![
            SourceModel {
                language: "python".into(), category: "env_var".into(), patterns: vec!["keep.me".into()],
                source: Some("learned".into()), learned_from: None,
                corroboration_count: 2, pollution_count: 0, last_seen_run: Some("20260821".into()),
            },
            SourceModel {
                language: "python".into(), category: "env_var".into(), patterns: vec!["upgrade.me".into()],
                source: Some("learned".into()), learned_from: None,
                corroboration_count: 1, pollution_count: 1, last_seen_run: Some("20260821".into()),
            },
        ];
        let new = vec![SourceModel {
            language: "python".into(), category: "env_var".into(), patterns: vec!["upgrade.me".into()],
            source: Some("learned".into()), learned_from: None,
            corroboration_count: 1, pollution_count: 0, last_seen_run: Some("20260824".into()),
        }];
        let merged = merge_source_models(&existing, &new);
        assert_eq!(merged.len(), 2);
        let keep = merged.iter().find(|m| m.patterns == vec!["keep.me"]).unwrap();
        assert_eq!(keep.corroboration_count, 2);
        let upgraded = merged.iter().find(|m| m.patterns == vec!["upgrade.me"]).unwrap();
        assert_eq!(upgraded.corroboration_count, 2); // 1 + 1
        assert_eq!(upgraded.last_seen_run.as_deref(), Some("20260824")); // newer run wins
    }

    #[test]
    fn merge_sanitizer_models_preserves_evidence() {
        let existing = SanitizerModel {
            language: "python".into(), patterns: vec!["shlex.quote".into()],
            neutralizes: vec!["command_execution".into()],
            source: Some("learned".into()), learned_from: None,
            corroboration_count: 2, pollution_count: 1, last_seen_run: Some("20260821".into()),
        };
        let new = SanitizerModel {
            language: "python".into(), patterns: vec!["shlex.quote".into()],
            neutralizes: vec!["command_execution".into()],
            source: Some("learned".into()), learned_from: Some("adjudication".into()),
            corroboration_count: 1, pollution_count: 0, last_seen_run: None,
        };
        let merged = merge_sanitizer_models(&[existing], &[new]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].corroboration_count, 3);
        assert_eq!(merged[0].pollution_count, 1);
    }

    #[test]
    fn merge_sanitizer_models_keeps_existing_not_in_new_and_newer_run() {
        let existing = vec![
            SanitizerModel {
                language: "python".into(), patterns: vec!["keep.me".into()],
                neutralizes: vec!["command_execution".into()],
                source: Some("learned".into()), learned_from: None,
                corroboration_count: 2, pollution_count: 0, last_seen_run: Some("20260821".into()),
            },
            SanitizerModel {
                language: "python".into(), patterns: vec!["upgrade.me".into()],
                neutralizes: vec!["command_execution".into()],
                source: Some("learned".into()), learned_from: None,
                corroboration_count: 1, pollution_count: 1, last_seen_run: Some("20260821".into()),
            },
        ];
        let new = vec![SanitizerModel {
            language: "python".into(), patterns: vec!["upgrade.me".into()],
            neutralizes: vec!["command_execution".into()],
            source: Some("learned".into()), learned_from: None,
            corroboration_count: 1, pollution_count: 0, last_seen_run: Some("20260824".into()),
        }];
        let merged = merge_sanitizer_models(&existing, &new);
        assert_eq!(merged.len(), 2);
        let keep = merged.iter().find(|m| m.patterns == vec!["keep.me"]).unwrap();
        assert_eq!(keep.corroboration_count, 2);
        let upgraded = merged.iter().find(|m| m.patterns == vec!["upgrade.me"]).unwrap();
        assert_eq!(upgraded.corroboration_count, 2); // 1 + 1
        assert_eq!(upgraded.last_seen_run.as_deref(), Some("20260824")); // newer run wins
    }

    #[test]
    fn merge_sink_models_keeps_existing_not_in_new_and_newer_run() {
        let existing = vec![
            SinkModel {
                language: "python".into(), category: "file_read".into(),
                severity: Severity::Medium, confidence: Confidence::Medium,
                reason: "old".into(), patterns: vec!["keep.me".into()],
                source: Some("learned".into()), learned_from: None,
                corroboration_count: 2, pollution_count: 0, last_seen_run: Some("20260821".into()),
            },
            SinkModel {
                language: "python".into(), category: "file_read".into(),
                severity: Severity::Medium, confidence: Confidence::Low,
                reason: "old".into(), patterns: vec!["upgrade.me".into()],
                source: Some("learned".into()), learned_from: None,
                corroboration_count: 1, pollution_count: 1, last_seen_run: Some("20260821".into()),
            },
        ];
        let new = vec![
            SinkModel {
                language: "python".into(), category: "file_read".into(),
                severity: Severity::Medium, confidence: Confidence::High,
                reason: "new".into(), patterns: vec!["upgrade.me".into()],
                source: Some("learned".into()), learned_from: None,
                corroboration_count: 1, pollution_count: 0, last_seen_run: Some("20260824".into()),
            },
        ];
        let merged = merge_sink_models(&existing, &new);
        // `keep.me` preserved, `upgrade.me` merged in place.
        assert_eq!(merged.len(), 2);
        let keep = merged.iter().find(|m| m.patterns == vec!["keep.me"]).unwrap();
        assert_eq!(keep.corroboration_count, 2);
        let upgraded = merged.iter().find(|m| m.patterns == vec!["upgrade.me"]).unwrap();
        assert_eq!(upgraded.corroboration_count, 2); // 1 + 1
        assert_eq!(upgraded.confidence, Confidence::High); // newer higher wins
        assert_eq!(upgraded.last_seen_run.as_deref(), Some("20260824")); // newer run wins
    }
}
