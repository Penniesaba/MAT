use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use crate::model::CodeqlOutput;
use crate::{
    AgentOutput, ConfigSnapshot, EvolutionReport, Fact, FusedFinding, ModelCandidate,
    RuleAnalysisResult, RuleBook, RuntimeConfig, Severity, StaticAnalysisResult,
    StaticAnalysisSummary, TaintAnalysisResult, load_rulebook,
};

use super::component::Component;
use super::facts::load_catalog;
use super::{
    DiscoveredFile, agent, codeql, component, diff, discover_files, fusion, learning, rule, taint,
    validate,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticScanContext {
    pub config: RuntimeConfig,
    pub rulebook_paths: Vec<String>,
    pub discovered_files: Vec<DiscoveredFile>,
}

pub fn run_static_scan(
    config: &RuntimeConfig,
    rulebook_paths: &[PathBuf],
    target_overrides: Option<&[PathBuf]>,
) -> Result<StaticAnalysisResult> {
    run_static_scan_with_progress(config, rulebook_paths, target_overrides, |_| {})
}

pub fn run_static_scan_with_progress(
    config: &RuntimeConfig,
    rulebook_paths: &[PathBuf],
    target_overrides: Option<&[PathBuf]>,
    mut progress: impl FnMut(&str),
) -> Result<StaticAnalysisResult> {
    let mut effective_config = config.clone();
    if let Some(targets) = target_overrides {
        effective_config.scan.targets = targets
            .iter()
            .map(|target| target.display().to_string())
            .collect();
    }

    let targets = effective_config
        .scan
        .targets
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();

    progress(&format!("Scanning {}", target_label(&targets)));

    if !effective_config.static_.enabled {
        progress("Static analysis disabled; returning empty result");
        return Ok(empty_result(
            effective_config,
            rulebook_paths_to_strings(rulebook_paths),
            target_label(&targets),
        ));
    }

    let discovery = discover_files(&targets, &effective_config.scan)?;
    progress(&format!(
        "Discovered {} files",
        discovery.discovered_files.len()
    ));

    let effective_rulebook_paths = if rulebook_paths.is_empty() {
        effective_config
            .static_
            .rule
            .rule_paths
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>()
    } else {
        rulebook_paths.to_vec()
    };

    let loaded_rulebook = if effective_config.static_.rule.enabled {
        Some(load_merged_rulebook(&effective_rulebook_paths)?)
    } else {
        None
    };

    let ctx = StaticScanContext {
        config: effective_config.clone(),
        rulebook_paths: rulebook_paths_to_strings(&effective_rulebook_paths),
        discovered_files: discovery.discovered_files,
    };

    let base_catalog = load_catalog(&ctx)?;

    // 基线组件指纹：四线路的能力决定性部件统一为 Component 抽象，记录各自
    // tool + fingerprint 作跨阶段对比的可观测锚点。
    let baseline_taint = component::TaintComponent {
        catalog: base_catalog.clone(),
    };
    let baseline_codeql = component::CodeqlComponent {
        mad_sinks: {
            let mut entries = Vec::new();
            for lang in ["python", "javascript", "rust"] {
                for e in codeql::models::sink_models_to_mad(base_catalog.sinks_for_language(lang)) {
                    entries.push(format!("{}:{} => {}", e.module, e.path, e.kind));
                }
            }
            entries.sort();
            entries
        },
        ..Default::default()
    };
    let baseline_rule = component::RuleComponent {
        capabilities: loaded_rulebook
            .as_ref()
            .map(|rb| rb.capabilities.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default(),
    };
    let baseline_prompt = component::PromptComponent::default();
    tracing::info!(
        target: "mcp_sec_audit::component",
        tool = ?baseline_taint.tool(),
        fingerprint = %baseline_taint.fingerprint(),
        "baseline taint component"
    );
    tracing::info!(
        target: "mcp_sec_audit::component",
        tool = ?baseline_codeql.tool(),
        fingerprint = %baseline_codeql.fingerprint(),
        "baseline codeql component"
    );
    tracing::info!(
        target: "mcp_sec_audit::component",
        tool = ?baseline_rule.tool(),
        fingerprint = %baseline_rule.fingerprint(),
        "baseline rule component"
    );
    tracing::info!(
        target: "mcp_sec_audit::component",
        tool = ?baseline_prompt.tool(),
        fingerprint = %baseline_prompt.fingerprint(),
        "baseline prompt component"
    );

    // ---------- 阶段 1：基线运行 ----------
    let rule_results = {
        let _enter = tracing::info_span!(
            target: "mcp_sec_audit::rule",
            "rule",
            enabled = effective_config.static_.rule.enabled
        )
        .entered();
        progress(if effective_config.static_.rule.enabled {
            "Running rule analysis..."
        } else {
            "Rule analysis: skipped (disabled)"
        });
        let start = std::time::Instant::now();
        let results = rule::run(&ctx, loaded_rulebook.as_ref())?;
        tracing::info!(
            target: "mcp_sec_audit::rule",
            findings = results.len(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "rule analysis complete"
        );
        progress(&format!("Rule analysis done: {} findings", results.len()));
        results
    };

    let (taint_results_1, facts_1) = {
        let _enter = tracing::info_span!(
            target: "mcp_sec_audit::taint",
            "taint",
            enabled = effective_config.static_.taint.enabled
        )
        .entered();
        progress(if effective_config.static_.taint.enabled {
            "Running taint analysis (phase 1)..."
        } else {
            "Taint analysis: skipped (disabled)"
        });
        let start = std::time::Instant::now();
        let (results, facts) = taint::run_with_catalog(&ctx, &base_catalog)?;
        tracing::info!(
            target: "mcp_sec_audit::taint",
            findings = results.len(),
            facts = facts.len(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "taint analysis complete (phase 1)"
        );
        progress(&format!("Taint analysis done: {} findings", results.len()));
        (results, facts)
    };

    let agent_output_1 = {
        let _enter = tracing::info_span!(
            target: "mcp_sec_audit::agent",
            "agent",
            enabled = effective_config.static_.agent.enabled
        )
        .entered();
        progress(if effective_config.static_.agent.enabled {
            "Running agent analysis..."
        } else {
            "Agent analysis: skipped (disabled)"
        });
        let start = std::time::Instant::now();
        let output = agent::run(&ctx)?;
        tracing::info!(
            target: "mcp_sec_audit::agent",
            findings = output.findings.len(),
            candidates = output.model_candidates.len(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "agent analysis complete"
        );
        progress(&format!(
            "Agent analysis done: {} findings",
            output.findings.len()
        ));
        output
    };

    let codeql_output_1 = {
        let _enter = tracing::info_span!(
            target: "mcp_sec_audit::codeql",
            "codeql",
            enabled = effective_config.static_.codeql.enabled
        )
        .entered();
        progress(if effective_config.static_.codeql.enabled {
            "Running CodeQL analysis (phase 1)..."
        } else {
            "CodeQL analysis: skipped (disabled)"
        });
        let start = std::time::Instant::now();
        let output = codeql::run(&ctx, &base_catalog, &mut progress)?;
        tracing::info!(
            target: "mcp_sec_audit::codeql",
            findings = output.results.len(),
            diagnostics = output.diagnostics.len(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "codeql analysis complete (phase 1)"
        );
        progress(&format!(
            "CodeQL analysis done: {} findings",
            output.results.len()
        ));
        for diag in &output.diagnostics {
            tracing::warn!(target: "mcp_sec_audit::codeql", "{diag}");
        }
        output
    };

    // ---------- 门控（G1/G2）+ 试探性进化（G3） ----------
    let rules = crate::models::default_package_rules();
    let mut gated: Vec<ModelCandidate> = Vec::new();
    let mut b0: Vec<ModelCandidate> = Vec::new();
    for c in &agent_output_1.model_candidates {
        let gate = learning::gate_sink_candidate(c, &rules);
        let representability = diff::classify_candidate(c);
        // G1 信号门控：sink 走 PackageRule（Hot/Warm）；source/sanitizer 无包门控，
        // 直接放行（可表达为 taint 模型）。
        let g1_pass = match c.kind.as_str() {
            "sink" => matches!(
                gate,
                learning::GateDecision::Hot | learning::GateDecision::Warm
            ),
            "source" | "sanitizer" => true,
            _ => false,
        };
        let g2_pass = matches!(
            representability,
            diff::Representability::MadSink | diff::Representability::TaintModel
        );
        // b0：语义漏洞（无法编码）+ 无信号的 Cold sink —— 显式筛出，交报告/人工。
        let is_b0 = matches!(representability, diff::Representability::SemanticOnly)
            || (c.kind == "sink" && matches!(gate, learning::GateDecision::Cold));
        tracing::info!(
            target: "mcp_sec_audit::evolution",
            candidate = %c.name,
            kind = %c.kind,
            category = %c.category,
            gate = ?gate,
            representability = ?representability,
            gated = g1_pass && g2_pass,
            b0 = is_b0,
            "gated agent candidate"
        );
        if g1_pass && g2_pass {
            gated.push(c.clone());
        } else if is_b0 {
            b0.push(c.clone());
        }
    }
    tracing::info!(
        target: "mcp_sec_audit::evolution",
        b0 = b0.len(),
        "semantic-only / cold candidates screened as b0"
    );

    // 无进化可做时，直接以阶段 1 结果走融合+汇总，返回（不重跑阶段 2）。
    let Some(staged) = learning::stage_catalog_evolution(&base_catalog, &gated) else {
        progress("Differential: no evolution candidates — skipping phase 2");
        let evolution = EvolutionReport {
            b0_count: b0.len(),
            b0_candidates: b0,
            ..Default::default()
        };
        return finish(
            &ctx,
            &targets,
            rule_results,
            taint_results_1,
            agent_output_1,
            codeql_output_1,
            facts_1,
            evolution,
            progress,
        );
    };

    tracing::info!(
        target: "mcp_sec_audit::evolution",
        sinks = staged.sinks.len(),
        sources = staged.sources.len(),
        sanitizers = staged.sanitizers.len(),
        fingerprint = %staged.fingerprint,
        "staged catalog evolution"
    );

    let diff_1 = diff::diff_lines(
        rule_results.clone(),
        taint_results_1.clone(),
        agent_output_1.findings.clone(),
        codeql_output_1.results.clone(),
        ctx.config.fusion.line_proximity,
    );

    // 进化统一走 Component trait：TaintComponent 承载三类 catalog，evolve 产出
    // 阶段 2 用的进化 catalog；写 staging 作可观测/回退锚点。
    let mut delta = component::ComponentDelta {
        sinks: staged.sinks.clone(),
        sources: staged.sources.clone(),
        sanitizers: staged.sanitizers.clone(),
        ..Default::default()
    };
    // 真溯源（C13）：learned_from = {scan_id}/{agent_id}，不再是占位。
    let provenance = format!(
        "{}/{}",
        scan_identifier(&ctx),
        ctx.config.static_.agent.provider
    );
    for m in delta.sinks.iter_mut() {
        m.learned_from = Some(provenance.clone());
    }
    for m in delta.sources.iter_mut() {
        m.learned_from = Some(provenance.clone());
    }
    for m in delta.sanitizers.iter_mut() {
        m.learned_from = Some(provenance.clone());
    }
    let base_component = component::TaintComponent {
        catalog: base_catalog.clone(),
    };
    let evolved_component = base_component.evolve(&delta);
    let evolved_catalog = evolved_component.catalog.clone();
    let staging_dir =
        std::env::temp_dir().join(format!("mcp-sec-audit-staging-{}", std::process::id()));
    learning::write_staging(&staging_dir, &staged)?;

    // 验证提示词 prompt'：把阶段 1 的 a-only 二分为 a1（高精度标准线命中，请复核）
    // 与 a2（仅 taint 启发式命中，疑似误报，请勿重复报告）。
    let (recheck, do_not_report) = build_recheck(&diff_1);
    let prompt_extra = if recheck.is_empty() && do_not_report.is_empty() {
        None
    } else {
        Some(agent::render_verification_prompt(
            "",
            &recheck,
            &do_not_report,
        ))
    };

    // ---------- 阶段 2：进化后重跑（rule 复用） ----------
    let (taint_results_2, facts_2) = {
        let _enter = tracing::info_span!(
            target: "mcp_sec_audit::taint",
            "taint2",
            enabled = effective_config.static_.taint.enabled
        )
        .entered();
        progress("Running taint analysis (phase 2)...");
        let start = std::time::Instant::now();
        let (results, facts) = taint::run_with_catalog(&ctx, &evolved_catalog)?;
        tracing::info!(
            target: "mcp_sec_audit::taint",
            findings = results.len(),
            facts = facts.len(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "taint analysis complete (phase 2)"
        );
        progress(&format!("Taint phase 2 done: {} findings", results.len()));
        (results, facts)
    };

    let agent_output_2 = {
        let _enter = tracing::info_span!(
            target: "mcp_sec_audit::agent",
            "agent2",
            enabled = effective_config.static_.agent.enabled
        )
        .entered();
        progress("Running agent analysis (phase 2)...");
        let start = std::time::Instant::now();
        let output = agent::run_with_prompt(&ctx, prompt_extra.as_deref())?;
        tracing::info!(
            target: "mcp_sec_audit::agent",
            findings = output.findings.len(),
            candidates = output.model_candidates.len(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "agent analysis complete (phase 2)"
        );
        progress(&format!(
            "Agent phase 2 done: {} findings",
            output.findings.len()
        ));
        output
    };

    let codeql_output_2 = {
        let _enter = tracing::info_span!(
            target: "mcp_sec_audit::codeql",
            "codeql2",
            enabled = effective_config.static_.codeql.enabled
        )
        .entered();
        progress("Running CodeQL analysis (phase 2)...");
        let start = std::time::Instant::now();
        let output = codeql::run(&ctx, &evolved_catalog, &mut progress)?;
        tracing::info!(
            target: "mcp_sec_audit::codeql",
            findings = output.results.len(),
            diagnostics = output.diagnostics.len(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "codeql analysis complete (phase 2)"
        );
        progress(&format!(
            "CodeQL phase 2 done: {} findings",
            output.results.len()
        ));
        for diag in &output.diagnostics {
            tracing::warn!(target: "mcp_sec_audit::codeql", "{diag}");
        }
        output
    };

    let diff_2 = diff::diff_lines(
        rule_results.clone(),
        taint_results_2.clone(),
        agent_output_2.findings.clone(),
        codeql_output_2.results.clone(),
        ctx.config.fusion.line_proximity,
    );

    // ---------- 迁移校验（L1）+ 固化/回退 ----------
    let mut migration = validate::migrate(&diff_1, &diff_2);
    migration.b0_count = b0.len();
    tracing::info!(target: "mcp_sec_audit::validate", ?migration, "cross-stage migration");

    // L2：仍混沌的 b-only 条目交 agent 语义解释（只产出解释，不下结论）。
    let mut ambiguous = validate::ambiguous_items(&diff_1, &diff_2);
    if !ambiguous.is_empty() && effective_config.static_.agent.enabled {
        let items: Vec<agent::PromptFinding> = ambiguous
            .iter()
            .map(|a| agent::PromptFinding {
                location: format!("{}:{}", a.file, a.line),
                category: String::new(),
                note: String::new(),
            })
            .collect();
        let explanation_extra = agent::render_explanation_prompt(&items);
        match agent::run_with_prompt(&ctx, Some(&explanation_extra)) {
            Ok(out) => attach_explanations(&mut ambiguous, &out.findings),
            Err(e) => tracing::warn!(
                target: "mcp_sec_audit::agent",
                error = %e,
                "L2 explanation pass failed"
            ),
        }
    }
    tracing::info!(
        target: "mcp_sec_audit::validate",
        ambiguous = ambiguous.len(),
        "L2/L3 residual items"
    );

    let rolled_back = migration.should_rollback();
    let (final_taint, final_agent, final_codeql, final_facts) = if rolled_back {
        base_component.rollback(&staging_dir)?;
        tracing::warn!(
            target: "mcp_sec_audit::evolution",
            "evolution polluted standard line — rolling back staged models"
        );
        (taint_results_1, agent_output_1, codeql_output_1, facts_1)
    } else {
        if let Some(dir) = &ctx.config.static_.learned_dir {
            base_component.promote(&delta, std::path::Path::new(dir))?;
        }
        tracing::info!(
            target: "mcp_sec_audit::evolution",
            learned = delta.model_count(),
            "promoted staged models to learned"
        );
        (taint_results_2, agent_output_2, codeql_output_2, facts_2)
    };

    let evolution = EvolutionReport {
        b1_confirmed: migration.b1_confirmed,
        a1_confirmed: migration.a1_confirmed,
        a2_confirmed: migration.a2_confirmed,
        b2_confirmed: migration.b2_confirmed,
        b0_count: migration.b0_count,
        b_still_ambiguous: migration.b_still_ambiguous,
        rolled_back,
        promoted: !rolled_back,
        b0_candidates: b0,
        ambiguous_for_review: ambiguous,
    };

    finish(
        &ctx,
        &targets,
        rule_results,
        final_taint,
        final_agent,
        final_codeql,
        final_facts,
        evolution,
        progress,
    )
}

/// L2 语义解释回填：把 agent 对某 file:line 的 reasoning_summary 贴到对应混沌项上。
fn attach_explanations(
    items: &mut [crate::AdjudicationItem],
    findings: &[crate::AgentAnalysisResult],
) {
    for item in items {
        let key = format!("{}:{}", item.file, item.line);
        if let Some(f) = findings
            .iter()
            .find(|f| f.affected_locations.iter().any(|loc| loc.ends_with(&key)))
        {
            item.agent_explanation = Some(f.reasoning_summary.clone());
        }
    }
}

/// 从 a-only 分区把 A 独有项二分为 `(a1 候选, a2 候选)`：
/// - a1（请复核）= 有 codeql/rule 确定性标准线支撑的（高精度，可能是真阳性）；
/// - a2（请勿重复报告）= 仅 taint 启发式命中的（低精度，疑似误报）。
fn build_recheck(diff: &diff::LineDiff) -> (Vec<agent::PromptFinding>, Vec<agent::PromptFinding>) {
    let mut recheck = Vec::new();
    let mut do_not_report = Vec::new();
    for g in &diff.a_only {
        let Some(finding) = finding_from_group(g) else {
            continue;
        };
        if !g.codeql_results.is_empty() || !g.rule_results.is_empty() {
            recheck.push(finding);
        } else {
            do_not_report.push(finding);
        }
    }
    (recheck, do_not_report)
}

/// 取 a-only 组首个标准线结果（codeql > rule > taint）的 `file:line` + 类别。
/// agent 结果无类别字段，故 a-only 组必有标准线成员。
fn finding_from_group(g: &fusion::matcher::MatchGroup) -> Option<agent::PromptFinding> {
    if let Some(c) = g.codeql_results.first()
        && let Some(loc) = c.locations.first()
    {
        let file = Path::new(&loc.file)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&loc.file);
        return Some(agent::PromptFinding {
            location: format!("{file}:{}", loc.line),
            category: c.category.clone(),
            note: String::new(),
        });
    }
    if let Some(r) = g.rule_results.first() {
        let file = Path::new(&r.file)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&r.file);
        return Some(agent::PromptFinding {
            location: format!("{file}:{}", r.line),
            category: r.category.clone(),
            note: String::new(),
        });
    }
    if let Some(t) = g.taint_results.first() {
        let parts: Vec<&str> = t.sink_id.splitn(4, ':').collect();
        let file = parts
            .get(2)
            .map(|s| {
                Path::new(s)
                    .file_name()
                    .and_then(|x| x.to_str())
                    .unwrap_or(s)
            })
            .unwrap_or_default();
        let line = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
        return Some(agent::PromptFinding {
            location: format!("{file}:{line}"),
            category: t.sink_kind.clone(),
            note: String::new(),
        });
    }
    None
}

/// 两阶段进化的收尾：融合 + 最终分区日志 + 汇总 + 构造结果。
/// 冷持久化由调用方（promote 分支）承担，这里不重复写 learned。
fn finish(
    ctx: &StaticScanContext,
    targets: &[PathBuf],
    rule_results: Vec<RuleAnalysisResult>,
    taint_results: Vec<TaintAnalysisResult>,
    agent_output: AgentOutput,
    codeql_output: CodeqlOutput,
    facts: Vec<Fact>,
    evolution: EvolutionReport,
    mut progress: impl FnMut(&str),
) -> Result<StaticAnalysisResult> {
    let agent_results = agent_output.findings;
    let model_candidates = agent_output.model_candidates;

    let fused_findings = {
        let _enter = tracing::info_span!(target: "mcp_sec_audit::fusion", "fusion").entered();
        progress("Fusing results...");
        let start = std::time::Instant::now();
        let findings = fusion::run(
            &ctx.config.fusion,
            rule_results.clone(),
            taint_results.clone(),
            agent_results.clone(),
            codeql_output.results.clone(),
        );
        tracing::info!(
            target: "mcp_sec_audit::fusion",
            findings = findings.len(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "fusion complete"
        );
        progress(&format!("Fused {} findings", findings.len()));
        findings
    };

    // 最终报告的分区（对最终选定的阶段结果）。
    let line_diff = diff::diff_lines(
        rule_results.clone(),
        taint_results.clone(),
        agent_results.clone(),
        codeql_output.results.clone(),
        ctx.config.fusion.line_proximity,
    );
    progress(&format!(
        "Differential: agreed={} standard-only={} agent-only={}",
        line_diff.agreed.len(),
        line_diff.a_only.len(),
        line_diff.b_only.len(),
    ));
    tracing::info!(
        target: "mcp_sec_audit::diff",
        agreed = line_diff.agreed.len(),
        a_only = line_diff.a_only.len(),
        b_only = line_diff.b_only.len(),
        "differential partition"
    );

    let codeql_fused_count = fused_findings
        .iter()
        .filter(|f| f.supported_by.contains(&"codeql".to_string()))
        .count();

    let summary = StaticAnalysisSummary {
        target: target_label(targets),
        fact_count: facts.len(),
        rule_result_count: rule_results.len(),
        taint_result_count: taint_results.len(),
        agent_result_count: agent_results.len(),
        codeql_result_count: codeql_output.results.len(),
        codeql_fused_count,
        fused_finding_count: fused_findings.len(),
        highest_severity: fused_findings
            .iter()
            .map(|f| f.severity.clone())
            .max_by(|a, b| scorer_ord(a).cmp(&scorer_ord(b))),
        risk_level: compute_risk_level(&fused_findings),
    };

    Ok(StaticAnalysisResult {
        facts,
        rule_results,
        taint_results,
        agent_results,
        codeql_results: codeql_output.results,
        codeql_diagnostics: codeql_output.diagnostics,
        codeql_raw_sarif: codeql_output.raw_sarif,
        model_candidates,
        fused_findings,
        summary,
        config_snapshot: ConfigSnapshot {
            runtime: ctx.config.clone(),
            rulebook_paths: ctx.rulebook_paths.clone(),
        },
        evolution,
    })
}

pub fn load_merged_rulebook(paths: &[PathBuf]) -> Result<RuleBook> {
    let files = expand_rulebook_paths(paths)?;
    let mut capabilities = BTreeMap::new();

    for path in files {
        let rulebook = load_rulebook(&path)?;
        for (name, rule) in rulebook.capabilities {
            if capabilities.insert(name.clone(), rule).is_some() {
                bail!("duplicate capability '{name}' while loading rulebooks");
            }
        }
    }

    Ok(RuleBook { capabilities })
}

fn expand_rulebook_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in paths {
        if !path.exists() {
            bail!("rulebook path does not exist: {}", path.display());
        }
        if path.is_file() {
            if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
                files.push(path.clone());
            }
            continue;
        }
        if path.is_dir() {
            collect_toml_files(path, &mut files)
                .with_context(|| format!("expand rulebook directory {}", path.display()))?;
            continue;
        }
        bail!(
            "rulebook path is neither file nor directory: {}",
            path.display()
        );
    }
    files.sort();
    Ok(files)
}

fn collect_toml_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("read rulebook directory {}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_toml_files(&path, files)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
            files.push(path);
        }
    }

    Ok(())
}

fn empty_result(
    runtime: RuntimeConfig,
    rulebook_paths: Vec<String>,
    target: String,
) -> StaticAnalysisResult {
    StaticAnalysisResult {
        facts: Vec::new(),
        rule_results: Vec::new(),
        taint_results: Vec::new(),
        agent_results: Vec::new(),
        codeql_results: Vec::new(),
        codeql_diagnostics: Vec::new(),
        codeql_raw_sarif: None,
        model_candidates: Vec::new(),
        fused_findings: Vec::new(),
        summary: StaticAnalysisSummary {
            target,
            fact_count: 0,
            rule_result_count: 0,
            taint_result_count: 0,
            agent_result_count: 0,
            codeql_result_count: 0,
            codeql_fused_count: 0,
            fused_finding_count: 0,
            highest_severity: None,
            risk_level: "none".to_string(),
        },
        config_snapshot: ConfigSnapshot {
            runtime,
            rulebook_paths,
        },
        evolution: Default::default(),
    }
}

/// 生成本次扫描的稳定标识：`scan-{target}-{unix_secs}`（供 learned_from 溯源）。
fn scan_identifier(ctx: &StaticScanContext) -> String {
    let target = ctx
        .config
        .scan
        .targets
        .first()
        .cloned()
        .unwrap_or_else(|| "<none>".to_string());
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(
        "scan-{}-{}",
        target.replace(['/', '\\', ' ', '.'], "_"),
        secs
    )
}

fn target_label(targets: &[PathBuf]) -> String {
    if targets.is_empty() {
        return "<none>".to_string();
    }
    targets
        .iter()
        .map(|target| target.display().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn rulebook_paths_to_strings(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

fn compute_risk_level(findings: &[FusedFinding]) -> String {
    let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
    let has_high = findings.iter().any(|f| f.severity == Severity::High);
    let has_medium = findings.iter().any(|f| f.severity == Severity::Medium);
    if has_critical {
        return "critical".into();
    }
    if has_high {
        return "high".into();
    }
    if has_medium {
        return "medium".into();
    }
    if findings.is_empty() {
        "none".into()
    } else {
        "low".into()
    }
}

fn scorer_ord(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::Fact;

    #[test]
    fn disabled_static_scan_returns_empty_result() {
        let root = temp_dir("disabled");
        fs::write(root.join("server.py"), "print('ok')").expect("write file");
        let mut config = RuntimeConfig::default();
        config.static_.enabled = false;

        let result = run_static_scan(&config, &[], Some(&[root.clone()])).expect("run scan");
        assert_eq!(result.summary.risk_level, "none");
        assert!(result.rule_results.is_empty());
        assert!(result.config_snapshot.runtime.static_.enabled == false);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn enabled_static_scan_runs_rule_line() {
        let root = temp_dir("enabled");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(root.join("server.py"), "subprocess.run('id')").expect("write file");

        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = true;
        let result =
            run_static_scan(&config, &[rules.clone()], Some(&[root.clone()])).expect("run scan");
        assert_eq!(result.summary.rule_result_count, 1);
        assert_eq!(result.rule_results[0].rule_id, "command_exec");
        assert_eq!(result.summary.taint_result_count, 0);
        assert_eq!(result.summary.agent_result_count, 0);
        assert!(!result.facts.is_empty());
        assert_eq!(result.summary.fact_count, result.facts.len());
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Call(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Sink(_)))
        );
        assert_eq!(
            result.config_snapshot.rulebook_paths,
            vec![rules.display().to_string()]
        );
        // Fusion enabled by default — rule result is fused into at least one finding
        assert!(result.summary.fused_finding_count > 0);
        assert!(!result.fused_findings.is_empty());

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn enabled_static_scan_includes_python_facts_and_fact_count() {
        let root = temp_dir("scan-facts");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(
            root.join("server.py"),
            r#"
import subprocess as sp

@mcp.tool()
def run_command(command: str):
    runner = sp.run
    command_text = command.strip()
    return runner(command_text, shell=True)
"#,
        )
        .expect("write file");

        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = true;
        let result = run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");

        assert!(!result.facts.is_empty());
        assert_eq!(result.summary.fact_count, result.facts.len());
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Import(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Function(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Entrypoint(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Source(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Call(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Assign(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Sink(_)))
        );
        assert!(result.summary.taint_result_count > 0);
        // Fusion produces findings from rule + taint results
        assert!(result.summary.fused_finding_count > 0);
        assert!(!result.fused_findings.is_empty());

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rulebook_directory_expands_toml_files() {
        let root = temp_dir("rule-dir");
        let rules_dir = root.join("rules");
        fs::create_dir_all(&rules_dir).expect("create rules dir");
        write_rulebook(&rules_dir, "a.toml", "command_exec");
        write_rulebook(&rules_dir, "b.toml", "file_read");

        let rulebook = load_merged_rulebook(&[rules_dir]).expect("load merged rulebook");
        assert_eq!(rulebook.len(), 2);
        assert!(rulebook.capabilities.contains_key("command_exec"));
        assert!(rulebook.capabilities.contains_key("file_read"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn duplicate_rulebook_capabilities_fail() {
        let root = temp_dir("duplicate-rules");
        let rules_dir = root.join("rules");
        fs::create_dir_all(&rules_dir).expect("create rules dir");
        write_rulebook(&rules_dir, "a.toml", "command_exec");
        write_rulebook(&rules_dir, "b.toml", "command_exec");

        let err = load_merged_rulebook(&[rules_dir]).expect_err("duplicate should fail");
        assert!(err.to_string().contains("duplicate capability"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn enabled_static_scan_includes_js_ts_facts() {
        let root = temp_dir("scan-js-facts");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(
            root.join("server.js"),
            r#"
const { exec } = require("child_process");

const server = { tool: (name, handler) => ({ name, handler }) };

server.tool("run_command", async (params) => {
    exec(params.command, (error, stdout) => {
        console.log(stdout);
    });
});
"#,
        )
        .expect("write JS file");

        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = true;
        let result = run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");

        assert!(!result.facts.is_empty());
        assert_eq!(result.summary.fact_count, result.facts.len());
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Import(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Function(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Entrypoint(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Source(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Call(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Sink(_)))
        );
        assert!(result.summary.taint_result_count > 0);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn enabled_static_scan_includes_typescript_facts() {
        let root = temp_dir("scan-ts-facts");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(
            root.join("server.ts"),
            r#"
import { exec } from "child_process";

interface ToolParams {
    command: string;
}

const server = {
    tool(name: string, handler: (params: any) => Promise<any>) {
        return { name, handler };
    }
};

server.tool("run_command", async (params: ToolParams) => {
    const { command } = params;
    exec(command);
});
"#,
        )
        .expect("write TS file");

        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = true;
        let result = run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");

        assert!(!result.facts.is_empty());
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Entrypoint(_)))
        );
        assert!(
            result
                .facts
                .iter()
                .any(|fact| matches!(fact, Fact::Sink(_)))
        );

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn enabled_static_scan_includes_codeql_result_count() {
        let root = temp_dir("codeql-count");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(
            root.join("server.py"),
            r#"
import subprocess as sp

@mcp.tool()
def run_command(command: str):
    return sp.run(command, shell=True)
"#,
        )
        .expect("write file");

        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = true;
        // codeql is disabled by default — count should be 0
        let result =
            run_static_scan(&config, &[rules.clone()], Some(&[root.clone()])).expect("run scan");
        assert_eq!(result.summary.codeql_result_count, 0);
        assert!(result.codeql_results.is_empty());
        assert!(result.summary.taint_result_count > 0);
        // Fusion still runs even though codeql is disabled — rule+taint findings exist
        assert!(result.summary.fused_finding_count > 0);
        assert!(!result.fused_findings.is_empty());

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn codeql_skip_diagnostic_is_surfaced_in_result() {
        let root = temp_dir("codeql-skip-diag");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(root.join("data.json"), "{}").expect("write json");
        let mut config = RuntimeConfig::default();
        config.static_.codeql.enabled = true;
        let result = run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");
        assert!(
            result
                .codeql_diagnostics
                .iter()
                .any(|d| d.contains("No CodeQL-supported language"))
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn fusion_produces_findings_when_enabled() {
        let root = temp_dir("fusion-test");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(
            root.join("server.py"),
            "import subprocess\nsubprocess.run('id')\n",
        )
        .expect("write file");

        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = true;
        config.fusion.enabled = true;
        let result = run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");

        assert!(result.summary.fused_finding_count > 0);
        assert!(!result.fused_findings.is_empty());
        // Rule line found subprocess.run — at least one fused finding
        let has_rule_support = result
            .fused_findings
            .iter()
            .any(|f| f.supported_by.contains(&"rule".to_string()));
        assert!(has_rule_support);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn fusion_disabled_returns_empty_findings() {
        let root = temp_dir("fusion-off");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(
            root.join("server.py"),
            "import subprocess\nsubprocess.run('id')\n",
        )
        .expect("write file");

        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = true;
        config.fusion.enabled = false;
        let result = run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");

        assert_eq!(result.summary.fused_finding_count, 0);
        assert!(result.fused_findings.is_empty());

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn agent_warm_reinjection_adds_taint_finding_for_learned_sink() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_dir("warm-reinject");
        let rules = write_rulebook(&root, "rules.toml", "command_exec");
        fs::write(
            root.join("server.py"),
            r#"
import openpyxl

@mcp.tool()
def read_sheet(filename: str):
    wb = openpyxl.load_workbook(filename)
    return wb
"#,
        )
        .expect("write file");

        // Stub agent: a tiny shell script that prints a fixed agent output
        // proposing `openpyxl.load_workbook` as a `file_read` sink.
        let stub = root.join("stub-agent.sh");
        fs::write(
            &stub,
            r#"#!/bin/sh
printf '%s\n' '{"findings":[],"model_candidates":[{"kind":"sink","name":"openpyxl.load_workbook","category":"file_read","language":"python","argument":0,"confidence":"medium","evidence_snippets":[]}]}'
"#,
        )
        .expect("write stub");
        let mut perms = fs::metadata(&stub).expect("stub metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&stub, perms).expect("chmod stub");

        let mut config = RuntimeConfig::default();
        config.static_.taint.enabled = true;
        config.static_.agent.enabled = true;
        config.static_.agent.provider = stub.display().to_string();

        let result = run_static_scan(&config, &[rules], Some(&[root.clone()])).expect("run scan");

        // The agent-proposed sink model should be surfaced in the result.
        assert_eq!(
            result.model_candidates.len(),
            1,
            "agent candidate should be surfaced"
        );
        // The warm re-injection should produce a file_read taint finding.
        assert!(
            result
                .taint_results
                .iter()
                .any(|t| t.sink_kind == "file_read"),
            "expected a file_read taint finding from the warm re-injected sink; got {:?}",
            result
                .taint_results
                .iter()
                .map(|t| &t.sink_kind)
                .collect::<Vec<_>>()
        );

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn build_recheck_splits_a1_and_a2() {
        use crate::model::{Confidence, RuleAnalysisResult, Severity, TaintAnalysisResult};
        use crate::static_analysis::fusion::matcher::MatchGroup;

        let rule_backed = MatchGroup {
            rule_results: vec![RuleAnalysisResult {
                result_id: "r".into(),
                rule_id: "r".into(),
                category: "command_execution".into(),
                owasp_mcp: None,
                file: "a.py".into(),
                line: 10,
                matched_text: None,
                evidence: vec![],
                severity: Severity::High,
                confidence: Confidence::High,
                recommendation: None,
                related_facts_exist: false,
            }],
            taint_results: vec![],
            agent_results: vec![],
            codeql_results: vec![],
        };
        let taint_only = MatchGroup {
            rule_results: vec![],
            taint_results: vec![TaintAnalysisResult {
                result_id: "t".into(),
                source_id: "source:x.py:0".into(),
                source_kind: "mcp_tool_param".into(),
                entrypoint_id: None,
                sink_id: "sink:file_read:b.py:5".into(),
                sink_kind: "file_read".into(),
                call_chain: vec![],
                dataflow_path: vec![],
                evidence: vec![],
                taint_confidence: Confidence::Medium,
                entrypoint_is_mcp: false,
                backward_trace_found_root: false,
            }],
            agent_results: vec![],
            codeql_results: vec![],
        };
        let d = diff::LineDiff {
            agreed: vec![],
            a_only: vec![rule_backed, taint_only],
            b_only: vec![],
        };

        let (recheck, do_not_report) = build_recheck(&d);
        assert_eq!(recheck.len(), 1, "rule-backed a-only → a1 (recheck)");
        assert_eq!(
            do_not_report.len(),
            1,
            "taint-only a-only → a2 (do_not_report)"
        );
    }

    fn write_rulebook(root: &Path, name: &str, capability: &str) -> PathBuf {
        let path = root.join(name);
        fs::write(
            &path,
            format!(
                r#"
                [[capabilities]]
                name = "{capability}"
                  [[capabilities.indicators]]
                  languages = ["python"]
                  patterns = ["subprocess."]
                "#
            ),
        )
        .expect("write rulebook");
        path
    }

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mcp-sec-audit-{name}-{suffix}"));
        fs::create_dir_all(&root).expect("create temp dir");
        root
    }
}
