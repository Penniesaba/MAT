//! Self-consistent adjudication: render the prompt that asks the claude CLI
//! to judge each ambiguous evolution candidate with three closed questions.
//!
//! Plan 2 (M3/M4) drives this postprocess stage (render → parse → vote) through
//! the agent-module re-exports. Until that wiring lands, the stage is only
//! exercised by unit tests, so dead-code is allowed for the not-yet-wired surface.
#![allow(dead_code)]

use anyhow::Result;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::AdjudicationItem;
use crate::Confidence;
use crate::models::{SanitizerModel, SinkModel, SourceModel};
use crate::static_analysis::pipeline::StaticScanContext;
use super::provider::{AgentRunConfig, CliAgentProvider};

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Abstraction {
    pub kind: String,
    pub category: String,
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AdjudicationVerdict {
    pub item_id: String,
    pub is_real: bool,
    pub reachable: String,
    pub abstractable: Option<Abstraction>,
    pub confidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjudicationOutcome { Promote, Reject, Uncertain }

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedVerdict {
    pub verdict: AdjudicationVerdict,
    pub outcome: AdjudicationOutcome,
    pub votes: u32,
}

/// Schema gate: `reachable` must be one of three enum values; else treat as unknown.
fn valid_reachable(s: &str) -> bool {
    matches!(s, "reachable" | "unreachable" | "unknown")
}

/// Majority-vote each item across rounds. Promote requires unanimity on BOTH
/// `is_real` (all true) AND `reachable` (all == "reachable"); 3:0 is_real false
/// => Reject; any split (2:1 / 1:2 on either axis, or reachable != "reachable")
/// => Uncertain; invalid reachable => Uncertain.
pub fn vote(rounds: &[Vec<AdjudicationVerdict>]) -> Vec<ResolvedVerdict> {
    use std::collections::BTreeMap;
    let mut by_item: BTreeMap<String, Vec<&AdjudicationVerdict>> = BTreeMap::new();
    for round in rounds {
        for v in round {
            by_item.entry(v.item_id.clone()).or_default().push(v);
        }
    }
    let mut out = Vec::new();
    // An item must be present (with valid schema) in *every* round before a
    // Promote/Reject is allowed. Missing data from a dropped/failed round must
    // downgrade to Uncertain, never promote on incomplete evidence.
    let expected = rounds.len() as u32;
    for (_item_id, vs) in by_item {
        if vs.is_empty() { continue; }
        let total = vs.len() as u32;
        let yes = vs.iter().filter(|v| v.is_real).count() as u32;
        let all_valid = vs.iter().all(|v| valid_reachable(&v.reachable));
        // Spec §5.3: a round that disagrees on reachability grounds the item
        // in no single observed path, so a 2:1 reachable split must downgrade
        // to Uncertain even when is_real is unanimous.
        let all_reachable = vs.iter().all(|v| v.reachable == "reachable");
        let outcome = if !all_valid || total != expected {
            AdjudicationOutcome::Uncertain
        } else if yes == total && all_reachable {
            AdjudicationOutcome::Promote
        } else if yes == 0 {
            AdjudicationOutcome::Reject
        } else {
            AdjudicationOutcome::Uncertain
        };
        out.push(ResolvedVerdict { verdict: vs[0].clone(), outcome, votes: total });
    }
    out.sort_by(|a, b| a.verdict.item_id.cmp(&b.verdict.item_id));
    out
}

/// Parse one JSON object per line; ignore blank/non-JSON lines.
pub fn parse_verdicts(stdout: &str) -> Result<Vec<AdjudicationVerdict>> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let t = line.trim();
        if t.is_empty() || !t.starts_with('{') {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<AdjudicationVerdict>(t) {
            out.push(v);
        }
    }
    Ok(out)
}

/// A concrete learned-model write the evolution executor should apply.
pub enum PromoteAction {
    Sink(SinkModel),
    Source(SourceModel),
    Sanitizer(SanitizerModel),
    Rule(String),
    Prompt(String),
}

/// Convert a resolved adjudication verdict into a promote action. Returns
/// `None` unless the outcome is Promote, the verdict is real and reachable,
/// and an abstraction was produced. New models enter at confidence Low with
/// corroboration_count = 1 (first evidence is this adjudication).
pub fn resolved_to_promote_action(r: &ResolvedVerdict) -> Option<PromoteAction> {
    if r.outcome != AdjudicationOutcome::Promote {
        return None;
    }
    let v = &r.verdict;
    if !v.is_real || v.reachable != "reachable" {
        return None;
    }
    let abs = v.abstractable.as_ref()?;
    let language = language_for_file(&v.item_id);
    match abs.kind.as_str() {
        "sink" => Some(PromoteAction::Sink(SinkModel {
            language,
            category: abs.category.clone(),
            severity: crate::Severity::Medium,
            confidence: Confidence::Low,
            reason: format!("learned sink via adjudication: {}", abs.category),
            patterns: vec![abs.pattern.clone()],
            source: Some("learned".into()),
            learned_from: Some("adjudication".into()),
            corroboration_count: 1,
            pollution_count: 0,
            last_seen_run: None,
        })),
        "source" => Some(PromoteAction::Source(SourceModel {
            language,
            category: abs.category.clone(),
            patterns: vec![abs.pattern.clone()],
            source: Some("learned".into()),
            learned_from: Some("adjudication".into()),
            corroboration_count: 1,
            pollution_count: 0,
            last_seen_run: None,
        })),
        "sanitizer" => Some(PromoteAction::Sanitizer(SanitizerModel {
            language,
            patterns: vec![abs.pattern.clone()],
            neutralizes: vec![abs.category.clone()],
            source: Some("learned".into()),
            learned_from: Some("adjudication".into()),
            corroboration_count: 1,
            pollution_count: 0,
            last_seen_run: None,
        })),
        "rule" => Some(PromoteAction::Rule(abs.category.clone())),
        "prompt" => Some(PromoteAction::Prompt(format!(
            "{} — {}",
            abs.category,
            abs.pattern
        ))),
        _ => None,
    }
}

/// Infer a language key from an item_id of the form `file.ext:line`.
fn language_for_file(item_id: &str) -> String {
    let file = item_id.split(':').next().unwrap_or(item_id).to_lowercase();
    match file.as_str() {
        "python" => return "python".into(),
        "rust" => return "rust".into(),
        "javascript" => return "javascript".into(),
        _ => {}
    }
    if file.ends_with(".py") {
        "python".into()
    } else if file.ends_with(".rs") {
        "rust".into()
    } else if file.ends_with(".ts") || file.ends_with(".js") {
        "javascript".into()
    } else {
        "javascript".into()
    }
}

const ROUNDS: u32 = 3;

/// Run the claude CLI adjudication ROUNDS times, returning one Vec per round.
pub(crate) async fn run_adjudication_async(
    ctx: &StaticScanContext,
    items: &[AdjudicationItem],
    cancel: &CancellationToken,
) -> Result<Vec<Vec<AdjudicationVerdict>>> {
    let agent_config = &ctx.config.static_.agent;
    let prompt = render_adjudication_prompt(items);
    let target_root = ctx
        .discovered_files
        .first()
        .and_then(|df| df.path.parent())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| ".".to_string());

    let mut rounds = Vec::new();
    for _ in 0..ROUNDS {
        let cfg = AgentRunConfig {
            working_dir: target_root.clone(),
            prompt: prompt.clone(),
            provider_binary: agent_config.provider.clone(),
            max_turns: agent_config.max_turns,
            timeout_seconds: agent_config.timeout_seconds,
            extra_args: agent_config.extra_args.clone(),
        };
        let output = CliAgentProvider.run(&cfg, cancel).await?;
        rounds.push(parse_verdicts(&output.stdout)?);
    }
    Ok(rounds)
}

/// Render the adjudication prompt. The agent must answer each item as a single
/// line of strict JSON, one per line, nothing else — so the post-processing
/// pass can parse lines deterministically.
pub fn render_adjudication_prompt(items: &[AdjudicationItem]) -> String {
    let mut s = String::from(
        "You are an evolution adjudicator for an MCP security scanner.\n\
         For each item below, judge three things and answer as ONE line of strict \
         JSON per item (no markdown, no prose, one object per line):\n\
         {\"item_id\":\"<file:line>\",\"is_real\":true|false,\"reachable\":\"reachable|unreachable|unknown\",\
         \"abstractable\":{\"kind\":\"sink|rule|prompt\",\"category\":\"<snake_case>\",\"pattern\":\"<callee>\"}|null,\
         \"confidence\":\"high|medium|low\",\"reason\":\"<one sentence>\"}\n\n",
    );
    for it in items {
        s.push_str(&format!("- item_id: {}:{} kind: {}\n", it.file, it.line, it.kind));
        if let Some(exp) = &it.agent_explanation {
            s.push_str(&format!("  prior_agent_note: {exp}\n"));
        }
    }
    s.push_str("\nAnswer now:\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_contains_items_and_json_contract() {
        let items = vec![crate::AdjudicationItem {
            file: "server.ts".into(),
            line: 22,
            kind: "b_still_ambiguous".into(),
            agent_explanation: Some("read_config reads arbitrary files".into()),
        }];
        let p = render_adjudication_prompt(&items);
        assert!(p.contains("server.ts"));
        assert!(p.contains("22"));
        assert!(p.contains("read_config"));
        // 强制结构化输出契约：要求每行一个 JSON 对象
        assert!(p.contains("JSON"));
        assert!(p.contains("is_real"));
        assert!(p.contains("reachable"));
    }

    #[test]
    fn parse_verdicts_parses_one_line_per_json() {
        let stdout = "{\"item_id\":\"server.ts:22\",\"is_real\":true,\"reachable\":\"reachable\",\"abstractable\":{\"kind\":\"sink\",\"category\":\"file_read\",\"pattern\":\"fs.readFileSync\"},\"confidence\":\"high\",\"reason\":\"arbitrary read\"}\n";
        let v = parse_verdicts(stdout).unwrap();
        assert_eq!(v.len(), 1);
        assert!(v[0].is_real);
        assert_eq!(v[0].abstractable.as_ref().unwrap().pattern, "fs.readFileSync");
    }

    #[test]
    fn vote_requires_unanimous_or_downgrades_to_uncertain() {
        use AdjudicationVerdict as V;
        let mk = |is_real: bool| V {
            item_id: "a.py:1".into(), is_real,
            reachable: "reachable".into(),
            abstractable: Some(Abstraction { kind: "sink".into(), category: "file_read".into(), pattern: "foo.read".into() }),
            confidence: "high".into(),
        };
        // 3:0 一致 → Promote
        let unanimous = vec![vec![mk(true)], vec![mk(true)], vec![mk(true)]];
        let r = vote(&unanimous);
        assert_eq!(r[0].outcome, AdjudicationOutcome::Promote);
        assert_eq!(r[0].votes, 3);
        // 2:1 分裂 → Uncertain
        let split = vec![vec![mk(true)], vec![mk(true)], vec![mk(false)]];
        let r2 = vote(&split);
        assert_eq!(r2[0].outcome, AdjudicationOutcome::Uncertain);
    }

    #[test]
    fn vote_downgrades_on_reachable_split() {
        let mk = |reachable: &str| AdjudicationVerdict {
            item_id: "a.py:1".into(), is_real: true, reachable: reachable.into(),
            abstractable: Some(Abstraction { kind: "sink".into(), category: "file_read".into(), pattern: "x.read".into() }),
            confidence: "high".into(),
        };
        // 3 轮 is_real 全 true，但 reachable 2:1 分裂（2 reachable + 1 unreachable）
        let rounds = vec![
            vec![mk("reachable")],
            vec![mk("reachable")],
            vec![mk("unreachable")],
        ];
        let r = vote(&rounds);
        assert_eq!(r[0].outcome, AdjudicationOutcome::Uncertain);
    }

    #[test]
    fn vote_rejects_unanimous_false_and_schema_gates_invalid_reachable() {
        use AdjudicationVerdict as V;
        let mk = |is_real: bool, reachable: &str| V {
            item_id: "a.py:1".into(), is_real,
            reachable: reachable.into(),
            abstractable: Some(Abstraction { kind: "sink".into(), category: "file_read".into(), pattern: "foo.read".into() }),
            confidence: "high".into(),
        };
        // 3:0 一致 false → Reject
        let reject = vec![vec![mk(false, "unreachable")], vec![mk(false, "unreachable")], vec![mk(false, "unreachable")]];
        let r = vote(&reject);
        assert_eq!(r[0].outcome, AdjudicationOutcome::Reject);
        assert_eq!(r[0].votes, 3);
        // 某轮 reachable 非法（schema 门控）→ Uncertain，即使 3:0 一致
        let bad_schema = vec![vec![mk(true, "reachable")], vec![mk(true, "reachable")], vec![mk(true, "maybe")]];
        let r2 = vote(&bad_schema);
        assert_eq!(r2[0].outcome, AdjudicationOutcome::Uncertain);
        // 多 item：按 item_id 排序输出
        let mk_id = |id: &str, is_real: bool| V {
            item_id: id.into(), is_real,
            reachable: "reachable".into(),
            abstractable: None,
            confidence: "high".into(),
        };
        let multi = vec![
            vec![mk_id("b.py:2", true)],
            vec![mk_id("a.py:1", true)],
        ];
        let r3 = vote(&multi);
        assert_eq!(r3.len(), 2);
        assert_eq!(r3[0].verdict.item_id, "a.py:1");
        assert_eq!(r3[1].verdict.item_id, "b.py:2");
        // Partial-round presence (1 of 2 rounds) must downgrade to Uncertain,
        // never Promote on incomplete evidence.
        assert_eq!(r3[0].votes, 1);
        assert_eq!(r3[0].outcome, AdjudicationOutcome::Uncertain);
        assert_eq!(r3[1].votes, 1);
        assert_eq!(r3[1].outcome, AdjudicationOutcome::Uncertain);
    }

    #[test]
    fn resolved_to_promote_action_maps_sink_verdict() {
        let r = ResolvedVerdict {
            verdict: AdjudicationVerdict {
                item_id: "server.ts:22".into(),
                is_real: true,
                reachable: "reachable".into(),
                abstractable: Some(Abstraction { kind: "sink".into(), category: "file_read".into(), pattern: "fs.readFileSync".into() }),
                confidence: "high".into(),
            },
            outcome: AdjudicationOutcome::Promote,
            votes: 3,
        };
        let a = resolved_to_promote_action(&r).expect("maps");
        match a {
            PromoteAction::Sink(m) => {
                assert_eq!(m.language, "javascript");
                assert_eq!(m.category, "file_read");
                assert_eq!(m.patterns, vec!["fs.readFileSync"]);
                assert_eq!(m.confidence, crate::Confidence::Low);
                assert_eq!(m.corroboration_count, 1);
            }
            _ => panic!("expected Sink"),
        }
    }

    #[test]
    fn resolved_to_promote_action_carries_language_from_b0_token() {
        // b0 candidates carry no file:line; pipeline prefixes the item_id with a
        // language token (`python:openpyxl.load_workbook:0`). The leading token
        // must win over the `.ts`/`.js`/default fallthrough so a python b0 sink
        // is not mislabeled `javascript`.
        let r = ResolvedVerdict {
            verdict: AdjudicationVerdict {
                item_id: "python:openpyxl.load_workbook:0".into(),
                is_real: true,
                reachable: "reachable".into(),
                abstractable: Some(Abstraction { kind: "sink".into(), category: "file_read".into(), pattern: "openpyxl.load_workbook".into() }),
                confidence: "high".into(),
            },
            outcome: AdjudicationOutcome::Promote,
            votes: 3,
        };
        let a = resolved_to_promote_action(&r).expect("maps");
        match a {
            PromoteAction::Sink(m) => assert_eq!(m.language, "python"),
            _ => panic!("expected Sink"),
        }
    }

    #[test]
    fn resolved_to_promote_action_rejects_on_uncertain_or_reject() {
        let mk = |outcome| ResolvedVerdict {
            verdict: AdjudicationVerdict {
                item_id: "a.py:1".into(), is_real: true, reachable: "reachable".into(),
                abstractable: Some(Abstraction { kind: "sink".into(), category: "file_read".into(), pattern: "foo.read".into() }),
                confidence: "high".into(),
            },
            outcome, votes: 1,
        };
        assert!(resolved_to_promote_action(&mk(AdjudicationOutcome::Reject)).is_none());
        assert!(resolved_to_promote_action(&mk(AdjudicationOutcome::Uncertain)).is_none());
    }

    // Helpers to build a resolved Promote verdict with a single expression.
    fn abs(kind: &str, category: &str, pattern: &str) -> Abstraction {
        Abstraction {
            kind: kind.into(),
            category: category.into(),
            pattern: pattern.into(),
        }
    }

    fn mk_resolved(
        item_id: &str,
        is_real: bool,
        reachable: &str,
        abstractable: Option<Abstraction>,
    ) -> ResolvedVerdict {
        ResolvedVerdict {
            verdict: AdjudicationVerdict {
                item_id: item_id.into(),
                is_real,
                reachable: reachable.into(),
                abstractable,
                confidence: "high".into(),
            },
            outcome: AdjudicationOutcome::Promote,
            votes: 3,
        }
    }

    #[test]
    fn resolved_to_promote_action_gates_on_is_real() {
        let r = mk_resolved("a.py:1", false, "reachable", Some(abs("sink", "file_read", "foo.read")));
        assert!(resolved_to_promote_action(&r).is_none());
    }

    #[test]
    fn resolved_to_promote_action_gates_on_reachable_grounding() {
        // The lightweight grounding gate: even a real, abstractable item must
        // not promote unless it was observed reachable.
        let unreachable = mk_resolved("a.py:1", true, "unreachable", Some(abs("sink", "file_read", "foo.read")));
        let unknown = mk_resolved("a.py:1", true, "unknown", Some(abs("sink", "file_read", "foo.read")));
        assert!(resolved_to_promote_action(&unreachable).is_none());
        assert!(resolved_to_promote_action(&unknown).is_none());
    }

    #[test]
    fn resolved_to_promote_action_gates_on_absent_abstraction() {
        let r = mk_resolved("a.py:1", true, "reachable", None);
        assert!(resolved_to_promote_action(&r).is_none());
    }

    #[test]
    fn resolved_to_promote_action_rejects_unknown_kind() {
        let r = mk_resolved("a.py:1", true, "reachable", Some(abs("mystery", "whatever", "x")));
        assert!(resolved_to_promote_action(&r).is_none());
    }

    #[test]
    fn resolved_to_promote_action_maps_rule_and_prompt() {
        let rule = mk_resolved("a.py:1", true, "reachable", Some(abs("rule", "path_traversal", "read")));
        match resolved_to_promote_action(&rule) {
            Some(PromoteAction::Rule(c)) => assert_eq!(c, "path_traversal"),
            _ => panic!("expected Rule"),
        }
        let prompt = mk_resolved("a.py:1", true, "reachable", Some(abs("prompt", "flag_exfil", "http.post")));
        match resolved_to_promote_action(&prompt) {
            Some(PromoteAction::Prompt(p)) => {
                assert!(p.contains("flag_exfil"), "prompt text should carry category");
                assert!(p.contains("http.post"), "prompt text should carry pattern");
            }
            _ => panic!("expected Prompt"),
        }
    }

    #[test]
    fn postprocess_stages_connect_render_parse_vote_without_claude() {
        // Compile-only wiring proof that the three postprocess stages connect
        // (render → parse → vote) without spawning claude. This is what Plan 2
        // drives via the agent-module re-exports.
        let items = vec![crate::AdjudicationItem {
            file: "server.ts".into(),
            line: 22,
            kind: "b_still_ambiguous".into(),
            agent_explanation: Some("reads arbitrary files".into()),
        }];
        let prompt = render_adjudication_prompt(&items);
        assert!(prompt.contains("server.ts:22"));

        // A fake single-line JSON verdict (what a real agent round would emit).
        let fake_stdout = "{\"item_id\":\"server.ts:22\",\"is_real\":true,\"reachable\":\"reachable\",\"abstractable\":null,\"confidence\":\"high\",\"reason\":\"arbitrary read\"}\n";
        let parsed = parse_verdicts(fake_stdout).expect("fake verdict parses");
        assert_eq!(parsed.len(), 1);

        // Simulate a full 3-round run where every round returns the same
        // verdict: unanimous → Promote, proving the full chain resolves.
        let resolved = vote(&[parsed.clone(), parsed.clone(), parsed]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].votes, 3);
        assert_eq!(resolved[0].outcome, AdjudicationOutcome::Promote);
    }
}
