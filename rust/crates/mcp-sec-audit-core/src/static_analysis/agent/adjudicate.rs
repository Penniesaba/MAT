//! Self-consistent adjudication: render the prompt that asks the claude CLI
//! to judge each ambiguous evolution candidate with three closed questions.
//!
//! Plan 2 (M3/M4) drives this postprocess stage (render → parse → vote) through
//! the agent-module re-exports. Until that wiring lands, the stage is only
//! exercised by unit tests, so dead-code is allowed for the not-yet-wired surface.
#![allow(dead_code)]

use anyhow::Result;
use serde::Deserialize;

use crate::AdjudicationItem;
use crate::static_analysis::pipeline::StaticScanContext;
use super::provider::{AgentProvider, AgentRunConfig, CliAgentProvider};

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

/// Majority-vote each item across rounds. 3:0 => Promote/Reject by is_real;
/// any split (2:1 / 1:2) => Uncertain; invalid reachable => Uncertain.
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
        let outcome = if !all_valid || total != expected {
            AdjudicationOutcome::Uncertain
        } else if yes == total {
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

const ROUNDS: u32 = 3;

/// Run the claude CLI adjudication ROUNDS times, returning one Vec per round.
pub fn run_adjudication(
    ctx: &StaticScanContext,
    items: &[AdjudicationItem],
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
        let output = CliAgentProvider.run(&cfg)?;
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
