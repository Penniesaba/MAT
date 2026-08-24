//! Self-consistent adjudication: render the prompt that asks the claude CLI
//! to judge each ambiguous evolution candidate with three closed questions.

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
}
