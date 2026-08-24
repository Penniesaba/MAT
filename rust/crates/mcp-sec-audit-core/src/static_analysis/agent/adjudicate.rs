//! Self-consistent adjudication: render the prompt that asks the claude CLI
//! to judge each ambiguous evolution candidate with three closed questions.

use crate::AdjudicationItem;

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
}
