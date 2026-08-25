//! Golden regression tests for the static-analysis pipeline.
//!
//! These tests are the safety net for the v5.0 async (tokio) migration: they
//! pin the *end-to-end rendered output* of [`run_static_scan`] so that any
//! behavior change introduced by a later task is caught as a fixture diff.
//!
//! Two cases (per controller amendment GAP-1):
//!
//! * **Case A** (`golden-python-mcp.json`) — agent + codeql disabled. Exercises
//!   discovery → facts → rule → taint → gating (no-op) → fusion → summary.
//! * **Case B** (`golden-agent-evolution.json`) — agent enabled via a stub
//!   shell script, driving the full two-phase self-evolution path (gating →
//!   staging → phase 2 → adjudication → promote). This is the path that Task 7
//!   actually rewrites with `.await`, so a baseline that left the agent line
//!   off would not cover it.
//!
//! Normalization contract (see [`normalize_for_golden`]):
//! * absolute paths (target, rulebook, temp dir) → stable `<ROOT>`/`<RULEBOOK>`/`<TMP>` tokens;
//! * UUIDs (e.g. fused `finding_id`) → `<UUID>`;
//! * run identifiers embedded in provenance → `<SCAN_ID>`;
//! * array ordering → canonical (sorted) so nondeterministic collection order
//!   does not produce a spurious diff.
//!
//! Everything else is left verbatim so a genuine regression (a missing/extra
//! finding, a changed category, a dropped fact) still changes the fixture.

use std::path::PathBuf;

use mcp_sec_audit_core::{render_json, run_static_scan, RuntimeConfig};
use serde_json::Value;

/// Absolute path to this crate's manifest directory (`rust/crates/mcp-sec-audit-core`).
fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The tracked python MCP server test target (a git-tracked fixture).
fn target_dir() -> PathBuf {
    manifest_dir().join("../../../test-targets/python-mcp-server")
}

/// The tracked rulebook used by the real pipeline (`rust/rules/languages/keywords.toml`).
fn rulebook_file() -> PathBuf {
    manifest_dir().join("../../rules/languages/keywords.toml")
}

fn fixture_path(name: &str) -> PathBuf {
    manifest_dir().join("tests/fixtures").join(name)
}

/// Normalize a rendered JSON document into a stable golden form.
///
/// `masks` is a list of `(needle, replacement)` applied (in order) to every
/// string value in the document; needles are canonical absolute path prefixes
/// that vary across machines/runs.
fn normalize_for_golden(json: &str, masks: &[(String, &str)]) -> Value {
    let mut value: Value = serde_json::from_str(json).expect("render_json output must parse");
    normalize_value(&mut value, masks);
    value
}

fn normalize_value(value: &mut Value, masks: &[(String, &str)]) {
    match value {
        Value::String(s) => {
            let mut out = s.clone();
            for (needle, replacement) in masks {
                out = out.replace(needle.as_str(), replacement);
            }
            out = mask_uuid(&out);
            out = mask_scan_id(&out);
            *s = out;
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                normalize_value(item, masks);
            }
            // Deterministic ordering: sort by canonical compact JSON form so a
            // stable total order exists even across mixed-type arrays.
            items.sort_by_key(canonical_json);
        }
        Value::Object(map) => {
            for child in map.values_mut() {
                normalize_value(child, masks);
            }
        }
        _ => {}
    }
}

/// Compact canonical form of a `Value`, used as the sort key for array
/// ordering. `serde_json::to_string` is infallible for a `Value`.
fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Replace a v4 UUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) with `<UUID>`.
/// The only per-run UUID in the result is the fused `finding_id`; this is
/// checked structurally (length + hyphen positions + hex) rather than by key so
/// any future UUID-shaped field is masked too.
fn mask_uuid(s: &str) -> String {
    if is_uuid(s) {
        return "<UUID>".to_string();
    }
    // UUIDs may be embedded as a substring of a composite id; scan the string
    // for the fixed hyphen skeleton and rewrite each hit.
    let bytes = s.as_bytes();
    if bytes.len() < 36 {
        return s.to_string();
    }
    let mut out = s.to_string();
    for start in 0..=bytes.len() - 36 {
        let candidate = &bytes[start..start + 36];
        if is_uuid_bytes(candidate) {
            out.replace_range(start..start + 36, "<UUID>");
            return out; // single occurrence expected; keep it simple
        }
    }
    out
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36 && is_uuid_bytes(s.as_bytes())
}

fn is_uuid_bytes(b: &[u8]) -> bool {
    b.len() == 36
        && b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && b
            .iter()
            .enumerate()
            .all(|(i, &c)| [8, 13, 18, 23].contains(&i) || c.is_ascii_hexdigit())
}

/// Replace a run identifier (`scan-<mangled-target>-<unix-seconds>`) with
/// `<SCAN_ID>`. Defensive: the current pipeline writes provenance
/// (`learned_from = scan-id/agent-id`) to disk rather than into the rendered
/// result, but the contract forbids any run identifier leaking into the golden
/// snapshot, so mask it structurally anyway.
fn mask_scan_id(s: &str) -> String {
    let Some(idx) = s.find("scan-") else {
        return s.to_string();
    };
    let rest = &s[idx + "scan-".len()..];
    // The identifier is `scan-` + a mangled target (no `/`, `\`, or
    // whitespace) + `-` + the unix-seconds digit run.
    let mut digits_start = None;
    for (i, ch) in rest.char_indices() {
        if ch.is_ascii_digit() {
            digits_start = Some(i);
            break;
        }
        if matches!(ch, '/' | '\\' | ' ') {
            break;
        }
    }
    let Some(ds) = digits_start else {
        return s.to_string();
    };
    let digit_len = rest[ds..].chars().take_while(|c| c.is_ascii_digit()).count();
    let head = &rest[..ds];
    // `head` must end with `-` (the separator before the seconds).
    if head.ends_with('-') && digit_len >= 9 {
        let full_end = idx + "scan-".len() + ds + digit_len;
        let mut out = s.to_string();
        out.replace_range(idx..full_end, "<SCAN_ID>");
        return out;
    }
    s.to_string()
}

fn assert_golden(name: &str, actual: &Value) {
    let path = fixture_path(name);
    if std::env::var_os("GOLDEN_REGEN").is_some() {
        std::fs::create_dir_all(path.parent().expect("fixture dir")).expect("create fixtures dir");
        let pretty = serde_json::to_string_pretty(actual).expect("pretty serialize");
        std::fs::write(&path, format!("{pretty}\n")).expect("write fixture");
        return;
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing golden fixture {}: {e} (run with GOLDEN_REGEN=1 to regenerate)",
            path.display()
        )
    });
    let expected: Value = serde_json::from_str(&text).expect("fixture must parse");
    assert_eq!(
        actual, &expected,
        "golden regression: pipeline output changed (fixture {})",
        path.display()
    );
}

/// Case A — rule + taint only (agent/codeql disabled). Pins the standard-line
/// pipeline end to end.
#[test]
fn golden_python_mcp_server_result_is_stable() {
    let target = target_dir().canonicalize().expect("canonicalize target");
    let rulebook = rulebook_file().canonicalize().expect("canonicalize rulebook");
    assert!(
        target.join("server.py").exists(),
        "test target must exist at {}",
        target.display()
    );

    let mut config = RuntimeConfig::default();
    config.static_.rule.enabled = true;
    config.static_.taint.enabled = true;
    config.static_.agent.enabled = false;
    config.static_.codeql.enabled = false;

    let result = run_static_scan(
        &config,
        std::slice::from_ref(&rulebook),
        Some(std::slice::from_ref(&target)),
    )
    .expect("case A scan");

    // Guard against a silently-empty snapshot: the target must actually yield
    // facts and fused findings, otherwise the fixture covers nothing.
    assert!(result.summary.fact_count > 0, "expected extracted facts");
    assert!(
        result.summary.fused_finding_count > 0,
        "expected fused findings from the vulnerable MCP server"
    );
    assert!(
        result.summary.rule_result_count > 0,
        "expected rule-line findings"
    );

    let json = render_json(&result).expect("case A json");
    let actual = normalize_for_golden(
        &json,
        &[
            (target.display().to_string(), "<ROOT>"),
            (rulebook.display().to_string(), "<RULEBOOK>"),
        ],
    );
    assert_golden("golden-python-mcp.json", &actual);
}

/// Case B — agent enabled via a stub shell script, with a temp `learned_dir`,
/// so the full two-phase self-evolution path runs (gating → staging → phase 2
/// → adjudication → promote) and actually persists models to disk.
#[cfg(unix)]
#[test]
fn golden_agent_evolution_result_is_stable() {
    use std::os::unix::fs::PermissionsExt;

    let target = target_dir().canonicalize().expect("canonicalize target");
    let rulebook = rulebook_file().canonicalize().expect("canonicalize rulebook");
    assert!(
        target.join("server.py").exists(),
        "test target must exist at {}",
        target.display()
    );

    // Fresh, unique temp root each run: holds the stub script and learned_dir.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let tmp = std::env::temp_dir().join(format!(
        "mcp-sec-audit-golden-b-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&tmp).expect("create temp root");
    let tmp = tmp.canonicalize().expect("canonicalize temp root");

    // Stub agent: a tiny shell script printing a fixed agent output proposing
    // `openpyxl.load_workbook` as a `file_read` sink (gated Hot by the package
    // rule, then staged and promoted).
    let stub = tmp.join("agent-stub.sh");
    std::fs::write(
        &stub,
        r#"#!/bin/sh
printf '%s\n' '{"findings":[],"model_candidates":[{"kind":"sink","name":"openpyxl.load_workbook","category":"file_read","language":"python","argument":0,"confidence":"medium","evidence_snippets":[]}]}'
"#,
    )
    .expect("write stub");
    let mut perms = std::fs::metadata(&stub).expect("stub metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&stub, perms).expect("chmod stub");

    let learned_dir = tmp.join("learned");
    // The scan's catalog loader reads `learned_dir` up front (to reload models
    // from prior runs), so the directory must already exist — empty is fine.
    std::fs::create_dir_all(&learned_dir).expect("create learned dir");

    let mut config = RuntimeConfig::default();
    config.static_.rule.enabled = true;
    config.static_.taint.enabled = true;
    config.static_.agent.enabled = true;
    config.static_.agent.provider = stub.display().to_string();
    config.static_.codeql.enabled = false;
    config.static_.learned_dir = Some(learned_dir.display().to_string());

    let result = run_static_scan(
        &config,
        std::slice::from_ref(&rulebook),
        Some(std::slice::from_ref(&target)),
    )
    .expect("case B scan");

    // The snapshot must NOT be silently empty: assert the evolution path
    // actually ran and persisted models.
    assert!(
        !result.model_candidates.is_empty(),
        "agent stub should surface a model candidate"
    );
    assert!(
        result.evolution.promoted,
        "staged delta should be promoted (not rolled back)"
    );
    assert!(result.evolution.promoted_count > 0, "promote must persist models");
    let persisted: Vec<_> = std::fs::read_dir(&learned_dir)
        .expect("learned_dir should exist after promote")
        .collect::<Result<Vec<_>, _>>()
        .expect("read learned_dir");
    assert!(
        !persisted.is_empty(),
        "promote path must write model files to learned_dir"
    );

    let json = render_json(&result).expect("case B json");
    let actual = normalize_for_golden(
        &json,
        &[
            (target.display().to_string(), "<ROOT>"),
            (rulebook.display().to_string(), "<RULEBOOK>"),
            (tmp.display().to_string(), "<TMP>"),
        ],
    );
    assert_golden("golden-agent-evolution.json", &actual);

    std::fs::remove_dir_all(&tmp).expect("cleanup temp root");
}
