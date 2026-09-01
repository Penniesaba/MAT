//! TOML import/validate/export for the config form.

use anyhow::{Context, Result};
use mcp_sec_audit_core::{BatchConfig, RuntimeConfig};

/// A parsed config: either a single-repo runtime config or a batch config.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ConfigKind {
    Single(RuntimeConfig),
    Batch(BatchConfig),
}

/// Parse a TOML document as a batch config first (a batch file is a superset of
/// the runtime config), falling back to a single-repo runtime config.
pub fn parse_config(input: &str) -> Result<ConfigKind> {
    // A batch config carries a top-level `[batch]` table (possibly empty).
    match mcp_sec_audit_core::parse_batch_config_toml(input) {
        Ok(batch) if !batch.batch.repos.is_empty() || contains_batch_table(input) => {
            Ok(ConfigKind::Batch(batch))
        }
        // A present-but-invalid `[batch]` table must surface its error rather
        // than silently falling through to a `Single` runtime config.
        Err(e) if contains_batch_table(input) => Err(e),
        // No `[batch]` table (or an empty one with no repos): a single repo.
        _ => {
            let runtime = mcp_sec_audit_core::parse_runtime_config_toml(input)
                .context("parse as runtime config")?;
            Ok(ConfigKind::Single(runtime))
        }
    }
}

fn contains_batch_table(input: &str) -> bool {
    input.lines().any(|l| l.trim_start().starts_with("[batch]"))
}

/// Serialize the config back to TOML (for export/download).
pub fn render_config(config: &ConfigKind) -> Result<String> {
    match config {
        ConfigKind::Single(r) => toml::to_string_pretty(r).context("serialize runtime config"),
        ConfigKind::Batch(b) => toml::to_string_pretty(b).context("serialize batch config"),
    }
}

/// Round-trip a config through JSON to confirm it is serde-representable
/// (the form/WS also transport it as JSON).
pub fn config_as_json(config: &ConfigKind) -> Result<serde_json::Value> {
    let json = match config {
        ConfigKind::Single(r) => serde_json::to_value(r)?,
        ConfigKind::Batch(b) => serde_json::to_value(b)?,
    };
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_repo_config() {
        let cfg = parse_config("[scan]\ntargets = [\"src\"]\n").expect("parse");
        assert!(matches!(cfg, ConfigKind::Single(_)));
    }

    #[test]
    fn parses_batch_config_with_repos() {
        let cfg = parse_config(
            "[batch]\nmax_parallel = 2\n[[batch.repo]]\nname = \"a\"\npath = \"/a\"\n",
        )
        .expect("parse");
        assert!(matches!(cfg, ConfigKind::Batch(_)));
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(parse_config("not [ valid toml").is_err());
    }

    #[test]
    fn rejects_batch_table_with_type_error() {
        // A `[batch]` table with a mistyped value must error, not fall through
        // to a `Single` runtime config.
        assert!(parse_config("[batch]\nmax_parallel = \"abc\"\n").is_err());
    }

    #[test]
    fn parses_empty_batch_table_as_batch() {
        // An explicit (empty) `[batch]` table with no repos still means batch.
        let cfg = parse_config("[batch]\nmax_parallel = 2\n").expect("parse");
        assert!(matches!(cfg, ConfigKind::Batch(_)));
    }

    #[test]
    fn parses_implicit_batch_table_as_batch() {
        // `[[batch.repo]]` implicitly creates the parent `[batch]` table.
        let cfg = parse_config("[[batch.repo]]\nname = \"a\"\npath = \"/a\"\n").expect("parse");
        assert!(matches!(cfg, ConfigKind::Batch(_)));
    }

    #[test]
    fn render_round_trips_single() {
        let cfg = parse_config("[scan]\ntargets = [\"src\"]\n").unwrap();
        let out = render_config(&cfg).unwrap();
        assert!(out.contains("src"));
    }

    #[test]
    fn json_round_trips_both_kinds() {
        let single = parse_config("[scan]\ntargets = [\"src\"]\n").unwrap();
        let s = config_as_json(&single).unwrap();
        assert_eq!(s["scan"]["targets"][0], "src");

        let batch = parse_config(
            "[batch]\nmax_parallel = 2\n[[batch.repo]]\nname = \"a\"\npath = \"/a\"\n",
        )
        .unwrap();
        let b = config_as_json(&batch).unwrap();
        assert_eq!(b["batch"]["repo"][0]["name"], "a");
    }
}
