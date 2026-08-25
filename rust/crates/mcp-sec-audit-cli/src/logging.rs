use std::io;

use anyhow::Result;
use mcp_sec_audit_core::{LogFormat, LogLevel, LoggingConfig};
use tracing_subscriber::Registry;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

/// `[logging.scopes]` keys mapped to the tracing targets used by the
/// pipeline and analysis lines.
const SCOPE_TARGETS: &[(&str, &str)] = &[
    ("pipeline", "mcp_sec_audit::pipeline"),
    ("rule", "mcp_sec_audit::rule"),
    ("taint", "mcp_sec_audit::taint"),
    ("agent", "mcp_sec_audit::agent"),
    ("codeql", "mcp_sec_audit::codeql"),
    ("fusion", "mcp_sec_audit::fusion"),
    ("learning", "mcp_sec_audit::learning"),
    ("facts", "mcp_sec_audit::facts"),
    ("infer", "mcp_sec_audit::infer"),
    ("diff", "mcp_sec_audit::diff"),
    ("validate", "mcp_sec_audit::validate"),
    ("evolution", "mcp_sec_audit::evolution"),
    ("component", "mcp_sec_audit::component"),
];

/// Pure mapping from config to per-target (target, level) directives.
/// The first entry is the default (`""` = all targets).
pub fn scope_directives(config: &LoggingConfig) -> Vec<(String, LevelFilter)> {
    let mut out = vec![("".to_string(), to_level_filter(config.level))];
    for (key, target) in SCOPE_TARGETS {
        if let Some(&level) = config.scopes.get(*key) {
            out.push((target.to_string(), to_level_filter(level)));
        }
    }
    out
}

/// Build the `Targets` filter consumed by the subscriber.
pub fn build_targets(config: &LoggingConfig) -> Targets {
    let mut targets = Targets::new().with_default(to_level_filter(config.level));
    for (target, level) in scope_directives(config).into_iter().skip(1) {
        targets = targets.with_target(target, level);
    }
    targets
}

fn to_level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Trace => LevelFilter::TRACE,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
    }
}

/// Initialize the process-global subscriber from `[logging]` config.
/// Writes to stderr, or to `log_file` when configured (redirect). Only call once.
pub fn init(config: &LoggingConfig) -> Result<()> {
    let result = match &config.log_file {
        Some(path) => {
            let file = std::fs::File::create(path)
                .map_err(|e| anyhow::anyhow!("create log file {path}: {e}"))?;
            init_with_writer(config, file)
        }
        None => init_with_writer(config, io::stderr),
    };
    result
}

fn init_with_writer<W>(config: &LoggingConfig, writer: W) -> Result<()>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let layer = fmt_layer(config, writer).with_filter(build_targets(config));
    tracing_subscriber::registry()
        .with(layer)
        .try_init()
        .map_err(|e| anyhow::anyhow!("tracing init failed: {e}"))
}

fn fmt_layer<W>(
    config: &LoggingConfig,
    writer: W,
) -> Box<dyn tracing_subscriber::Layer<Registry> + Send + Sync>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(config.ansi)
        .with_target(true)
        .with_writer(writer);

    match (config.format, config.show_timestamps) {
        (LogFormat::Full, true) => Box::new(layer),
        (LogFormat::Full, false) => Box::new(layer.without_time()),
        (LogFormat::Compact, true) => Box::new(layer.compact()),
        (LogFormat::Compact, false) => Box::new(layer.compact().without_time()),
        (LogFormat::Pretty, true) => Box::new(layer.pretty()),
        (LogFormat::Pretty, false) => Box::new(layer.pretty().without_time()),
        (LogFormat::Json, true) => Box::new(layer.json()),
        (LogFormat::Json, false) => Box::new(layer.json().without_time()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_sec_audit_core::LoggingConfig;

    #[test]
    fn scope_directives_maps_scopes_to_targets() {
        let mut config = LoggingConfig::default();
        config.level = LogLevel::Info;
        config.scopes.insert("codeql".to_string(), LogLevel::Trace);
        config.scopes.insert("rule".to_string(), LogLevel::Debug);

        let directives = scope_directives(&config);

        assert_eq!(directives[0], ("".to_string(), LevelFilter::INFO));
        assert!(directives.contains(&("mcp_sec_audit::codeql".to_string(), LevelFilter::TRACE)));
        assert!(directives.contains(&("mcp_sec_audit::rule".to_string(), LevelFilter::DEBUG)));
    }

    #[test]
    fn scope_directives_ignores_unknown_scope_keys() {
        let mut config = LoggingConfig::default();
        config.scopes.insert("bogus".to_string(), LogLevel::Trace);

        let directives = scope_directives(&config);
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0], ("".to_string(), LevelFilter::INFO));
    }

    #[test]
    fn scope_directives_includes_new_v4_targets() {
        let mut config = LoggingConfig::default();
        config.scopes.insert("facts".to_string(), LogLevel::Debug);
        config.scopes.insert("infer".to_string(), LogLevel::Debug);
        config.scopes.insert("diff".to_string(), LogLevel::Debug);
        config
            .scopes
            .insert("validate".to_string(), LogLevel::Debug);
        config
            .scopes
            .insert("evolution".to_string(), LogLevel::Trace);
        config
            .scopes
            .insert("component".to_string(), LogLevel::Debug);

        let directives = scope_directives(&config);
        assert!(directives.contains(&("mcp_sec_audit::facts".to_string(), LevelFilter::DEBUG)));
        assert!(directives.contains(&("mcp_sec_audit::infer".to_string(), LevelFilter::DEBUG)));
        assert!(directives.contains(&("mcp_sec_audit::diff".to_string(), LevelFilter::DEBUG)));
        assert!(directives.contains(&("mcp_sec_audit::validate".to_string(), LevelFilter::DEBUG)));
        assert!(directives.contains(&("mcp_sec_audit::evolution".to_string(), LevelFilter::TRACE)));
        assert!(directives.contains(&("mcp_sec_audit::component".to_string(), LevelFilter::DEBUG)));
    }
}
