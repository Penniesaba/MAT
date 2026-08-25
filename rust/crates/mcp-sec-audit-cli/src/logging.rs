use std::fmt;
use std::io;

use anyhow::Result;
use mcp_sec_audit_core::{LogFormat, LogLevel, LoggingConfig};
use tracing::{Event, Subscriber};
use tracing_subscriber::Registry;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::format::{FormatEvent, Writer};
use tracing_subscriber::fmt::{FmtContext, FormatFields, MakeWriter};
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
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
            // A log file is not a terminal: never write color escapes into it,
            // whatever `ansi` says. Otherwise the green module highlight lands
            // in the file as literal `\e[32m` noise.
            let mut file_config = config.clone();
            file_config.ansi = false;
            init_with_writer(&file_config, file)
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
    // `json` stays machine-oriented (structured, its own timestamp field).
    // The human-readable formats (full/compact/pretty) all use the same custom
    // event format: `<local-minute> <module>: <message>`, so a log line reads
    // e.g. `2026-08-25 19:00 pipeline: Scanning ...` with no level and no
    // `mcp_sec_audit::` crate prefix in between.
    if config.format == LogFormat::Json {
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(config.ansi)
            .with_writer(writer);
        if config.show_timestamps {
            return Box::new(layer.json());
        }
        return Box::new(layer.json().without_time());
    }

    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(config.ansi)
        .with_writer(writer)
        .event_format(ModuleFormat {
            show_timestamps: config.show_timestamps,
        });
    Box::new(layer)
}

/// Custom event formatter: `<local-minute-timestamp> <module>: <message>`.
///
/// Dropping the tracing level and the `mcp_sec_audit::` crate prefix keeps a
/// line to the essential `<module>: <record>` shape requested for the audit log.
struct ModuleFormat {
    show_timestamps: bool,
}

impl<S, N> FormatEvent<S, N> for ModuleFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        if self.show_timestamps {
            write!(writer, "{} ", local_minute_timestamp())?;
        }
        let ansi = writer.has_ansi_escapes();
        let module = module_name(event.metadata().target());
        write!(writer, "{}: ", styled_module(module, ansi))?;
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// Last `::`-separated segment of a tracing target: the module name.
/// `mcp_sec_audit::pipeline` → `pipeline`; `mcp_sec_audit` → `mcp_sec_audit`.
fn module_name(target: &str) -> &str {
    target.rsplit("::").next().unwrap_or(target)
}

/// SGR green, then a foreground-only reset (`39`) so the message text after the
/// module keeps whatever styling the field formatter applies.
const GREEN: &str = "\u{1b}[32m";
const RESET_FG: &str = "\u{1b}[39m";

/// The module name, green when the writer accepts ANSI escapes.
///
/// `ansi` comes from the layer's `with_ansi(config.ansi)` setting, so a
/// `log_file` redirect with `ansi = false` stays free of escape codes.
fn styled_module(name: &str, ansi: bool) -> String {
    if ansi {
        format!("{GREEN}{name}{RESET_FG}")
    } else {
        name.to_string()
    }
}

/// Current local time as `YYYY-MM-DD HH:MM` (minute precision, no seconds).
fn local_minute_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as libc::time_t;

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `tm` is a valid writable buffer outliving the call; `secs` is a
    // valid `time_t`. `localtime_r` writes into `tm` and never reads it first.
    let result = unsafe { libc::localtime_r(&secs, &mut tm) };
    if result.is_null() {
        // No local timezone data — fall back to a placeholder rather than UTC,
        // since a wrong-looking hour is exactly what we're trying to avoid.
        return "????-??-?? ??:??".to_string();
    }

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
    )
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

    #[test]
    fn module_name_strips_crate_prefix() {
        assert_eq!(module_name("mcp_sec_audit::pipeline"), "pipeline");
        assert_eq!(module_name("mcp_sec_audit::agent"), "agent");
        assert_eq!(module_name("mcp_sec_audit"), "mcp_sec_audit");
        assert_eq!(module_name("tracing"), "tracing");
    }

    #[test]
    fn styled_module_is_green_when_ansi_enabled() {
        assert_eq!(
            styled_module("pipeline", true),
            "\u{1b}[32mpipeline\u{1b}[39m"
        );
        assert_eq!(styled_module("agent", true), "\u{1b}[32magent\u{1b}[39m");
    }

    #[test]
    fn styled_module_is_plain_when_ansi_disabled() {
        assert_eq!(styled_module("pipeline", false), "pipeline");
    }

    /// In-memory `MakeWriter` so a test can read back a formatted line.
    #[derive(Clone, Default)]
    struct BufWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl BufWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufWriter {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn capture(config: &LoggingConfig) -> String {
        let buf = BufWriter::default();
        let layer = fmt_layer(config, buf.clone()).with_filter(build_targets(config));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "mcp_sec_audit::agent", "probing component");
        });
        buf.contents()
    }

    #[test]
    fn formatted_line_greens_the_module_after_the_timestamp() {
        let config = LoggingConfig::default();
        let line = capture(&config);

        // `<timestamp> <green>agent</green>: <message>`
        assert!(
            line.contains("\u{1b}[32magent\u{1b}[39m: probing component"),
            "module not highlighted: {line:?}"
        );
        // The timestamp itself stays unstyled.
        assert!(!line.starts_with('\u{1b}'), "timestamp styled: {line:?}");
    }

    #[test]
    fn formatted_line_has_no_escapes_when_ansi_disabled() {
        let config = LoggingConfig {
            ansi: false,
            ..Default::default()
        };
        let line = capture(&config);

        assert!(line.contains("agent: probing component"), "{line:?}");
        assert!(!line.contains('\u{1b}'), "escape codes leaked: {line:?}");
    }

    #[test]
    fn local_minute_timestamp_has_minute_precision_and_no_seconds() {
        let ts = local_minute_timestamp();
        // `YYYY-MM-DD HH:MM` — exactly 16 chars, no seconds, no timezone suffix.
        assert_eq!(ts.len(), 16, "unexpected timestamp: {ts}");
        let bytes = ts.as_bytes();
        assert!(ts.chars().all(|c| c.is_ascii_digit() || c == '-' || c == ' ' || c == ':'));
        assert_eq!(bytes[4], b'-');
        assert_eq!(bytes[7], b'-');
        assert_eq!(bytes[10], b' ');
        assert_eq!(bytes[13], b':');
    }
}
