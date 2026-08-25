mod batch;
mod logging;

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(name = "mcp-sec-audit")]
#[command(author, version, about = "Rust CLI for MCP Security Auditor", long_about = None)]
struct Cli {
    /// Path to the runtime TOML config file. Runs the static scan when no subcommand is given.
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show Rust rewrite status.
    Status,
    /// Validate runtime scan configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Validate TOML rulebooks.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Render synthetic reports for Phase 4 verification.
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    /// Analyze multiple MCP repositories in parallel.
    Batch(BatchArgs),
}

#[derive(Debug, Args)]
struct BatchArgs {
    /// Path to the batch TOML config file.
    config: PathBuf,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Parse a runtime TOML config file.
    Validate(ConfigValidateArgs),
}

#[derive(Debug, Args)]
struct ConfigValidateArgs {
    /// Path to the runtime TOML config file.
    #[arg(long)]
    config: PathBuf,
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    /// Parse a TOML rulebook file.
    Validate(RulesValidateArgs),
}

#[derive(Debug, Args)]
struct RulesValidateArgs {
    /// Path to a TOML rulebook file.
    #[arg(long)]
    rules: PathBuf,
}

#[derive(Debug, Subcommand)]
enum ReportCommand {
    /// Render a synthetic static analysis report.
    Demo(ReportDemoArgs),
}

#[derive(Debug, Args)]
struct ReportDemoArgs {
    /// Output format for the synthetic report.
    #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
    format: OutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Jsonl,
    Markdown,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Status) => {
            println!("{}", mcp_sec_audit_core::product_name());
            println!("phase: {}", mcp_sec_audit_core::CURRENT_PHASE);
        }
        Some(Command::Config { command }) => match command {
            ConfigCommand::Validate(args) => {
                let config = mcp_sec_audit_core::load_runtime_config(&args.config)?;
                println!("runtime config loaded: {}", args.config.display());
                println!(
                    "static lines: rule={}, taint={}, agent={}",
                    config.static_.rule.enabled,
                    config.static_.taint.enabled,
                    config.static_.agent.enabled
                );
                println!("dynamic enabled: {}", config.dynamic.enabled);
            }
        },
        Some(Command::Rules { command }) => match command {
            RulesCommand::Validate(args) => {
                let rulebook = mcp_sec_audit_core::load_rulebook(&args.rules)?;
                println!("rulebook loaded: {}", args.rules.display());
                println!("capabilities: {}", rulebook.len());
            }
        },
        Some(Command::Report { command }) => match command {
            ReportCommand::Demo(args) => {
                let result = mcp_sec_audit_core::fixtures::synthetic_static_analysis_result();
                println!(
                    "{}",
                    render_static_result(
                        &result,
                        args.format,
                        &mcp_sec_audit_core::ReportConfig::default(),
                    )?
                );
            }
        },
        Some(Command::Batch(args)) => {
            // The batch path needs an async runtime, but the single-repo path
            // (and the other subcommands) are synchronous and must keep running
            // *outside* any runtime — `run_static_scan_inner` bridges to the
            // async pipeline via `block_on`, which panics from inside an active
            // runtime thread. So build the runtime here, for batch only.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("build tokio runtime")?;
            let cancel = CancellationToken::new();
            // A separate token tracks the *user's* Ctrl-C specifically: `cancel`
            // is also cancelled by `run_batch` itself when `fail_fast` aborts the
            // batch, and that must map to exit 1 (failures), not 130 (interrupt).
            let ctrl_c = CancellationToken::new();
            {
                let cancel = cancel.clone();
                let ctrl_c = ctrl_c.clone();
                rt.spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    ctrl_c.cancel();
                    cancel.cancel();
                });
            }
            let summary = rt.block_on(batch::run(&args.config, cancel.clone()));
            // `std::process::exit` terminates immediately so the exit code is
            // fully under our control; the other subcommands keep returning
            // `Ok(())` and let `main`'s `Result` map their errors normally.
            std::process::exit(match summary {
                Ok(_) if ctrl_c.is_cancelled() => 130,
                Ok(s) if s.failed > 0 || s.cancelled > 0 => 1,
                Ok(_) => 0,
                Err(_) => 2,
            });
        }
        None => match cli.config {
            Some(config_path) => run_static_scan_from_config(&config_path)?,
            None => {
                println!(
                    "{} Rust CLI skeleton is ready.",
                    mcp_sec_audit_core::product_name()
                );
                println!("Run `mcp-sec-audit --help` to see available commands.");
            }
        },
    }

    Ok(())
}

fn run_static_scan_from_config(config_path: &PathBuf) -> Result<()> {
    let config = mcp_sec_audit_core::load_runtime_config(config_path)?;
    logging::init(&config.logging)?;
    // The single-repo path uses `Progress`'s tracing form so progress stays
    // live (each `report` emits a `tracing::info!` immediately) instead of
    // being buffered and dumped at the end. `show_progress` downgrades it to
    // the noop form, preserving the previous "quiet" behavior.
    let progress = if config.logging.show_progress {
        mcp_sec_audit_core::Progress::tracing()
    } else {
        mcp_sec_audit_core::Progress::noop()
    };
    let result =
        mcp_sec_audit_core::run_static_scan_inner(&config, &[] as &[PathBuf], None, &progress)?;
    for path in write_report_files(&result, &config.report)? {
        tracing::info!(target: "mcp_sec_audit::pipeline", path = %path.display(), "wrote report");
    }
    Ok(())
}

fn render_static_result(
    result: &mcp_sec_audit_core::StaticAnalysisResult,
    format: OutputFormat,
    report: &mcp_sec_audit_core::ReportConfig,
) -> Result<String> {
    match format {
        OutputFormat::Json => mcp_sec_audit_core::render_json(result),
        OutputFormat::Jsonl => mcp_sec_audit_core::render_jsonl(
            result,
            &mcp_sec_audit_core::JsonlRenderOptions::from(report),
        ),
        OutputFormat::Markdown => Ok(mcp_sec_audit_core::render_markdown(
            result,
            &mcp_sec_audit_core::MarkdownRenderOptions::from(report),
        )),
    }
}

fn write_report_files(
    result: &mcp_sec_audit_core::StaticAnalysisResult,
    report: &mcp_sec_audit_core::ReportConfig,
) -> Result<Vec<PathBuf>> {
    use mcp_sec_audit_core::ReportFormat;

    if report.formats.is_empty() {
        eprintln!("No report formats configured; nothing written");
        return Ok(Vec::new());
    }

    let output =
        mcp_sec_audit_core::resolve_output_path(&report.output, Some(&result.summary.target));

    let mut written = Vec::new();
    for fmt in &report.formats {
        let Some(format) = ReportFormat::parse(fmt) else {
            bail!("unsupported report format: {fmt}");
        };
        let content = match format {
            ReportFormat::Json => mcp_sec_audit_core::render_json(result)?,
            ReportFormat::Jsonl => mcp_sec_audit_core::render_jsonl(
                result,
                &mcp_sec_audit_core::JsonlRenderOptions::from(report),
            )?,
            ReportFormat::Markdown => mcp_sec_audit_core::render_markdown(
                result,
                &mcp_sec_audit_core::MarkdownRenderOptions::from(report),
            ),
        };
        let path = PathBuf::from(format!("{}.{}", output, format.extension()));
        fs::write(&path, content).with_context(|| format!("write report to {}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn write_report_files_writes_configured_formats() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base = std::env::temp_dir()
            .join(format!("mcp-sec-audit-cli-{nanos}"))
            .to_string_lossy()
            .to_string();

        let result = mcp_sec_audit_core::fixtures::synthetic_static_analysis_result();
        let mut report = mcp_sec_audit_core::ReportConfig::default();
        report.output = base;
        report.formats = vec!["json".to_string(), "markdown".to_string()];

        let written = write_report_files(&result, &report).expect("write reports");
        assert_eq!(written.len(), 2);
        assert!(
            written
                .iter()
                .any(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        );
        assert!(
            written
                .iter()
                .any(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
        );

        for path in written {
            std::fs::remove_file(&path).expect("cleanup");
        }
    }
}
