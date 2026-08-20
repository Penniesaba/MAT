mod logging;

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};

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
    let result = mcp_sec_audit_core::run_static_scan_with_progress(
        &config,
        &[] as &[PathBuf],
        None,
        |msg| eprintln!("{msg}"),
    )?;
    for path in write_report_files(&result, &config.report)? {
        eprintln!("Wrote {}", path.display());
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

    let output = mcp_sec_audit_core::resolve_output_path(&report.output);

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
        fs::write(&path, content)
            .with_context(|| format!("write report to {}", path.display()))?;
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
        assert!(written
            .iter()
            .any(|p| p.extension().and_then(|e| e.to_str()) == Some("json")));
        assert!(written
            .iter()
            .any(|p| p.extension().and_then(|e| e.to_str()) == Some("md")));

        for path in written {
            std::fs::remove_file(&path).expect("cleanup");
        }
    }
}
