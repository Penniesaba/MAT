use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "mcp-sec-audit")]
#[command(author, version, about = "Rust CLI for MCP Security Auditor", long_about = None)]
struct Cli {
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
    /// Run scan entrypoints.
    Scan {
        #[command(subcommand)]
        command: ScanCommand,
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

#[derive(Debug, Subcommand)]
enum ScanCommand {
    /// Run the Phase 5 static scan shell.
    Static(StaticScanArgs),
}

#[derive(Debug, Args)]
struct StaticScanArgs {
    /// Path to the runtime TOML config file.
    #[arg(long)]
    config: PathBuf,
    /// Override scan targets from the runtime config.
    #[arg(long)]
    target: Vec<PathBuf>,
    /// Override rulebook paths from the runtime config.
    #[arg(long)]
    rules: Vec<PathBuf>,
    /// Output format for the scan result.
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
        Some(Command::Scan { command }) => match command {
            ScanCommand::Static(args) => {
                let config = mcp_sec_audit_core::load_runtime_config(&args.config)?;
                let target_overrides = (!args.target.is_empty()).then_some(args.target.as_slice());
                let result =
                    mcp_sec_audit_core::run_static_scan(&config, &args.rules, target_overrides)?;
                println!("{}", render_static_result(&result, args.format, &config.report)?);
            }
        },
        None => {
            println!(
                "{} Rust CLI skeleton is ready.",
                mcp_sec_audit_core::product_name()
            );
            println!("Run `mcp-sec-audit --help` to see available commands.");
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
