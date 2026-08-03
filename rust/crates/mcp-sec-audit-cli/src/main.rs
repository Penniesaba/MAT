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
    #[arg(long, value_enum, default_value_t = DemoReportFormat::Markdown)]
    format: DemoReportFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DemoReportFormat {
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
                let rendered = match args.format {
                    DemoReportFormat::Json => mcp_sec_audit_core::render_json(&result)?,
                    DemoReportFormat::Jsonl => mcp_sec_audit_core::render_jsonl(
                        &result,
                        &mcp_sec_audit_core::JsonlRenderOptions::default(),
                    )?,
                    DemoReportFormat::Markdown => mcp_sec_audit_core::render_markdown(
                        &result,
                        &mcp_sec_audit_core::MarkdownRenderOptions::default(),
                    ),
                };
                println!("{rendered}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
