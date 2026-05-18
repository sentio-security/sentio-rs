use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sentio_core::{RuleCatalog, ScanOptions, Scanner};

fn main() {
    let exit_code = match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            2
        }
    };

    std::process::exit(exit_code);
}

fn run() -> Result<i32> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            rule,
            include_tests,
        } => {
            let scanner = Scanner::new();
            let options = ScanOptions {
                include_tests,
                rule_filter: rule,
            };
            let result = scanner.scan_path(&path, &options);

            match format {
                OutputFormat::Human => render_human(&result),
                OutputFormat::Json => render_json(&result)?,
            }

            Ok(if result.findings.is_empty() { 0 } else { 1 })
        }
        Commands::Rules {
            command: RulesCommands::List,
        } => render_rule_list(),
    }
}

fn render_rule_list() -> Result<i32> {
    let catalog = RuleCatalog::baseline();
    for rule in catalog.all() {
        println!("{}  {}", rule.id.0, rule.title);
    }
    Ok(0)
}

fn render_human(result: &sentio_core::ScanResult) {
    if result.findings.is_empty() {
        println!("No findings.");
        return;
    }

    for finding in &result.findings {
        println!(
            "{} [{}] {}:{}:{} {}",
            finding.rule_id,
            severity_label(finding.severity),
            finding.location.path,
            finding.location.line,
            finding.location.column,
            finding.message
        );
    }
}

fn render_json(result: &sentio_core::ScanResult) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(result)?);
    Ok(())
}

fn severity_label(severity: sentio_core::Severity) -> &'static str {
    match severity {
        sentio_core::Severity::Low => "low",
        sentio_core::Severity::Medium => "medium",
        sentio_core::Severity::High => "high",
        sentio_core::Severity::Critical => "critical",
    }
}

#[derive(Debug, Parser)]
#[command(name = "sentio-rs")]
#[command(about = "CLI scanner for common Solana program vulnerability patterns")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Scan {
        #[arg(default_value = ".")]
        path: String,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        #[arg(long)]
        rule: Option<String>,
        #[arg(long)]
        include_tests: bool,
    },
    Rules {
        #[command(subcommand)]
        command: RulesCommands,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Subcommand)]
enum RulesCommands {
    List,
}
