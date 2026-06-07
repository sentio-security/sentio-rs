use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sentio_cli::render_human_report;
use sentio_core::{RuleRegistry, ScanOptions, Scanner};
use std::io::{self, IsTerminal, Write};

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
        Commands::Scan { path, format, rule, include_tests } => {
            let scanner = Scanner::new();
            let options = ScanOptions { include_tests, rule_filter: rule };
            let result = scanner.scan_path(&path, &options);

            match format {
                OutputFormat::Human => render_human(&result),
                OutputFormat::Json => render_json(&result)?,
            }

            Ok(if !result.parse_failures.is_empty() {
                2
            } else if result.findings.is_empty() {
                0
            } else {
                1
            })
        }
        Commands::Rules { command: RulesCommands::List } => render_rule_list(),
    }
}

fn render_rule_list() -> Result<i32> {
    let registry = RuleRegistry::baseline();
    for rule in registry.all() {
        let meta = rule.metadata();
        println!("{}  {}", meta.id, meta.title);
    }
    Ok(0)
}

fn render_human(result: &sentio_core::ScanResult) {
    let registry = RuleRegistry::baseline();
    let stdout = io::stdout();
    let use_color = stdout.is_terminal();
    let mut locked = stdout.lock();
    let _ = render_human_report(result, &registry, &mut locked, use_color);
}

fn render_json(result: &sentio_core::ScanResult) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(result)?);
    Ok(())
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
