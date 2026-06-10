use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sentio_cli::render_human_report;
use sentio_core::{RuleRegistry, ScanOptions, Scanner};
use std::io::{self, IsTerminal};

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
#[command(name = "sentio")]
#[command(author = "Sentio Security")]
#[command(version)]
#[command(about = "AST-based security scanner for Solana/Anchor programs")]
#[command(long_about = "sentio scans Rust source files in Solana programs for common vulnerability\n\
patterns using syn — Rust's macro-safe AST parser. It understands\n\
Anchor account constraints, instruction logic, and CPI call graphs to produce\n\
high-signal findings with minimal false positives.\n\n\
Exit codes:\n  \
0  No findings\n  \
1  One or more findings\n  \
2  Parse error in one or more files")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan a Solana program directory or file for vulnerabilities
    Scan {
        /// Path to the program directory or Rust source file to scan
        #[arg(default_value = ".", value_name = "PATH")]
        path: String,

        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Human, value_name = "FORMAT")]
        format: OutputFormat,

        /// Run only a specific rule (e.g. SW001, SW003). Run `sentio rules list` to see all rules.
        #[arg(long, value_name = "RULE_ID")]
        rule: Option<String>,

        /// Include test files in the scan (excluded by default to reduce noise)
        #[arg(long)]
        include_tests: bool,
    },
    /// Manage and inspect the built-in rule set
    Rules {
        #[command(subcommand)]
        command: RulesCommands,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Human-readable output with source excerpts and remediation guidance (default)
    Human,
    /// Machine-readable JSON — useful for CI pipelines and tooling integrations
    Json,
}

#[derive(Debug, Subcommand)]
enum RulesCommands {
    /// Print all available rules with their IDs and titles
    List,
}
