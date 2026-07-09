use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use sentio_cli::render_human_report;
use sentio_core::{
    resolve_config_path, to_sarif_json, Baseline, FailOn, RuleRegistry, ScanOptions, ScanResult,
    Scanner, SentioConfig, Severity,
};
use std::collections::HashMap;
use std::io::{self, IsTerminal};
use std::path::PathBuf;

mod telemetry;

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

    // `--version`/`-V` is handled manually (instead of clap's built-in flag)
    // so it goes through the same version-check ping as `sentio version`.
    if cli.version {
        return render_version();
    }

    let Some(command) = cli.command else {
        Cli::command()
            .error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "a subcommand is required (try `sentio --help`)",
            )
            .exit();
    };

    match command {
        Commands::Scan {
            path,
            format,
            rule,
            include_tests,
            output,
            config,
            fail_on,
            baseline,
            update_baseline,
        } => run_scan(ScanArgs {
            path,
            format,
            rule,
            include_tests,
            output,
            config,
            fail_on,
            baseline,
            update_baseline,
        }),
        Commands::Rules {
            command: RulesCommands::List,
        } => render_rule_list(),
        Commands::Version => render_version(),
    }
}

struct ScanArgs {
    path: String,
    format: OutputFormat,
    rule: Option<String>,
    include_tests: bool,
    output: Option<String>,
    config: Option<PathBuf>,
    fail_on: Option<String>,
    baseline: Option<PathBuf>,
    update_baseline: Option<PathBuf>,
}

fn run_scan(args: ScanArgs) -> Result<i32> {
    if args.output.is_some() && matches!(args.format, OutputFormat::Human) {
        bail!("--output requires --format json or --format sarif");
    }

    let scan_path = PathBuf::from(&args.path);
    let config_path = resolve_config_path(args.config.as_deref(), &scan_path);
    let file_config = match config_path {
        Some(ref path) => {
            let cfg = SentioConfig::load_from_path(path).map_err(|e| anyhow::anyhow!(e))?;
            eprintln!("Using config {}", path.display());
            Some(cfg)
        }
        None => None,
    };

    let options = build_scan_options(&args, file_config.as_ref())?;
    let fail_on = resolve_fail_on(args.fail_on.as_deref(), file_config.as_ref())?;

    let scanner = Scanner::new();
    let full_result = scanner.scan_path(&args.path, &options);

    // Persist baseline from the full (pre-baseline-filter) finding set.
    if let Some(ref baseline_path) = args.update_baseline {
        let to_write = Baseline::from_findings(&full_result.findings);
        to_write
            .save(baseline_path)
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!(
            "Baseline written to {} ({} finding(s))",
            baseline_path.display(),
            to_write.findings.len()
        );
    }

    // Apply baseline filter for reporting / exit code (hide known findings).
    let mut result = full_result;
    if let Some(ref baseline_path) = args.baseline {
        let baseline = Baseline::load(baseline_path).map_err(|e| anyhow::anyhow!(e))?;
        let (remaining, baselined) = baseline.filter_findings(result.findings);
        result.findings = remaining;
        result.baselined_count = baselined;
        if baselined > 0 {
            eprintln!(
                "Baseline: hid {baselined} known finding(s) from {}",
                baseline_path.display()
            );
        }
    }

    let registry = RuleRegistry::baseline();
    match args.format {
        OutputFormat::Human => {
            render_human(&result);
            if result.baselined_count > 0 {
                eprintln!(
                    "(Plus {} baselined finding(s) not shown)",
                    result.baselined_count
                );
            }
        }
        OutputFormat::Json => {
            write_or_print(&args.output, &serde_json::to_string_pretty(&result)?)?
        }
        OutputFormat::Sarif => {
            let sarif = to_sarif_json(&result, &registry, env!("CARGO_PKG_VERSION"))
                .map_err(|e| anyhow::anyhow!(e))?;
            write_or_print(&args.output, &sarif)?;
        }
    }

    Ok(exit_code_for(&result, fail_on))
}

fn build_scan_options(args: &ScanArgs, config: Option<&SentioConfig>) -> Result<ScanOptions> {
    let mut options = ScanOptions {
        include_tests: args.include_tests,
        rule_filter: args.rule.clone(),
        disabled_rules: Vec::new(),
        severity_overrides: HashMap::new(),
        exclude: Vec::new(),
        config_paths: Vec::new(),
    };

    if let Some(cfg) = config {
        options.include_tests = args.include_tests || cfg.scan.include_tests;
        options.exclude = cfg.scan.exclude.clone();
        options.config_paths = cfg.scan.paths.clone();
        options.disabled_rules = cfg.disabled_rule_ids();

        for (id, section) in &cfg.rules {
            if let Some(ref sev) = section.severity {
                let parsed = parse_severity_str(sev).with_context(|| {
                    format!("invalid severity `{sev}` for rule {id} in sentio.toml")
                })?;
                options
                    .severity_overrides
                    .insert(id.to_ascii_uppercase(), parsed);
            }
        }
    }

    // Single-rule CLI filter: do not also need disabled list interaction.
    Ok(options)
}

fn resolve_fail_on(cli: Option<&str>, config: Option<&SentioConfig>) -> Result<FailOn> {
    if let Some(raw) = cli {
        return FailOn::parse(raw).map_err(|e| anyhow::anyhow!(e));
    }
    Ok(config.map(|c| c.scan.fail_on).unwrap_or(FailOn::Low))
}

fn parse_severity_str(raw: &str) -> Result<Severity> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(Severity::Low),
        "medium" | "med" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" | "crit" => Ok(Severity::Critical),
        other => bail!("invalid severity `{other}` (expected low|medium|high|critical)"),
    }
}

fn exit_code_for(result: &ScanResult, fail_on: FailOn) -> i32 {
    if !result.parse_failures.is_empty() {
        return 2;
    }
    if fail_on.any_should_fail(result.findings.iter().map(|f| f.severity)) {
        1
    } else {
        0
    }
}

fn write_or_print(output: &Option<String>, content: &str) -> Result<()> {
    if let Some(file_path) = output {
        std::fs::write(file_path, content)
            .with_context(|| format!("failed to write {file_path}"))?;
        eprintln!("Report written to {file_path}");
    } else {
        println!("{content}");
    }
    Ok(())
}

fn render_version() -> Result<i32> {
    let installed = env!("CARGO_PKG_VERSION");
    println!("sentio {installed}");

    let check = telemetry::check_version(installed);
    if let Some(latest) = check.latest {
        if latest != installed {
            println!(
                "A newer version is available: {latest} (run `cargo install sentio-cli --force`)"
            );
        }
    }

    Ok(0)
}

fn render_rule_list() -> Result<i32> {
    let registry = RuleRegistry::baseline();
    for rule in registry.all() {
        let meta = rule.metadata();
        println!("{}  {}", meta.id, meta.title);
    }
    Ok(0)
}

fn render_human(result: &ScanResult) {
    let registry = RuleRegistry::baseline();
    let stdout = io::stdout();
    let use_color = stdout.is_terminal();
    let mut locked = stdout.lock();
    let _ = render_human_report(result, &registry, &mut locked, use_color);
}

#[derive(Debug, Parser)]
#[command(name = "sentio")]
#[command(author = "Sentio Security")]
#[command(disable_version_flag = true)]
#[command(about = "AST-based security scanner for Solana/Anchor programs")]
#[command(
    long_about = "sentio is a local pre-audit layer for Anchor programs. It scans Rust source\n\
with syn (no build, no source upload) for high-signal Solana vulnerability patterns.\n\n\
Exit codes:\n  \
0  Clean (or findings below --fail-on threshold)\n  \
1  Findings at or above --fail-on threshold\n  \
2  Parse error in one or more files"
)]
struct Cli {
    /// Print the installed sentio version and check for updates
    #[arg(short = 'V', long = "version")]
    version: bool,

    #[command(subcommand)]
    command: Option<Commands>,
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

        /// Write output to a file instead of stdout (json or sarif)
        #[arg(long, value_name = "FILE")]
        output: Option<String>,

        /// Path to sentio.toml (default: <PATH>/sentio.toml or ./sentio.toml)
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,

        /// Fail (exit 1) only on findings at this severity or higher: off|low|medium|high|critical
        #[arg(long, value_name = "LEVEL")]
        fail_on: Option<String>,

        /// Path to a baseline JSON file; known findings are hidden
        #[arg(long, value_name = "FILE")]
        baseline: Option<PathBuf>,

        /// Write current findings to a baseline file (creates or overwrites)
        #[arg(long, value_name = "FILE")]
        update_baseline: Option<PathBuf>,
    },
    /// Manage and inspect the built-in rule set
    Rules {
        #[command(subcommand)]
        command: RulesCommands,
    },
    /// Print the installed sentio version and check for updates
    Version,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Human-readable output with source excerpts and remediation guidance (default)
    Human,
    /// Machine-readable JSON — useful for CI pipelines and tooling integrations
    Json,
    /// SARIF 2.1.0 — for GitHub Code Scanning and security dashboards
    Sarif,
}

#[derive(Debug, Subcommand)]
enum RulesCommands {
    /// Print all available rules with their IDs and titles
    List,
}
