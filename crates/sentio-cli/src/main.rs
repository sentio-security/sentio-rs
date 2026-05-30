use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sentio_core::{RuleRegistry, ScanOptions, Scanner};
use std::collections::BTreeMap;
use std::fs;
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

            Ok(if !result.parse_failures.is_empty() {
                2
            } else if result.findings.is_empty() {
                0
            } else {
                1
            })
        }
        Commands::Rules {
            command: RulesCommands::List,
        } => render_rule_list(),
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

fn severity_label(severity: sentio_core::Severity) -> &'static str {
    match severity {
        sentio_core::Severity::Low => "low",
        sentio_core::Severity::Medium => "medium",
        sentio_core::Severity::High => "high",
        sentio_core::Severity::Critical => "critical",
    }
}

fn render_human_report<W: Write>(
    result: &sentio_core::ScanResult,
    registry: &RuleRegistry,
    mut writer: W,
    use_color: bool,
) -> io::Result<()> {
    if !result.parse_failures.is_empty() {
        writeln!(
            writer,
            "{}",
            colorize("==============PARSE FAILURES==============", "1;31", use_color)
        )?;
        for failure in &result.parse_failures {
            writeln!(writer, "{}\n  {}", failure.path, failure.message)?;
        }
        writeln!(writer)?;
    }

    if result.findings.is_empty() {
        if result.parse_failures.is_empty() {
            writeln!(writer, "No findings.")?;
        } else {
            writeln!(writer, "No findings in successfully parsed files.")?;
        }
        return Ok(());
    }

    for (index, finding) in result.findings.iter().enumerate() {
        let meta = lookup_metadata(registry, &finding.rule_id);
        let title = meta.map(|item| item.title).unwrap_or("Unknown rule");
        let description = meta.map(|item| item.description);
        let guidance = finding
            .help
            .as_deref()
            .or_else(|| meta.map(|item| item.fix_guidance));
        let severity = severity_label(finding.severity);
        let severity_color = severity_ansi(finding.severity);
        let banner = format!(
            "==============FINDING {}: {} {}==============",
            index + 1,
            finding.rule_id,
            title
        );

        writeln!(
            writer,
            "{}",
            colorize(&banner, severity_color, use_color)
        )?;
        writeln!(
            writer,
            "{} {}",
            colorize("Severity:", "1;37", use_color),
            colorize(severity, severity_color, use_color)
        )?;
        writeln!(
            writer,
            "{} {}:{}:{}",
            colorize("Location:", "1;36", use_color),
            finding.location.path, finding.location.line, finding.location.column
        )?;
        writeln!(writer)?;

        if let Some(description) = description {
            writeln!(writer, "{}", colorize("Rule:", "1;36", use_color))?;
            writeln!(writer, "  {description}")?;
            writeln!(writer)?;
        }

        writeln!(writer, "{}", colorize("Matched Because:", "1;36", use_color))?;
        writeln!(writer, "  {}", finding.message)?;
        writeln!(writer)?;

        writeln!(writer, "{}", colorize("Source:", "1;36", use_color))?;
        match format_source_excerpt(
            &finding.location.path,
            finding.location.line,
            finding.location.column,
            2,
            severity_color,
            use_color,
        ) {
            Some(excerpt) => {
                write!(writer, "{excerpt}")?;
            }
            None => {
                writeln!(writer, "  Source excerpt unavailable.")?;
            }
        }
        writeln!(writer)?;

        if let Some(guidance) = guidance {
            writeln!(writer, "{}", colorize("Guidance:", "1;36", use_color))?;
            writeln!(writer, "  {guidance}")?;
            writeln!(writer)?;
        }
    }

    write_summary(&mut writer, result, registry, use_color)?;
    Ok(())
}

fn lookup_metadata<'a>(
    registry: &'a RuleRegistry,
    rule_id: &str,
) -> Option<&'a sentio_core::RuleMetadata> {
    registry
        .all()
        .iter()
        .find(|rule| rule.metadata().id.eq_ignore_ascii_case(rule_id))
        .map(|rule| rule.metadata())
}

fn format_source_excerpt(
    path: &str,
    line: usize,
    column: usize,
    radius: usize,
    highlight_color: &str,
    use_color: bool,
) -> Option<String> {
    let source = fs::read_to_string(path).ok()?;
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return None;
    }

    let hit_index = line.saturating_sub(1).min(lines.len().saturating_sub(1));
    let start = hit_index.saturating_sub(radius);
    let end = (hit_index + radius).min(lines.len().saturating_sub(1));
    let width = (end + 1).to_string().len();
    let mut output = String::new();

    for current in start..=end {
        let marker = if current == hit_index { '>' } else { ' ' };
        let source_line = format!(
            " {marker}{:>width$}| {}\n",
            current + 1,
            lines[current],
            width = width
        );

        if current == hit_index {
            if use_color {
                output.push_str(&colorize(&source_line, highlight_color, true));
            } else {
                output.push_str(&source_line);
            }
            let caret_indent = " ".repeat(column.saturating_sub(1));
            let caret_line = format!(
                "  {:>width$}| {caret_indent}^\n",
                "",
                width = width
            );
            if use_color {
                output.push_str(&colorize(&caret_line, highlight_color, true));
            } else {
                output.push_str(&caret_line);
            }
        } else {
            output.push_str(&source_line);
        }
    }

    Some(output)
}

fn write_summary<W: Write>(
    writer: &mut W,
    result: &sentio_core::ScanResult,
    registry: &RuleRegistry,
    use_color: bool,
) -> io::Result<()> {
    let mut rule_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;

    for finding in &result.findings {
        *rule_counts.entry(finding.rule_id.clone()).or_default() += 1;
        match finding.severity {
            sentio_core::Severity::Critical => critical += 1,
            sentio_core::Severity::High => high += 1,
            sentio_core::Severity::Medium => medium += 1,
            sentio_core::Severity::Low => low += 1,
        }
    }

    writeln!(
        writer,
        "{}",
        colorize("-------- Summary --------", "1;36", use_color)
    )?;
    writeln!(writer, "Total findings: {}", result.findings.len())?;
    writeln!(
        writer,
        "{} {}",
        colorize("Critical:", "1;37", use_color),
        colorize(&critical.to_string(), "1;31", use_color)
    )?;
    writeln!(
        writer,
        "{} {}",
        colorize("High:", "1;37", use_color),
        colorize(&high.to_string(), "31", use_color)
    )?;
    writeln!(
        writer,
        "{} {}",
        colorize("Medium:", "1;37", use_color),
        colorize(&medium.to_string(), "33", use_color)
    )?;
    writeln!(
        writer,
        "{} {}",
        colorize("Low:", "1;37", use_color),
        colorize(&low.to_string(), "32", use_color)
    )?;
    writeln!(writer)?;
    writeln!(writer, "{}", colorize("By rule:", "1;36", use_color))?;

    for (rule_id, count) in rule_counts {
        let title = lookup_metadata(registry, &rule_id)
            .map(|item| item.title)
            .unwrap_or("Unknown rule");
        writeln!(writer, "  {count}  {rule_id} {title}")?;
    }

    Ok(())
}

fn severity_ansi(severity: sentio_core::Severity) -> &'static str {
    match severity {
        sentio_core::Severity::Critical => "1;31",
        sentio_core::Severity::High => "31",
        sentio_core::Severity::Medium => "33",
        sentio_core::Severity::Low => "32",
    }
}

fn colorize(text: &str, ansi_code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{ansi_code}m{text}\x1b[0m")
    } else {
        text.to_string()
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

#[cfg(test)]
mod tests {
    use super::*;
    use sentio_core::{Finding, ScanResult, Severity, SourceLocation};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn formats_source_excerpt_with_highlighted_line() {
        let path = create_temp_file(
            "excerpt.rs",
            "fn main() {\n    let a = 1;\n    let b = a + 1;\n}\n",
        );

        let excerpt =
            format_source_excerpt(path.to_str().expect("valid path"), 3, 9, 1, "33", false)
                .expect("excerpt");

        assert!(excerpt.contains("  2|     let a = 1;"));
        assert!(excerpt.contains(" >3|     let b = a + 1;"));
        assert!(excerpt.contains("  4| }"));
        assert!(excerpt.contains("^"));

        fs::remove_file(path).expect("temp file should be removed");
    }

    #[test]
    fn renders_detailed_human_report() {
        let path = create_temp_file(
            "report.rs",
            "use anchor_lang::prelude::*;\n#[derive(Accounts)]\npub struct Example<'info> {\n    #[account(init_if_needed, payer = authority, space = 8 + Vault::LEN)]\n    pub vault: Account<'info, Vault>,\n}\n",
        );
        let result = ScanResult {
            findings: vec![Finding {
                rule_id: "SW016".to_string(),
                severity: Severity::Medium,
                message:
                    "Account `vault` uses `init_if_needed`; review for re-initialization or state-reset risk."
                        .to_string(),
                location: SourceLocation {
                    path: path.display().to_string(),
                    line: 4,
                    column: 1,
                },
                help: Some(
                    "Prefer #[account(init, ...)] when possible. If init_if_needed is necessary, confirm the account cannot be abused to reset state."
                        .to_string(),
                ),
                suppressed: false,
            }],
            files_scanned: 1,
            files_parsed: 1,
            parse_failures: Vec::new(),
        };

        let mut output = Vec::new();
        render_human_report(&result, &RuleRegistry::baseline(), &mut output, false)
            .expect("report should render");
        let output = String::from_utf8(output).expect("utf8 output");

        assert!(output.contains("==============FINDING 1: SW016 init_if_needed usage (manual review)=============="));
        assert!(output.contains("Severity: medium"));
        assert!(output.contains("Matched Because:"));
        assert!(output.contains("Source:"));
        assert!(output.contains(" >4|     #[account(init_if_needed, payer = authority, space = 8 + Vault::LEN)]"));
        assert!(output.contains("-------- Summary --------"));
        assert!(output.contains("1  SW016 init_if_needed usage (manual review)"));

        fs::remove_file(path).expect("temp file should be removed");
    }

    #[test]
    fn renders_human_report_with_ansi_color_when_enabled() {
        let path = create_temp_file(
            "color-report.rs",
            "use anchor_lang::prelude::*;\n#[derive(Accounts)]\npub struct Example<'info> {\n    #[account(init_if_needed, payer = authority, space = 8 + Vault::LEN)]\n    pub vault: Account<'info, Vault>,\n}\n",
        );
        let result = ScanResult {
            findings: vec![Finding {
                rule_id: "SW016".to_string(),
                severity: Severity::Medium,
                message:
                    "Account `vault` uses `init_if_needed`; review for re-initialization or state-reset risk."
                        .to_string(),
                location: SourceLocation {
                    path: path.display().to_string(),
                    line: 4,
                    column: 1,
                },
                help: None,
                suppressed: false,
            }],
            files_scanned: 1,
            files_parsed: 1,
            parse_failures: Vec::new(),
        };

        let mut output = Vec::new();
        render_human_report(&result, &RuleRegistry::baseline(), &mut output, true)
            .expect("report should render");
        let output = String::from_utf8(output).expect("utf8 output");

        assert!(output.contains("\u{1b}[33m"));
        assert!(output.contains("\u{1b}[1;36m"));
        assert!(output.contains("\u{1b}[0m"));

        fs::remove_file(path).expect("temp file should be removed");
    }

    fn create_temp_file(name: &str, source: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sentio-cli-{unique}-{name}"));
        fs::write(&path, source).expect("temp file should be written");
        path
    }
}
