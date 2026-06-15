use sentio_core::{RuleRegistry, ScanResult, Severity};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};

pub fn render_human_report<W: Write>(
    result: &ScanResult,
    registry: &RuleRegistry,
    mut writer: W,
    use_color: bool,
) -> io::Result<()> {
    if !result.parse_failures.is_empty() {
        writeln!(
            writer,
            "{}",
            colorize(
                "==============PARSE FAILURES==============",
                "1;31",
                use_color
            )
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

        writeln!(writer, "{}", colorize(&banner, severity_color, use_color))?;
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
            finding.location.path,
            finding.location.line,
            finding.location.column
        )?;
        writeln!(writer)?;

        if let Some(description) = description {
            writeln!(writer, "{}", colorize("Rule:", "1;36", use_color))?;
            writeln!(writer, "  {description}")?;
            writeln!(writer)?;
        }

        writeln!(
            writer,
            "{}",
            colorize("Matched Because:", "1;36", use_color)
        )?;
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
            Some(excerpt) => write!(writer, "{excerpt}")?,
            None => writeln!(writer, "  Source excerpt unavailable.")?,
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

pub fn format_source_excerpt(
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

    for (current, line_str) in lines.iter().enumerate().take(end + 1).skip(start) {
        let marker = if current == hit_index { '>' } else { ' ' };
        let source_line = format!(
            " {marker}{:>width$}| {}\n",
            current + 1,
            line_str,
            width = width
        );

        if current == hit_index {
            if use_color {
                output.push_str(&colorize(&source_line, highlight_color, true));
            } else {
                output.push_str(&source_line);
            }
            let caret_indent = " ".repeat(column.saturating_sub(1));
            let caret_line = format!("  {:>width$}| {caret_indent}^\n", "", width = width);
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
    result: &ScanResult,
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
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
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

pub fn lookup_metadata<'a>(
    registry: &'a RuleRegistry,
    rule_id: &str,
) -> Option<&'a sentio_core::RuleMetadata> {
    registry
        .all()
        .iter()
        .find(|rule| rule.metadata().id.eq_ignore_ascii_case(rule_id))
        .map(|rule| rule.metadata())
}

pub fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

pub fn severity_ansi(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "1;31",
        Severity::High => "31",
        Severity::Medium => "33",
        Severity::Low => "32",
    }
}

pub fn colorize(text: &str, ansi_code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{ansi_code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}
