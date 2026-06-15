use sentio_cli::{format_source_excerpt, render_human_report};
use sentio_core::{Finding, RuleRegistry, ScanResult, Severity, SourceLocation};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn create_temp_file(name: &str, source: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be valid")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sentio-cli-{unique}-{name}"));
    fs::write(&path, source).expect("temp file should be written");
    path
}

#[test]
fn formats_source_excerpt_with_highlighted_line() {
    let path = create_temp_file(
        "excerpt.rs",
        "fn main() {\n    let a = 1;\n    let b = a + 1;\n}\n",
    );

    let excerpt = format_source_excerpt(path.to_str().expect("valid path"), 3, 9, 1, "33", false)
        .expect("excerpt should be produced");

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
            message: "Account `vault` uses `init_if_needed`; review for re-initialization or state-reset risk.".to_string(),
            location: SourceLocation {
                path: path.display().to_string(),
                line: 4,
                column: 1,
            },
            help: Some(
                "Prefer #[account(init, ...)] when possible. If init_if_needed is necessary, confirm the account cannot be abused to reset state.".to_string(),
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

    assert!(output.contains(
        "==============FINDING 1: SW016 init_if_needed usage (manual review)=============="
    ));
    assert!(output.contains("Severity: medium"));
    assert!(output.contains("Matched Because:"));
    assert!(output.contains("Source:"));
    assert!(output.contains(
        " >4|     #[account(init_if_needed, payer = authority, space = 8 + Vault::LEN)]"
    ));
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
            message: "Account `vault` uses `init_if_needed`; review for re-initialization or state-reset risk.".to_string(),
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
