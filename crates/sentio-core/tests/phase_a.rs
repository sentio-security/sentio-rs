//! Phase A integration: config, exclude, disabled rules, severity override, baseline, SARIF.

use sentio_core::{
    to_sarif_json, Baseline, FailOn, RuleRegistry, ScanOptions, Scanner, SentioConfig, Severity,
};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn create_temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be valid")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("sentio-phase-a-{label}-{unique}"));
    fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

fn write_file(path: &Path, source: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent dir should be created");
    }
    fs::write(path, source).expect("file should be written");
}

const INIT_IF_NEEDED: &str = r#"
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Example<'info> {
    #[account(init_if_needed, payer = authority, space = 8 + 32)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub data: [u8; 32],
}
"#;

#[test]
fn disabled_rule_via_options_skips_findings() {
    let dir = create_temp_dir("disabled");
    write_file(&dir.join("src/lib.rs"), INIT_IF_NEEDED);

    let with_rule = Scanner::new().scan_path(
        dir.to_str().unwrap(),
        &ScanOptions {
            rule_filter: Some("SW016".into()),
            ..Default::default()
        },
    );
    assert!(
        !with_rule.findings.is_empty(),
        "expected SW016 findings without disable"
    );

    let disabled = Scanner::new().scan_path(
        dir.to_str().unwrap(),
        &ScanOptions {
            disabled_rules: vec!["SW016".into()],
            ..Default::default()
        },
    );
    assert!(
        disabled
            .findings
            .iter()
            .all(|f| !f.rule_id.eq_ignore_ascii_case("SW016")),
        "SW016 should be disabled"
    );

    fs::remove_dir_all(dir).ok();
}

#[test]
fn severity_override_applies() {
    let dir = create_temp_dir("severity");
    write_file(&dir.join("src/lib.rs"), INIT_IF_NEEDED);

    let mut overrides = HashMap::new();
    overrides.insert("SW016".into(), Severity::Low);

    let result = Scanner::new().scan_path(
        dir.to_str().unwrap(),
        &ScanOptions {
            rule_filter: Some("SW016".into()),
            severity_overrides: overrides,
            ..Default::default()
        },
    );

    assert!(!result.findings.is_empty());
    assert!(result.findings.iter().all(|f| f.severity == Severity::Low));

    fs::remove_dir_all(dir).ok();
}

#[test]
fn exclude_skips_matching_paths() {
    let dir = create_temp_dir("exclude");
    write_file(&dir.join("src/lib.rs"), "pub fn ok() {}\n");
    write_file(&dir.join("migrations/bad.rs"), INIT_IF_NEEDED);

    let result = Scanner::new().scan_path(
        dir.to_str().unwrap(),
        &ScanOptions {
            exclude: vec!["migrations".into()],
            rule_filter: Some("SW016".into()),
            ..Default::default()
        },
    );

    assert_eq!(result.files_scanned, 1);
    assert!(result.findings.is_empty());

    fs::remove_dir_all(dir).ok();
}

#[test]
fn baseline_filters_known_findings() {
    let dir = create_temp_dir("baseline");
    write_file(&dir.join("src/lib.rs"), INIT_IF_NEEDED);

    let result = Scanner::new().scan_path(
        dir.to_str().unwrap(),
        &ScanOptions {
            rule_filter: Some("SW016".into()),
            ..Default::default()
        },
    );
    assert!(!result.findings.is_empty());

    let baseline = Baseline::from_findings(&result.findings);
    let path = dir.join("baseline.json");
    baseline.save(&path).expect("save baseline");

    let loaded = Baseline::load(&path).expect("load baseline");
    let (remaining, baselined) = loaded.filter_findings(result.findings.clone());
    assert_eq!(remaining.len(), 0);
    assert_eq!(baselined, result.findings.len());

    fs::remove_dir_all(dir).ok();
}

#[test]
fn fail_on_high_ignores_medium() {
    assert!(!FailOn::High.should_fail(Severity::Medium));
    assert!(FailOn::High.should_fail(Severity::High));
    assert!(!FailOn::Off.any_should_fail([Severity::Critical]));
}

#[test]
fn config_disabled_and_fail_on_parse() {
    let cfg = SentioConfig::parse_toml(
        r#"
        [scan]
        fail_on = "critical"
        exclude = ["foo"]

        [rules.SW016]
        enabled = false
        "#,
    )
    .unwrap();
    assert_eq!(cfg.scan.fail_on, FailOn::Critical);
    assert!(!cfg.is_rule_enabled("sw016"));
    assert_eq!(cfg.disabled_rule_ids(), vec!["SW016".to_string()]);
}

#[test]
fn sarif_export_contains_results() {
    let dir = create_temp_dir("sarif");
    write_file(&dir.join("src/lib.rs"), INIT_IF_NEEDED);

    let result = Scanner::new().scan_path(
        dir.to_str().unwrap(),
        &ScanOptions {
            rule_filter: Some("SW016".into()),
            ..Default::default()
        },
    );

    let json = to_sarif_json(&result, &RuleRegistry::baseline(), "0.3.0").unwrap();
    assert!(json.contains("\"version\": \"2.1.0\""));
    assert!(json.contains("SW016"));
    assert!(json.contains("startLine"));

    fs::remove_dir_all(dir).ok();
}
