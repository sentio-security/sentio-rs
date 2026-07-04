mod common;

#[test]
fn sw025_flags_risky_fixture() {
    let result = common::scan_fixture("sw025/risky.rs", "SW025");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW025");
}

#[test]
fn sw025_passes_safe_fixture() {
    let result = common::scan_fixture("sw025/safe.rs", "SW025");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw025_respects_suppression() {
    let result = common::scan_fixture("sw025/suppressed.rs", "SW025");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
