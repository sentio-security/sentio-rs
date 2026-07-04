mod common;

#[test]
fn sw023_flags_risky_fixture() {
    let result = common::scan_fixture("sw023/risky.rs", "SW023");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW023");
}

#[test]
fn sw023_passes_safe_fixture() {
    let result = common::scan_fixture("sw023/safe.rs", "SW023");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw023_respects_suppression() {
    let result = common::scan_fixture("sw023/suppressed.rs", "SW023");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
