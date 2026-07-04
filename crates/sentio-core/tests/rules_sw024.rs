mod common;

#[test]
fn sw024_flags_risky_fixture() {
    let result = common::scan_fixture("sw024/risky.rs", "SW024");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW024");
}

#[test]
fn sw024_passes_safe_fixture() {
    let result = common::scan_fixture("sw024/safe.rs", "SW024");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw024_respects_suppression() {
    let result = common::scan_fixture("sw024/suppressed.rs", "SW024");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
