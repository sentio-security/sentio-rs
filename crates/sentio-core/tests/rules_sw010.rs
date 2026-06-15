mod common;

#[test]
fn sw010_flags_risky_fixture() {
    let result = common::scan_fixture("sw010/risky.rs", "SW010");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW010");
}

#[test]
fn sw010_passes_safe_fixture() {
    let result = common::scan_fixture("sw010/safe.rs", "SW010");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw010_respects_suppression() {
    let result = common::scan_fixture("sw010/suppressed.rs", "SW010");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
