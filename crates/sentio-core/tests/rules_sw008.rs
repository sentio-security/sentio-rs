mod common;

#[test]
fn sw008_flags_risky_fixture() {
    let result = common::scan_fixture("sw008/risky.rs", "SW008");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW008");
}

#[test]
fn sw008_passes_safe_fixture() {
    let result = common::scan_fixture("sw008/safe.rs", "SW008");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw008_respects_suppression() {
    let result = common::scan_fixture("sw008/suppressed.rs", "SW008");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
