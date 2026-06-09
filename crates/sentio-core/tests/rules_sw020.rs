mod common;

#[test]
fn sw020_flags_risky_fixture() {
    let result = common::scan_fixture("sw020/risky.rs", "SW020");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW020");
}

#[test]
fn sw020_passes_safe_fixture() {
    let result = common::scan_fixture("sw020/safe.rs", "SW020");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw020_respects_suppression() {
    let result = common::scan_fixture("sw020/suppressed.rs", "SW020");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
