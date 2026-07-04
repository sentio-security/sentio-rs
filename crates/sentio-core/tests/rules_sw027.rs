mod common;

#[test]
fn sw027_flags_risky_fixture() {
    let result = common::scan_fixture("sw027/risky.rs", "SW027");
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW027");
}

#[test]
fn sw027_passes_safe_fixture() {
    let result = common::scan_fixture("sw027/safe.rs", "SW027");
    assert_eq!(result.files_scanned, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw027_respects_suppression() {
    let result = common::scan_fixture("sw027/suppressed.rs", "SW027");
    assert_eq!(result.files_scanned, 1);
    assert!(result.findings.is_empty());
}
