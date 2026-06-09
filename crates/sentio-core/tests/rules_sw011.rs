mod common;

#[test]
fn sw011_flags_risky_fixture() {
    let result = common::scan_fixture("sw011/risky.rs", "SW011");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW011");
}

#[test]
fn sw011_passes_safe_fixture() {
    let result = common::scan_fixture("sw011/safe.rs", "SW011");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw011_respects_suppression() {
    let result = common::scan_fixture("sw011/suppressed.rs", "SW011");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
