mod common;

#[test]
fn sw014_flags_risky_fixture() {
    let result = common::scan_fixture("sw014/risky.rs", "SW014");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW014");
}

#[test]
fn sw014_passes_safe_fixture() {
    let result = common::scan_fixture("sw014/safe.rs", "SW014");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw014_respects_suppression() {
    let result = common::scan_fixture("sw014/suppressed.rs", "SW014");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
