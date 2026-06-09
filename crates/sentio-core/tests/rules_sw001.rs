mod common;

#[test]
fn sw001_flags_risky_fixture() {
    let result = common::scan_fixture("sw001/risky.rs", "SW001");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW001");
}

#[test]
fn sw001_passes_safe_fixture() {
    let result = common::scan_fixture("sw001/safe.rs", "SW001");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw001_respects_suppression() {
    let result = common::scan_fixture("sw001/suppressed.rs", "SW001");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
