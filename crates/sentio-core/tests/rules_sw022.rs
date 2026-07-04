mod common;

#[test]
fn sw022_flags_risky_fixture() {
    let result = common::scan_fixture("sw022/risky.rs", "SW022");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW022");
}

#[test]
fn sw022_passes_safe_fixture() {
    let result = common::scan_fixture("sw022/safe.rs", "SW022");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw022_respects_suppression() {
    let result = common::scan_fixture("sw022/suppressed.rs", "SW022");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
