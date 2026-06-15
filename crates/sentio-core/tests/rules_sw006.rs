mod common;

#[test]
fn sw006_flags_risky_fixture() {
    let result = common::scan_fixture("sw006/risky.rs", "SW006");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW006");
}

#[test]
fn sw006_passes_safe_fixture() {
    let result = common::scan_fixture("sw006/safe.rs", "SW006");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw006_respects_suppression() {
    let result = common::scan_fixture("sw006/suppressed.rs", "SW006");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
