mod common;

#[test]
fn sw003_flags_risky_fixture() {
    let result = common::scan_fixture("sw003/risky.rs", "SW003");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW003");
}

#[test]
fn sw003_passes_safe_fixture() {
    let result = common::scan_fixture("sw003/safe.rs", "SW003");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw003_respects_suppression() {
    let result = common::scan_fixture("sw003/suppressed.rs", "SW003");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
