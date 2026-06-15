mod common;

#[test]
fn sw013_flags_risky_fixture() {
    let result = common::scan_fixture("sw013/risky.rs", "SW013");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW013");
}

#[test]
fn sw013_passes_safe_fixture() {
    let result = common::scan_fixture("sw013/safe.rs", "SW013");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw013_respects_suppression() {
    let result = common::scan_fixture("sw013/suppressed.rs", "SW013");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
