mod common;

#[test]
fn sw018_flags_risky_fixture() {
    let result = common::scan_fixture("sw018/risky.rs", "SW018");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW018");
}

#[test]
fn sw018_passes_safe_fixture() {
    let result = common::scan_fixture("sw018/safe.rs", "SW018");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw018_respects_suppression() {
    let result = common::scan_fixture("sw018/suppressed.rs", "SW018");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
