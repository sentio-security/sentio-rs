mod common;

#[test]
fn sw012_flags_risky_fixture() {
    let result = common::scan_fixture("sw012/risky.rs", "SW012");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW012");
}

#[test]
fn sw012_passes_safe_fixture() {
    let result = common::scan_fixture("sw012/safe.rs", "SW012");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw012_respects_suppression() {
    let result = common::scan_fixture("sw012/suppressed.rs", "SW012");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
