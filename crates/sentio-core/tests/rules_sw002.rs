mod common;

#[test]
fn sw002_flags_risky_fixture() {
    let result = common::scan_fixture("sw002/risky.rs", "SW002");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW002");
}

#[test]
fn sw002_passes_safe_fixture() {
    let result = common::scan_fixture("sw002/safe.rs", "SW002");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw002_respects_suppression() {
    let result = common::scan_fixture("sw002/suppressed.rs", "SW002");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
