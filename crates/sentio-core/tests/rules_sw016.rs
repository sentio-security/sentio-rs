mod common;

#[test]
fn sw016_flags_risky_fixture() {
    let result = common::scan_fixture("sw016/risky.rs", "SW016");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW016");
}

#[test]
fn sw016_passes_safe_fixture() {
    let result = common::scan_fixture("sw016/safe.rs", "SW016");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw016_respects_suppression() {
    let result = common::scan_fixture("sw016/suppressed.rs", "SW016");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
