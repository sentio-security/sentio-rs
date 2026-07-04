mod common;

#[test]
fn sw026_flags_risky_fixture() {
    let result = common::scan_fixture("sw026/risky.rs", "SW026");
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW026");
}

#[test]
fn sw026_passes_safe_fixture() {
    let result = common::scan_fixture("sw026/safe.rs", "SW026");
    assert_eq!(result.files_scanned, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw026_respects_suppression() {
    let result = common::scan_fixture("sw026/suppressed.rs", "SW026");
    assert_eq!(result.files_scanned, 1);
    assert!(result.findings.is_empty());
}
