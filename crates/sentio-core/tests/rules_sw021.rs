mod common;

#[test]
fn sw021_flags_risky_fixture() {
    let result = common::scan_fixture("sw021/risky.rs", "SW021");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SW021");
}

#[test]
fn sw021_passes_safe_fixture() {
    let result = common::scan_fixture("sw021/safe.rs", "SW021");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw021_respects_suppression() {
    let result = common::scan_fixture("sw021/suppressed.rs", "SW021");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
