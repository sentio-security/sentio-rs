mod common;

#[test]
fn sw009_flags_risky_fixture() {
    let result = common::scan_fixture("sw009/risky.rs", "SW009");

    assert_eq!(result.findings.len(), 2);
    assert!(result.findings.iter().all(|f| f.rule_id == "SW009"));
}

#[test]
fn sw009_passes_safe_fixture() {
    let result = common::scan_fixture("sw009/safe.rs", "SW009");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn sw009_respects_suppression() {
    let result = common::scan_fixture("sw009/suppressed.rs", "SW009");

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.findings.is_empty());
}
