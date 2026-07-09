use sentio_core::{ScanOptions, ScanResult, Scanner};
use std::path::PathBuf;

pub fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(relative)
}

pub fn scan_fixture(fixture: &str, rule_id: &str) -> ScanResult {
    let options = ScanOptions {
        include_tests: true,
        rule_filter: Some(rule_id.to_string()),
        ..Default::default()
    };
    Scanner::new().scan_path(
        fixture_path(fixture).to_str().expect("valid fixture path"),
        &options,
    )
}
