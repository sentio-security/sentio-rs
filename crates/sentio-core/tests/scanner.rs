use sentio_core::{ScanOptions, Scanner};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// helpers

fn create_temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be valid")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("sentio-rs-{label}-{unique}"));
    fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

fn write_file(path: &Path, source: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent dir should be created");
    }
    fs::write(path, source).expect("file should be written");
}

// scanner behaviour

#[test]
fn scan_reports_parse_failures() {
    let dir = create_temp_dir("parse-failures");
    write_file(&dir.join("src/lib.rs"), "pub fn ok() {}\n");
    write_file(&dir.join("src/broken.rs"), "pub fn broken( {}\n");

    let result = Scanner::new().scan_path(dir.to_str().expect("valid path"), &ScanOptions::default());

    assert_eq!(result.files_scanned, 2);
    assert_eq!(result.files_parsed, 1);
    assert_eq!(result.parse_failures.len(), 1);

    fs::remove_dir_all(dir).expect("temp dir should be removed");
}

#[test]
fn scan_skips_test_files_by_default() {
    let dir = create_temp_dir("skip-tests");
    write_file(&dir.join("src/lib.rs"), "pub fn ok() {}\n");
    write_file(&dir.join("tests/broken.rs"), "pub fn broken( {}\n");

    let result = Scanner::new().scan_path(dir.to_str().expect("valid path"), &ScanOptions::default());

    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.files_parsed, 1);
    assert!(result.parse_failures.is_empty());

    fs::remove_dir_all(dir).expect("temp dir should be removed");
}

