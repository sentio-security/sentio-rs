use crate::finding::Finding;
use crate::syntax::{parse_rust_files, ParseFailure};
use serde::Serialize;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub include_tests: bool,
    pub rule_filter: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub files_parsed: usize,
    pub parse_failures: Vec<ParseFailure>,
}

#[derive(Debug, Default)]
pub struct Scanner;

impl Scanner {
    pub fn new() -> Self {
        Self
    }

    pub fn scan_path(&self, path: &str, options: &ScanOptions) -> ScanResult {
        let file_paths: Vec<PathBuf> = discover_rust_files(path, options).collect();
        let files_scanned = file_paths.len();
        let syntax_report = parse_rust_files(file_paths);
        let files_parsed = syntax_report.files.len();

        ScanResult {
            findings: Vec::new(),
            files_scanned,
            files_parsed,
            parse_failures: syntax_report.parse_failures,
        }
    }
}

fn discover_rust_files<'a>(
    path: &'a str,
    options: &'a ScanOptions,
) -> impl Iterator<Item = PathBuf> + 'a {
    WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .filter(|entry| !is_excluded_path(entry.path()))
        .filter(move |entry| options.include_tests || !is_test_path(entry.path()))
        .map(|entry| entry.into_path())
}

fn is_excluded_path(path: &Path) -> bool {
    path.components().any(|component| {
        let part = component.as_os_str().to_string_lossy();
        matches!(part.as_ref(), "target" | ".git")
    })
}

fn is_test_path(path: &Path) -> bool {
    path.components().any(|component| {
        let part = component.as_os_str().to_string_lossy();
        matches!(part.as_ref(), "tests" | "test" | "fixtures")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

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
}
