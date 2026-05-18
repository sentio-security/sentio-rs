use crate::finding::Finding;
use serde::Serialize;
use std::path::Path;
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
}

#[derive(Debug, Default)]
pub struct Scanner;

impl Scanner {
    pub fn new() -> Self {
        Self
    }

    pub fn scan_path(&self, path: &str, options: &ScanOptions) -> ScanResult {
        let files_scanned = discover_rust_files(path, options).count();

        ScanResult {
            findings: Vec::new(),
            files_scanned,
        }
    }
}

fn discover_rust_files<'a>(
    path: &'a str,
    options: &'a ScanOptions,
) -> impl Iterator<Item = String> + 'a {
    WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .filter(|entry| !is_excluded_path(entry.path()))
        .filter(move |entry| options.include_tests || !is_test_path(entry.path()))
        .map(|entry| entry.path().display().to_string())
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
