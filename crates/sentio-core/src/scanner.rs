use crate::finding::Finding;
use crate::rules::{convert_severity, RuleContext, RuleRegistry, SuppressionSet};
use crate::syntax::{parse_rust_files, ParseFailure, ParsedFile, SyntaxReport};
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

#[derive(Default)]
pub struct Scanner {
    rules: RuleRegistry,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            rules: RuleRegistry::baseline(),
        }
    }

    pub fn scan_path(&self, path: &str, options: &ScanOptions) -> ScanResult {
        let file_paths: Vec<PathBuf> = discover_rust_files(path, options).collect();
        let files_scanned = file_paths.len();
        let syntax_report = parse_rust_files(file_paths);
        self.scan_report(files_scanned, syntax_report, options)
    }

    pub fn scan_report(
        &self,
        files_scanned: usize,
        report: SyntaxReport,
        options: &ScanOptions,
    ) -> ScanResult {
        let files_parsed = report.files.len();
        let findings = self.run_rules(&report.files, options);
        let parse_failures = report.parse_failures;

        ScanResult {
            findings,
            files_scanned,
            files_parsed,
            parse_failures,
        }
    }

    fn run_rules(&self, files: &[ParsedFile], options: &ScanOptions) -> Vec<Finding> {
        let ctx = RuleContext { files };
        let suppressions: Vec<(String, SuppressionSet)> = files
            .iter()
            .map(|file| (file.path.display().to_string(), SuppressionSet::from_source(&file.source)))
            .collect();

        let mut findings = Vec::new();
        for file in files {
            for rule in self.rules.matching_rules(options.rule_filter.as_deref()) {
                for matched in rule.match_file(file, &ctx) {
                    let finding = Finding {
                        rule_id: matched.rule_id.to_string(),
                        severity: convert_severity(matched.severity),
                        message: matched.message,
                        location: matched.location,
                        help: matched.help,
                        suppressed: false,
                    };

                    if is_suppressed(&finding, &suppressions) {
                        continue;
                    }

                    findings.push(finding);
                }
            }
        }

        findings
    }
}

fn is_suppressed(finding: &Finding, suppressions: &[(String, SuppressionSet)]) -> bool {
    suppressions
        .iter()
        .find(|(path, _)| path == &finding.location.path)
        .is_some_and(|(_, set)| set.is_suppressed(finding))
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

    #[test]
    fn scan_applies_rule_filter_and_suppressions() {
        let mut options = ScanOptions::default();
        options.include_tests = true;
        options.rule_filter = Some("SW012".to_string());
        let path = fixture_path("sw012/suppressed.rs");
        let result = Scanner::new().scan_path(path.to_str().expect("valid path"), &options);

        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.files_parsed, 1);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn scan_reports_unsuppressed_sw012() {
        let mut options = ScanOptions::default();
        options.include_tests = true;
        options.rule_filter = Some("SW012".to_string());
        let path = fixture_path("sw012/risky.rs");
        let result = Scanner::new().scan_path(path.to_str().expect("valid path"), &options);

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule_id, "SW012");
    }

    #[test]
    fn scan_does_not_report_safe_sw012_fixture() {
        let mut options = ScanOptions::default();
        options.include_tests = true;
        options.rule_filter = Some("SW012".to_string());
        let path = fixture_path("sw012/safe.rs");
        let result = Scanner::new().scan_path(path.to_str().expect("valid path"), &options);

        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.files_parsed, 1);
        assert!(result.findings.is_empty());
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

    fn fixture_path(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(relative)
    }
}
