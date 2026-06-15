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
        let (roots, anchor_programs) = resolve_scan_roots(path);

        if let Some(ref programs) = anchor_programs {
            eprintln!(
                "Anchor workspace detected — scanning {} program(s): {}",
                programs.len(),
                programs.join(", ")
            );
        }

        let file_paths: Vec<PathBuf> = roots
            .iter()
            .flat_map(|root| discover_rust_files(root, options))
            .collect();

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
            .map(|file| {
                (
                    file.path.display().to_string(),
                    SuppressionSet::from_source(&file.source),
                )
            })
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

/// Detects an Anchor workspace at `path` by looking for `Anchor.toml`.
/// If found, expands `[workspace] members` glob patterns and returns the program roots.
/// Returns `(roots_to_scan, Some(program_names))` on detection, or `([path], None)` otherwise.
fn resolve_scan_roots(path: &str) -> (Vec<PathBuf>, Option<Vec<String>>) {
    let root = PathBuf::from(path);
    let anchor_toml_path = root.join("Anchor.toml");

    if !anchor_toml_path.exists() {
        return (vec![root], None);
    }

    let content = match std::fs::read_to_string(&anchor_toml_path) {
        Ok(c) => c,
        Err(_) => return (vec![root], None),
    };

    let parsed: toml::Value = match content.parse() {
        Ok(v) => v,
        Err(_) => return (vec![root], None),
    };

    let members: Vec<&str> = parsed
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    if members.is_empty() {
        return (vec![root], Some(vec![]));
    }

    let mut roots: Vec<PathBuf> = Vec::new();
    for member in &members {
        if let Some(prefix) = member.strip_suffix("/*") {
            // glob pattern like "programs/*" — expand to all subdirs with a Cargo.toml
            let dir = root.join(prefix);
            if let Ok(entries) = std::fs::read_dir(&dir) {
                let mut subdirs: Vec<PathBuf> = entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir() && p.join("Cargo.toml").exists())
                    .collect();
                subdirs.sort();
                roots.extend(subdirs);
            }
        } else {
            let p = root.join(member);
            if p.exists() {
                roots.push(p);
            }
        }
    }

    if roots.is_empty() {
        return (vec![root], Some(vec![]));
    }

    let names: Vec<String> = roots
        .iter()
        .filter_map(|r| r.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .collect();

    (roots, Some(names))
}

fn is_suppressed(finding: &Finding, suppressions: &[(String, SuppressionSet)]) -> bool {
    suppressions
        .iter()
        .find(|(path, _)| path == &finding.location.path)
        .is_some_and(|(_, set)| set.is_suppressed(finding))
}

fn discover_rust_files<'a>(
    root: &'a Path,
    options: &'a ScanOptions,
) -> impl Iterator<Item = PathBuf> + 'a {
    WalkDir::new(root)
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
