use crate::config::path_is_excluded;
use crate::finding::{Finding, Severity};
use crate::rules::{convert_severity, RuleContext, RuleRegistry, SuppressionSet};
use crate::syntax::{parse_rust_files, ParseFailure, ParsedFile, SyntaxReport};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub include_tests: bool,
    /// If set, only run this single rule id (e.g. `SW003`).
    pub rule_filter: Option<String>,
    /// Rule ids that are disabled via config (uppercase).
    pub disabled_rules: Vec<String>,
    /// Per-rule severity overrides (uppercase rule id → severity).
    pub severity_overrides: HashMap<String, Severity>,
    /// Path exclude patterns (component name, substring, or simple `*` glob).
    pub exclude: Vec<String>,
    /// Optional extra roots relative to the scan path (from config `scan.paths`).
    pub config_paths: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub files_parsed: usize,
    pub parse_failures: Vec<ParseFailure>,
    /// Findings hidden because they matched a baseline (informational).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub baselined_count: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
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

    pub fn rules(&self) -> &RuleRegistry {
        &self.rules
    }

    pub fn scan_path(&self, path: &str, options: &ScanOptions) -> ScanResult {
        let target = PathBuf::from(path);

        // Explicit single-file scan always includes that file (even under tests/).
        if target.is_file() && target.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            let syntax_report = parse_rust_files(vec![target]);
            return self.scan_report(1, syntax_report, options);
        }

        let (roots, anchor_programs) = resolve_scan_roots(path, options);

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
            baselined_count: 0,
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
            for rule in self
                .rules
                .matching_rules(options.rule_filter.as_deref(), &options.disabled_rules)
            {
                for matched in rule.match_file(file, &ctx) {
                    let mut severity = convert_severity(matched.severity);
                    if let Some(overridden) = options
                        .severity_overrides
                        .get(&matched.rule_id.to_ascii_uppercase())
                    {
                        severity = *overridden;
                    }

                    let finding = Finding {
                        rule_id: matched.rule_id.to_string(),
                        severity,
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
///
/// When `options.config_paths` is non-empty, those subpaths (relative to `path`) are used
/// as roots instead of full Anchor workspace expansion — unless they themselves contain
/// Anchor programs.
fn resolve_scan_roots(path: &str, options: &ScanOptions) -> (Vec<PathBuf>, Option<Vec<String>>) {
    let root = PathBuf::from(path);

    if !options.config_paths.is_empty() {
        let mut roots: Vec<PathBuf> = options
            .config_paths
            .iter()
            .map(|p| {
                let candidate = root.join(p);
                if candidate.exists() {
                    candidate
                } else {
                    PathBuf::from(p)
                }
            })
            .filter(|p| p.exists())
            .collect();
        roots.sort();
        roots.dedup();
        if !roots.is_empty() {
            let names: Vec<String> = roots
                .iter()
                .filter_map(|r| r.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .collect();
            return (roots, Some(names));
        }
    }

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

    // No [workspace] section or empty members — fall back to programs/ convention
    if members.is_empty() {
        return fallback_to_programs_dir(&root);
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
        return fallback_to_programs_dir(&root);
    }

    let names: Vec<String> = roots
        .iter()
        .filter_map(|r| r.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .collect();

    (roots, Some(names))
}

/// Falls back to scanning `programs/` when Anchor.toml has no `[workspace] members`.
/// This covers the majority of single-program Anchor projects.
fn fallback_to_programs_dir(root: &Path) -> (Vec<PathBuf>, Option<Vec<String>>) {
    let programs_dir = root.join("programs");
    if !programs_dir.is_dir() {
        return (vec![root.to_path_buf()], None);
    }

    let mut roots: Vec<PathBuf> = std::fs::read_dir(&programs_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("Cargo.toml").exists())
        .collect();
    roots.sort();

    if roots.is_empty() {
        return (vec![root.to_path_buf()], None);
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
        .filter(|entry| !path_is_excluded(entry.path(), &options.exclude))
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
