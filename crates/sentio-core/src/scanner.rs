use crate::config::path_is_excluded;
use crate::finding::{Finding, Severity};
use crate::global_index::GlobalIndex;
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
    /// Accounts struct names that collided within a single program / scan scope
    /// (first definition wins for GlobalIndex). Surfaced so multi-definition bugs
    /// are not silent. Entries may be `name` or `program::name`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate_accounts_names: Vec<String>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

fn warn_duplicate_accounts(scope: &str, names: &[String]) {
    if names.is_empty() {
        return;
    }
    eprintln!(
        "warning: duplicate #[derive(Accounts)] name(s) in {scope}: {}. \
         First definition wins; cross-file rules (SW001/SW002/SW003/SW022) may mis-link.",
        names.join(", ")
    );
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

        // One GlobalIndex per program root — same-named Accounts in different
        // programs must not merge (issue #8).
        let mut findings = Vec::new();
        let mut parse_failures = Vec::new();
        let mut duplicate_accounts_names = Vec::new();
        let mut files_scanned = 0usize;
        let mut files_parsed = 0usize;

        for root in &roots {
            let file_paths: Vec<PathBuf> = discover_rust_files(root, options).collect();
            files_scanned += file_paths.len();
            let report = parse_rust_files(file_paths);
            files_parsed += report.files.len();
            parse_failures.extend(report.parse_failures);

            let scope = root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| root.display().to_string());
            let (root_findings, root_dups) = self.run_rules(&report.files, options);
            findings.extend(root_findings);
            for name in root_dups {
                let labeled = if roots.len() > 1 {
                    format!("{scope}::{name}")
                } else {
                    name
                };
                if !duplicate_accounts_names.iter().any(|n| n == &labeled) {
                    duplicate_accounts_names.push(labeled);
                }
            }
        }

        if !duplicate_accounts_names.is_empty() {
            warn_duplicate_accounts("scan", &duplicate_accounts_names);
        }

        ScanResult {
            findings,
            files_scanned,
            files_parsed,
            parse_failures,
            baselined_count: 0,
            duplicate_accounts_names,
        }
    }

    pub fn scan_report(
        &self,
        files_scanned: usize,
        report: SyntaxReport,
        options: &ScanOptions,
    ) -> ScanResult {
        let files_parsed = report.files.len();
        let (findings, duplicate_accounts_names) = self.run_rules(&report.files, options);
        warn_duplicate_accounts("scan", &duplicate_accounts_names);
        let parse_failures = report.parse_failures;

        ScanResult {
            findings,
            files_scanned,
            files_parsed,
            parse_failures,
            baselined_count: 0,
            duplicate_accounts_names,
        }
    }

    /// Run rules with a GlobalIndex scoped to `files` only.
    /// Returns findings and any duplicate Accounts struct names in that scope.
    fn run_rules(
        &self,
        files: &[ParsedFile],
        options: &ScanOptions,
    ) -> (Vec<Finding>, Vec<String>) {
        let global = GlobalIndex::from_parsed_files(files);
        let duplicate_accounts_names = global.duplicate_accounts_names.clone();
        let ctx = RuleContext::new(files, &global);
        let suppressions: Vec<(String, SuppressionSet)> = files
            .iter()
            .map(|file| {
                (
                    file.path.display().to_string(),
                    SuppressionSet::from_parsed(&file.source, &file.syntax),
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

        (findings, duplicate_accounts_names)
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

    // toml 1.x: use `from_str`, not `str::parse` — the latter rejects normal tables.
    let parsed: toml::Value = match toml::from_str(&content) {
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
            // Exact member path — also accept a directory of program crates.
            let p = root.join(member);
            if p.is_dir() && p.join("Cargo.toml").exists() {
                roots.push(p);
            } else if p.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&p) {
                    let mut subdirs: Vec<PathBuf> = entries
                        .flatten()
                        .map(|e| e.path())
                        .filter(|d| d.is_dir() && d.join("Cargo.toml").exists())
                        .collect();
                    subdirs.sort();
                    roots.extend(subdirs);
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sentio-gi-{label}-{unique}"));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(path, body).expect("write");
    }

    /// Two programs both define `Deposit` with different signer setups.
    /// Per-program GlobalIndex: risky flags SW001, safe stays quiet.
    #[test]
    fn multi_program_same_accounts_name_keeps_separate_indexes() {
        let root = temp_dir("multi");
        write(
            &root.join("Anchor.toml"),
            "[workspace]\nmembers = [\"programs/*\"]\n",
        );

        // Risky: authority AccountInfo, no is_signer guard
        write(
            &root.join("programs/risky/Cargo.toml"),
            "[package]\nname = \"risky\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(
            &root.join("programs/risky/src/lib.rs"),
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Deposit<'info> {
                #[account(mut)]
                pub authority: AccountInfo<'info>,
            }
            pub fn deposit(_ctx: Context<Deposit>) -> Result<()> {
                Ok(())
            }
            "#,
        );

        // Safe: same Accounts name, but is_signer in handler
        write(
            &root.join("programs/safe/Cargo.toml"),
            "[package]\nname = \"safe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(
            &root.join("programs/safe/src/lib.rs"),
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Deposit<'info> {
                #[account(mut)]
                pub authority: AccountInfo<'info>,
            }
            pub fn deposit(ctx: Context<Deposit>) -> Result<()> {
                require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { Unauthorized }
            "#,
        );

        assert!(root.join("Anchor.toml").is_file());
        assert!(root.join("programs/risky/Cargo.toml").is_file());
        assert!(root.join("programs/safe/Cargo.toml").is_file());

        let (roots, programs) = resolve_scan_roots(root.to_str().unwrap(), &ScanOptions::default());
        assert_eq!(
            roots.len(),
            2,
            "expected 2 program roots, got {roots:?} programs={programs:?}"
        );

        let result = Scanner::new().scan_path(
            root.to_str().expect("utf8"),
            &ScanOptions {
                rule_filter: Some("SW001".into()),
                ..Default::default()
            },
        );

        let sw001: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "SW001")
            .collect();
        assert_eq!(
            sw001.len(),
            1,
            "only risky program should flag SW001: {:?}",
            result.findings
        );
        assert!(
            sw001[0].location.path.contains("risky"),
            "finding must be on risky program: {}",
            sw001[0].location.path
        );
        assert!(
            result.duplicate_accounts_names.is_empty(),
            "cross-program same name must not count as in-scope duplicate: {:?}",
            result.duplicate_accounts_names
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn duplicate_accounts_within_program_is_reported() {
        let root = temp_dir("dup");
        write(
            &root.join("a.rs"),
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Deposit<'info> {
                pub authority: Signer<'info>,
            }
            "#,
        );
        write(
            &root.join("b.rs"),
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Deposit<'info> {
                pub authority: AccountInfo<'info>,
            }
            "#,
        );

        let result =
            Scanner::new().scan_path(root.to_str().expect("utf8"), &ScanOptions::default());
        assert!(
            result
                .duplicate_accounts_names
                .iter()
                .any(|n| n == "Deposit"),
            "expected Deposit in {:?}",
            result.duplicate_accounts_names
        );
        let _ = fs::remove_dir_all(&root);
    }
}
