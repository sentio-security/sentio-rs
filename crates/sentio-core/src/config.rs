//! Project configuration loaded from `sentio.toml`.
//!
//! CLI flags always override values from the config file.

use crate::finding::Severity;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Minimum severity that causes a non-zero exit code on findings.
///
/// - `off` — never fail the process on findings (parse errors still exit 2)
/// - `low` — fail on any finding (historical default)
/// - `medium` / `high` / `critical` — fail only if a finding meets or exceeds that level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    Off,
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl FailOn {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "never" => Ok(Self::Off),
            "low" | "any" => Ok(Self::Low),
            "medium" | "med" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" | "crit" => Ok(Self::Critical),
            other => Err(format!(
                "invalid fail-on value `{other}` (expected off|low|medium|high|critical)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Returns true when `severity` should cause exit code 1.
    pub fn should_fail(self, severity: Severity) -> bool {
        match self {
            Self::Off => false,
            Self::Low => true,
            Self::Medium => matches!(
                severity,
                Severity::Medium | Severity::High | Severity::Critical
            ),
            Self::High => matches!(severity, Severity::High | Severity::Critical),
            Self::Critical => matches!(severity, Severity::Critical),
        }
    }

    pub fn any_should_fail(self, severities: impl IntoIterator<Item = Severity>) -> bool {
        severities.into_iter().any(|s| self.should_fail(s))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct SentioConfig {
    #[serde(default)]
    pub scan: ScanSection,
    /// Per-rule overrides keyed by rule id (case-insensitive match applied at use time).
    #[serde(default)]
    pub rules: HashMap<String, RuleSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct ScanSection {
    /// Optional path globs/subpaths relative to the project root to limit the scan.
    /// Empty means “use the CLI path as-is”.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Path fragments or simple globs to exclude from discovery.
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub include_tests: bool,
    #[serde(default)]
    pub fail_on: FailOn,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct RuleSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional severity override (`low` | `medium` | `high` | `critical`).
    #[serde(default)]
    pub severity: Option<String>,
}

fn default_true() -> bool {
    true
}

impl SentioConfig {
    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;
        Self::parse_toml(&content)
            .map_err(|e| format!("failed to parse config {}: {e}", path.display()))
    }

    pub fn parse_toml(content: &str) -> Result<Self, String> {
        toml::from_str(content).map_err(|e| e.to_string())
    }

    /// Look up a rule section by id (case-insensitive).
    pub fn rule(&self, rule_id: &str) -> Option<&RuleSection> {
        let upper = rule_id.to_ascii_uppercase();
        self.rules
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&upper))
            .map(|(_, v)| v)
    }

    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        self.rule(rule_id).map(|r| r.enabled).unwrap_or(true)
    }

    pub fn severity_override(&self, rule_id: &str) -> Option<Severity> {
        self.rule(rule_id)
            .and_then(|r| r.severity.as_deref())
            .and_then(parse_severity)
    }

    /// Rules explicitly disabled in config.
    pub fn disabled_rule_ids(&self) -> Vec<String> {
        self.rules
            .iter()
            .filter(|(_, section)| !section.enabled)
            .map(|(id, _)| id.to_ascii_uppercase())
            .collect()
    }
}

fn parse_severity(raw: &str) -> Option<Severity> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" | "med" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" | "crit" => Some(Severity::Critical),
        _ => None,
    }
}

/// Resolve which config file to use.
///
/// Priority:
/// 1. Explicit `--config` path
/// 2. `sentio.toml` next to the scan target (if target is a directory)
/// 3. `sentio.toml` in the current working directory
pub fn resolve_config_path(explicit: Option<&Path>, scan_path: &Path) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }

    if scan_path.is_dir() {
        let candidate = scan_path.join("sentio.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    let cwd = std::env::current_dir().ok()?;
    let candidate = cwd.join("sentio.toml");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

/// Returns true when `path` should be skipped based on exclude patterns.
///
/// Patterns match if:
/// - any path component equals the pattern (case-sensitive), or
/// - the full path (forward-slash normalized) contains the pattern, or
/// - a simple `*` wildcard pattern matches (e.g. `*/migrations/*`)
pub fn path_is_excluded(path: &Path, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }

    let normalized = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");

    for pattern in patterns {
        if pattern.is_empty() {
            continue;
        }

        if pattern.contains('*') {
            if wildcard_match(pattern, &normalized) {
                return true;
            }
            continue;
        }

        if path
            .components()
            .any(|c| c.as_os_str().to_string_lossy() == pattern.as_str())
        {
            return true;
        }

        if normalized.contains(pattern.as_str()) {
            return true;
        }
    }

    false
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }

    let mut rest = text;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !rest.starts_with(part) {
                return false;
            }
            rest = &rest[part.len()..];
        } else if i == parts.len() - 1 {
            if !rest.ends_with(part) {
                return false;
            }
        } else if let Some(idx) = rest.find(part) {
            rest = &rest[idx + part.len()..];
        } else {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let cfg = SentioConfig::parse_toml(
            r#"
            [scan]
            paths = ["programs"]
            exclude = ["migrations", "*/idls/*"]
            include_tests = true
            fail_on = "high"

            [rules.SW027]
            enabled = false

            [rules.SW016]
            severity = "low"
            "#,
        )
        .expect("config should parse");

        assert_eq!(cfg.scan.paths, vec!["programs"]);
        assert_eq!(cfg.scan.exclude, vec!["migrations", "*/idls/*"]);
        assert!(cfg.scan.include_tests);
        assert_eq!(cfg.scan.fail_on, FailOn::High);
        assert!(!cfg.is_rule_enabled("SW027"));
        assert!(cfg.is_rule_enabled("SW001"));
        assert_eq!(cfg.severity_override("SW016"), Some(Severity::Low));
    }

    #[test]
    fn fail_on_thresholds() {
        assert!(!FailOn::Off.should_fail(Severity::Critical));
        assert!(FailOn::Low.should_fail(Severity::Low));
        assert!(!FailOn::High.should_fail(Severity::Medium));
        assert!(FailOn::High.should_fail(Severity::High));
        assert!(FailOn::Critical.should_fail(Severity::Critical));
        assert!(!FailOn::Critical.should_fail(Severity::High));
    }

    #[test]
    fn exclude_matches_component_and_wildcard() {
        let path = Path::new("programs/vault/migrations/mod.rs");
        assert!(path_is_excluded(path, &["migrations".to_string()]));
        assert!(path_is_excluded(path, &["*/migrations/*".to_string()]));
        assert!(!path_is_excluded(path, &["idls".to_string()]));
    }
}
