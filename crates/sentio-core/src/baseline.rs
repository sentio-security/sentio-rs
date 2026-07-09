//! Baseline support for “only report new findings”.
//!
//! A baseline captures findings that are already known / accepted. On subsequent
//! scans, baselined findings are filtered out so CI only fails on regressions.

use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

const BASELINE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub findings: Vec<BaselineEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub rule_id: String,
    pub path: String,
    pub message: String,
    /// Optional line for human readability; not used for matching (lines drift).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

impl Baseline {
    pub fn empty() -> Self {
        Self {
            version: BASELINE_VERSION,
            findings: Vec::new(),
        }
    }

    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut entries: Vec<BaselineEntry> =
            findings.iter().map(BaselineEntry::from_finding).collect();
        // Stable order for diffs / VCS noise reduction.
        entries.sort_by(|a, b| {
            (&a.rule_id, &a.path, &a.message).cmp(&(&b.rule_id, &b.path, &b.message))
        });
        entries.dedup();
        Self {
            version: BASELINE_VERSION,
            findings: entries,
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read baseline {}: {e}", path.display()))?;
        let baseline: Baseline = serde_json::from_str(&content)
            .map_err(|e| format!("failed to parse baseline {}: {e}", path.display()))?;
        if baseline.version != BASELINE_VERSION {
            return Err(format!(
                "unsupported baseline version {} in {} (expected {BASELINE_VERSION})",
                baseline.version,
                path.display()
            ));
        }
        Ok(baseline)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "failed to create baseline directory {}: {e}",
                        parent.display()
                    )
                })?;
            }
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize baseline: {e}"))?;
        std::fs::write(path, json + "\n")
            .map_err(|e| format!("failed to write baseline {}: {e}", path.display()))
    }

    /// Fingerprint set used for membership checks.
    pub fn fingerprint_set(&self) -> HashSet<String> {
        self.findings.iter().map(|e| e.fingerprint()).collect()
    }

    /// Drop findings that appear in the baseline. Returns (remaining, baselined_count).
    pub fn filter_findings(&self, findings: Vec<Finding>) -> (Vec<Finding>, usize) {
        let known = self.fingerprint_set();
        let mut remaining = Vec::new();
        let mut baselined = 0usize;
        for finding in findings {
            if known.contains(&BaselineEntry::from_finding(&finding).fingerprint()) {
                baselined += 1;
            } else {
                remaining.push(finding);
            }
        }
        (remaining, baselined)
    }
}

impl BaselineEntry {
    pub fn from_finding(finding: &Finding) -> Self {
        Self {
            rule_id: finding.rule_id.to_ascii_uppercase(),
            path: normalize_path(&finding.location.path),
            message: finding.message.clone(),
            line: Some(finding.location.line),
        }
    }

    /// Stable identity for a finding. Line numbers are intentionally excluded
    /// so small refactors that shift code do not re-surface accepted findings.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}",
            self.rule_id.to_ascii_uppercase(),
            normalize_path(&self.path),
            self.message
        )
    }
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Severity, SourceLocation};

    fn finding(rule: &str, path: &str, line: usize, message: &str) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            severity: Severity::High,
            message: message.to_string(),
            location: SourceLocation {
                path: path.to_string(),
                line,
                column: 1,
            },
            help: None,
            suppressed: false,
        }
    }

    #[test]
    fn filters_known_findings_ignoring_line() {
        let baseline =
            Baseline::from_findings(&[finding("SW001", "src/lib.rs", 10, "missing signer")]);

        let (remaining, baselined) = baseline.filter_findings(vec![
            finding("SW001", "src/lib.rs", 99, "missing signer"),
            finding("SW003", "src/lib.rs", 20, "arbitrary cpi"),
        ]);

        assert_eq!(baselined, 1);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].rule_id, "SW003");
    }

    #[test]
    fn roundtrip_json() {
        let baseline = Baseline::from_findings(&[finding(
            "SW016",
            "programs/a/src/lib.rs",
            4,
            "init_if_needed",
        )]);
        let json = serde_json::to_string_pretty(&baseline).unwrap();
        let loaded: Baseline = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.version, BASELINE_VERSION);
    }
}
