pub mod anchor;
pub mod math;

use crate::finding::{Finding, Severity, SourceLocation};
use crate::syntax::ParsedFile;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: RuleSeverity,
    pub description: &'static str,
    pub fix_guidance: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub rule_id: &'static str,
    pub severity: RuleSeverity,
    pub message: String,
    pub location: SourceLocation,
    pub help: Option<String>,
}

pub trait Rule {
    fn metadata(&self) -> &RuleMetadata;
    fn match_file(&self, file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch>;
}

#[derive(Clone, Copy)]
pub struct RuleContext<'a> {
    pub files: &'a [ParsedFile],
}

pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleRegistry {
    pub fn new(rules: Vec<Box<dyn Rule>>) -> Self {
        Self { rules }
    }

    pub fn baseline() -> Self {
        Self::new(vec![
            Box::new(anchor::missing_signer_check::MissingSignerCheckRule),
            Box::new(anchor::missing_pda_seeds_bump::MissingPdaSeedsBumpRule),
            Box::new(anchor::init_if_needed_usage::InitIfNeededUsageRule),
            Box::new(anchor::missing_realloc_zero::MissingReallocZeroRule),
            Box::new(anchor::account_info_as_data_account::AccountInfoAsDataAccountRule),
            Box::new(anchor::account_info_as_cpi_program::AccountInfoAsCpiProgramRule),
            Box::new(anchor::missing_owner_check::MissingOwnerCheckRule),
            Box::new(anchor::arbitrary_cpi::ArbitraryCpiRule),
            Box::new(anchor::missing_cpi_reload::MissingCpiReloadRule),
            Box::new(anchor::unchecked_arithmetic::UncheckedArithmeticRule),
            Box::new(anchor::type_cosplay::TypeCosplayRule),
            Box::new(anchor::missing_token_mint_check::MissingTokenMintCheckRule),
            Box::new(anchor::missing_token_owner_check::MissingTokenOwnerCheckRule),
            Box::new(anchor::pda_seed_unvalidated_account::PdaSeedUnvalidatedAccountRule),
            Box::new(anchor::pda_bump_not_canonical::PdaBumpNotCanonicalRule),
            Box::new(anchor::pda_seed_collision_risk::PdaSeedCollisionRiskRule),
            Box::new(anchor::missing_close_constraint::MissingCloseConstraintRule),
            Box::new(anchor::cpi_remaining_accounts::CpiRemainingAccountsRule),
            Box::new(math::division_by_zero::DivisionByZeroRule),
        ])
    }

    pub fn all(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }

    pub fn matching_rules(&self, rule_filter: Option<&str>) -> Vec<&dyn Rule> {
        let filter = rule_filter
            .map(normalize_rule_id)
            .filter(|filter| !filter.is_empty());

        self.rules
            .iter()
            .map(|rule| rule.as_ref())
            .filter(|rule| {
                filter
                    .as_ref()
                    .is_none_or(|filter| rule.metadata().id.eq_ignore_ascii_case(filter))
            })
            .collect()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::baseline()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionSet {
    same_line: HashMap<usize, Vec<String>>,
    next_line: HashMap<usize, Vec<String>>,
    /// (start_line, end_line, rule_ids) — inclusive line range for sentio-ignore-fn
    fn_ranges: Vec<(usize, usize, Vec<String>)>,
}

impl SuppressionSet {
    pub fn empty() -> Self {
        Self {
            same_line: HashMap::new(),
            next_line: HashMap::new(),
            fn_ranges: Vec::new(),
        }
    }

    pub fn from_source(source: &str) -> Self {
        let mut same_line: HashMap<usize, Vec<String>> = HashMap::new();
        let mut next_line: HashMap<usize, Vec<String>> = HashMap::new();
        let mut fn_ranges: Vec<(usize, usize, Vec<String>)> = Vec::new();

        let lines: Vec<&str> = source.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            if let Some(ids) = parse_ignore_directive(line, "sentio-ignore-fn") {
                // Scan forward from the next line to find the function's closing brace.
                if let Some(end_line) = find_fn_end_line(&lines, idx + 1) {
                    fn_ranges.push((line_no + 1, end_line, ids));
                }
            } else if let Some(ids) = parse_ignore_directive(line, "sentio-ignore") {
                same_line.insert(line_no, ids);
            }
            if let Some(ids) = parse_ignore_directive(line, "sentio-ignore-next-line") {
                next_line.insert(line_no + 1, ids);
            }
        }

        Self {
            same_line,
            next_line,
            fn_ranges,
        }
    }

    pub fn is_suppressed(&self, finding: &Finding) -> bool {
        let rule_id = finding.rule_id.to_uppercase();
        let line = finding.location.line;

        self.same_line
            .get(&line)
            .is_some_and(|ids| ids.iter().any(|id| id == &rule_id))
            || self
                .next_line
                .get(&line)
                .is_some_and(|ids| ids.iter().any(|id| id == &rule_id))
            || self.fn_ranges.iter().any(|(start, end, ids)| {
                line >= *start && line <= *end && ids.iter().any(|id| id == &rule_id)
            })
    }
}

/// Finds the 1-indexed line number of the closing brace of the first `{...}` block
/// that starts at or after `from_idx` (0-indexed). Used to determine the end of a
/// function body following a `sentio-ignore-fn` comment.
fn find_fn_end_line(lines: &[&str], from_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut started = false;
    for (i, line) in lines[from_idx..].iter().enumerate() {
        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => {
                    depth -= 1;
                    if started && depth == 0 {
                        return Some(from_idx + i + 1); // convert to 1-indexed
                    }
                }
                _ => {}
            }
        }
    }
    None
}

pub fn convert_severity(severity: RuleSeverity) -> Severity {
    match severity {
        RuleSeverity::Low => Severity::Low,
        RuleSeverity::Medium => Severity::Medium,
        RuleSeverity::High => Severity::High,
        RuleSeverity::Critical => Severity::Critical,
    }
}

fn normalize_rule_id(rule_id: &str) -> String {
    rule_id.trim().to_uppercase()
}

fn parse_ignore_directive(line: &str, directive: &str) -> Option<Vec<String>> {
    let lower = line.to_lowercase();
    let compact = lower.replace(char::is_whitespace, "");
    let marker = format!("//{directive}");
    let start = compact.find(&marker)? + marker.len();
    let ids = compact[start..]
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|s| s.trim().to_uppercase())
        .filter(|id| is_rule_id(id))
        .collect::<Vec<_>>();

    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

fn is_rule_id(id: &str) -> bool {
    id.len() == 5 && id.starts_with("SW") && id[2..].chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_same_line_and_next_line_suppressions() {
        let suppressions = SuppressionSet::from_source(
            r#"
            // sentio-ignore SW012, SW018
            let a = 1;
            // sentio-ignore-next-line SW012
            let b = 2;
            "#,
        );

        let same_line = Finding {
            rule_id: "SW012".to_string(),
            severity: Severity::High,
            message: String::new(),
            location: SourceLocation {
                path: "x.rs".to_string(),
                line: 2,
                column: 1,
            },
            help: None,
            suppressed: false,
        };
        let next_line = Finding {
            rule_id: "SW012".to_string(),
            severity: Severity::High,
            message: String::new(),
            location: SourceLocation {
                path: "x.rs".to_string(),
                line: 5,
                column: 1,
            },
            help: None,
            suppressed: false,
        };

        assert!(suppressions.is_suppressed(&same_line));
        assert!(suppressions.is_suppressed(&next_line));
    }

    #[test]
    fn fn_level_suppression_covers_body_not_outside() {
        let source = r#"
// sentio-ignore-fn SW007
pub fn permissionless(ctx: Context<Foo>) -> Result<()> {
    let x = 1;
    let y = 2;
    Ok(())
}
pub fn other() -> Result<()> {
    Ok(())
}
"#;
        let suppressions = SuppressionSet::from_source(source);

        let make = |line: usize| Finding {
            rule_id: "SW007".to_string(),
            severity: Severity::High,
            message: String::new(),
            location: SourceLocation {
                path: "x.rs".to_string(),
                line,
                column: 1,
            },
            help: None,
            suppressed: false,
        };

        // Lines 3-7 are inside the permissionless fn body
        assert!(suppressions.is_suppressed(&make(3)));
        assert!(suppressions.is_suppressed(&make(5)));
        assert!(suppressions.is_suppressed(&make(7)));
        // Lines 8-10 are outside (second fn)
        assert!(!suppressions.is_suppressed(&make(8)));
        assert!(!suppressions.is_suppressed(&make(9)));
    }

    #[test]
    fn fn_level_suppression_does_not_suppress_other_rules() {
        let source = r#"
// sentio-ignore-fn SW007
pub fn permissionless(ctx: Context<Foo>) -> Result<()> {
    Ok(())
}
"#;
        let suppressions = SuppressionSet::from_source(source);
        let finding = Finding {
            rule_id: "SW001".to_string(),
            severity: Severity::Critical,
            message: String::new(),
            location: SourceLocation {
                path: "x.rs".to_string(),
                line: 4,
                column: 1,
            },
            help: None,
            suppressed: false,
        };
        assert!(!suppressions.is_suppressed(&finding));
    }
}
