pub mod anchor;
pub mod math;
pub mod rust;

use crate::finding::{Finding, Severity, SourceLocation};
use crate::global_index::GlobalIndex;
use crate::syntax::ParsedFile;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::LazyLock;
use syn::spanned::Spanned;

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

/// Shared empty index for unit tests that only exercise single-file rule logic.
static EMPTY_GLOBAL_INDEX: LazyLock<GlobalIndex> = LazyLock::new(GlobalIndex::empty);

/// Per-scan context passed to every rule.
///
/// `global` is built once for the whole workspace so rules can resolve
/// `Context<T>` handlers against `#[derive(Accounts)]` structs in other files.
#[derive(Clone, Copy)]
pub struct RuleContext<'a> {
    pub files: &'a [ParsedFile],
    pub global: &'a GlobalIndex,
}

impl<'a> RuleContext<'a> {
    /// Build a full scan context (files + precomputed workspace index).
    pub fn new(files: &'a [ParsedFile], global: &'a GlobalIndex) -> Self {
        Self { files, global }
    }

    /// Unit-test helper: files only, empty cross-file index.
    ///
    /// Prefer this over constructing `RuleContext` fields by hand in rule tests.
    pub fn files_only(files: &'a [ParsedFile]) -> Self {
        Self {
            files,
            global: &EMPTY_GLOBAL_INDEX,
        }
    }
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
            Box::new(rust::unwrap_on_result::UnwrapOnResultRule),
            Box::new(rust::create_program_address::CreateProgramAddressRule),
            Box::new(rust::missing_state_change_event::MissingStateChangeEventRule),
        ])
    }

    pub fn all(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }

    pub fn matching_rules(
        &self,
        rule_filter: Option<&str>,
        disabled_rules: &[String],
    ) -> Vec<&dyn Rule> {
        let filter = rule_filter
            .map(normalize_rule_id)
            .filter(|filter| !filter.is_empty());

        self.rules
            .iter()
            .map(|rule| rule.as_ref())
            .filter(|rule| {
                let id = rule.metadata().id;
                if disabled_rules
                    .iter()
                    .any(|disabled| disabled.eq_ignore_ascii_case(id))
                {
                    return false;
                }
                filter
                    .as_ref()
                    .is_none_or(|filter| id.eq_ignore_ascii_case(filter))
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

    /// Build suppressions from source text (parses with `syn` when possible).
    pub fn from_source(source: &str) -> Self {
        match syn::parse_file(source) {
            Ok(file) => Self::from_parsed(source, &file),
            // Still honor line/next-line comment directives when the snippet isn't a full file.
            Err(_) => Self::from_parsed(source, &syn::parse_file("").expect("empty file")),
        }
    }

    /// Build suppressions using AST fn spans for `sentio-ignore-fn` ranges.
    pub fn from_parsed(source: &str, syntax: &syn::File) -> Self {
        let mut same_line: HashMap<usize, Vec<String>> = HashMap::new();
        let mut next_line: HashMap<usize, Vec<String>> = HashMap::new();
        let mut fn_ranges: Vec<(usize, usize, Vec<String>)> = Vec::new();

        let fn_spans = collect_fn_line_spans(syntax);

        for (idx, line) in source.lines().enumerate() {
            let line_no = idx + 1;
            // Only honor directives that appear in real `//` comments (not string literals).
            if let Some(ids) = parse_ignore_directive_in_comment(line, "sentio-ignore-fn") {
                if let Some((fn_start, fn_end)) = first_fn_span_at_or_after(&fn_spans, line_no) {
                    fn_ranges.push((fn_start, fn_end, ids));
                }
            } else if let Some(ids) = parse_ignore_directive_in_comment(line, "sentio-ignore") {
                same_line.insert(line_no, ids);
            }
            if let Some(ids) = parse_ignore_directive_in_comment(line, "sentio-ignore-next-line") {
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

/// `(start_line, end_line)` inclusive, 1-indexed, for every `fn` / impl method.
fn collect_fn_line_spans(file: &syn::File) -> Vec<(usize, usize)> {
    use syn::visit::Visit;

    struct Collector(Vec<(usize, usize)>);

    impl<'ast> Visit<'ast> for Collector {
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            let start = node.span().start().line;
            let end = node.span().end().line;
            if start > 0 && end >= start {
                self.0.push((start, end));
            }
            syn::visit::visit_item_fn(self, node);
        }

        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            let start = node.span().start().line;
            let end = node.span().end().line;
            if start > 0 && end >= start {
                self.0.push((start, end));
            }
            syn::visit::visit_impl_item_fn(self, node);
        }
    }

    let mut c = Collector(Vec::new());
    c.visit_file(file);
    c.0.sort_by_key(|(start, _)| *start);
    c.0
}

fn first_fn_span_at_or_after(
    spans: &[(usize, usize)],
    comment_line: usize,
) -> Option<(usize, usize)> {
    spans
        .iter()
        .copied()
        .find(|(start, _)| *start >= comment_line)
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

/// Parse a sentio-ignore* directive only from a real `//` comment on the line
/// (ignores the same text inside string / char literals).
fn parse_ignore_directive_in_comment(line: &str, directive: &str) -> Option<Vec<String>> {
    let comment = line_comment_payload(line)?;
    let lower = comment.to_lowercase();
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

/// Returns the `// ...` comment payload on a line, skipping `//` inside strings/chars.
/// Distinguishes Rust lifetimes (`'info`) from char literals (`'x'`) so trailing
/// `// sentio-ignore` after `AccountInfo<'info>` still works.
fn line_comment_payload(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_double = false;
    let mut in_single = false;

    while i < bytes.len() {
        let c = bytes[i] as char;

        if in_double {
            if c == '\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if c == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }

        if in_single {
            if c == '\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if c == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }

        match c {
            '"' => {
                in_double = true;
                i += 1;
            }
            '\'' => {
                // Lifetime `'foo` vs char `'x'` / `'\n'`.
                if i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                    in_single = true;
                    i += 1;
                    continue;
                }
                if i + 1 < bytes.len() {
                    let next = bytes[i + 1] as char;
                    if next.is_ascii_alphanumeric() || next == '_' {
                        let mut j = i + 1;
                        while j < bytes.len() {
                            let ch = bytes[j] as char;
                            if ch.is_ascii_alphanumeric() || ch == '_' {
                                j += 1;
                            } else {
                                break;
                            }
                        }
                        // `'a'` — single ident char then closing quote.
                        if j == i + 2 && j < bytes.len() && bytes[j] == b'\'' {
                            i = j + 1;
                            continue;
                        }
                        // Lifetime — skip `'ident`.
                        i = j;
                        continue;
                    }
                }
                in_single = true;
                i += 1;
            }
            '/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                return Some(&line[i..]);
            }
            _ => i += 1,
        }
    }
    None
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

    #[test]
    fn fn_ignore_does_not_extend_past_fn_when_string_has_brace() {
        // Issue #9: raw brace-counting would see `{` in the string and swallow `other`.
        let source = r#"
// sentio-ignore-fn SW007
pub fn permissionless() -> Result<()> {
    msg!("missing { here");
    Ok(())
}
pub fn other() -> Result<()> {
    let should_flag = 1;
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

        assert!(suppressions.is_suppressed(&make(4))); // inside permissionless
        assert!(!suppressions.is_suppressed(&make(8))); // other() must NOT be covered
        assert!(!suppressions.is_suppressed(&make(9)));
    }

    #[test]
    fn ignore_marker_inside_string_is_not_a_directive() {
        let source = r#"
pub fn demo() -> Result<()> {
    let s = "// sentio-ignore SW012";
    let a = 1;
    Ok(())
}
"#;
        let suppressions = SuppressionSet::from_source(source);
        let finding = Finding {
            rule_id: "SW012".to_string(),
            severity: Severity::High,
            message: String::new(),
            location: SourceLocation {
                path: "x.rs".to_string(),
                line: 3,
                column: 1,
            },
            help: None,
            suppressed: false,
        };
        assert!(!suppressions.is_suppressed(&finding));
    }

    #[test]
    fn trailing_ignore_after_lifetime_still_works() {
        // Fixture style: `pub vault: AccountInfo<'info>, // sentio-ignore SW002`
        let source = r#"
use anchor_lang::prelude::*;
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub vault: AccountInfo<'info>, // sentio-ignore SW002
    pub authority: Signer<'info>,
}
"#;
        let suppressions = SuppressionSet::from_source(source);
        let finding = Finding {
            rule_id: "SW002".to_string(),
            severity: Severity::Critical,
            message: String::new(),
            location: SourceLocation {
                path: "x.rs".to_string(),
                line: 5,
                column: 1,
            },
            help: None,
            suppressed: false,
        };
        assert!(
            suppressions.is_suppressed(&finding),
            "trailing ignore after 'info lifetime must apply"
        );
    }
}
