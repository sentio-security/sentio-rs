use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, ExprBinary};

#[derive(Debug, Default)]
pub struct DivisionByZeroRule;

impl Rule for DivisionByZeroRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW024",
            title: "Division by zero",
            severity: RuleSeverity::High,
            description: "Detects division or modulo where the divisor is a non-literal value \
                          (field access, variable, or parameter) with no prior zero-check. \
                          In Solana programs, user-supplied or account-sourced denominators can \
                          be zero, causing a runtime panic and a failed transaction.",
            fix_guidance:
                "Guard the divisor with require!(divisor != 0, ErrorCode::DivisionByZero) \
                           before dividing, or use checked_div() / checked_rem() and propagate \
                           the None case as an error.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let mut collector = DivisionCollector {
            findings: Vec::new(),
        };
        visit::visit_file(&mut collector, &file.syntax);

        collector
            .findings
            .into_iter()
            .map(|(message, line, column)| RuleMatch {
                rule_id: "SW024",
                severity: RuleSeverity::High,
                message,
                location: SourceLocation {
                    path: file.path.display().to_string(),
                    line,
                    column,
                },
                help: Some(
                    "Use checked_div() or checked_rem() and handle the None case, or add \
                     require!(divisor != 0, ...) before the operation."
                        .to_string(),
                ),
            })
            .collect()
    }
}

struct DivisionCollector {
    findings: Vec<(String, usize, usize)>,
}

impl<'ast> Visit<'ast> for DivisionCollector {
    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        match &node.op {
            BinOp::Div(_) | BinOp::Rem(_) => {
                let divisor = node.right.to_token_stream().to_string();
                let op = match &node.op {
                    BinOp::Div(_) => "/",
                    BinOp::Rem(_) => "%",
                    _ => unreachable!(),
                };

                // Only flag when the divisor is not a numeric literal — literals
                // like `/ 2` or `% 100` cannot be zero at runtime.
                if !is_numeric_literal(&divisor) {
                    let loc = node.span().start();
                    self.findings.push((
                        format!(
                            "`{}` used as divisor in `{op}` without a zero-check; \
                             if zero at runtime the transaction will panic",
                            divisor.trim()
                        ),
                        loc.line,
                        loc.column + 1,
                    ));
                }
            }
            _ => {}
        }

        visit::visit_expr_binary(self, node);
    }
}

/// Returns true when the expression is a plain numeric literal (e.g. `2`, `100u64`, `0x10`).
fn is_numeric_literal(expr: &str) -> bool {
    let s = expr
        .trim()
        .trim_end_matches(|c: char| c.is_ascii_alphabetic()); // strip suffixes
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_digit() || c == '_' || c == 'x' || c == 'b' || c == 'o')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleContext;
    use crate::syntax::ParsedFile;
    use std::path::PathBuf;

    fn parse_file(source: &str) -> ParsedFile {
        ParsedFile {
            path: PathBuf::from("src/lib.rs"),
            source: source.to_string(),
            syntax: syn::parse_file(source).expect("source should parse"),
        }
    }

    #[test]
    fn flags_division_by_variable_divisor() {
        let file = parse_file(
            r#"
            pub fn calc_fee(amount: u64, rate: u64) -> u64 {
                amount / rate
            }
            "#,
        );
        let rule = DivisionByZeroRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW024");
    }

    #[test]
    fn flags_division_by_account_field() {
        let file = parse_file(
            r#"
            pub fn calc(ctx: Context<Foo>, amount: u64) -> u64 {
                amount / ctx.accounts.config.rate
            }
            "#,
        );
        let rule = DivisionByZeroRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW024");
    }

    #[test]
    fn does_not_flag_literal_divisor() {
        let file = parse_file(
            r#"
            pub fn calc(amount: u64) -> u64 {
                amount / 100
            }
            "#,
        );
        let rule = DivisionByZeroRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_checked_div() {
        let file = parse_file(
            r#"
            pub fn calc(amount: u64, rate: u64) -> Option<u64> {
                amount.checked_div(rate)
            }
            "#,
        );
        let rule = DivisionByZeroRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
