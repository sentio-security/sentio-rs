use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, ExprBinary};

#[derive(Debug, Default)]
pub struct UncheckedArithmeticRule;

impl Rule for UncheckedArithmeticRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW005",
            title: "Unchecked arithmetic",
            severity: RuleSeverity::High,
            description: "Detects arithmetic operations (+, -, *) on account data that can \
                silently overflow or underflow in release builds, where Rust wraps by default.",
            fix_guidance: "Use checked_add(), checked_sub(), or checked_mul() and propagate \
                the error with ?, or use saturating_add()/saturating_sub() when wrapping is intentional.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let mut collector = ArithmeticCollector {
            findings: Vec::new(),
        };
        visit::visit_file(&mut collector, &file.syntax);

        collector
            .findings
            .into_iter()
            .map(|(message, line, column)| RuleMatch {
                rule_id: "SW005",
                severity: RuleSeverity::High,
                message,
                location: SourceLocation {
                    path: file.path.display().to_string(),
                    line,
                    column,
                },
                help: Some(
                    "Replace `x += y` with `x = x.checked_add(y).ok_or(ErrorCode::Overflow)?`, \
                    or use `saturating_add` if overflow should saturate rather than error."
                        .to_string(),
                ),
            })
            .collect()
    }
}

struct ArithmeticCollector {
    findings: Vec<(String, usize, usize)>,
}

impl<'ast> Visit<'ast> for ArithmeticCollector {
    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        let left = node.left.to_token_stream().to_string();
        let right = node.right.to_token_stream().to_string();
        let loc = node.left.span().start();

        match &node.op {
            // Compound assignments: +=, -=, *=
            // Only flag when the target has a field access — loop counters like `i += 1` are skipped.
            BinOp::AddAssign(_) | BinOp::SubAssign(_) | BinOp::MulAssign(_)
                if has_field_access(&left) =>
            {
                let op = op_symbol(&node.op);
                self.findings.push((
                    format!(
                        "unchecked `{op}` on `{}`; can overflow or underflow in release builds",
                        left.trim()
                    ),
                    loc.line,
                    loc.column + 1,
                ));
            }
            // Pure arithmetic: +, -, *
            // Flag when at least one operand is a field access (account data involved).
            BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_)
                if has_field_access(&left) || has_field_access(&right) =>
            {
                let op = op_symbol(&node.op);
                self.findings.push((
                    format!(
                        "unchecked `{op}` involving account field; can overflow or underflow in release builds"
                    ),
                    loc.line,
                    loc.column + 1,
                ));
            }
            _ => {}
        }

        visit::visit_expr_binary(self, node);
    }
}

fn has_field_access(expr: &str) -> bool {
    let trimmed = expr.trim();
    // Exclude float literals like "1.0" or "3.14_f64" that contain dots but are not field accesses.
    if trimmed.chars().all(|c| {
        c.is_ascii_digit()
            || c == '.'
            || c == '_'
            || c.is_ascii_alphabetic() && c.is_ascii_lowercase() && !matches!(c, 'a'..='f')
    }) && !trimmed.contains("::")
        && !trimmed.contains('(')
    {
        let without_suffix = trimmed.trim_end_matches(|c: char| c.is_ascii_alphabetic());
        if without_suffix
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '_')
        {
            return false;
        }
    }
    trimmed.contains('.')
}

fn op_symbol(op: &BinOp) -> &'static str {
    match op {
        BinOp::Add(_) | BinOp::AddAssign(_) => "+",
        BinOp::Sub(_) | BinOp::SubAssign(_) => "-",
        BinOp::Mul(_) | BinOp::MulAssign(_) => "*",
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleContext;
    use std::path::PathBuf;

    fn parse_file(source: &str) -> ParsedFile {
        ParsedFile {
            path: PathBuf::from("src/lib.rs"),
            source: source.to_string(),
            syntax: syn::parse_file(source).expect("source should parse"),
        }
    }

    #[test]
    fn flags_compound_add_assign_on_account_field() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                ctx.accounts.vault.balance += amount;
                Ok(())
            }
        "#,
        );
        let rule = UncheckedArithmeticRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW005");
        assert!(findings[0].message.contains("+"));
    }

    #[test]
    fn flags_sub_assign_and_mul_on_account_field() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Transfer>, amount: u64, rate: u64) -> Result<()> {
                ctx.accounts.vault.balance -= amount;
                let fee = ctx.accounts.vault.balance * rate;
                Ok(())
            }
        "#,
        );
        let rule = UncheckedArithmeticRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.rule_id == "SW005"));
    }

    #[test]
    fn does_not_flag_loop_counter_or_local_arithmetic() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(_ctx: Context<Example>, amount: u64, fee: u64) -> Result<()> {
                let mut i = 0u64;
                i += 1;
                let total = amount + fee;
                Ok(())
            }
        "#,
        );
        let rule = UncheckedArithmeticRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_checked_arithmetic() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                ctx.accounts.vault.balance = ctx.accounts.vault.balance
                    .checked_add(amount)
                    .ok_or(ErrorCode::Overflow)?;
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { Overflow }
        "#,
        );
        let rule = UncheckedArithmeticRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_saturating_arithmetic() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                ctx.accounts.vault.balance = ctx.accounts.vault.balance.saturating_add(amount);
                Ok(())
            }
        "#,
        );
        let rule = UncheckedArithmeticRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
