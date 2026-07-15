use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprCast, ExprParen, ExprUnary, Type};

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
        match &node.op {
            // Compound assignments: +=, -=, *=
            // Only flag when the target has a field access — loop counters like `i += 1` are skipped.
            BinOp::AddAssign(_) | BinOp::SubAssign(_) | BinOp::MulAssign(_)
                if expr_has_field_access(&node.left) && !expr_is_widened_to_128(&node.left) =>
            {
                let op = op_symbol(&node.op);
                let left = node.left.to_token_stream().to_string();
                let loc = node.left.span().start();
                self.findings.push((
                    format!(
                        "unchecked `{op}` on `{}`; can overflow or underflow in release builds",
                        left.split_whitespace().collect::<Vec<_>>().join(" ")
                    ),
                    loc.line,
                    loc.column + 1,
                ));
            }
            // Pure arithmetic: +, -, *
            // Flag only when account-field operands are not cast to u128/i128 first.
            // Widening to 128-bit before math is the standard Solana/Anchor overflow pattern
            // (e.g. `supply as u128 + MINIMUM as u128` inside checked_div).
            BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_)
                if should_flag_binary_arithmetic(&node.left, &node.right) =>
            {
                let op = op_symbol(&node.op);
                let loc = node.left.span().start();
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

/// Flag when at least one operand touches account field data AND that field-side is not
/// widened to 128-bit. Local-only arithmetic stays quiet.
fn should_flag_binary_arithmetic(left: &Expr, right: &Expr) -> bool {
    let left_field = expr_has_field_access(left);
    let right_field = expr_has_field_access(right);
    if !left_field && !right_field {
        return false;
    }
    // Every field-involving operand must be widened; otherwise flag.
    let left_risky = left_field && !expr_is_widened_to_128(left);
    let right_risky = right_field && !expr_is_widened_to_128(right);
    left_risky || right_risky
}

fn expr_has_field_access(expr: &Expr) -> bool {
    match expr {
        Expr::Field(_) => true,
        Expr::Paren(ExprParen { expr, .. }) => expr_has_field_access(expr),
        Expr::Unary(ExprUnary { expr, .. }) => expr_has_field_access(expr),
        Expr::Cast(ExprCast { expr, .. }) => expr_has_field_access(expr),
        Expr::Reference(r) => expr_has_field_access(&r.expr),
        Expr::Try(t) => expr_has_field_access(&t.expr),
        Expr::MethodCall(m) => {
            // `pool.amount.checked_add(x)` — field is on the receiver path
            expr_has_field_access(&m.receiver)
                || m.args.iter().any(expr_has_field_access)
        }
        Expr::Call(c) => {
            expr_has_field_access(&c.func) || c.args.iter().any(expr_has_field_access)
        }
        Expr::Binary(b) => expr_has_field_access(&b.left) || expr_has_field_access(&b.right),
        Expr::Path(_) | Expr::Lit(_) => false,
        _ => {
            // Fallback for unusual shapes: token string with a real field-like dot.
            let s = expr.to_token_stream().to_string();
            token_string_has_field_access(&s)
        }
    }
}

/// True when the expression (after parens/refs) is `… as u128` or `… as i128`.
fn expr_is_widened_to_128(expr: &Expr) -> bool {
    match expr {
        Expr::Paren(ExprParen { expr, .. }) => expr_is_widened_to_128(expr),
        Expr::Reference(r) => expr_is_widened_to_128(&r.expr),
        Expr::Cast(ExprCast { ty, .. }) => type_is_128_bit(ty),
        _ => false,
    }
}

fn type_is_128_bit(ty: &Type) -> bool {
    match ty {
        Type::Path(p) => p
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "u128" || s.ident == "i128"),
        Type::Paren(p) => type_is_128_bit(&p.elem),
        _ => false,
    }
}

fn token_string_has_field_access(expr: &str) -> bool {
    let trimmed = expr.trim();
    // Exclude float literals like "1.0" or "3.14_f64".
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

    fn run(file: &ParsedFile) -> Vec<RuleMatch> {
        UncheckedArithmeticRule.match_file(
            file,
            &RuleContext {
                files: std::slice::from_ref(file),
            },
        )
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
        let findings = run(&file);
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
        let findings = run(&file);
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
        assert!(run(&file).is_empty());
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
        assert!(run(&file).is_empty());
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
        assert!(run(&file).is_empty());
    }

    #[test]
    fn does_not_flag_u128_widened_account_field_add() {
        // Foundation token-swap style: widen then add constant inside checked_div.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            const MINIMUM_LIQUIDITY: u64 = 100;
            pub fn handler(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
                let amount_a = (amount as u128)
                    .checked_mul(ctx.accounts.pool_account_a.amount as u128)
                    .unwrap()
                    .checked_div(
                        ctx.accounts.mint_liquidity.supply as u128 + MINIMUM_LIQUIDITY as u128,
                    )
                    .unwrap() as u64;
                let _ = amount_a;
                Ok(())
            }
        "#,
        );
        let findings = run(&file);
        assert!(
            findings.is_empty(),
            "u128-widened supply + constant must not be SW005: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_u128_widened_mul_of_account_fields() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Swap>) -> Result<()> {
                let product = (ctx.accounts.pool_a.amount as u128)
                    * (ctx.accounts.pool_b.amount as u128);
                let _ = product;
                Ok(())
            }
        "#,
        );
        assert!(
            run(&file).is_empty(),
            "u128 cast before mul is the safe pattern"
        );
    }

    #[test]
    fn still_flags_raw_u64_mul_of_account_fields() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Swap>) -> Result<()> {
                let invariant = ctx.accounts.pool_a.amount * ctx.accounts.pool_b.amount;
                let _ = invariant;
                Ok(())
            }
        "#,
        );
        let findings = run(&file);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW005");
    }

    #[test]
    fn still_flags_fee_math_on_u64_with_account_field() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Swap>, input: u64) -> Result<()> {
                let taxed = input - input * ctx.accounts.amm.fee as u64 / 10000;
                let _ = taxed;
                Ok(())
            }
        "#,
        );
        let findings = run(&file);
        assert!(
            !findings.is_empty(),
            "raw u64 fee math should still flag: {findings:?}"
        );
    }
}
