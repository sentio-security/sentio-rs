use crate::cargo_profile::release_overflow_checks_enabled;
use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprCast, ExprParen, ExprUnary, Lit, Type};

#[derive(Debug, Default)]
pub struct UncheckedArithmeticRule;

impl Rule for UncheckedArithmeticRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW005",
            title: "Unchecked arithmetic",
            severity: RuleSeverity::High,
            description: "Detects unchecked +, -, * on account data with a non-trivial (variable \
                or non-unit) delta that can silently overflow/underflow in release builds when \
                `[profile.release] overflow-checks` is off (Rust default). Focuses on \
                economically relevant steps (e.g. user-controlled `amount`), not unit counter \
                bumps like `count += 1`. Suppressed when the package enables release overflow-checks.",
            fix_guidance: "Use checked_add(), checked_sub(), or checked_mul() and propagate \
                the error with ?, or use saturating_add()/saturating_sub() when wrapping is intentional. \
                Alternatively set `[profile.release] overflow-checks = true` so overflow panics in release.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        // Mature protocols often enable panic-on-overflow in release; raw += then does
        // *not* wrap, so "can overflow in release builds" would be a false claim.
        if release_overflow_checks_enabled(&file.path) {
            return Vec::new();
        }

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
                    "Replace `x += y` with `x = x.checked_add(y).ok_or(ErrorCode::Overflow)?` \
                    when `y` is variable or non-unit. Unit steps like `count += 1` are lower risk; \
                    still prefer checked math for money/supply fields. Or enable \
                    `[profile.release] overflow-checks = true`."
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
            // Compound assignments: +=, -=, *= on account fields.
            // Skip unit steps (`+= 1`, `-= 1`, `*= 1`) — not practical overflow paths.
            BinOp::AddAssign(_) | BinOp::SubAssign(_) | BinOp::MulAssign(_)
                if expr_has_field_access(&node.left)
                    && !expr_is_widened_to_128(&node.left)
                    && !is_trivial_compound_step(&node.op, &node.right) =>
            {
                let op = op_symbol(&node.op);
                let left = node.left.to_token_stream().to_string();
                let loc = node.left.span().start();
                self.findings.push((
                    format!(
                        "unchecked `{op}` on `{}` with non-unit/variable delta; \
                         can overflow or underflow in release builds",
                        left.split_whitespace().collect::<Vec<_>>().join(" ")
                    ),
                    loc.line,
                    loc.column + 1,
                ));
            }
            // Pure arithmetic: +, -, *
            // Flag field-involving ops unless widened to u128/i128, or field ± 1 unit step.
            BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_)
                if should_flag_binary_arithmetic(&node.op, &node.left, &node.right) =>
            {
                let op = op_symbol(&node.op);
                let loc = node.left.span().start();
                self.findings.push((
                    format!(
                        "unchecked `{op}` involving account field with non-unit/variable delta; \
                         can overflow or underflow in release builds"
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

/// `+= 1`, `-= 1`, `*= 1` — counter bumps, not attacker-chosen magnitude.
fn is_trivial_compound_step(op: &BinOp, rhs: &Expr) -> bool {
    match op {
        BinOp::AddAssign(_) | BinOp::SubAssign(_) => is_unit_integer_literal(rhs),
        BinOp::MulAssign(_) => integer_literal_value(rhs) == Some(1),
        _ => false,
    }
}

/// Flag when account-field data is involved without u128 widen, except field ± 1.
fn should_flag_binary_arithmetic(op: &BinOp, left: &Expr, right: &Expr) -> bool {
    let left_field = expr_has_field_access(left);
    let right_field = expr_has_field_access(right);
    if !left_field && !right_field {
        return false;
    }

    // field + 1 / 1 + field / field - 1 — unit step, skip for + and -
    if matches!(op, BinOp::Add(_) | BinOp::Sub(_)) && is_field_unit_step(left, right) {
        return false;
    }

    let left_risky = left_field && !expr_is_widened_to_128(left);
    let right_risky = right_field && !expr_is_widened_to_128(right);
    left_risky || right_risky
}

/// True when one side is a field path and the other is literal `1` (add/sub only).
fn is_field_unit_step(left: &Expr, right: &Expr) -> bool {
    let left_field = expr_has_field_access(left);
    let right_field = expr_has_field_access(right);
    (left_field && !right_field && is_unit_integer_literal(right))
        || (right_field && !left_field && is_unit_integer_literal(left))
}

fn is_unit_integer_literal(expr: &Expr) -> bool {
    integer_literal_value(expr) == Some(1)
}

fn integer_literal_value(expr: &Expr) -> Option<u128> {
    match peel_expr(expr) {
        Expr::Lit(expr_lit) => match &expr_lit.lit {
            Lit::Int(int_lit) => int_lit.base10_parse::<u128>().ok(),
            _ => None,
        },
        _ => None,
    }
}

fn peel_expr(expr: &Expr) -> &Expr {
    match expr {
        Expr::Paren(ExprParen { expr, .. }) => peel_expr(expr),
        Expr::Group(g) => peel_expr(&g.expr),
        Expr::Reference(r) => peel_expr(&r.expr),
        other => other,
    }
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
            expr_has_field_access(&m.receiver) || m.args.iter().any(expr_has_field_access)
        }
        Expr::Call(c) => expr_has_field_access(&c.func) || c.args.iter().any(expr_has_field_access),
        Expr::Binary(b) => expr_has_field_access(&b.left) || expr_has_field_access(&b.right),
        Expr::Path(_) | Expr::Lit(_) => false,
        _ => {
            let s = expr.to_token_stream().to_string();
            token_string_has_field_access(&s)
        }
    }
}

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
    fn does_not_flag_unit_counter_increment() {
        // Auditor thesis: += 1 is not an economically practical overflow attack.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn mint_one(ctx: Context<MintNft>) -> Result<()> {
                ctx.accounts.profile.nft_count += 1;
                Ok(())
            }
        "#,
        );
        assert!(
            run(&file).is_empty(),
            "unit step += 1 must not be SW005: {:?}",
            run(&file)
        );
    }

    #[test]
    fn does_not_flag_unit_counter_decrement() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn burn_one(ctx: Context<Burn>) -> Result<()> {
                ctx.accounts.profile.nft_count -= 1;
                Ok(())
            }
        "#,
        );
        assert!(run(&file).is_empty());
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

    #[test]
    fn still_flags_add_assign_with_literal_other_than_one() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Deposit>) -> Result<()> {
                ctx.accounts.vault.balance += 100;
                Ok(())
            }
        "#,
        );
        assert_eq!(run(&file).len(), 1);
    }

    #[test]
    fn suppresses_when_release_overflow_checks_enabled() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sentio-sw005-overflow-{n}"));
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"hardened\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[profile.release]\noverflow-checks = true\n",
        )
        .unwrap();
        let lib = dir.join("src/lib.rs");
        fs::write(
            &lib,
            "use anchor_lang::prelude::*;\npub fn handler(ctx: Context<Deposit>, amount: u64) -> Result<()> {\n    ctx.accounts.vault.balance += amount;\n    Ok(())\n}\n",
        )
        .unwrap();

        let source = fs::read_to_string(&lib).unwrap();
        let file = ParsedFile {
            path: lib.clone(),
            syntax: syn::parse_file(&source).unwrap(),
            source,
        };
        assert!(
            run(&file).is_empty(),
            "SW005 must not fire when overflow-checks = true"
        );
        fs::remove_dir_all(dir).ok();
    }
}
