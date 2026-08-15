use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ImplItem, Item, Lit};

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
        let nonzero_consts = collect_nonzero_const_names(&file.syntax);
        let mut collector = DivisionCollector {
            findings: Vec::new(),
            nonzero_consts,
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
    nonzero_consts: HashSet<String>,
}

impl<'ast> Visit<'ast> for DivisionCollector {
    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        match &node.op {
            BinOp::Div(_) | BinOp::Rem(_) => {
                let op = match &node.op {
                    BinOp::Div(_) => "/",
                    BinOp::Rem(_) => "%",
                    _ => unreachable!(),
                };

                // Safe: non-zero integer literal, or named const with a non-zero
                // integer literal value (e.g. `% ROOT_RING_SIZE as u32`).
                if !is_safe_divisor(&node.right, &self.nonzero_consts) {
                    let divisor = node.right.to_token_stream().to_string();
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

/// `const NAME: T = <nonzero int literal>` (file + nested mods + impl consts).
fn collect_nonzero_const_names(file: &syn::File) -> HashSet<String> {
    let mut names = HashSet::new();
    collect_nonzero_consts_from_items(&file.items, &mut names);
    names
}

fn collect_nonzero_consts_from_items(items: &[Item], names: &mut HashSet<String>) {
    for item in items {
        match item {
            Item::Const(item_const) if expr_is_nonzero_int_literal(&item_const.expr) => {
                names.insert(item_const.ident.to_string());
            }
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_nonzero_consts_from_items(nested, names);
                }
            }
            Item::Impl(item_impl) => {
                for impl_item in &item_impl.items {
                    if let ImplItem::Const(c) = impl_item {
                        if expr_is_nonzero_int_literal(&c.expr) {
                            names.insert(c.ident.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn is_safe_divisor(expr: &Expr, nonzero_consts: &HashSet<String>) -> bool {
    match expr {
        Expr::Lit(expr_lit) => lit_is_nonzero_int(&expr_lit.lit),
        Expr::Paren(p) => is_safe_divisor(&p.expr, nonzero_consts),
        Expr::Group(g) => is_safe_divisor(&g.expr, nonzero_consts),
        Expr::Cast(c) => is_safe_divisor(&c.expr, nonzero_consts),
        Expr::Reference(r) => is_safe_divisor(&r.expr, nonzero_consts),
        Expr::Path(p) => {
            path_last_ident(&p.path).is_some_and(|name| nonzero_consts.contains(&name))
        }
        _ => false,
    }
}

fn path_last_ident(path: &syn::Path) -> Option<String> {
    path.segments.last().map(|s| s.ident.to_string())
}

fn expr_is_nonzero_int_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(expr_lit) => lit_is_nonzero_int(&expr_lit.lit),
        Expr::Paren(p) => expr_is_nonzero_int_literal(&p.expr),
        Expr::Group(g) => expr_is_nonzero_int_literal(&g.expr),
        // Allow `const X: u64 = 30u64;` — already Lit with suffix via syn
        _ => false,
    }
}

fn lit_is_nonzero_int(lit: &Lit) -> bool {
    match lit {
        Lit::Int(int_lit) => int_lit.base10_parse::<u128>().ok().is_some_and(|v| v != 0),
        _ => false,
    }
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

    fn run(source: &str) -> Vec<RuleMatch> {
        let file = parse_file(source);
        DivisionByZeroRule.match_file(
            &file,
            &RuleContext::files_only(std::slice::from_ref(&file)),
        )
    }

    #[test]
    fn flags_division_by_variable_divisor() {
        let findings = run(r#"
            pub fn calc_fee(amount: u64, rate: u64) -> u64 {
                amount / rate
            }
            "#);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW024");
    }

    #[test]
    fn flags_division_by_account_field() {
        let findings = run(r#"
            pub fn calc(ctx: Context<Foo>, amount: u64) -> u64 {
                amount / ctx.accounts.config.rate
            }
            "#);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_literal_divisor() {
        let findings = run(r#"
            pub fn calc(amount: u64) -> u64 {
                amount / 100
            }
            "#);
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_checked_div() {
        let findings = run(r#"
            pub fn calc(amount: u64, rate: u64) -> Option<u64> {
                amount.checked_div(rate)
            }
            "#);
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_nonzero_const_divisor() {
        // FP from privacy/ZK codebase: ring buffer index with const size.
        let findings = run(r#"
            pub const ROOT_RING_SIZE: usize = 30;

            pub fn advance(head: u32) -> u32 {
                (head + 1) % ROOT_RING_SIZE as u32
            }
            "#);
        assert!(
            findings.is_empty(),
            "nonzero const as divisor must be safe: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_bare_const_name_divisor() {
        let findings = run(r#"
            const SCALE: u64 = 100;
            pub fn pct(amount: u64) -> u64 {
                amount / SCALE
            }
            "#);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_zero_const_divisor() {
        let findings = run(r#"
            const ZERO: u64 = 0;
            pub fn bad(amount: u64) -> u64 {
                amount / ZERO
            }
            "#);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_literal_zero_divisor() {
        let findings = run(r#"
            pub fn bad(amount: u64) -> u64 {
                amount / 0
            }
            "#);
        assert_eq!(findings.len(), 1);
    }
}
