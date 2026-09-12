use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, ItemFn};

#[derive(Debug, Default)]
pub struct UnwrapOnResultRule;

impl Rule for UnwrapOnResultRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW025",
            title: "unwrap() / expect() in instruction handler",
            severity: RuleSeverity::Medium,
            description: "Detects .unwrap() and .expect() calls in instruction handlers. \
                          In Solana programs these cause a runtime panic, which fails the \
                          transaction with a generic error and can be triggered by crafting \
                          inputs that produce None or Err, making it a potential DoS vector.",
            fix_guidance: "Replace .unwrap() with ? to propagate the error as an Anchor \
                           ErrorCode, or use .ok_or(ErrorCode::Foo)? to return a meaningful \
                           program error instead of panicking.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let mut collector = UnwrapCollector {
            findings: Vec::new(),
            in_test: false,
            panic_nesting: 0,
        };
        visit::visit_file(&mut collector, &file.syntax);

        collector
            .findings
            .into_iter()
            .map(|(message, line, column)| RuleMatch {
                rule_id: "SW025",
                severity: RuleSeverity::Medium,
                message,
                location: SourceLocation {
                    path: file.path.display().to_string(),
                    line,
                    column,
                },
                help: Some(
                    "Use `?` to propagate errors or `.ok_or(ErrorCode::Foo)?` to convert \
                     Option to a typed program error."
                        .to_string(),
                ),
            })
            .collect()
    }
}

struct UnwrapCollector {
    findings: Vec<(String, usize, usize)>,
    in_test: bool,
    /// Depth of nested `.unwrap()` / `.expect()` while walking receivers.
    /// Only the outermost call in a chain is reported (avoids double-counting
    /// `checked_mul(...).unwrap().checked_div(...).unwrap()`).
    panic_nesting: usize,
}

impl<'ast> Visit<'ast> for UnwrapCollector {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        // Skip functions marked #[test] to avoid noise from test utilities.
        let was_in_test = self.in_test;
        if node.attrs.iter().any(|a| a.path().is_ident("test")) {
            self.in_test = true;
        }
        visit::visit_item_fn(self, node);
        self.in_test = was_in_test;
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        let is_panic = method == "unwrap" || method == "expect";

        if is_panic {
            self.panic_nesting += 1;
        }

        // Walk children first so nested panics bump nesting before we decide.
        self.visit_expr(&node.receiver);
        for arg in &node.args {
            self.visit_expr(arg);
        }

        if is_panic {
            if !self.in_test && self.panic_nesting == 1 {
                let receiver = node.receiver.to_token_stream().to_string();
                let receiver_compact = receiver.split_whitespace().collect::<Vec<_>>().join(" ");
                // Production Anchor dialects often unwrap infallible PDA / borsh helpers.
                // Keep flagging user-influenced Results (try_into, checked_*, CPI, account data).
                if !is_benign_unwrap_receiver(&receiver_compact) {
                    let loc = node.span().start();
                    self.findings.push((
                        format!(
                            "`.{method}()` on `{receiver_compact}` will panic on None/Err; use `?` or \
                             `.ok_or(ErrorCode::...)?` instead"
                        ),
                        loc.line,
                        loc.column + 1,
                    ));
                }
            }
            self.panic_nesting -= 1;
        }
    }
}

/// Receivers that are noise on mature protocols (Marinade-style), not attacker-chosen Options.
fn is_benign_unwrap_receiver(receiver: &str) -> bool {
    let compact: String = receiver.chars().filter(|c| !c.is_whitespace()).collect();
    let lower = compact.to_ascii_lowercase();

    // Pubkey::create_program_address / create_with_seed / find_program_address
    // (and associated helpers that wrap those calls).
    if lower.contains("create_program_address")
        || lower.contains("create_with_seed")
        || lower.contains("find_program_address")
    {
        return true;
    }

    // Fixed-layout borsh of Default / zeroed placeholders — effectively infallible size helpers.
    // e.g. `ValidatorRecord::default().try_to_vec()` or `MaybeUninit::zeroed().assume_init().try_to_vec()`.
    if lower.contains("try_to_vec")
        && (lower.contains("::default()")
            || lower.contains(".default()")
            || lower.contains("assume_init")
            || lower.contains("zeroed"))
    {
        return true;
    }

    false
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
    fn flags_unwrap_in_instruction() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, raw: &[u8]) -> Result<()> {
                let val: u64 = raw.try_into().unwrap();
                Ok(())
            }
            "#,
        );
        let rule = UnwrapOnResultRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW025");
    }

    #[test]
    fn flags_expect_in_instruction() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, amount: u64) -> Result<()> {
                let val = ctx.accounts.vault.amount.checked_add(amount).expect("overflow");
                Ok(())
            }
            "#,
        );
        let rule = UnwrapOnResultRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW025");
    }

    #[test]
    fn does_not_flag_unwrap_inside_test_fn() {
        let file = parse_file(
            r#"
            #[cfg(test)]
            mod tests {
                #[test]
                fn it_works() {
                    let x: Option<u64> = Some(1);
                    assert_eq!(x.unwrap(), 1);
                }
            }
            "#,
        );
        let rule = UnwrapOnResultRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_question_mark_propagation() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, amount: u64) -> Result<()> {
                let val = ctx.accounts.vault.amount
                    .checked_add(amount)
                    .ok_or(error!(ErrorCode::Overflow))?;
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { Overflow }
            "#,
        );
        let rule = UnwrapOnResultRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn dedupes_nested_unwrap_chain_to_one_finding() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, amount: u64) -> Result<()> {
                let amount_a = (amount as u128)
                    .checked_mul(ctx.accounts.pool.amount as u128)
                    .unwrap()
                    .checked_div(ctx.accounts.mint.supply as u128 + 100)
                    .unwrap() as u64;
                let _ = amount_a;
                Ok(())
            }
            "#,
        );
        let rule = UnwrapOnResultRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(
            findings.len(),
            1,
            "one finding for the whole unwrap chain, got: {findings:?}"
        );
    }

    #[test]
    fn still_flags_separate_unwrap_statements() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, a: u64, b: u64) -> Result<()> {
                let x = a.checked_add(1).unwrap();
                let y = b.checked_mul(2).unwrap();
                let _ = (x, y);
                Ok(())
            }
            "#,
        );
        let rule = UnwrapOnResultRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn does_not_flag_pubkey_create_program_address_unwrap() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn helper(state: &Pubkey) -> Pubkey {
                Pubkey::create_program_address(&[state.as_ref(), b"reserve"], &crate::ID).unwrap()
            }
            "#,
        );
        let findings = UnwrapOnResultRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "Pubkey::create_* unwrap must be quiet: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_create_with_seed_unwrap() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn default_msol_leg(state: &Pubkey) -> Pubkey {
                Pubkey::create_with_seed(state, b"leg", &spl_token::ID).unwrap()
            }
            "#,
        );
        let findings = UnwrapOnResultRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn does_not_flag_default_try_to_vec_unwrap() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Default)]
            pub struct ValidatorRecord { pub x: u64 }
            pub fn size() -> usize {
                ValidatorRecord::default().try_to_vec().unwrap().len()
            }
            "#,
        );
        let findings = UnwrapOnResultRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "default().try_to_vec() unwrap must be quiet: {findings:?}"
        );
    }

    #[test]
    fn still_flags_user_input_try_into_unwrap() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn process(raw: Vec<u8>) -> Result<()> {
                let amount = u64::from_le_bytes(raw.try_into().unwrap());
                let _ = amount;
                Ok(())
            }
            "#,
        );
        let findings = UnwrapOnResultRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(findings.len(), 1);
    }
}
