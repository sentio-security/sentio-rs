use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::ExprCall;

#[derive(Debug, Default)]
pub struct TypeCosplayRule;

impl Rule for TypeCosplayRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW006",
            title: "Type cosplay — missing discriminator check",
            severity: RuleSeverity::Critical,
            description: "Detects try_from_slice calls that do not skip the 8-byte Anchor \
                discriminator prefix. An attacker can supply an account of a different type with \
                the same byte layout, causing the program to operate on crafted data.",
            fix_guidance: "Skip the discriminator with &data[8..], or use Account<'info, T> so \
                Anchor verifies the discriminator automatically on every instruction.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let mut collector = TypeCosplayCollector {
            findings: Vec::new(),
        };
        visit::visit_file(&mut collector, &file.syntax);

        collector
            .findings
            .into_iter()
            .map(|(message, line, column)| RuleMatch {
                rule_id: "SW006",
                severity: RuleSeverity::Critical,
                message,
                location: SourceLocation {
                    path: file.path.display().to_string(),
                    line,
                    column,
                },
                help: Some(
                    "Use Account<'info, T> (Anchor checks the discriminator for you), or \
                    pass &account.data.borrow()[8..] to skip the discriminator bytes manually."
                        .to_string(),
                ),
            })
            .collect()
    }
}

struct TypeCosplayCollector {
    findings: Vec<(String, usize, usize)>,
}

impl<'ast> Visit<'ast> for TypeCosplayCollector {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let func = compact(&node.func.to_token_stream().to_string());

        if is_try_from_slice(&func) {
            let args_safe = node.args.iter().any(|arg| {
                let s = compact(&arg.to_token_stream().to_string());
                // Safe if the argument slices off the first 8 bytes or references the discriminator.
                s.contains("8..") || s.contains("discriminator")
            });

            if !args_safe {
                let loc = node.func.span().start();
                self.findings.push((
                    format!(
                        "`{func}` called without skipping the 8-byte discriminator; \
                        an attacker can pass an account of a different type with the same byte layout"
                    ),
                    loc.line,
                    loc.column + 1,
                ));
            }
        }

        visit::visit_expr_call(self, node);
    }
}

fn is_try_from_slice(func: &str) -> bool {
    func.ends_with("::try_from_slice") || func == "try_from_slice"
}

fn compact(s: &str) -> String {
    s.split_whitespace().collect()
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
    fn flags_try_from_slice_without_discriminator_skip() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Process>) -> Result<()> {
                let data = VaultData::try_from_slice(&ctx.accounts.raw.data.borrow())?;
                Ok(())
            }
        "#,
        );
        let rule = TypeCosplayRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW006");
    }

    #[test]
    fn does_not_flag_try_from_slice_with_discriminator_skip() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Process>) -> Result<()> {
                let data = VaultData::try_from_slice(&ctx.accounts.raw.data.borrow()[8..])?;
                Ok(())
            }
        "#,
        );
        let rule = TypeCosplayRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_typed_account_with_no_manual_deserialization() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Process<'info> {
                pub vault: Account<'info, VaultData>,
                pub authority: Signer<'info>,
            }
            pub fn handler(ctx: Context<Process>) -> Result<()> {
                msg!("{}", ctx.accounts.vault.balance);
                Ok(())
            }
        "#,
        );
        let rule = TypeCosplayRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_anchor_try_deserialize() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Process>) -> Result<()> {
                let mut data: &[u8] = &ctx.accounts.raw.data.borrow();
                let account = VaultData::try_deserialize(&mut data)?;
                Ok(())
            }
        "#,
        );
        let rule = TypeCosplayRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
