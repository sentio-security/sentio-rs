use crate::anchor_accounts::collect_anchor_accounts_index;
use crate::finding::SourceLocation;
use crate::instruction_analysis::collect_instruction_index;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingCloseConstraintRule;

impl Rule for MissingCloseConstraintRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW022",
            title: "Manual account closure without close constraint",
            severity: RuleSeverity::High,
            description: "Detects manual lamport draining (borrow_mut on lamports) used to close \
                          accounts without Anchor's `close` constraint. Without `close`, account \
                          data is not zeroed and the discriminator is not overwritten, leaving the \
                          account vulnerable to reinitialization or data revival attacks.",
            fix_guidance: "Use #[account(mut, close = recipient)] instead of manually zeroing \
                           lamports. Anchor's close constraint zeroes account data, sets the \
                           CLOSED_ACCOUNT_DISCRIMINATOR, and transfers lamports atomically.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let accounts_index = collect_anchor_accounts_index(&file.syntax);
        let instruction_index = collect_instruction_index(&file.syntax);
        let mut findings = Vec::new();

        // Check if the file already uses close constraint anywhere — if so, the author is
        // aware of it and the manual drain may be intentional in a separate context.
        let has_close_constraint = accounts_index
            .structs
            .iter()
            .any(|s| s.fields.iter().any(|f| f.constraints.close));

        if has_close_constraint {
            return findings;
        }

        // Look for manual lamport drains: writes whose target contains both "lamports"
        // and "borrow_mut" — the canonical pattern for manual account closure.
        // Report once per function (both the drain and the recipient top-up match,
        // but they describe the same closure operation).
        for function in &instruction_index.functions {
            let drain = function.writes.iter().find(|w| {
                let t = w.target.to_lowercase();
                t.contains("lamports") && t.contains("borrow_mut")
            });
            if let Some(write) = drain {
                findings.push(RuleMatch {
                    rule_id: "SW022",
                    severity: RuleSeverity::High,
                    message: format!(
                        "Function `{}` manually drains lamports to close an account without \
                         using Anchor's `close` constraint; account data is not zeroed and \
                         the account may be revived with stale data.",
                        function.name
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: write.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "Replace manual lamport draining with #[account(mut, close = recipient)] \
                         to zero account data and prevent reinitialization attacks."
                            .to_string(),
                    ),
                });
            }
        }

        findings
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

    #[test]
    fn flags_manual_lamport_drain_without_close_constraint() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct CloseVault<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                #[account(mut)]
                pub authority: Signer<'info>,
            }

            pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
                let vault = &ctx.accounts.vault;
                let authority = &ctx.accounts.authority;
                let lamports = vault.to_account_info().lamports();
                **vault.to_account_info().lamports.borrow_mut() = 0;
                **authority.lamports.borrow_mut() += lamports;
                Ok(())
            }
            "#,
        );

        let rule = MissingCloseConstraintRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW022");
    }

    #[test]
    fn does_not_flag_when_close_constraint_present() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct CloseVault<'info> {
                #[account(mut, close = authority)]
                pub vault: Account<'info, Vault>,
                #[account(mut)]
                pub authority: Signer<'info>,
            }

            pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
                Ok(())
            }
            "#,
        );

        let rule = MissingCloseConstraintRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_normal_lamport_read() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                #[account(mut)]
                pub authority: Signer<'info>,
            }

            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
                let balance = ctx.accounts.vault.to_account_info().lamports();
                msg!("balance: {}", balance);
                Ok(())
            }
            "#,
        );

        let rule = MissingCloseConstraintRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
