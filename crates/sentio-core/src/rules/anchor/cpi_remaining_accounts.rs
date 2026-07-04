use crate::finding::SourceLocation;
use crate::instruction_analysis::{collect_instruction_index, CallKind};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct CpiRemainingAccountsRule;

impl Rule for CpiRemainingAccountsRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW023",
            title: "Unvalidated remaining_accounts forwarded to CPI",
            severity: RuleSeverity::High,
            description: "Detects instruction handlers that forward ctx.remaining_accounts into a \
                          CPI call. Accounts in remaining_accounts are not declared in the Accounts \
                          struct so they carry no type, owner, or signer constraints. Any account \
                          that was a signer in the outer transaction retains that signer privilege \
                          inside the CPI, letting an attacker escalate privileges by supplying \
                          unexpected signers.",
            fix_guidance: "Declare every account needed by the CPI in the Accounts struct with \
                           explicit constraints (Program<'info, T>, Signer<'info>, owner, address). \
                           If remaining_accounts is unavoidable, validate each account's owner, \
                           key, and signer status before passing it to the CPI.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_instruction_index(&file.syntax);
        let source_lines: Vec<&str> = file.source.lines().collect();
        let mut findings = Vec::new();

        for function in &index.functions {
            let cpi_calls: Vec<_> = function
                .calls
                .iter()
                .filter(|c| c.kind == CallKind::Cpi)
                .collect();

            if cpi_calls.is_empty() {
                continue;
            }

            // Check whether remaining_accounts appears in the function body.
            let start = function.span.start_line.saturating_sub(1);
            let end = function.span.end_line.min(source_lines.len());
            let body_uses_remaining = source_lines[start..end]
                .iter()
                .any(|line| line.contains("remaining_accounts"));

            if !body_uses_remaining {
                continue;
            }

            // Flag the first CPI call in this function as the anchor location.
            if let Some(cpi_call) = cpi_calls.first() {
                findings.push(RuleMatch {
                    rule_id: "SW023",
                    severity: RuleSeverity::High,
                    message: format!(
                        "Function `{}` forwards `remaining_accounts` into a CPI; unvalidated \
                         accounts retain outer-transaction signer privileges inside the call.",
                        function.name
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: cpi_call.span.start_line,
                        column: cpi_call.span.start_column,
                    },
                    help: Some(
                        "Declare CPI accounts explicitly in the Accounts struct with typed \
                         constraints. If remaining_accounts is required, validate each account's \
                         owner, key, and is_signer before forwarding it."
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
    fn flags_remaining_accounts_forwarded_to_cpi() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct RouteSwap<'info> {
                pub user: Signer<'info>,
            }

            pub fn route_swap(ctx: Context<RouteSwap>, data: Vec<u8>) -> Result<()> {
                let ix = build_ix(&data);
                let mut accounts = vec![ctx.accounts.user.to_account_info()];
                accounts.extend_from_slice(ctx.remaining_accounts);
                invoke(&ix, &accounts)?;
                Ok(())
            }
            "#,
        );

        let rule = CpiRemainingAccountsRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW023");
    }

    #[test]
    fn does_not_flag_cpi_without_remaining_accounts() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Swap<'info> {
                pub user: Signer<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub token_program: Program<'info, Token>,
            }

            pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
                token::transfer(
                    CpiContext::new(ctx.accounts.token_program.to_account_info(), Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.user.to_account_info(),
                        authority: ctx.accounts.user.to_account_info(),
                    }),
                    amount,
                )?;
                Ok(())
            }

            #[account]
            pub struct Vault { pub amount: u64 }
            "#,
        );

        let rule = CpiRemainingAccountsRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_remaining_accounts_without_cpi() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct ReadAccounts<'info> {
                pub authority: Signer<'info>,
            }

            pub fn read_all(ctx: Context<ReadAccounts>) -> Result<()> {
                for acc in ctx.remaining_accounts.iter() {
                    msg!("account: {}", acc.key());
                }
                Ok(())
            }
            "#,
        );

        let rule = CpiRemainingAccountsRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
