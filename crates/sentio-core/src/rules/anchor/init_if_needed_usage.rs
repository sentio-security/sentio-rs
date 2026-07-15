use crate::anchor_accounts::collect_anchor_accounts_index;
use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct InitIfNeededUsageRule;

impl Rule for InitIfNeededUsageRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW016",
            title: "init_if_needed usage (manual review)",
            severity: RuleSeverity::Medium,
            description:
                "Flags Anchor account fields using init_if_needed because the pattern can permit unintended re-initialization or state reset.",
            fix_guidance:
                "Prefer init when possible. If init_if_needed is required, verify the account cannot be reset or re-initialized by an attacker and that authority and seed constraints are strict.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_anchor_accounts_index(&file.syntax);
        let mut findings = Vec::new();

        for item in index.structs {
            for field in item.fields {
                if !field.constraints.init_if_needed {
                    continue;
                }

                // ATA-style init_if_needed (associated_token / token mint+authority) is a
                // common UX pattern: fixed SPL layout, not custom program state that can
                // be re-inited to reset balances. Flag program data accounts instead.
                if field.constraints.has_token_mint_check()
                    && field.constraints.has_token_authority_check()
                {
                    continue;
                }

                let field_name = field.ast.name.clone().unwrap_or_default();
                findings.push(RuleMatch {
                    rule_id: "SW016",
                    severity: RuleSeverity::Medium,
                    message: format!(
                        "Account `{field_name}` uses `init_if_needed`; review for re-initialization or state-reset risk."
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: field.ast.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "Prefer #[account(init, ...)] when possible. If init_if_needed is necessary, confirm the account cannot be abused to reset state."
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
    fn flags_fields_using_init_if_needed() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(init_if_needed, payer = authority, space = 8 + Vault::LEN)]
                pub vault: Account<'info, Vault>,
                #[account(mut)]
                pub authority: Signer<'info>,
                pub system_program: Program<'info, System>,
            }
            "#,
        );

        let rule = InitIfNeededUsageRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW016");
        assert!(findings[0].message.contains("init_if_needed"));
    }

    #[test]
    fn does_not_flag_plain_init_usage() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(init, payer = authority, space = 8 + Vault::LEN)]
                pub vault: Account<'info, Vault>,
                #[account(mut)]
                pub authority: Signer<'info>,
                pub system_program: Program<'info, System>,
            }
            "#,
        );

        let rule = InitIfNeededUsageRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_ata_init_if_needed() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::associated_token::AssociatedToken;
            use anchor_spl::token::{Mint, Token, TokenAccount};

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(
                    init_if_needed,
                    payer = payer,
                    associated_token::mint = mint,
                    associated_token::authority = owner,
                )]
                pub ata: Account<'info, TokenAccount>,
                pub mint: Account<'info, Mint>,
                pub owner: Signer<'info>,
                #[account(mut)]
                pub payer: Signer<'info>,
                pub token_program: Program<'info, Token>,
                pub associated_token_program: Program<'info, AssociatedToken>,
                pub system_program: Program<'info, System>,
            }
            "#,
        );

        let rule = InitIfNeededUsageRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(
            findings.is_empty(),
            "ATA init_if_needed should not be SW016: {findings:?}"
        );
    }
}
