use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorFieldTypeKind};
use crate::finding::SourceLocation;
use crate::instruction_analysis::{analyze_account_field_usage, collect_instruction_index};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingSignerCheckRule;

impl Rule for MissingSignerCheckRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW001",
            title: "Missing signer check",
            severity: RuleSeverity::Critical,
            description: "Detects AccountInfo or UncheckedAccount fields whose names suggest an authority role but have no signer constraint and no is_signer guard in instruction logic, allowing an attacker to pass an unsigned account as the authority.",
            fix_guidance: "Use Signer<'info> as the field type, add #[account(signer)], or validate account.is_signer in your instruction handler.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let accounts_index = collect_anchor_accounts_index(&file.syntax);
        let instruction_index = collect_instruction_index(&file.syntax);
        let mut findings = Vec::new();

        // Build a set of word tokens that appear in signer-referencing guards across all
        // instruction functions — used to detect explicit is_signer checks in handler bodies.
        let signer_guarded_tokens: Vec<String> = instruction_index
            .functions
            .iter()
            .flat_map(|f| f.guards.iter())
            .filter(|g| g.references_signer)
            .flat_map(|g| {
                g.expression
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .collect();

        for item in accounts_index.structs {
            for field in item.fields {
                let kind = &field.type_info.kind;

                if *kind != AnchorFieldTypeKind::AccountInfo
                    && *kind != AnchorFieldTypeKind::UncheckedAccount
                {
                    continue;
                }

                let field_name = field.ast.name.as_deref().unwrap_or("").to_string();
                let name_lower = field_name.to_lowercase();

                // Only flag fields whose names suggest an authority/signer role.
                // Using Signer<'info> as the type (already caught by type system) and
                // plain data/program fields are intentionally excluded.
                let is_authority_named = name_lower.contains("authority")
                    || name_lower.contains("admin")
                    || name_lower == "signer"
                    || name_lower.contains("initializer");

                if !is_authority_named {
                    continue;
                }

                let c = &field.constraints;

                // `#[account(signer)]` — Anchor enforces the signer check at runtime.
                if c.is_signer {
                    continue;
                }

                // `#[account(address = ...)]` — hard-coded pubkey effectively validates identity.
                if c.address {
                    continue;
                }

                // PDA with seeds (+ bump): address is constrained by derivation.
                // These are seed-signers for CPI (`invoke_signed`), not transaction signers —
                // requiring Signer<'info> would be incorrect (e.g. pool_authority PDAs).
                if c.has_seeds {
                    continue;
                }

                // Stored-pubkey only (e.g. `state.admin = ctx.accounts.admin.key()`):
                // not a live signer authority — do not require Signer / is_signer.
                // Require !mut so we don't suppress accounts that can still be mutated.
                if !c.is_mut
                    && analyze_account_field_usage(&file.syntax, &field_name).is_pubkey_only()
                {
                    continue;
                }

                // Explicit is_signer guard in any instruction handler body.
                let has_signer_guard = signer_guarded_tokens.iter().any(|tok| tok == &field_name);

                if !has_signer_guard {
                    findings.push(RuleMatch {
                        rule_id: "SW001",
                        severity: RuleSeverity::Critical,
                        message: format!(
                            "Account `{field_name}` appears to be an authority but has no signer constraint and no is_signer guard; an attacker can pass an unsigned account.",
                        ),
                        location: SourceLocation {
                            path: file.path.display().to_string(),
                            line: field.ast.span.start_line,
                            column: 1,
                        },
                        help: Some(
                            "Use Signer<'info> as the field type, add #[account(signer)], or add require!(account.is_signer, ...) in the instruction handler."
                                .to_string(),
                        ),
                    });
                }
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
    fn flags_account_info_authority_without_signer_check() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(mut)]
                pub authority: AccountInfo<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                ctx.accounts.vault.balance += 1;
                Ok(())
            }
        "#,
        );

        let rule = MissingSignerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW001");
    }

    #[test]
    fn does_not_flag_when_signer_constraint_present() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(mut, signer)]
                pub authority: AccountInfo<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );

        let rule = MissingSignerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_when_is_signer_guard_in_instruction() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(mut)]
                pub authority: AccountInfo<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                require!(
                    ctx.accounts.authority.is_signer,
                    ErrorCode::Unauthorized
                );
                ctx.accounts.vault.balance += 1;
                Ok(())
            }
        "#,
        );

        let rule = MissingSignerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_signer_type() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub authority: Signer<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );

        let rule = MissingSignerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_non_authority_named_account_info() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub treasury: AccountInfo<'info>,
                pub vault: AccountInfo<'info>,
            }
        "#,
        );

        let rule = MissingSignerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_pda_authority_with_seeds() {
        // Classic AMM pool_authority: AccountInfo + seeds/bump, seed-signs CPIs.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                /// CHECK: PDA authority for pool vaults
                #[account(
                    seeds = [pool.key().as_ref(), b"authority"],
                    bump,
                )]
                pub pool_authority: AccountInfo<'info>,
                pub depositor: Signer<'info>,
            }
        "#,
        );

        let rule = MissingSignerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(
            findings.is_empty(),
            "PDA seed-signer must not be flagged as missing signer: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_admin_named_pda_with_seeds() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Config<'info> {
                #[account(seeds = [b"admin"], bump)]
                pub admin: UncheckedAccount<'info>,
            }
        "#,
        );

        let rule = MissingSignerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_admin_stored_as_pubkey_only() {
        // create_amm-style: admin is only copied via .key() into state.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct CreateAmm<'info> {
                #[account(init, payer = payer, space = 8 + 64)]
                pub amm: Account<'info, Amm>,
                /// CHECK: Read only, delegatable creation
                pub admin: AccountInfo<'info>,
                #[account(mut)]
                pub payer: Signer<'info>,
                pub system_program: Program<'info, System>,
            }

            pub fn create_amm(ctx: Context<CreateAmm>, id: Pubkey, fee: u16) -> Result<()> {
                let amm = &mut ctx.accounts.amm;
                amm.id = id;
                amm.admin = ctx.accounts.admin.key();
                amm.fee = fee;
                Ok(())
            }

            #[account]
            pub struct Amm {
                pub id: Pubkey,
                pub admin: Pubkey,
                pub fee: u16,
            }
        "#,
        );

        let rule = MissingSignerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(
            findings.is_empty(),
            "stored-pubkey admin must not be SW001: {findings:?}"
        );
    }
}
