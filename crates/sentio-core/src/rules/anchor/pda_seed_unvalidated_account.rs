use crate::anchor_accounts::{
    collect_anchor_accounts_index, AnchorConstraintKind, AnchorFieldTypeKind,
};
use crate::finding::SourceLocation;
use crate::instruction_analysis::analyze_account_field_usage;
use crate::rules::anchor::missing_owner_check::direct_callee_enforces_system_owner_and_pda_or_signer;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct PdaSeedUnvalidatedAccountRule;

impl Rule for PdaSeedUnvalidatedAccountRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW013",
            title: "PDA seed references unvalidated account",
            severity: RuleSeverity::High,
            description: "Detects PDA accounts whose seeds include a reference to an \
                AccountInfo or UncheckedAccount field that has no owner, address, or signer \
                constraint. An attacker can seed-grind a PDA for an account they control.",
            fix_guidance: "Validate every account referenced in PDA seeds with an owner \
                constraint, address constraint, or Signer<'info> type so the seed input \
                cannot be attacker-controlled.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_anchor_accounts_index(&file.syntax);
        let mut findings = Vec::new();

        for item in &index.structs {
            for pda_field in &item.fields {
                if !pda_field.constraints.has_seeds || !pda_field.constraints.has_bump {
                    continue;
                }

                let seeds_value = match pda_field
                    .constraints
                    .items
                    .iter()
                    .find(|c| c.kind == AnchorConstraintKind::Seeds)
                    .and_then(|c| c.value.as_deref())
                {
                    Some(v) => v,
                    None => continue,
                };

                let seed_idents = extract_idents(seeds_value);

                for other in &item.fields {
                    let other_name = match &other.ast.name {
                        Some(n) => n.clone(),
                        None => continue,
                    };

                    if !seed_idents.contains(&other_name) {
                        continue;
                    }

                    let unverified = matches!(
                        other.type_info.kind,
                        AnchorFieldTypeKind::AccountInfo | AnchorFieldTypeKind::UncheckedAccount
                    );

                    let has_validation = other.constraints.owner
                        || other.constraints.address
                        || other.constraints.is_signer
                        || matches!(
                            other.type_info.kind,
                            AnchorFieldTypeKind::Signer | AnchorFieldTypeKind::Program
                        );

                    let other_is_identity_only =
                        analyze_account_field_usage(&file.syntax, &other_name).is_identity_only();

                    let has_fixed_identity_signer = item.fields.iter().any(|candidate| {
                        let Some(candidate_name) = candidate.ast.name.as_deref() else {
                            return false;
                        };

                        candidate_name != other_name
                            && candidate.type_info.kind == AnchorFieldTypeKind::Signer
                            && candidate.constraints.has_fixed_identity_check()
                    });

                    let identity_only_with_fixed_signer =
                        other_is_identity_only && has_fixed_identity_signer;

                    let proved_in_callee = direct_callee_enforces_system_owner_and_pda_or_signer(
                        ctx,
                        item.ast.name.as_str(),
                        &other_name,
                    );

                    if unverified
                        && !has_validation
                        && !identity_only_with_fixed_signer
                        && !proved_in_callee
                    {
                        let pda_name = pda_field.ast.name.clone().unwrap_or_default();
                        findings.push(RuleMatch {
                            rule_id: "SW013",
                            severity: RuleSeverity::High,
                            message: format!(
                                "PDA `{pda_name}` uses `{other_name}` as a seed, but \
                                `{other_name}` is an unvalidated AccountInfo — an attacker \
                                can supply any account as the seed input"
                            ),
                            location: SourceLocation {
                                path: file.path.display().to_string(),
                                line: pda_field.ast.span.start_line,
                                column: 1,
                            },
                            help: Some(format!(
                                "Add `owner`, `address`, or `signer` constraint to `{other_name}`, \
                                or change its type to Signer<'info> or Program<'info, T>."
                            )),
                        });
                    }
                }
            }
        }

        findings
    }
}

fn extract_idents(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|w| !w.is_empty() && w.starts_with(|c: char| c.is_alphabetic() || c == '_'))
        .map(|w| w.to_string())
        .collect()
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
    fn flags_pda_seeded_with_unvalidated_account_info() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Create<'info> {
                /// CHECK: used as seed
                pub user: AccountInfo<'info>,
                #[account(seeds = [b"vault", user.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = PdaSeedUnvalidatedAccountRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW013");
        assert!(findings[0].message.contains("user"));
    }

    #[test]
    fn does_not_flag_pda_seeded_with_signer() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Create<'info> {
                pub authority: Signer<'info>,
                #[account(seeds = [b"vault", authority.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
            }
        "#,
        );
        let rule = PdaSeedUnvalidatedAccountRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_pda_seeded_with_owner_constrained_account() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Create<'info> {
                #[account(owner = crate::ID)]
                pub user: AccountInfo<'info>,
                #[account(seeds = [b"vault", user.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = PdaSeedUnvalidatedAccountRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_pda_with_only_literal_seeds() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Create<'info> {
                #[account(seeds = [b"global-config"], bump)]
                pub config: Account<'info, Config>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = PdaSeedUnvalidatedAccountRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_identity_only_seed_account_without_fixed_identity_signer() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;

        #[derive(Accounts)]
        pub struct Create<'info> {
            pub permission_authority: UncheckedAccount<'info>,

            #[account(
                seeds = [b"vault", permission_authority.key().as_ref()],
                bump
            )]
            pub vault: Account<'info, Vault>,
        }

        #[account]
        pub struct Vault {
            pub balance: u64,
        }

        pub fn create(ctx: Context<Create>) -> Result<()> {
            let _ = ctx.accounts.permission_authority.key();
            Ok(())
        }
    "#,
        );

        let rule = PdaSeedUnvalidatedAccountRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW013");
    }

    #[test]
    fn does_not_flag_identity_only_seed_account_with_fixed_identity_signer() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;

        pub mod admin {
            use super::*;
            pub const ID: Pubkey = pubkey!("11111111111111111111111111111111");
        }

        #[derive(Accounts)]
        pub struct Create<'info> {
            pub permission_authority: UncheckedAccount<'info>,

            #[account(address = crate::admin::ID)]
            pub admin: Signer<'info>,

            #[account(
                seeds = [b"vault", permission_authority.key().as_ref()],
                bump
            )]
            pub vault: Account<'info, Vault>,
        }

        #[account]
        pub struct Vault {
            pub balance: u64,
        }

        pub fn create(ctx: Context<Create>) -> Result<()> {
            let _ = ctx.accounts.permission_authority.key();
            let _ = ctx.accounts.admin.key();
            Ok(())
        }
    "#,
        );

        let rule = PdaSeedUnvalidatedAccountRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert!(
        findings.is_empty(),
        "identity-only seed account with a fixed-identity signer must not be flagged: {findings:?}"
    );
    }

    #[test]
    fn flags_identity_only_seed_account_with_unconstrained_signer() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;

        #[derive(Accounts)]
        pub struct Create<'info> {
            pub permission_authority: UncheckedAccount<'info>,

            pub admin: Signer<'info>,

            #[account(
                seeds = [b"vault", permission_authority.key().as_ref()],
                bump
            )]
            pub vault: Account<'info, Vault>,
        }

        #[account]
        pub struct Vault {
            pub balance: u64,
        }

        pub fn create(ctx: Context<Create>) -> Result<()> {
            let _ = ctx.accounts.permission_authority.key();
            let _ = ctx.accounts.admin.key();
            Ok(())
        }
    "#,
        );

        let rule = PdaSeedUnvalidatedAccountRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert!(
            findings.iter().any(|finding| finding.rule_id == "SW013"),
            "an unrelated unconstrained signer must not suppress SW013"
        );
    }

    #[test]
    fn does_not_flag_identity_only_seed_account_with_multiple_fixed_identity_signers() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;

        pub mod admin {
            use super::*;
            pub const ID: Pubkey = pubkey!("11111111111111111111111111111111");
        }

        pub mod create_permission_pda_owner {
            use super::*;
            pub const ID: Pubkey = pubkey!("11111111111111111111111111111111");
        }

        #[derive(Accounts)]
        pub struct Create<'info> {
            pub permission_authority: UncheckedAccount<'info>,

            #[account(
                constraint = (
                    owner.key() == crate::admin::ID
                    || owner.key() == crate::create_permission_pda_owner::ID
                )
            )]
            pub owner: Signer<'info>,

            #[account(
                seeds = [b"vault", permission_authority.key().as_ref()],
                bump
            )]
            pub vault: Account<'info, Vault>,
        }

        #[account]
        pub struct Vault {
            pub balance: u64,
        }

        pub fn create(ctx: Context<Create>) -> Result<()> {
            let _ = ctx.accounts.permission_authority.key();
            let _ = ctx.accounts.owner.key();
            Ok(())
        }
    "#,
        );

        let rule = PdaSeedUnvalidatedAccountRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert!(
        findings.is_empty(),
        "multiple fixed identities in an OR constraint must count as fixed signer validation: {findings:?}"
    );
    }

    #[test]
    fn does_not_flag_seed_when_direct_callee_checks_system_owner_and_pda_or_signer() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Create<'info> {
                /// CHECK: system-owned until init
                pub pool_state: UncheckedAccount<'info>,
                #[account(seeds = [b"vault", pool_state.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
            }
            pub fn create(ctx: Context<Create>) -> Result<()> {
                open(&ctx.accounts.pool_state.to_account_info())?;
                Ok(())
            }
            pub fn open(account: &AccountInfo) -> Result<()> {
                if account.owner != &system_program::ID {
                    return err!(ErrorCode::NotApproved);
                }
                let (expect_pda_address, _bump) =
                    Pubkey::find_program_address(&[b"pool"], &crate::id());
                if account.key() != expect_pda_address {
                    require_eq!(account.is_signer, true);
                }
                Ok(())
            }
            "#,
        );
        let findings = PdaSeedUnvalidatedAccountRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "seed account proved by a direct callee must not flag SW013: {findings:?}"
        );
    }

    #[test]
    fn still_flags_seed_when_handler_and_callee_never_check_owner() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Create<'info> {
                /// CHECK: used as seed
                pub pool_state: UncheckedAccount<'info>,
                #[account(seeds = [b"vault", pool_state.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
            }
            pub fn create(ctx: Context<Create>) -> Result<()> {
                open(&ctx.accounts.pool_state.to_account_info())?;
                Ok(())
            }
            pub fn open(account: &AccountInfo) -> Result<()> {
                let _ = account.key();
                Ok(())
            }
            "#,
        );
        let findings = PdaSeedUnvalidatedAccountRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(
            findings.len(),
            1,
            "unchecked seed with no owner check in the callee must stay SW013: {findings:?}"
        );
        assert!(findings[0].message.contains("pool_state"));
    }
}
