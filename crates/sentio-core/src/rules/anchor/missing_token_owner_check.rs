use crate::anchor_accounts::{
    collect_anchor_accounts_index, AnchorAccountsField, AnchorFieldTypeKind,
};
use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingTokenOwnerCheckRule;

impl Rule for MissingTokenOwnerCheckRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW010",
            title: "Missing token account owner check",
            severity: RuleSeverity::Critical,
            description: "Detects mutable token account fields that have no token::authority or \
                associated_token::authority constraint, allowing an attacker to substitute a token \
                account they control as the signer's account.",
            fix_guidance: "Add token::authority = <authority_field> to the account constraint, \
                or use associated_token::authority = <authority_field> for an associated token account.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_anchor_accounts_index(&file.syntax);
        let mut findings = Vec::new();

        for item in index.structs {
            for field in &item.fields {
                if !is_token_account(field) {
                    continue;
                }
                if !field.constraints.is_mut {
                    continue;
                }
                if field.constraints.has_token_authority_check()
                    || field.constraints.address
                    || field.constraints.has_owner_or_address_check()
                    || field.constraints.init
                    || field.constraints.init_if_needed
                {
                    continue;
                }

                let name = field.ast.name.clone().unwrap_or_default();

                // User mint destinations / burn sources with mint pinned are normal Anchor
                // dialect (Marinade mint_to, burn_from, transfer_*_to). Vault/custody
                // accounts (e.g. `from`, `vault`) without authority still flag.
                if field.constraints.has_token_mint_check()
                    && (is_user_token_endpoint_name(&name)
                        || has_companion_authority_signer(&item, &name))
                {
                    continue;
                }

                findings.push(RuleMatch {
                    rule_id: "SW010",
                    severity: RuleSeverity::Critical,
                    message: format!(
                        "Mutable token account `{name}` has no `token::authority` constraint; \
                        an attacker can pass a token account they own as the signer's account"
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: field.ast.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "Add token::authority = <signer_field> to pin this account to the expected \
                        owner, or use associated_token::authority = <signer_field>."
                            .to_string(),
                    ),
                });
            }
        }

        findings
    }
}

fn is_token_account(field: &AnchorAccountsField) -> bool {
    matches!(
        field.type_info.kind,
        AnchorFieldTypeKind::Account | AnchorFieldTypeKind::InterfaceAccount
    ) && field.type_info.display.contains("TokenAccount")
}

/// Names that typically mean "user-chosen token account" (mint dest / user burn source),
/// not protocol vault custody.
fn is_user_token_endpoint_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    // Keep classic custody / debit sources flagged.
    if n == "from" || n == "vault" || n == "pool" || n.contains("leg") || n.contains("escrow") {
        return false;
    }
    n == "mint_to"
        || n.ends_with("_to")
        || n.contains("destination")
        || n.contains("recipient")
        || n.starts_with("user_")
        || n == "burn_from"
        || (n.ends_with("_from") && (n.contains("burn") || n.starts_with("get_")))
}

/// `burn_from` + `burn_from_authority: Signer` (and similar) — authority checked via sibling.
fn has_companion_authority_signer(
    item: &crate::anchor_accounts::AnchorAccountsStruct,
    token_field: &str,
) -> bool {
    let expected = format!("{token_field}_authority");
    item.fields.iter().any(|f| {
        f.ast.name.as_deref() == Some(expected.as_str())
            && (f.type_info.kind == AnchorFieldTypeKind::Signer || f.constraints.is_signer)
    })
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
    fn flags_mut_token_account_without_authority_constraint() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut, token::mint = mint)]
                pub from: Account<'info, TokenAccount>,
                pub mint: Account<'info, Mint>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW010");
    }

    #[test]
    fn does_not_flag_when_token_authority_constraint_present() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut, token::mint = mint, token::authority = authority)]
                pub from: Account<'info, TokenAccount>,
                pub mint: Account<'info, Mint>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_associated_token_account() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::TokenAccount;

            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut, associated_token::mint = mint, associated_token::authority = authority)]
                pub from: Account<'info, TokenAccount>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_has_one_authority() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut, token::mint = mint, has_one = authority)]
                pub from: Account<'info, TokenAccount>,
                pub mint: Account<'info, Mint>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_read_only_token_account() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::TokenAccount;

            #[derive(Accounts)]
            pub struct CheckBalance<'info> {
                pub token_account: Account<'info, TokenAccount>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_custom_constraint_owner_check() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::TokenAccount;

            #[derive(Accounts)]
            pub struct PlaceBet<'info> {
                pub market: Account<'info, Market>,
                #[account(
                    mut,
                    constraint = user_token_account.owner == user.key(),
                    constraint = user_token_account.mint == market.mint,
                )]
                pub user_token_account: Account<'info, TokenAccount>,
                #[account(
                    mut,
                    constraint = vault.mint == market.mint,
                    constraint = vault.owner == market.key(),
                )]
                pub vault: Account<'info, TokenAccount>,
                pub user: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "custom .owner == constraints should count: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_user_mint_destination_with_mint_pinned() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct AddLiquidity<'info> {
                #[account(mut, token::mint = lp_mint)]
                pub mint_to: Account<'info, TokenAccount>,
                pub lp_mint: Account<'info, Mint>,
                pub user: Signer<'info>,
            }
            "#,
        );
        let findings = MissingTokenOwnerCheckRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "user mint_to with token::mint must be quiet: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_burn_from_with_companion_authority_signer() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct RemoveLiquidity<'info> {
                #[account(mut, token::mint = lp_mint)]
                pub burn_from: Account<'info, TokenAccount>,
                pub burn_from_authority: Signer<'info>,
                pub lp_mint: Account<'info, Mint>,
            }
            "#,
        );
        let findings = MissingTokenOwnerCheckRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn still_flags_vault_without_authority_even_with_mint() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut, token::mint = mint)]
                pub vault: Account<'info, TokenAccount>,
                pub mint: Account<'info, Mint>,
                pub admin: Signer<'info>,
            }
            "#,
        );
        let findings = MissingTokenOwnerCheckRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(
            findings.len(),
            1,
            "protocol vault must still require authority: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_mut_token_account_with_address_constraint() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;
        use anchor_spl::token::TokenAccount;

        #[derive(Accounts)]
        pub struct Test<'info> {
            #[account(mut, address = expected.key())]
            pub vault: Account<'info, TokenAccount>,
            pub expected: UncheckedAccount<'info>,
        }
    "#,
        );

        let rule = MissingTokenOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn does_not_flag_mut_token_account_with_owner_constraint() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;
        use anchor_spl::token::TokenAccount;

        #[derive(Accounts)]
        pub struct Test<'info> {
            #[account(mut, owner = expected.key())]
            pub vault: Account<'info, TokenAccount>,
            pub expected: UncheckedAccount<'info>,
        }
    "#,
        );

        let rule = MissingTokenOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn does_not_flag_mut_token_account_with_key_identity_constraint() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;
        use anchor_spl::token::TokenAccount;

        #[derive(Accounts)]
        pub struct Test<'info> {
            #[account(
                mut,
                constraint = vault.key() == expected.key()
            )]
            pub vault: Account<'info, TokenAccount>,
            pub expected: UncheckedAccount<'info>,
        }
    "#,
        );

        let rule = MissingTokenOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn does_not_flag_mut_token_account_with_owner_identity_constraint() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;
        use anchor_spl::token::TokenAccount;

        #[derive(Accounts)]
        pub struct Test<'info> {
            #[account(
                mut,
                constraint = vault.owner == expected.key()
            )]
            pub vault: Account<'info, TokenAccount>,
            pub expected: UncheckedAccount<'info>,
        }
    "#,
        );

        let rule = MissingTokenOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn flags_mut_token_account_without_identity_constraint() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;
        use anchor_spl::token::TokenAccount;

        #[derive(Accounts)]
        pub struct Test<'info> {
            #[account(mut)]
            pub vault: Account<'info, TokenAccount>,
        }
    "#,
        );

        let rule = MissingTokenOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW010");
    }
}
