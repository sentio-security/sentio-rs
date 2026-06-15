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
            severity: RuleSeverity::High,
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
                if field.constraints.token_authority
                    || field.constraints.address
                    || field.constraints.init
                    || field.constraints.init_if_needed
                    || has_associated_token(field)
                    || has_authority_has_one(field)
                {
                    continue;
                }

                let name = field.ast.name.clone().unwrap_or_default();
                findings.push(RuleMatch {
                    rule_id: "SW010",
                    severity: RuleSeverity::High,
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

fn has_associated_token(field: &AnchorAccountsField) -> bool {
    field
        .constraints
        .items
        .iter()
        .any(|c| c.path.starts_with("associated_token"))
}

/// `has_one = authority` on a TokenAccount field validates the authority sub-field
/// of the on-chain token account data, which counts as an owner check.
fn has_authority_has_one(field: &AnchorAccountsField) -> bool {
    field.constraints.has_one.iter().any(|v| {
        let lower = v.to_lowercase();
        lower.contains("authority") || lower.contains("owner")
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
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
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
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
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
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
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
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
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
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
