use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorFieldTypeKind};
use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct AccountInfoAsDataAccountRule;

impl Rule for AccountInfoAsDataAccountRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW011",
            title: "AccountInfo used as data account",
            severity: RuleSeverity::High,
            description: "Detects data-account-like fields declared as AccountInfo<'info> instead of a typed Account<'info, T> wrapper, which skips owner and discriminator validation.",
            fix_guidance: "Replace AccountInfo<'info> with Account<'info, T> for data accounts so Anchor enforces owner and discriminator checks automatically.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_anchor_accounts_index(&file.syntax);
        let mut findings = Vec::new();

        for item in index.structs {
            for field in item.fields {
                if field.type_info.kind != AnchorFieldTypeKind::AccountInfo {
                    continue;
                }

                let c = &field.constraints;
                let looks_like_data_account = c.init
                    || c.init_if_needed
                    || c.owner
                    || c.address
                    || !c.has_one.is_empty()
                    || c.has_seeds;

                if !looks_like_data_account {
                    continue;
                }

                findings.push(RuleMatch {
                    rule_id: "SW011",
                    severity: RuleSeverity::High,
                    message: format!(
                        "Account `{}` is typed as `AccountInfo` but has data-account constraints; use `Account<'info, T>` to enforce owner and discriminator checks.",
                        field.ast.name.clone().unwrap_or_default()
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: field.ast.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "Define a typed account struct and use Account<'info, YourStruct> so Anchor validates the owner program and discriminator on deserialization."
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
    fn flags_account_info_with_data_constraints() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(init, payer = authority, space = 8 + 32)]
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
        "#);

        let rule = AccountInfoAsDataAccountRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW011");
    }

    #[test]
    fn does_not_flag_typed_account() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(init, payer = authority, space = 8 + 32)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }
        "#);

        let rule = AccountInfoAsDataAccountRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_bare_account_info_without_data_constraints() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub clock: AccountInfo<'info>,
            }
        "#);

        let rule = AccountInfoAsDataAccountRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }
}
