use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorFieldTypeKind};
use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct AccountInfoAsCpiProgramRule;

impl Rule for AccountInfoAsCpiProgramRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW020",
            title: "AccountInfo used as CPI target program",
            severity: RuleSeverity::Critical,
            description: "Detects CPI target program fields typed as AccountInfo<'info> instead of Program<'info, T>, which skips program ID validation and allows an attacker to substitute any program.",
            fix_guidance: "Use Program<'info, T> (e.g. Program<'info, Token>) so Anchor validates the executable flag and program ID. For unknown programs use UncheckedAccount with a /// CHECK: comment and a manual key check.",
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

                let name = field.ast.name.as_deref().unwrap_or("").to_lowercase();
                if !name.contains("program") {
                    continue;
                }

                // Skip if it already has data-account constraints — that's SW011's domain.
                let c = &field.constraints;
                let is_data_account = c.init
                    || c.init_if_needed
                    || c.owner
                    || c.address
                    || !c.has_one.is_empty()
                    || c.has_seeds;

                if is_data_account {
                    continue;
                }

                findings.push(RuleMatch {
                    rule_id: "SW020",
                    severity: RuleSeverity::Critical,
                    message: format!(
                        "CPI target program `{}` is typed as `AccountInfo`; an attacker can pass any program in its place.",
                        field.ast.name.clone().unwrap_or_default()
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: field.ast.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "Use Program<'info, T> to let Anchor verify the program ID and executable flag automatically."
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
    fn flags_account_info_named_program() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub token_program: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
        "#,
        );

        let rule = AccountInfoAsCpiProgramRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW020");
    }

    #[test]
    fn does_not_flag_typed_program() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub token_program: Program<'info, Token>,
                pub authority: Signer<'info>,
            }
        "#,
        );

        let rule = AccountInfoAsCpiProgramRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_account_info_without_program_in_name() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub clock: AccountInfo<'info>,
            }
        "#,
        );

        let rule = AccountInfoAsCpiProgramRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
