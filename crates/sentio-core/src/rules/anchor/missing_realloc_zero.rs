use crate::anchor_accounts::collect_anchor_accounts_index;
use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingReallocZeroRule;

impl Rule for MissingReallocZeroRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW018",
            title: "Missing realloc::zero = true",
            severity: RuleSeverity::Medium,
            description: "Detects realloc usage without realloc::zero = true. Without zeroing, reallocated memory may contain stale data readable by the program or attackers.",
            fix_guidance: "Add realloc::zero = true to your #[account(realloc = ..., realloc::zero = true, realloc_authority = ...)] constraint.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_anchor_accounts_index(&file.syntax);
        let mut findings = Vec::new();

        for item in index.structs {
            for field in item.fields {
                if field.constraints.realloc && !field.constraints.realloc_zero {
                    findings.push(RuleMatch {
                        rule_id: "SW018",
                        severity: RuleSeverity::Medium,
                        message: format!(
                            "Account `{}` uses `realloc` without `realloc::zero = true`; reallocated memory may contain stale data.",
                            field.ast.name.clone().unwrap_or_default()
                        ),
                        location: SourceLocation {
                            path: file.path.display().to_string(),
                            line: field.ast.span.start_line,
                            column: 1,
                        },
                        help: Some(
                            "Add realloc::zero = true to zero out reallocated memory and prevent data leaks."
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
    fn flags_realloc_without_zero() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(mut, realloc = 256, realloc_authority = authority)]
                pub data: Account<'info, Data>,
                pub authority: Signer<'info>,
            }
        "#,
        );

        let rule = MissingReallocZeroRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW018");
    }

    #[test]
    fn does_not_flag_realloc_with_zero() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(mut, realloc = 256, realloc::zero = true, realloc_authority = authority)]
                pub data: Account<'info, Data>,
                pub authority: Signer<'info>,
            }
        "#,
        );

        let rule = MissingReallocZeroRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_account_without_realloc() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(mut)]
                pub data: Account<'info, Data>,
            }
        "#,
        );

        let rule = MissingReallocZeroRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
