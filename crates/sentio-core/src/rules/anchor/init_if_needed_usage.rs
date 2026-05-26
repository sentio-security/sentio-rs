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
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
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
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }
}
