use crate::anchor_accounts::collect_anchor_accounts_index;
use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingPdaSeedsBumpRule;

impl Rule for MissingPdaSeedsBumpRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW012",
            title: "Missing seeds + bump on PDA",
            severity: RuleSeverity::High,
            description:
                "Detects PDA-like account field constraints that do not include both seeds and bump.",
            fix_guidance:
                "For PDA accounts, use #[account(seeds = [...], bump)] or bump = <expr> and keep derivation tied to trusted inputs.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_anchor_accounts_index(&file.syntax);
        let mut findings = Vec::new();

        for item in index.structs {
            for field in item.fields {
                let has_seeds = field.constraints.has_seeds;
                let has_bump = field.constraints.has_bump;

                if !has_seeds && !has_bump {
                    continue;
                }

                if has_seeds && has_bump {
                    continue;
                }

                let line = field.ast.span.start_line;
                findings.push(RuleMatch {
                    rule_id: "SW012",
                    severity: RuleSeverity::High,
                    message: format!(
                        "PDA-like account constraint on `{}` is missing either `seeds` or `bump`.",
                        field.ast.name.clone().unwrap_or_default()
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line,
                        column: 1,
                    },
                    help: Some(
                        "Use #[account(seeds = [...], bump)] (or bump = <expr>) for PDA fields."
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
    fn flags_pda_without_bump() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(seeds = [b"vault"])]
                pub vault: Account<'info, Vault>,
            }
            "#,
        );

        let rule = MissingPdaSeedsBumpRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW012");
    }

    #[test]
    fn does_not_flag_when_seeds_and_bump_exist() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(seeds = [b"vault"], bump)]
                pub vault: Account<'info, Vault>,
            }
            "#,
        );

        let rule = MissingPdaSeedsBumpRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }
}
