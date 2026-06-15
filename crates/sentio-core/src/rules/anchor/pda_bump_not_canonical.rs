use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorConstraintKind};
use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct PdaBumpNotCanonicalRule;

impl Rule for PdaBumpNotCanonicalRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW014",
            title: "PDA bump may not be canonical",
            severity: RuleSeverity::Medium,
            description: "Detects PDA accounts where the bump constraint is set to an explicit \
                bare identifier rather than a stored field (e.g. account.bump). A user-supplied \
                or re-derived bump may not be the canonical bump, opening a second-preimage \
                attack where an attacker finds an alternate valid bump.",
            fix_guidance: "Store the canonical bump in the account on init \
                (#[account(init, seeds = [...], bump)]) and reuse it with \
                bump = account.bump on subsequent instructions.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_anchor_accounts_index(&file.syntax);
        let mut findings = Vec::new();

        for item in &index.structs {
            for field in &item.fields {
                if !field.constraints.has_seeds || !field.constraints.has_bump {
                    continue;
                }

                let bump_constraint = match field
                    .constraints
                    .items
                    .iter()
                    .find(|c| c.kind == AnchorConstraintKind::Bump)
                {
                    Some(c) => c,
                    None => continue,
                };

                // `bump` alone (no value) means Anchor derives the canonical bump — safe.
                let bump_value = match bump_constraint.value.as_deref() {
                    Some(v) => v,
                    None => continue,
                };

                let compact = bump_value.split_whitespace().collect::<String>();

                // `bump = account.field` is safe — the dot means it's reading a stored value.
                if compact.contains('.') {
                    continue;
                }

                let field_name = field.ast.name.clone().unwrap_or_default();
                findings.push(RuleMatch {
                    rule_id: "SW014",
                    severity: RuleSeverity::Medium,
                    message: format!(
                        "PDA `{field_name}` uses `bump = {compact}` — verify `{compact}` is \
                        the canonical bump stored on-chain rather than a user-supplied value"
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: field.ast.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "On init, let Anchor derive the canonical bump with just `bump` (no \
                        value). Store it in the account and reuse it with `bump = account.bump` \
                        on every subsequent instruction."
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
    use std::path::PathBuf;

    fn parse_file(source: &str) -> ParsedFile {
        ParsedFile {
            path: PathBuf::from("src/lib.rs"),
            source: source.to_string(),
            syntax: syn::parse_file(source).expect("source should parse"),
        }
    }

    #[test]
    fn flags_bump_set_to_bare_identifier() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct UseVault<'info> {
                #[account(seeds = [b"vault"], bump = bump_seed)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }
        "#);
        let rule = PdaBumpNotCanonicalRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW014");
        assert!(findings[0].message.contains("bump_seed"));
    }

    #[test]
    fn does_not_flag_bare_bump_anchor_derives_canonical() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct UseVault<'info> {
                #[account(seeds = [b"vault"], bump)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }
        "#);
        let rule = PdaBumpNotCanonicalRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_bump_read_from_stored_field() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct UseVault<'info> {
                #[account(seeds = [b"vault"], bump = vault.bump)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }
        "#);
        let rule = PdaBumpNotCanonicalRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_init_without_explicit_bump() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct CreateVault<'info> {
                #[account(init, seeds = [b"vault"], bump, payer = authority, space = 64)]
                pub vault: Account<'info, Vault>,
                #[account(mut)]
                pub authority: Signer<'info>,
                pub system_program: Program<'info, System>,
            }
        "#);
        let rule = PdaBumpNotCanonicalRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }
}
