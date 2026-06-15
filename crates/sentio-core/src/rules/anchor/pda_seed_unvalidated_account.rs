use crate::anchor_accounts::{
    collect_anchor_accounts_index, AnchorConstraintKind, AnchorFieldTypeKind,
};
use crate::finding::SourceLocation;
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

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
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

                    if unverified && !has_validation {
                        let pda_name =
                            pda_field.ast.name.clone().unwrap_or_default();
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
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Create<'info> {
                /// CHECK: used as seed
                pub user: AccountInfo<'info>,
                #[account(seeds = [b"vault", user.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }
        "#);
        let rule = PdaSeedUnvalidatedAccountRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW013");
        assert!(findings[0].message.contains("user"));
    }

    #[test]
    fn does_not_flag_pda_seeded_with_signer() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Create<'info> {
                pub authority: Signer<'info>,
                #[account(seeds = [b"vault", authority.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
            }
        "#);
        let rule = PdaSeedUnvalidatedAccountRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_pda_seeded_with_owner_constrained_account() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Create<'info> {
                #[account(owner = crate::ID)]
                pub user: AccountInfo<'info>,
                #[account(seeds = [b"vault", user.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }
        "#);
        let rule = PdaSeedUnvalidatedAccountRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_pda_with_only_literal_seeds() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Create<'info> {
                #[account(seeds = [b"global-config"], bump)]
                pub config: Account<'info, Config>,
                pub authority: Signer<'info>,
            }
        "#);
        let rule = PdaSeedUnvalidatedAccountRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }
}
