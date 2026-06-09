use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorFieldTypeKind};
use crate::finding::SourceLocation;
use crate::instruction_analysis::collect_instruction_index;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingOwnerCheckRule;

impl Rule for MissingOwnerCheckRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW002",
            title: "Missing owner check",
            severity: RuleSeverity::Critical,
            description: "Detects AccountInfo or UncheckedAccount fields with no owner or address constraint and no owner guard in instruction logic, allowing an attacker to pass an account owned by any program.",
            fix_guidance: "Add an owner constraint (#[account(owner = expected_program::ID)]) or an address constraint, or validate account.owner in your instruction handler.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let accounts_index = collect_anchor_accounts_index(&file.syntax);
        let instruction_index = collect_instruction_index(&file.syntax);
        let mut findings = Vec::new();

        // Build a set of field names that have an owner guard in any instruction function.
        let guarded_names: Vec<String> = instruction_index
            .functions
            .iter()
            .flat_map(|f| f.guards.iter())
            .filter(|g| g.references_owner)
            .flat_map(|g| {
                // Extract word tokens from the expression that could be field names.
                g.expression
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .collect();

        for item in accounts_index.structs {
            for field in item.fields {
                let kind = &field.type_info.kind;

                // Only target AccountInfo and UncheckedAccount.
                if *kind != AnchorFieldTypeKind::AccountInfo
                    && *kind != AnchorFieldTypeKind::UncheckedAccount
                {
                    continue;
                }

                let field_name = field.ast.name.as_deref().unwrap_or("").to_string();
                let c = &field.constraints;

                // Skip if the constraint layer already enforces owner/address.
                if c.owner || c.address {
                    continue;
                }

                // Skip data-account fields (SW011) and program-named fields (SW020).
                let is_data_account =
                    c.init || c.init_if_needed || !c.has_one.is_empty() || c.has_seeds;
                let is_program_field = field_name.to_lowercase().contains("program");

                if is_data_account || is_program_field {
                    continue;
                }

                // Check if any instruction guard references owner AND names this field.
                let has_owner_guard = guarded_names.iter().any(|token| token == &field_name);

                if !has_owner_guard {
                    findings.push(RuleMatch {
                        rule_id: "SW002",
                        severity: RuleSeverity::Critical,
                        message: format!(
                            "Account `{field_name}` has no owner constraint and no owner guard in instruction logic; any program-owned account can be passed.",
                        ),
                        location: SourceLocation {
                            path: file.path.display().to_string(),
                            line: field.ast.span.start_line,
                            column: 1,
                        },
                        help: Some(
                            "Add #[account(owner = expected_program::ID)] or verify account.owner explicitly in the instruction handler."
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
    fn flags_account_info_without_owner_check() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                let data = ctx.accounts.vault.try_borrow_data()?;
                Ok(())
            }
        "#);

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW002");
    }

    #[test]
    fn does_not_flag_when_owner_constraint_present() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(owner = token::ID)]
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
        "#);

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_when_owner_guard_in_instruction() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                require!(
                    ctx.accounts.vault.owner == &token::ID,
                    ErrorCode::InvalidOwner
                );
                Ok(())
            }
        "#);

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_address_constrained_account() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(address = some_known::ID)]
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
        "#);

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }
}
