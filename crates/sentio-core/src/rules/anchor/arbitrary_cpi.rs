use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorFieldTypeKind};
use crate::finding::SourceLocation;
use crate::instruction_analysis::{collect_instruction_index, CallKind};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct ArbitraryCpiRule;

impl Rule for ArbitraryCpiRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW003",
            title: "Arbitrary CPI target",
            severity: RuleSeverity::Critical,
            description: "Detects CPI calls (invoke/invoke_signed) without prior program ID \
                validation. An attacker-supplied program can receive the transaction's signer \
                privileges (confused deputy): e.g. a marketplace CPI to a fake \"royalty\" \
                program that drains the buyer. Always validate program IDs or use \
                Program<'info, T> / an allowlist — never trust user-provided program addresses.",
            fix_guidance: "require!(program.key() == expected::ID, ...) or Program<'info, T> \
                before CPI. Prefer allowlists for optional external programs (royalties, hooks). \
                Never pass a Signer into a CPI whose program account is unvalidated.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_instruction_index(&file.syntax);
        let accounts = collect_anchor_accounts_index(&file.syntax);
        // Same-file Signers (unit tests / co-located Accounts).
        let local_signers = collect_signer_field_names(&accounts);
        let mut findings = Vec::new();

        for function in &index.functions {
            let cpi_calls: Vec<_> = function
                .calls
                .iter()
                .filter(|c| c.kind == CallKind::Cpi && is_raw_invoke(&c.callee))
                .collect();

            if cpi_calls.is_empty() {
                continue;
            }

            // Union local Signers with Accounts struct from other files via Context<T>.
            let mut signer_fields = local_signers.clone();
            if let Some(ref accounts_name) = function.accounts_struct {
                for name in ctx.global.signer_field_names_for(accounts_name) {
                    signer_fields.insert(name);
                }
            }

            for cpi_call in cpi_calls {
                if has_program_validation_before(function, cpi_call.order) {
                    continue;
                }

                let delegated_signers: Vec<&String> = cpi_call
                    .cpi_account_names
                    .iter()
                    .filter(|name| signer_fields.iter().any(|s| s.eq_ignore_ascii_case(name)))
                    .collect();

                let (message, help) = if !delegated_signers.is_empty() {
                    let names = delegated_signers
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    (
                        format!(
                            "CPI `{}` in `{}` has no program ID check and passes signer \
                             privilege(s) (`{names}`) into the callee — classic confused-deputy: \
                             a malicious program can act with those signers (e.g. extra transfers).",
                            cpi_call.callee, function.name
                        ),
                        "Validate the CPI program ID (require! / Program<'info, T> / allowlist) \
                         before invoke. Do not forward buyer/authority Signers to untrusted programs."
                            .to_string(),
                    )
                } else {
                    (
                        format!(
                            "CPI call `{}` in `{}` has no preceding program key validation; \
                             an attacker can supply a malicious CPI target.",
                            cpi_call.callee, function.name
                        ),
                        "Add require!(program.key() == expected::ID, ...) before the CPI, use \
                         Program<'info, T>, or an allowlist for external programs (royalties, hooks)."
                            .to_string(),
                    )
                };

                findings.push(RuleMatch {
                    rule_id: "SW003",
                    severity: RuleSeverity::Critical,
                    message,
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: cpi_call.span.start_line,
                        column: cpi_call.span.start_column,
                    },
                    help: Some(help),
                });
            }
        }

        findings
    }
}

fn is_raw_invoke(callee: &str) -> bool {
    let n = callee.trim();
    n == "invoke"
        || n == "invoke_signed"
        || n == "invoke_unchecked"
        || n.ends_with("::invoke")
        || n.ends_with("::invoke_signed")
        || n.ends_with("::invoke_unchecked")
}

fn has_program_validation_before(
    function: &crate::instruction_analysis::InstructionFunction,
    cpi_order: usize,
) -> bool {
    function.guards.iter().any(|g| {
        g.order < cpi_order
            && (g.references_key || guard_looks_like_program_allowlist(&g.expression))
    })
}

/// Broader than bare `.key()` — allowlist / program_id / ::ID comparisons in require!/if.
fn guard_looks_like_program_allowlist(expression: &str) -> bool {
    let compact: String = expression
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    compact.contains("program_id")
        || compact.contains("::id")
        || compact.contains("allowlist")
        || compact.contains("allowed_program")
        || compact.contains("approved_program")
        || (compact.contains("program") && compact.contains("key()") && compact.contains("=="))
}

fn collect_signer_field_names(
    accounts: &crate::anchor_accounts::AnchorAccountsIndex,
) -> HashSet<String> {
    let mut names = HashSet::new();
    for item in &accounts.structs {
        for field in &item.fields {
            let Some(name) = field.ast.name.clone() else {
                continue;
            };
            let is_signer_type = field.type_info.kind == AnchorFieldTypeKind::Signer;
            let has_signer_constraint = field.constraints.is_signer;
            if is_signer_type || has_signer_constraint {
                names.insert(name);
            }
        }
    }
    names
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

    fn run(file: &ParsedFile) -> Vec<RuleMatch> {
        ArbitraryCpiRule.match_file(file, &RuleContext::files_only(std::slice::from_ref(file)))
    }

    #[test]
    fn flags_cpi_without_key_check() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke(
                    &instruction,
                    &[ctx.accounts.target_program.to_account_info()],
                )?;
                Ok(())
            }
        "#,
        );
        let findings = run(&file);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW003");
    }

    #[test]
    fn does_not_flag_cpi_with_key_check_before() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                require!(
                    ctx.accounts.target_program.key() == &expected_program::ID,
                    ErrorCode::InvalidProgram
                );
                invoke(
                    &instruction,
                    &[ctx.accounts.target_program.to_account_info()],
                )?;
                Ok(())
            }
        "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn does_not_flag_function_with_no_cpi() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                ctx.accounts.vault.balance = 100;
                Ok(())
            }
        "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn flags_confused_deputy_signer_passed_to_unvalidated_program() {
        // Marketplace-style: CPI to user-supplied royalty program with buyer as signer.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct Buy<'info> {
                pub buyer: Signer<'info>,
                /// CHECK: supposed royalty program — unvalidated
                pub royalty_program: AccountInfo<'info>,
                #[account(mut)]
                pub buyer_token: AccountInfo<'info>,
            }

            pub fn buy(ctx: Context<Buy>) -> Result<()> {
                let ix = solana_program::instruction::Instruction {
                    program_id: *ctx.accounts.royalty_program.key,
                    accounts: vec![],
                    data: vec![],
                };
                invoke(
                    &ix,
                    &[
                        ctx.accounts.buyer.to_account_info(),
                        ctx.accounts.buyer_token.to_account_info(),
                        ctx.accounts.royalty_program.to_account_info(),
                    ],
                )?;
                Ok(())
            }
        "#,
        );
        let findings = run(&file);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.to_lowercase().contains("signer")
                || findings[0].message.to_lowercase().contains("confused"),
            "expected confused-deputy messaging: {}",
            findings[0].message
        );
    }

    #[test]
    fn does_not_flag_when_program_validated_even_with_signer_in_metas() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct Buy<'info> {
                pub buyer: Signer<'info>,
                pub royalty_program: AccountInfo<'info>,
            }

            pub fn buy(ctx: Context<Buy>) -> Result<()> {
                require_keys_eq!(*ctx.accounts.royalty_program.key, royalty::ID);
                invoke(
                    &ix,
                    &[
                        ctx.accounts.buyer.to_account_info(),
                        ctx.accounts.royalty_program.to_account_info(),
                    ],
                )?;
                Ok(())
            }
        "#,
        );
        assert!(
            run(&file).is_empty(),
            "validated program ID must clear SW003 even with signer in metas: {:?}",
            run(&file)
        );
    }

    #[test]
    fn confused_deputy_when_signer_on_accounts_in_other_file() {
        use crate::global_index::GlobalIndex;

        let accounts = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Buy<'info> {
                pub buyer: Signer<'info>,
                /// CHECK: supposed royalty program — unvalidated
                pub royalty_program: AccountInfo<'info>,
            }
            "#,
        );
        let handler = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            pub fn buy(ctx: Context<Buy>) -> Result<()> {
                invoke(
                    &ix,
                    &[
                        ctx.accounts.buyer.to_account_info(),
                        ctx.accounts.royalty_program.to_account_info(),
                    ],
                )?;
                Ok(())
            }
            "#,
        );

        let global = GlobalIndex::from_syn_files(&[&accounts.syntax, &handler.syntax]);
        let files = [accounts, handler];
        let ctx = RuleContext::new(&files, &global);

        let findings = ArbitraryCpiRule.match_file(&files[1], &ctx);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.to_lowercase().contains("signer")
                || findings[0].message.to_lowercase().contains("confused"),
            "cross-file Signer must upgrade to confused-deputy: {}",
            findings[0].message
        );
    }
}
