use crate::finding::SourceLocation;
use crate::instruction_analysis::{collect_instruction_index, CallKind};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct ArbitraryCpiRule;

impl Rule for ArbitraryCpiRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW003",
            title: "Arbitrary CPI target",
            severity: RuleSeverity::Critical,
            description: "Detects CPI calls where no key or program ID check precedes the invocation, allowing an attacker to supply a malicious program as the CPI target.",
            fix_guidance: "Verify the target program key before invoking (e.g. require!(cpi_program.key() == expected::ID, ...)) or use Program<'info, T> so Anchor validates the program ID automatically.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_instruction_index(&file.syntax);
        let mut findings = Vec::new();

        for function in &index.functions {
            // Only flag raw invoke/invoke_signed — Anchor CpiContext calls are validated
            // at the account struct level via Program<'info, T> (covered by SW020).
            let cpi_calls: Vec<_> = function
                .calls
                .iter()
                .filter(|c| c.kind == CallKind::Cpi && is_raw_invoke(&c.callee))
                .collect();

            if cpi_calls.is_empty() {
                continue;
            }

            for cpi_call in cpi_calls {
                // Check if any key-referencing guard appears before this CPI call.
                let guarded = function
                    .guards
                    .iter()
                    .any(|g| g.references_key && g.order < cpi_call.order);

                if !guarded {
                    findings.push(RuleMatch {
                        rule_id: "SW003",
                        severity: RuleSeverity::Critical,
                        message: format!(
                            "CPI call `{}` in `{}` has no preceding program key validation.",
                            cpi_call.callee, function.name
                        ),
                        location: SourceLocation {
                            path: file.path.display().to_string(),
                            line: cpi_call.span.start_line,
                            column: cpi_call.span.start_column,
                        },
                        help: Some(
                            "Add require!(program.key() == expected::ID, ...) before the CPI, or use Program<'info, T> to enforce program ID validation at the account level."
                                .to_string(),
                        ),
                    });
                }
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
    fn flags_cpi_without_key_check() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke(
                    &instruction,
                    &[ctx.accounts.target_program.to_account_info()],
                )?;
                Ok(())
            }
        "#);

        let rule = ArbitraryCpiRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW003");
    }

    #[test]
    fn does_not_flag_cpi_with_key_check_before() {
        let file = parse_file(r#"
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
        "#);

        let rule = ArbitraryCpiRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_function_with_no_cpi() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                ctx.accounts.vault.balance = 100;
                Ok(())
            }
        "#);

        let rule = ArbitraryCpiRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }
}
