use crate::finding::SourceLocation;
use crate::instruction_analysis::{collect_instruction_index, CallKind};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingCpiReloadRule;

impl Rule for MissingCpiReloadRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW008",
            title: "Missing post-CPI account reload",
            severity: RuleSeverity::High,
            description: "Detects functions where account data is written after a CPI call without an intervening reload(), meaning the program may act on stale account state mutated by the callee.",
            fix_guidance: "Call account.reload()? after any CPI that may mutate accounts you read or write afterwards.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_instruction_index(&file.syntax);
        let mut findings = Vec::new();

        for function in &index.functions {
            let cpi_calls: Vec<_> = function
                .calls
                .iter()
                .filter(|c| c.kind == CallKind::Cpi)
                .collect();

            if cpi_calls.is_empty() {
                continue;
            }

            for cpi_call in cpi_calls {
                // Look for a write after this CPI with no reload between them.
                let has_write_after = function
                    .writes
                    .iter()
                    .any(|w| w.order > cpi_call.order);

                if !has_write_after {
                    continue;
                }

                // Check if a reload call exists between this CPI and the first subsequent write.
                let first_write_order = function
                    .writes
                    .iter()
                    .filter(|w| w.order > cpi_call.order)
                    .map(|w| w.order)
                    .min()
                    .unwrap_or(usize::MAX);

                let has_reload = function.calls.iter().any(|c| {
                    c.kind == CallKind::Reload
                        && c.order > cpi_call.order
                        && c.order < first_write_order
                });

                if !has_reload {
                    findings.push(RuleMatch {
                        rule_id: "SW008",
                        severity: RuleSeverity::High,
                        message: format!(
                            "Function `{}` writes to an account after a CPI call to `{}` without reloading; account data may be stale.",
                            function.name, cpi_call.callee
                        ),
                        location: SourceLocation {
                            path: file.path.display().to_string(),
                            line: cpi_call.span.start_line,
                            column: cpi_call.span.start_column,
                        },
                        help: Some(
                            "Call account.reload()? after the CPI to refresh account data before reading or writing."
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
    fn flags_write_after_cpi_without_reload() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke_signed(&ix, &accounts, &seeds)?;
                ctx.accounts.vault.balance = 100;
                Ok(())
            }
        "#);

        let rule = MissingCpiReloadRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW008");
    }

    #[test]
    fn does_not_flag_when_reload_between_cpi_and_write() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke_signed(&ix, &accounts, &seeds)?;
                ctx.accounts.vault.reload()?;
                ctx.accounts.vault.balance = 100;
                Ok(())
            }
        "#);

        let rule = MissingCpiReloadRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_cpi_with_no_subsequent_writes() {
        let file = parse_file(r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke_signed(&ix, &accounts, &seeds)?;
                Ok(())
            }
        "#);

        let rule = MissingCpiReloadRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }
}
