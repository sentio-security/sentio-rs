use crate::finding::SourceLocation;
use crate::instruction_analysis::{
    collect_instruction_index, CallEvidence, CallKind, WriteEvidence,
};
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
            // Exclude CpiContext builders — those are not invocations; the actual CPI
            // call (e.g. `token::transfer`) appears separately and carries the resolved
            // `cpi_account_names` from the builder's arguments.
            let cpi_calls: Vec<_> = function
                .calls
                .iter()
                .filter(|c| c.kind == CallKind::Cpi && !is_cpi_context_builder(&c.callee))
                .collect();

            if cpi_calls.is_empty() {
                continue;
            }

            // Report at most one finding per function (the first unguarded CPI with a
            // post-CPI write to an account that was part of that CPI).
            let first_unguarded = cpi_calls.iter().find(|cpi_call| {
                let has_write_after = function
                    .writes
                    .iter()
                    .any(|w| w.order > cpi_call.order && write_concerns_cpi_account(w, cpi_call));

                if !has_write_after {
                    return false;
                }

                let first_write_order = function
                    .writes
                    .iter()
                    .filter(|w| w.order > cpi_call.order && write_concerns_cpi_account(w, cpi_call))
                    .map(|w| w.order)
                    .min()
                    .unwrap_or(usize::MAX);

                !function.calls.iter().any(|c| {
                    c.kind == CallKind::Reload
                        && c.order > cpi_call.order
                        && c.order < first_write_order
                })
            });

            if let Some(cpi_call) = first_unguarded {
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

        findings
    }
}

fn is_cpi_context_builder(callee: &str) -> bool {
    callee.contains("CpiContext::new")
}

/// Returns true when `write` targets an account that was part of `cpi_call`.
///
/// If `cpi_account_names` is empty (raw invoke / unresolvable binding) we fall
/// back to flagging any field-access write (`target` contains `'.'`), which is
/// the conservative pre-cross-reference behaviour.
fn write_concerns_cpi_account(write: &WriteEvidence, cpi_call: &CallEvidence) -> bool {
    if cpi_call.cpi_account_names.is_empty() {
        return write.target.contains('.');
    }
    let account = extract_account_name_from_target(&write.target);
    !account.is_empty() && cpi_call.cpi_account_names.contains(&account)
}

/// Extract the account name from a write target string.
///
/// - `ctx.accounts.vault.amount`  → `"vault"`
/// - `vault.amount`               → `"vault"`
/// - plain identifier             → `""`  (not a field write, ignore)
fn extract_account_name_from_target(target: &str) -> String {
    if let Some(pos) = target.find(".accounts.") {
        let after = &target[pos + ".accounts.".len()..];
        return after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
    }
    if target.contains('.') {
        return target.split('.').next().unwrap_or("").to_string();
    }
    String::new()
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
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke_signed(&ix, &accounts, &seeds)?;
                ctx.accounts.vault.balance = 100;
                Ok(())
            }
        "#,
        );

        let rule = MissingCpiReloadRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW008");
    }

    #[test]
    fn does_not_flag_when_reload_between_cpi_and_write() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke_signed(&ix, &accounts, &seeds)?;
                ctx.accounts.vault.reload()?;
                ctx.accounts.vault.balance = 100;
                Ok(())
            }
        "#,
        );

        let rule = MissingCpiReloadRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_cpi_with_no_subsequent_writes() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke_signed(&ix, &accounts, &seeds)?;
                Ok(())
            }
        "#,
        );

        let rule = MissingCpiReloadRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
