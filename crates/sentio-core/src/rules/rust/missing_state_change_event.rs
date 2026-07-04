use crate::finding::SourceLocation;
use crate::instruction_analysis::collect_instruction_index;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingStateChangeEventRule;

impl Rule for MissingStateChangeEventRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW027",
            title: "Missing event emission on state change",
            severity: RuleSeverity::Low,
            description: "Detects instruction handlers that write to account state but never \
                          call emit!() to log a structured event. Without events, off-chain \
                          indexers, dashboards, and audit trails cannot observe state transitions, \
                          making incidents harder to detect and investigate.",
            fix_guidance: "Add emit!(MyEvent { field: value, ... }) after significant state \
                           changes. Define event structs with #[event] and include the accounts \
                           and values involved in the change.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_instruction_index(&file.syntax);
        let source_lines: Vec<&str> = file.source.lines().collect();
        let mut findings = Vec::new();

        for function in &index.functions {
            // Only flag functions that write to ctx.accounts.* (real state changes).
            let has_account_write = function
                .writes
                .iter()
                .any(|w| w.target.contains("ctx.accounts") || w.target.contains("accounts."));

            if !has_account_write {
                continue;
            }

            // Check if emit!() appears anywhere in the function body.
            let start = function.span.start_line.saturating_sub(1);
            let end = function.span.end_line.min(source_lines.len());
            let has_emit = source_lines[start..end]
                .iter()
                .any(|line| line.contains("emit!") || line.contains("emit_cpi!"));

            if !has_emit {
                findings.push(RuleMatch {
                    rule_id: "SW027",
                    severity: RuleSeverity::Low,
                    message: format!(
                        "Function `{}` writes to account state but emits no event; \
                         off-chain observers cannot track this state change.",
                        function.name
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: function.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "Add emit!(MyEvent { ... }) after state changes so indexers and \
                         dashboards can observe transitions."
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
    fn flags_state_change_without_emit() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn update(ctx: Context<Update>, new_val: u64) -> Result<()> {
                ctx.accounts.vault.value = new_val;
                Ok(())
            }
            "#,
        );
        let rule = MissingStateChangeEventRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW027");
    }

    #[test]
    fn does_not_flag_when_emit_present() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn update(ctx: Context<Update>, new_val: u64) -> Result<()> {
                ctx.accounts.vault.value = new_val;
                emit!(VaultUpdated { value: new_val });
                Ok(())
            }
            "#,
        );
        let rule = MissingStateChangeEventRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_read_only_function() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn read(ctx: Context<Read>) -> Result<u64> {
                Ok(ctx.accounts.vault.value)
            }
            "#,
        );
        let rule = MissingStateChangeEventRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }
}
