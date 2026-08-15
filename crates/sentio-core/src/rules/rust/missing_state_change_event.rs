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
                          call emit!()/emit_cpi!() or msg!() to expose the change. Without \
                          events or program logs, off-chain indexers and audit trails cannot \
                          observe state transitions. (Sentio is AST-based: it does not model \
                          ZK proofs or external indexers.)",
            fix_guidance: "Add emit!(MyEvent { ... }) after significant state changes, or a \
                           structured msg!(\"...\") log that indexers can parse (common outside \
                           Anchor event style).",
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

            // Observability sinks: Anchor events or program logs (msg!) that many
            // Solana programs / indexers use instead of emit!.
            let start = function.span.start_line.saturating_sub(1);
            let end = function.span.end_line.min(source_lines.len());
            let has_observability = source_lines[start..end].iter().any(|line| {
                let t = line.trim_start();
                // Ignore commented-out sinks.
                if t.starts_with("//") {
                    return false;
                }
                line.contains("emit!") || line.contains("emit_cpi!") || line.contains("msg!")
            });

            if !has_observability {
                findings.push(RuleMatch {
                    rule_id: "SW027",
                    severity: RuleSeverity::Low,
                    message: format!(
                        "Function `{}` writes to account state but has no emit!() or msg!(); \
                         off-chain observers cannot track this state change.",
                        function.name
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: function.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "Add emit!(MyEvent { ... }) or a structured msg!(\"...\") after state \
                         changes so indexers and dashboards can observe transitions."
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
        let findings = rule.match_file(
            &file,
            &RuleContext::files_only(std::slice::from_ref(&file)),
        );
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
        let findings = rule.match_file(
            &file,
            &RuleContext::files_only(std::slice::from_ref(&file)),
        );
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
        let findings = rule.match_file(
            &file,
            &RuleContext::files_only(std::slice::from_ref(&file)),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_when_msg_present() {
        // FP: many programs (incl. SPL-style) use structured msg! for indexers.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn init_vault(ctx: Context<InitVault>) -> Result<()> {
                ctx.accounts.vault.bump = ctx.bumps.vault;
                msg!("conf-vault-init:{}", ctx.accounts.vault.key());
                Ok(())
            }
            "#,
        );
        let rule = MissingStateChangeEventRule;
        let findings = rule.match_file(
            &file,
            &RuleContext::files_only(std::slice::from_ref(&file)),
        );
        assert!(
            findings.is_empty(),
            "msg! should count as observability: {findings:?}"
        );
    }
}
