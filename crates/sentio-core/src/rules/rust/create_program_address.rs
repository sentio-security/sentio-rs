use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::ExprCall;
use quote::ToTokens;

#[derive(Debug, Default)]
pub struct CreateProgramAddressRule;

impl Rule for CreateProgramAddressRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW026",
            title: "create_program_address used instead of find_program_address",
            severity: RuleSeverity::High,
            description: "Detects use of create_program_address, which accepts a caller-supplied \
                          bump and does not verify it is canonical. An attacker can provide a \
                          non-canonical bump to derive a different valid PDA, bypassing address \
                          derivation assumptions. find_program_address always returns the \
                          canonical (highest valid) bump.",
            fix_guidance: "Use Pubkey::find_program_address to derive canonical PDAs, or in \
                           Anchor use the seeds + bump constraint which enforces canonicality \
                           automatically.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let mut collector = CreateProgramAddressCollector { findings: Vec::new() };
        visit::visit_file(&mut collector, &file.syntax);

        collector
            .findings
            .into_iter()
            .map(|(message, line, column)| RuleMatch {
                rule_id: "SW026",
                severity: RuleSeverity::High,
                message,
                location: SourceLocation {
                    path: file.path.display().to_string(),
                    line,
                    column,
                },
                help: Some(
                    "Replace with Pubkey::find_program_address(&seeds, program_id) which \
                     returns the canonical bump, or use Anchor's seeds + bump constraint."
                        .to_string(),
                ),
            })
            .collect()
    }
}

struct CreateProgramAddressCollector {
    findings: Vec<(String, usize, usize)>,
}

impl<'ast> Visit<'ast> for CreateProgramAddressCollector {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let callee = node.func.to_token_stream().to_string().replace(' ', "");
        if callee.contains("create_program_address") {
            let loc = node.span().start();
            self.findings.push((
                "create_program_address accepts a caller-supplied bump and does not enforce \
                 canonical derivation; use find_program_address instead"
                    .to_string(),
                loc.line,
                loc.column + 1,
            ));
        }
        visit::visit_expr_call(self, node);
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
    fn flags_create_program_address() {
        let file = parse_file(
            r#"
            use solana_program::pubkey::Pubkey;
            pub fn derive(seeds: &[&[u8]], program_id: &Pubkey, bump: u8) -> Pubkey {
                let seeds_with_bump: Vec<&[u8]> = seeds.iter().copied()
                    .chain(std::iter::once(&[bump][..]))
                    .collect();
                Pubkey::create_program_address(&seeds_with_bump, program_id).unwrap()
            }
            "#,
        );
        let rule = CreateProgramAddressRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW026");
    }

    #[test]
    fn does_not_flag_find_program_address() {
        let file = parse_file(
            r#"
            use solana_program::pubkey::Pubkey;
            pub fn derive(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
                Pubkey::find_program_address(seeds, program_id)
            }
            "#,
        );
        let rule = CreateProgramAddressRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }
}
