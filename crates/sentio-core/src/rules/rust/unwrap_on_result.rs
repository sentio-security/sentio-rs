use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, ItemFn};

#[derive(Debug, Default)]
pub struct UnwrapOnResultRule;

impl Rule for UnwrapOnResultRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW025",
            title: "unwrap() / expect() in instruction handler",
            severity: RuleSeverity::Medium,
            description: "Detects .unwrap() and .expect() calls in instruction handlers. \
                          In Solana programs these cause a runtime panic, which fails the \
                          transaction with a generic error and can be triggered by crafting \
                          inputs that produce None or Err, making it a potential DoS vector.",
            fix_guidance: "Replace .unwrap() with ? to propagate the error as an Anchor \
                           ErrorCode, or use .ok_or(ErrorCode::Foo)? to return a meaningful \
                           program error instead of panicking.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let mut collector = UnwrapCollector { findings: Vec::new(), in_test: false };
        visit::visit_file(&mut collector, &file.syntax);

        collector
            .findings
            .into_iter()
            .map(|(message, line, column)| RuleMatch {
                rule_id: "SW025",
                severity: RuleSeverity::Medium,
                message,
                location: SourceLocation {
                    path: file.path.display().to_string(),
                    line,
                    column,
                },
                help: Some(
                    "Use `?` to propagate errors or `.ok_or(ErrorCode::Foo)?` to convert \
                     Option to a typed program error."
                        .to_string(),
                ),
            })
            .collect()
    }
}

struct UnwrapCollector {
    findings: Vec<(String, usize, usize)>,
    in_test: bool,
}

impl<'ast> Visit<'ast> for UnwrapCollector {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        // Skip functions marked #[test] to avoid noise from test utilities.
        let was_in_test = self.in_test;
        if node.attrs.iter().any(|a| a.path().is_ident("test")) {
            self.in_test = true;
        }
        visit::visit_item_fn(self, node);
        self.in_test = was_in_test;
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if !self.in_test {
            let method = node.method.to_string();
            if method == "unwrap" || method == "expect" {
                let receiver = node.receiver.to_token_stream().to_string();
                let loc = node.span().start();
                self.findings.push((
                    format!(
                        "`.{method}()` on `{}` will panic on None/Err; use `?` or \
                         `.ok_or(ErrorCode::...)?` instead",
                        receiver.trim()
                    ),
                    loc.line,
                    loc.column + 1,
                ));
            }
        }
        visit::visit_expr_method_call(self, node);
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
    fn flags_unwrap_in_instruction() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, raw: &[u8]) -> Result<()> {
                let val: u64 = raw.try_into().unwrap();
                Ok(())
            }
            "#,
        );
        let rule = UnwrapOnResultRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW025");
    }

    #[test]
    fn flags_expect_in_instruction() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, amount: u64) -> Result<()> {
                let val = ctx.accounts.vault.amount.checked_add(amount).expect("overflow");
                Ok(())
            }
            "#,
        );
        let rule = UnwrapOnResultRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW025");
    }

    #[test]
    fn does_not_flag_unwrap_inside_test_fn() {
        let file = parse_file(
            r#"
            #[cfg(test)]
            mod tests {
                #[test]
                fn it_works() {
                    let x: Option<u64> = Some(1);
                    assert_eq!(x.unwrap(), 1);
                }
            }
            "#,
        );
        let rule = UnwrapOnResultRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_question_mark_propagation() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, amount: u64) -> Result<()> {
                let val = ctx.accounts.vault.amount
                    .checked_add(amount)
                    .ok_or(error!(ErrorCode::Overflow))?;
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { Overflow }
            "#,
        );
        let rule = UnwrapOnResultRule;
        let findings = rule.match_file(&file, &RuleContext { files: std::slice::from_ref(&file) });
        assert!(findings.is_empty());
    }
}
