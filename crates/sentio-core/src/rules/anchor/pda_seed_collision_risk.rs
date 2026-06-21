use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorConstraintKind};
use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use syn::{Expr, ExprArray};

#[derive(Debug, Default)]
pub struct PdaSeedCollisionRiskRule;

impl Rule for PdaSeedCollisionRiskRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW021",
            title: "PDA seed collision risk",
            severity: RuleSeverity::High,
            description: "Detects `seeds = [...]` arrays where two or more adjacent elements \
                are both variable-length (e.g. `name.as_bytes()` next to `symbol.as_bytes()`) \
                with no fixed-length seed between them. find_program_address hashes seeds as \
                concatenated bytes with no boundary markers, so distinct inputs such as \
                (\"ab\", \"cd\") and (\"a\", \"bcd\") can derive the same PDA, letting an \
                attacker collide two logically different accounts onto one address.",
            fix_guidance: "Insert a fixed-length seed (a byte literal, or `.key().as_ref()`) \
                between adjacent variable-length seeds, or length-prefix variable seeds before \
                hashing, e.g. `&(name.len() as u32).to_le_bytes()`.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_anchor_accounts_index(&file.syntax);
        let mut findings = Vec::new();

        for item in &index.structs {
            for field in &item.fields {
                if !field.constraints.has_seeds {
                    continue;
                }

                let Some(seeds_constraint) = field
                    .constraints
                    .items
                    .iter()
                    .find(|c| c.kind == AnchorConstraintKind::Seeds)
                else {
                    continue;
                };

                let Some(raw) = seeds_constraint.value.as_deref() else {
                    continue;
                };

                let Ok(Expr::Array(array)) = syn::parse_str::<Expr>(raw) else {
                    continue;
                };

                let Some((left, right)) = adjacent_variable_seeds(&array) else {
                    continue;
                };
                let (left, right) = (compact(&left), compact(&right));

                let field_name = field.ast.name.clone().unwrap_or_default();
                findings.push(RuleMatch {
                    rule_id: "SW021",
                    severity: RuleSeverity::High,
                    message: format!(
                        "PDA `{field_name}` has adjacent variable-length seeds `{left}` and \
                        `{right}` with no fixed-length seed between them; different inputs can \
                        hash to the same PDA"
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: field.ast.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "Insert a fixed-length separator seed between them, or length-prefix \
                        the variable-length values before passing them as seeds."
                            .to_string(),
                    ),
                });
            }
        }

        findings
    }
}

fn adjacent_variable_seeds(array: &ExprArray) -> Option<(String, String)> {
    let elems: Vec<&Expr> = array.elems.iter().collect();
    elems.windows(2).find_map(|window| {
        let (left, right) = (window[0], window[1]);
        if is_variable_length_seed(left) && is_variable_length_seed(right) {
            Some((expr_to_string(left), expr_to_string(right)))
        } else {
            None
        }
    })
}

fn is_variable_length_seed(expr: &Expr) -> bool {
    let text = expr_to_string(expr).replace(' ', "");

    // Fixed-length seeds: byte string literals, Pubkeys, and numeric byte encodings.
    if text.starts_with("b\"")
        || text.ends_with(".key().as_ref()")
        || text.ends_with(".key()")
        || text.ends_with(".to_le_bytes()")
        || text.ends_with(".to_be_bytes()")
        || text.ends_with(".to_ne_bytes()")
    {
        return false;
    }

    // Variable-length seeds: string/byte-slice conversions with no fixed size.
    text.ends_with(".as_bytes()") || text.ends_with(".as_slice()") || text.ends_with(".as_ref()")
}

fn expr_to_string(expr: &Expr) -> String {
    expr.to_token_stream().to_string()
}

fn compact(text: &str) -> String {
    text.split_whitespace().collect()
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
    fn flags_adjacent_variable_length_seeds() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct CreatePool<'info> {
                #[account(seeds = [name.as_bytes(), symbol.as_bytes()], bump)]
                pub pool: Account<'info, Pool>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = PdaSeedCollisionRiskRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW021");
        assert!(findings[0].message.contains("name.as_bytes()"));
    }

    #[test]
    fn does_not_flag_fixed_seed_between_variable_seeds() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct CreatePool<'info> {
                #[account(seeds = [name.as_bytes(), b"::", symbol.as_bytes()], bump)]
                pub pool: Account<'info, Pool>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = PdaSeedCollisionRiskRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_single_variable_seed_with_pubkey() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct UseVault<'info> {
                #[account(seeds = [b"vault", authority.key().as_ref(), name.as_bytes()], bump)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = PdaSeedCollisionRiskRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
