use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprMethodCall, ImplItemFn, ItemFn, Local, Pat};

#[derive(Debug, Default)]
pub struct CpiRemainingAccountsRule;

impl Rule for CpiRemainingAccountsRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW023",
            title: "Unvalidated remaining_accounts forwarded to CPI",
            severity: RuleSeverity::Critical,
            description: "Detects instruction handlers that forward ctx.remaining_accounts into a \
                          CPI call. Accounts in remaining_accounts are not declared in the Accounts \
                          struct so they carry no type, owner, or signer constraints. Any account \
                          that was a signer in the outer transaction retains that signer privilege \
                          inside the CPI, letting an attacker escalate privileges by supplying \
                          unexpected signers.",
            fix_guidance: "Declare every account needed by the CPI in the Accounts struct with \
                           explicit constraints (Program<'info, T>, Signer<'info>, owner, address). \
                           If remaining_accounts is unavoidable, validate each account's owner, \
                           key, and signer status before passing it to the CPI.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
         let mut scanner = ForwardScanner {
            path: file.path.display().to_string(),
            findings: Vec::new(),
        };
        visit::visit_file(&mut scanner, &file.syntax);
        scanner.findings
    }
}
struct ForwardScanner {
    path: String,
    findings: Vec<RuleMatch>,
}

impl ForwardScanner {
    fn push_finding(&mut self, function: &str, span: proc_macro2::Span) {
        let loc = span.start();
        self.findings.push(RuleMatch {
            rule_id: "SW023",
            severity: RuleSeverity::Critical,
            message: format!(
                "Function `{function}` forwards `remaining_accounts` into a CPI; unvalidated \
                 accounts retain outer-transaction signer privileges inside the call."
            ),
            location: SourceLocation {
                path: self.path.clone(),
                line: loc.line,
                column: loc.column + 1,
            },
            help: Some(
                "Declare CPI accounts explicitly in the Accounts struct with typed \
                 constraints. If remaining_accounts is required, validate each account's \
                 owner, key, and is_signer before forwarding it."
                    .to_string(),
            ),
        });
    }
}

impl<'ast> Visit<'ast> for ForwardScanner {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if let Some(span) = forwarding_span(&node.block) {
            self.push_finding(&node.sig.ident.to_string(), span);
        }
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if let Some(span) = forwarding_span(&node.block) {
            self.push_finding(&node.sig.ident.to_string(), span);
        }
        visit::visit_impl_item_fn(self, node);
    }
}

/// First CPI in this body whose arguments carry `remaining_accounts`.
/// Nested functions are visited on their own by `ForwardScanner`.
fn forwarding_span(block: &syn::Block) -> Option<proc_macro2::Span> {
    let mut finder = ForwardFinder {
        tainted: HashSet::new(),
        forwarded: None,
    };
    finder.visit_block(block);
    finder.forwarded
}

struct ForwardFinder {
    tainted: HashSet<String>,
    forwarded: Option<proc_macro2::Span>,
}

impl<'ast> Visit<'ast> for ForwardFinder {
    fn visit_item_fn(&mut self, _node: &'ast ItemFn) {}
    fn visit_impl_item_fn(&mut self, _node: &'ast ImplItemFn) {}

    fn visit_local(&mut self, node: &'ast Local) {
        visit::visit_local(self, node);
        let Some(name) = simple_pat_ident(&node.pat) else {
            return;
        };
        if node
            .init
            .as_ref()
            .is_some_and(|init| expr_carries_remaining(&init.expr, &self.tainted))
        {
            self.tainted.insert(name);
        }
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        visit::visit_expr_assign(self, node);
        if expr_carries_remaining(&node.right, &self.tainted) {
            if let Some(name) = expr_path_ident(&node.left) {
                self.tainted.insert(name);
            }
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        visit::visit_expr_method_call(self, node);
        // `accounts.extend_from_slice(ctx.remaining_accounts)` taints `accounts`.
        let mixes = matches!(
            node.method.to_string().as_str(),
            "extend" | "extend_from_slice" | "append" | "push" | "clone_from"
        );
        if mixes
            && node
                .args
                .iter()
                .any(|arg| expr_carries_remaining(arg, &self.tainted))
        {
            if let Some(name) = expr_path_ident(&node.receiver) {
                self.tainted.insert(name);
            }
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        visit::visit_expr_call(self, node);
        if self.forwarded.is_some() {
            return;
        }
        let callee = node
            .func
            .to_token_stream()
            .to_string()
            .split_whitespace()
            .collect::<String>();
        if is_cpi_callee(&callee)
            && node
                .args
                .iter()
                .any(|arg| expr_carries_remaining(arg, &self.tainted))
        {
            self.forwarded = Some(node.span());
        }
    }
}

/// Same CPI names as `instruction_analysis::classify_call_kind`.
fn is_cpi_callee(callee: &str) -> bool {
    let lower = callee.to_lowercase();
    callee == "invoke"
        || callee == "invoke_signed"
        || callee.ends_with("::invoke")
        || callee.ends_with("::invoke_signed")
        || callee.contains("CpiContext::new")
        || callee.contains("CpiContext::new_with_signer")
        || callee.starts_with("token::")
        || callee.contains("anchor_spl::token::")
        || lower.contains("cpicontext::new")
}

fn simple_pat_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(p) => Some(p.ident.to_string()),
        Pat::Type(p) => simple_pat_ident(&p.pat),
        _ => None,
    }
}

fn expr_path_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(p) => p.path.get_ident().map(|id| id.to_string()),
        Expr::Reference(r) => expr_path_ident(&r.expr),
        _ => None,
    }
}

fn expr_carries_remaining(expr: &Expr, tainted: &HashSet<String>) -> bool {
    struct Finder<'a> {
        tainted: &'a HashSet<String>,
        hit: bool,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if let Some(id) = node.path.get_ident() {
                if self.tainted.contains(&id.to_string()) {
                    self.hit = true;
                }
            }
            visit::visit_expr_path(self, node);
        }

        fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
            if let syn::Member::Named(id) = &node.member {
                if id == "remaining_accounts" {
                    self.hit = true;
                }
            }
            visit::visit_expr_field(self, node);
        }
    }
    let mut finder = Finder { tainted, hit: false };
    finder.visit_expr(expr);
    finder.hit
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
    fn flags_remaining_accounts_forwarded_to_cpi() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct RouteSwap<'info> {
                pub user: Signer<'info>,
            }

            pub fn route_swap(ctx: Context<RouteSwap>, data: Vec<u8>) -> Result<()> {
                let ix = build_ix(&data);
                let mut accounts = vec![ctx.accounts.user.to_account_info()];
                accounts.extend_from_slice(ctx.remaining_accounts);
                invoke(&ix, &accounts)?;
                Ok(())
            }
            "#,
        );

        let rule = CpiRemainingAccountsRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW023");
    }

    #[test]
    fn does_not_flag_cpi_without_remaining_accounts() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Swap<'info> {
                pub user: Signer<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub token_program: Program<'info, Token>,
            }

            pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
                token::transfer(
                    CpiContext::new(ctx.accounts.token_program.to_account_info(), Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.user.to_account_info(),
                        authority: ctx.accounts.user.to_account_info(),
                    }),
                    amount,
                )?;
                Ok(())
            }

            #[account]
            pub struct Vault { pub amount: u64 }
            "#,
        );

        let rule = CpiRemainingAccountsRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_remaining_accounts_without_cpi() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct ReadAccounts<'info> {
                pub authority: Signer<'info>,
            }

            pub fn read_all(ctx: Context<ReadAccounts>) -> Result<()> {
                for acc in ctx.remaining_accounts.iter() {
                    msg!("account: {}", acc.key());
                }
                Ok(())
            }
            "#,
        );

        let rule = CpiRemainingAccountsRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

     #[test]
    fn does_not_flag_remaining_accounts_read_beside_unrelated_cpi() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Initialize<'info> {
                pub creator: Signer<'info>,
                pub token_program: Program<'info, Token>,
                pub mint: Account<'info, Mint>,
                pub destination: Account<'info, TokenAccount>,
                pub authority: AccountInfo<'info>,
            }

            pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
                let _ = support_mint_associated_is_initialized(&ctx.remaining_accounts)?;
                token::token_mint_to(
                    ctx.accounts.authority.to_account_info(),
                    ctx.accounts.token_program.to_account_info(),
                    ctx.accounts.mint.to_account_info(),
                    ctx.accounts.destination.to_account_info(),
                    1,
                    &[],
                )?;
                Ok(())
            }
            "#,
        );
        let findings = CpiRemainingAccountsRule.match_file(
            &file,
            &RuleContext::files_only(std::slice::from_ref(&file)),
        );
        assert!(
            findings.is_empty(),
            "reading remaining_accounts must not flag an unrelated CPI: {findings:?}"
        );
    }
}
