use crate::anchor_accounts::{
    collect_anchor_accounts_index, AnchorAccountsField, AnchorAccountsStruct, AnchorFieldTypeKind,
};
use crate::finding::SourceLocation;
use crate::instruction_analysis::extract_context_accounts_struct;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use std::collections::HashMap;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, FnArg, Item, Pat};

#[derive(Debug, Default)]
pub struct MissingTokenMintCheckRule;

impl Rule for MissingTokenMintCheckRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW009",
            title: "Missing token account mint check",
            severity: RuleSeverity::High,
            description: "Detects mutable token account fields that have no token::mint or \
                associated_token::mint constraint, allowing an attacker to substitute a token \
                account for a different mint.",
            fix_guidance: "Add token::mint = <expected_mint> to the account constraint, or \
                use associated_token::mint = <mint> if this is an associated token account.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_anchor_accounts_index(&file.syntax);
        let mut findings = Vec::new();

        for item in &index.structs {
            for field in &item.fields {
                if !is_token_account(field) {
                    continue;
                }
                if !field.constraints.is_mut {
                    continue;
                }
                if field.constraints.has_token_mint_check()
                    || field.constraints.address
                    || field.constraints.has_owner_or_address_check()
                    || field.constraints.init
                    || field.constraints.init_if_needed
                {
                    continue;
                }

                let name = field.ast.name.clone().unwrap_or_default();
                // Mint is pinned by transfer_checked / mint_to / burn, not by the field name.
                // One hop into the helper that builds the CPI struct. Plain `transfer` and a
                // raw invoke do not count.
                if checked_cpi_uses_constrained_mint(ctx, item, &name) {
                    continue;
                }
                findings.push(RuleMatch {
                    rule_id: "SW009",
                    severity: RuleSeverity::High,
                    message: format!(
                        "Mutable token account `{name}` has no `token::mint` constraint; \
                        an attacker can substitute a token account for a different mint"
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: field.ast.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "Add #[account(mut, token::mint = <mint_field>)] to pin this account \
                        to the expected mint, or use associated_token::mint = <mint_field>."
                            .to_string(),
                    ),
                });
            }
        }

        findings
    }
}

fn is_token_account(field: &AnchorAccountsField) -> bool {
    matches!(
        field.type_info.kind,
        AnchorFieldTypeKind::Account | AnchorFieldTypeKind::InterfaceAccount
    ) && field.type_info.display.contains("TokenAccount")
}

/// True when every use of `field` as a token account is the `from`/`to` of
/// `transfer_checked`, `mint_to`, or `burn`, and that call's `mint` is a
/// constrained account. A plain `transfer` or `invoke` of the field blocks this.
fn checked_cpi_uses_constrained_mint(
    ctx: &RuleContext<'_>,
    accounts: &AnchorAccountsStruct,
    field: &str,
) -> bool {
    let (proved, blocked, _) = collect_token_cpi(ctx, accounts, field);
    proved && !blocked
}

/// SW010. Same CPI proof as SW009. A credit (`to`) needs no signer. A debit
/// (`from` / `burn`) also needs the CPI authority to be a `Signer` field.
pub(crate) fn checked_cpi_has_safe_owner(
    ctx: &RuleContext<'_>,
    accounts: &AnchorAccountsStruct,
    field: &str,
) -> bool {
    let (proved, blocked, debit_unsigned) = collect_token_cpi(ctx, accounts, field);
    proved && !blocked && !debit_unsigned
}

fn collect_token_cpi(
    ctx: &RuleContext<'_>,
    accounts: &AnchorAccountsStruct,
    field: &str,
) -> (bool, bool, bool) {
    let mut proved = false;
    let mut blocked = false;
    let mut debit_unsigned = false;
    let map = HashMap::new();
    for file in ctx.files {
        for_each_fn(&file.syntax.items, &mut |sig, block| {
            if extract_context_accounts_struct(sig).as_deref() != Some(accounts.ast.name.as_str()) {
                return;
            }
            let mut walk = Walk {
                ctx,
                accounts,
                field,
                map: &map,
                in_callee: false,
                proved: false,
                blocked: false,
                debit_unsigned: false,
            };
            walk.visit_block(block);
            proved |= walk.proved;
            blocked |= walk.blocked;
            debit_unsigned |= walk.debit_unsigned;
        });
    }
    (proved, blocked, debit_unsigned)
}

struct Walk<'a> {
    ctx: &'a RuleContext<'a>,
    accounts: &'a AnchorAccountsStruct,
    field: &'a str,
    map: &'a HashMap<String, String>,
    in_callee: bool,
    proved: bool,
    blocked: bool,
    /// `from` of a checked CPI whose authority is not a Signer field.
    debit_unsigned: bool,
}

impl<'ast> Visit<'ast> for Walk<'_> {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        self.on_call(node);
        visit::visit_expr_call(self, node);
    }
}

impl Walk<'_> {
    fn on_call(&mut self, call: &ExprCall) {
        let Some(name) = call_name(call) else {
            return;
        };
        if let Some(kind) = TokenOp::from_name(&name) {
            self.on_token_op(kind, call);
            return;
        }
        if is_invoke(&name) {
            if call_passes_field(call, self.field, self.map) {
                self.blocked = true;
            }
            return;
        }
        if !call_passes_field(call, self.field, self.map) {
            return;
        }
        if self.in_callee {
            self.blocked = true;
            return;
        }
        match hop(self.ctx, self.accounts, self.field, call) {
            Some((proved, blocked, debit_unsigned)) => {
                self.blocked |= blocked || !proved;
                self.proved |= proved && !blocked;
                self.debit_unsigned |= debit_unsigned;
            }
            None => self.blocked = true,
        }
    }

    fn on_token_op(&mut self, kind: TokenOp, call: &ExprCall) {
        let Some(struct_expr) = call.args.first().and_then(nested_struct) else {
            if self.call_mentions_field(call) {
                self.blocked = true;
            }
            return;
        };
        let hit = kind.token_fields().iter().any(|slot| {
            struct_field(struct_expr, slot)
                .and_then(|expr| resolve_field(expr, self.map))
                .as_deref()
                == Some(self.field)
        });
        if !hit {
            return;
        }
        if kind == TokenOp::Transfer {
            self.blocked = true;
            return;
        }
        let mint_ok = struct_field(struct_expr, "mint")
            .and_then(|expr| resolve_field(expr, self.map))
            .is_some_and(|mint| mint_is_constrained(self.accounts, &mint));
        if !mint_ok {
            self.blocked = true;
            return;
        }
        self.proved = true;
        if self.is_debit(kind, struct_expr)
            && !authority_is_signer(self.accounts, struct_expr, self.map)
        {
            self.debit_unsigned = true;
        }
    }

    fn is_debit(&self, kind: TokenOp, struct_expr: &syn::ExprStruct) -> bool {
        match kind {
            TokenOp::Burn => true,
            TokenOp::TransferChecked => {
                struct_field(struct_expr, "from")
                    .and_then(|expr| resolve_field(expr, self.map))
                    .as_deref()
                    == Some(self.field)
            }
            TokenOp::MintTo | TokenOp::Transfer => false,
        }
    }

    fn call_mentions_field(&self, call: &ExprCall) -> bool {
        call_passes_field(call, self.field, self.map)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenOp {
    TransferChecked,
    MintTo,
    Burn,
    Transfer,
}

impl TokenOp {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "transfer_checked" => Some(Self::TransferChecked),
            "mint_to" => Some(Self::MintTo),
            "burn" => Some(Self::Burn),
            "transfer" => Some(Self::Transfer),
            _ => None,
        }
    }

    fn token_fields(self) -> &'static [&'static str] {
        match self {
            Self::TransferChecked | Self::Transfer => &["from", "to"],
            Self::MintTo => &["to"],
            Self::Burn => &["from"],
        }
    }
}

fn hop(
    ctx: &RuleContext<'_>,
    accounts: &AnchorAccountsStruct,
    field: &str,
    call: &ExprCall,
) -> Option<(bool, bool, bool)> {
    let name = call_name(call)?;
    let mut found = false;
    let mut proved = true;
    let mut blocked = false;
    let mut debit_unsigned = false;
    for file in ctx.files {
        for_each_fn(&file.syntax.items, &mut |sig, block| {
            if sig.ident != name {
                return;
            }
            let params = param_names(sig);
            if params.len() != call.args.len() {
                return;
            }
            found = true;
            let mut map = HashMap::new();
            for (index, arg) in call.args.iter().enumerate() {
                let Some(param) = params.get(index).and_then(|p| p.clone()) else {
                    continue;
                };
                if let Some(passed) = resolve_field(arg, &HashMap::new()) {
                    map.insert(param, passed);
                }
            }
            let mut walk = Walk {
                ctx,
                accounts,
                field,
                map: &map,
                in_callee: true,
                proved: false,
                blocked: false,
                debit_unsigned: false,
            };
            walk.visit_block(block);
            proved &= walk.proved && !walk.blocked;
            blocked |= walk.blocked || !walk.proved;
            debit_unsigned |= walk.debit_unsigned;
        });
    }
    found.then_some((proved, blocked, debit_unsigned))
}

fn authority_is_signer(
    accounts: &AnchorAccountsStruct,
    struct_expr: &syn::ExprStruct,
    map: &HashMap<String, String>,
) -> bool {
    let Some(name) =
        struct_field(struct_expr, "authority").and_then(|expr| resolve_field(expr, map))
    else {
        return false;
    };
    accounts.fields.iter().any(|candidate| {
        candidate.ast.name.as_deref() == Some(name.as_str())
            && (candidate.type_info.kind == AnchorFieldTypeKind::Signer
                || candidate.constraints.is_signer)
    })
}

fn mint_is_constrained(accounts: &AnchorAccountsStruct, field: &str) -> bool {
    accounts.fields.iter().any(|candidate| {
        candidate.ast.name.as_deref() == Some(field)
            && (candidate.constraints.has_owner_or_address_check()
                || candidate.constraints.has_token_mint_check())
    })
}

fn call_passes_field(call: &ExprCall, field: &str, map: &HashMap<String, String>) -> bool {
    call.args.iter().any(|arg| {
        resolve_field(arg, map).as_deref() == Some(field) || array_has_field(arg, field, map)
    })
}

fn array_has_field(expr: &Expr, field: &str, map: &HashMap<String, String>) -> bool {
    match peel(expr) {
        Expr::Array(array) => array.elems.iter().any(|elem| {
            resolve_field(elem, map).as_deref() == Some(field) || array_has_field(elem, field, map)
        }),
        Expr::Reference(reference) => array_has_field(&reference.expr, field, map),
        _ => false,
    }
}

fn nested_struct(expr: &Expr) -> Option<&syn::ExprStruct> {
    match peel(expr) {
        Expr::Struct(struct_expr) => Some(struct_expr),
        Expr::Call(call) => call.args.iter().find_map(nested_struct),
        Expr::MethodCall(call) => {
            nested_struct(&call.receiver).or_else(|| call.args.iter().find_map(nested_struct))
        }
        _ => None,
    }
}

fn struct_field<'a>(struct_expr: &'a syn::ExprStruct, name: &str) -> Option<&'a Expr> {
    struct_expr
        .fields
        .iter()
        .find_map(|field| match &field.member {
            syn::Member::Named(ident) if ident == name => Some(&field.expr),
            _ => None,
        })
}

fn resolve_field(expr: &Expr, map: &HashMap<String, String>) -> Option<String> {
    let expr = strip_account(expr);
    if let Some(name) = accounts_field_name(expr) {
        return Some(name);
    }
    let ident = bare_ident(expr)?;
    map.get(&ident).cloned()
}

fn accounts_field_name(expr: &Expr) -> Option<String> {
    let Expr::Field(field) = expr else {
        return None;
    };
    let syn::Member::Named(ident) = &field.member else {
        return None;
    };
    if receiver_is_accounts(&field.base) {
        Some(ident.to_string())
    } else {
        None
    }
}

fn receiver_is_accounts(expr: &Expr) -> bool {
    match peel(expr) {
        Expr::Field(field) => {
            matches!(&field.member, syn::Member::Named(ident) if ident == "accounts")
        }
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "accounts"),
        _ => false,
    }
}

fn strip_account(expr: &Expr) -> &Expr {
    let mut current = peel(expr);
    loop {
        match current {
            Expr::MethodCall(call)
                if matches!(
                    call.method.to_string().as_str(),
                    "to_account_info" | "clone" | "into"
                ) =>
            {
                current = peel(&call.receiver);
            }
            _ => return current,
        }
    }
}

fn bare_ident(expr: &Expr) -> Option<String> {
    let Expr::Path(path) = expr else {
        return None;
    };
    if path.path.segments.len() != 1 {
        return None;
    }
    Some(path.path.segments[0].ident.to_string())
}

fn peel(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(reference) => peel(&reference.expr),
        Expr::Paren(paren) => peel(&paren.expr),
        Expr::Group(group) => peel(&group.expr),
        _ => expr,
    }
}

fn call_name(call: &ExprCall) -> Option<String> {
    let Expr::Path(path) = peel(&call.func) else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn is_invoke(name: &str) -> bool {
    matches!(name, "invoke" | "invoke_signed" | "invoke_unchecked")
}

fn param_names(sig: &syn::Signature) -> Vec<Option<String>> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Receiver(_) => None,
            FnArg::Typed(typed) => Some(simple_pat(&typed.pat)),
        })
        .collect()
}

fn simple_pat(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        Pat::Type(typed) => simple_pat(&typed.pat),
        Pat::Reference(reference) => simple_pat(&reference.pat),
        _ => None,
    }
}

fn for_each_fn(items: &[Item], visit_fn: &mut dyn FnMut(&syn::Signature, &syn::Block)) {
    for item in items {
        match item {
            Item::Fn(func) => visit_fn(&func.sig, &func.block),
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    for_each_fn(nested, visit_fn);
                }
            }
            Item::Impl(impl_item) => {
                for inner in &impl_item.items {
                    if let syn::ImplItem::Fn(func) = inner {
                        visit_fn(&func.sig, &func.block);
                    }
                }
            }
            _ => {}
        }
    }
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
    fn flags_mut_token_account_without_mint_constraint() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::TokenAccount;

            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut)]
                pub from: Account<'info, TokenAccount>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenMintCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW009");
    }

    #[test]
    fn does_not_flag_when_token_mint_constraint_present() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut, token::mint = mint)]
                pub from: Account<'info, TokenAccount>,
                pub mint: Account<'info, Mint>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenMintCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_associated_token_account() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::TokenAccount;

            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut, associated_token::mint = mint, associated_token::authority = authority)]
                pub from: Account<'info, TokenAccount>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenMintCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_read_only_token_account() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::TokenAccount;

            #[derive(Accounts)]
            pub struct CheckBalance<'info> {
                pub token_account: Account<'info, TokenAccount>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenMintCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_custom_constraint_mint_check() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::TokenAccount;

            #[derive(Accounts)]
            pub struct PlaceBet<'info> {
                pub market: Account<'info, Market>,
                #[account(
                    mut,
                    constraint = user_token_account.owner == user.key(),
                    constraint = user_token_account.mint == market.mint,
                )]
                pub user_token_account: Account<'info, TokenAccount>,
                #[account(
                    mut,
                    constraint = vault.mint == market.mint,
                    constraint = vault.owner == market.key(),
                )]
                pub vault: Account<'info, TokenAccount>,
                pub user: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenMintCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "custom .mint == constraints should count: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_mut_token_account_with_address_constraint() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;
        use anchor_spl::token::TokenAccount;

        #[derive(Accounts)]
        pub struct Test<'info> {
            #[account(mut, address = expected.key())]
            pub vault: Account<'info, TokenAccount>,
            pub expected: UncheckedAccount<'info>,
        }
    "#,
        );

        let rule = MissingTokenMintCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn does_not_flag_mut_token_account_with_owner_constraint() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;
        use anchor_spl::token::TokenAccount;

        #[derive(Accounts)]
        pub struct Test<'info> {
            #[account(mut, owner = expected.key())]
            pub vault: Account<'info, TokenAccount>,
            pub expected: UncheckedAccount<'info>,
        }
    "#,
        );

        let rule = MissingTokenMintCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn does_not_flag_mut_token_account_with_key_identity_constraint() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;
        use anchor_spl::token::TokenAccount;

        #[derive(Accounts)]
        pub struct Test<'info> {
            #[account(
                mut,
                constraint = vault.key() == expected.key()
            )]
            pub vault: Account<'info, TokenAccount>,
            pub expected: UncheckedAccount<'info>,
        }
    "#,
        );

        let rule = MissingTokenMintCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn does_not_flag_mut_token_account_with_owner_identity_constraint() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;
        use anchor_spl::token::TokenAccount;

        #[derive(Accounts)]
        pub struct Test<'info> {
            #[account(
                mut,
                constraint = vault.owner == expected.key()
            )]
            pub vault: Account<'info, TokenAccount>,
            pub expected: UncheckedAccount<'info>,
        }
    "#,
        );

        let rule = MissingTokenMintCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn flags_mut_token_account_without_identity_constraint() {
        let file = parse_file(
            r#"
        use anchor_lang::prelude::*;
        use anchor_spl::token::TokenAccount;

        #[derive(Accounts)]
        pub struct Test<'info> {
            #[account(mut)]
            pub vault: Account<'info, TokenAccount>,
        }
    "#,
        );

        let rule = MissingTokenMintCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW009");
    }

    fn run_files(files: &[ParsedFile], index: usize) -> Vec<RuleMatch> {
        use crate::global_index::GlobalIndex;

        let syns: Vec<&syn::File> = files.iter().map(|file| &file.syntax).collect();
        let global = GlobalIndex::from_syn_files(&syns);
        let ctx = RuleContext::new(files, &global);
        MissingTokenMintCheckRule.match_file(&files[index], &ctx)
    }

    #[test]
    fn does_not_flag_when_helper_transfer_checked_mint_is_constrained() {
        let handler = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct Collect<'info> {
                #[account(mut)]
                pub recipient: Account<'info, TokenAccount>,
                #[account(mut, address = expected.key())]
                pub vault: Account<'info, TokenAccount>,
                pub expected: UncheckedAccount<'info>,
                #[account(address = vault.mint)]
                pub mint: Account<'info, Mint>,
            }

            pub fn collect(ctx: Context<Collect>) -> Result<()> {
                send(
                    ctx.accounts.vault.to_account_info(),
                    ctx.accounts.recipient.to_account_info(),
                    ctx.accounts.mint.to_account_info(),
                )?;
                Ok(())
            }
            "#,
        );
        let helper = parse_file(
            r#"
            use anchor_lang::prelude::*;

            pub fn send(from: AccountInfo, to: AccountInfo, mint: AccountInfo) -> Result<()> {
                token::transfer_checked(
                    CpiContext::new(program, TransferChecked { from, to, authority: from, mint }),
                    amount,
                    decimals,
                )?;
                Ok(())
            }
            "#,
        );
        let files = [handler, helper];
        let findings = run_files(&files, 0);
        assert!(
            findings.is_empty(),
            "transfer_checked to a constrained mint must quiet SW009: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_mint_to_or_burn_when_mint_account_is_constrained() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct Deposit<'info> {
                #[account(mut)]
                pub owner_lp: Account<'info, TokenAccount>,
                #[account(mut, address = pool.lp_mint)]
                pub lp_mint: Account<'info, Mint>,
                pub pool: UncheckedAccount<'info>,
            }

            pub fn deposit(ctx: Context<Deposit>) -> Result<()> {
                token::mint_to(
                    CpiContext::new(
                        program,
                        MintTo {
                            mint: ctx.accounts.lp_mint.to_account_info(),
                            to: ctx.accounts.owner_lp.to_account_info(),
                            authority: ctx.accounts.pool.to_account_info(),
                        },
                    ),
                    amount,
                )?;
                Ok(())
            }

            pub fn withdraw(ctx: Context<Deposit>) -> Result<()> {
                token::burn(
                    CpiContext::new_with_signer(
                        program,
                        Burn {
                            mint: ctx.accounts.lp_mint.to_account_info(),
                            from: ctx.accounts.owner_lp.to_account_info(),
                            authority: ctx.accounts.pool.to_account_info(),
                        },
                        seeds,
                    ),
                    amount,
                )?;
                Ok(())
            }
            "#,
        );
        let findings = MissingTokenMintCheckRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "mint_to and burn against a pinned mint must quiet SW009: {findings:?}"
        );
    }

    #[test]
    fn still_flags_plain_transfer_even_when_named_recipient() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct Collect<'info> {
                #[account(mut)]
                pub recipient: Account<'info, TokenAccount>,
                #[account(address = vault.mint)]
                pub mint: Account<'info, Mint>,
                pub vault: Account<'info, TokenAccount>,
            }

            pub fn collect(ctx: Context<Collect>) -> Result<()> {
                token::transfer(
                    CpiContext::new(
                        program,
                        Transfer {
                            from: ctx.accounts.vault.to_account_info(),
                            to: ctx.accounts.recipient.to_account_info(),
                            authority: ctx.accounts.vault.to_account_info(),
                        },
                    ),
                    amount,
                )?;
                Ok(())
            }
            "#,
        );
        let findings = MissingTokenMintCheckRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("recipient")),
            "unchecked transfer must keep SW009: {findings:?}"
        );
    }

    #[test]
    fn still_flags_raw_invoke_of_transfer_alongside_checked_cpi() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct Collect<'info> {
                #[account(mut)]
                pub recipient: Account<'info, TokenAccount>,
                #[account(address = vault.mint)]
                pub mint: Account<'info, Mint>,
                pub vault: Account<'info, TokenAccount>,
            }

            pub fn collect(ctx: Context<Collect>) -> Result<()> {
                token::transfer_checked(
                    CpiContext::new(
                        program,
                        TransferChecked {
                            from: ctx.accounts.vault.to_account_info(),
                            to: ctx.accounts.recipient.to_account_info(),
                            authority: ctx.accounts.vault.to_account_info(),
                            mint: ctx.accounts.mint.to_account_info(),
                        },
                    ),
                    amount,
                    decimals,
                )?;
                let ix = Instruction {
                    program_id: *program.key,
                    accounts: vec![],
                    data: vec![3],
                };
                invoke(&ix, &[ctx.accounts.recipient.to_account_info()])?;
                Ok(())
            }
            "#,
        );
        let findings = MissingTokenMintCheckRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("recipient")),
            "raw transfer invoke must keep SW009: {findings:?}"
        );
    }

    #[test]
    fn still_flags_transfer_checked_when_mint_is_not_constrained() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct Collect<'info> {
                #[account(mut)]
                pub recipient: Account<'info, TokenAccount>,
                pub mint: Account<'info, Mint>,
            }

            pub fn collect(ctx: Context<Collect>) -> Result<()> {
                token::transfer_checked(
                    CpiContext::new(
                        program,
                        TransferChecked {
                            from: ctx.accounts.recipient.to_account_info(),
                            to: ctx.accounts.recipient.to_account_info(),
                            authority: ctx.accounts.recipient.to_account_info(),
                            mint: ctx.accounts.mint.to_account_info(),
                        },
                    ),
                    amount,
                    decimals,
                )?;
                Ok(())
            }
            "#,
        );
        let findings = MissingTokenMintCheckRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(
            findings.len(),
            1,
            "unconstrained mint must keep SW009: {findings:?}"
        );
    }
}
