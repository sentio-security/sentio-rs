use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorFieldTypeKind};
use crate::finding::SourceLocation;
use crate::instruction_analysis::{
    analyze_account_field_usage, collect_instruction_index, extract_context_accounts_struct,
};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, FnArg, Item, Pat, Stmt};

#[derive(Debug, Default)]
pub struct MissingOwnerCheckRule;

impl Rule for MissingOwnerCheckRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW002",
            title: "Missing owner check",
            severity: RuleSeverity::Critical,
            description: "Detects AccountInfo or UncheckedAccount fields with no owner or address constraint and no owner guard in instruction logic, allowing an attacker to pass an account owned by any program. Skips fields used only as pubkey/seed identity. Does not model ZK proofs or checks in other programs (AST limitation).",
            fix_guidance: "Add an owner constraint (#[account(owner = expected_program::ID)]) or an address constraint, or validate account.owner in your instruction handler. If integrity is intentional via ZK public inputs or another program, document with /// CHECK: and use // sentio-ignore SW002 or a baseline — Sentio cannot verify that.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let accounts_index = collect_anchor_accounts_index(&file.syntax);
        let instruction_index = collect_instruction_index(&file.syntax);
        let mut findings = Vec::new();

        // Same-file owner guards (unit tests use empty GlobalIndex via `files_only`).
        let local_owner_tokens: Vec<String> = instruction_index
            .functions
            .iter()
            .flat_map(|f| f.guards.iter())
            .filter(|g| g.references_owner)
            .flat_map(|g| {
                g.expression
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .collect();

        for item in accounts_index.structs {
            let struct_name = item.ast.name.as_str();

            // Cross-file: handlers with `Context<StructName>` in other files.
            let mut guarded_names = ctx.global.owner_guard_tokens_for(struct_name);
            guarded_names.extend(local_owner_tokens.iter().cloned());

            for field in item.fields {
                let kind = &field.type_info.kind;

                // Only target AccountInfo and UncheckedAccount.
                if *kind != AnchorFieldTypeKind::AccountInfo
                    && *kind != AnchorFieldTypeKind::UncheckedAccount
                {
                    continue;
                }

                let field_name = field.ast.name.as_deref().unwrap_or("").to_string();
                let c = &field.constraints;

                // Skip if owner/address is pinned — including custom
                // `constraint = account.key() == stored` (address identity).
                if c.has_owner_or_address_check() {
                    continue;
                }

                // Skip data-account fields (SW011) and program-named fields (SW020).
                let is_data_account =
                    c.init || c.init_if_needed || !c.has_one.is_empty() || c.has_seeds;
                let is_program_field = field_name.to_lowercase().contains("program");

                if is_data_account || is_program_field {
                    continue;
                }

                // Identity-only: `.key()` and/or PDA seed input — never data/owner/lamports.
                // Applies even when `mut` (payout keys copied into state / seeds).
                // Does NOT skip "trust me, ZK / other program validates" without usage proof.
                // Usage is still file-local (handler-only identity may still flag — known limit).
                if analyze_account_field_usage(&file.syntax, &field_name).is_identity_only() {
                    continue;
                }

                // Owner guard in a handler for this accounts struct (same file or GlobalIndex).
                let has_owner_guard = guarded_names.iter().any(|token| token == &field_name);
                // One direct call: the callee returns on `param.owner != system_program::ID`
                // and requires the derived PDA or `is_signer`. The parameter name is not the field name.
                let proved_in_callee = direct_callee_enforces_system_owner_and_pda_or_signer(
                    ctx,
                    struct_name,
                    &field_name,
                );

                if !has_owner_guard && !proved_in_callee {
                    findings.push(RuleMatch {
                        rule_id: "SW002",
                        severity: RuleSeverity::Critical,
                        message: format!(
                            "Account `{field_name}` has no owner constraint and no owner guard in instruction logic; any program-owned account can be passed.",
                        ),
                        location: SourceLocation {
                            path: file.path.display().to_string(),
                            line: field.ast.span.start_line,
                            column: 1,
                        },
                        help: Some(
                            "Add #[account(owner = expected_program::ID)] or verify account.owner explicitly in the instruction handler."
                                .to_string(),
                        ),
                    });
                }
            }
        }

        findings
    }
}

/// One hop. A handler for `accounts_struct` passes `field` straight into a callee,
/// and that callee rejects `param.owner != system_program::ID` and, when the key is
/// not a `find_program_address` / `create_program_address` result, requires
/// `is_signer` or rejects the account. A comparison that is only stored does not count.
pub(crate) fn direct_callee_enforces_system_owner_and_pda_or_signer(
    ctx: &RuleContext<'_>,
    accounts_struct: &str,
    field: &str,
) -> bool {
    let mut saw = false;
    let mut ok = true;
    for file in ctx.files {
        for_each_fn(&file.syntax.items, &mut |sig, block| {
            if extract_context_accounts_struct(sig).as_deref() != Some(accounts_struct) {
                return;
            }
            let mut calls = Vec::new();
            collect_field_calls(block, field, &mut calls);
            for (callee, index, arity) in calls {
                saw = true;
                ok = ok && callee_proves(ctx, &callee, index, arity);
            }
        });
    }
    saw && ok
}

fn callee_proves(ctx: &RuleContext<'_>, callee: &str, index: usize, arity: usize) -> bool {
    let mut found = false;
    let mut ok = true;
    for file in ctx.files {
        for_each_fn(&file.syntax.items, &mut |sig, block| {
            if sig.ident != callee {
                return;
            }
            let params = param_names(sig);
            if params.len() != arity {
                return;
            }
            found = true;
            match params.get(index).and_then(|name| name.as_deref()) {
                Some(param) => ok = ok && body_proves(block, param),
                None => ok = false,
            }
        });
    }
    found && ok
}

fn body_proves(block: &syn::Block, param: &str) -> bool {
    let pdas = pda_binding_names(block);
    if pdas.is_empty() {
        return false;
    }
    let mut checks = Checks {
        param,
        pdas: &pdas,
        owner_ok: false,
        pda_ok: false,
    };
    checks.visit_block(block);
    checks.owner_ok && checks.pda_ok
}

fn pda_binding_names(block: &syn::Block) -> std::collections::HashSet<String> {
    struct Finder {
        names: std::collections::HashSet<String>,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let Some(init) = &node.init {
                if contains_address_derive(&init.expr) {
                    if let Some(name) = first_binding(&node.pat) {
                        self.names.insert(name);
                    }
                }
            }
            visit::visit_local(self, node);
        }
    }
    let mut finder = Finder {
        names: std::collections::HashSet::new(),
    };
    finder.visit_block(block);
    finder.names
}

struct Checks<'a> {
    param: &'a str,
    pdas: &'a std::collections::HashSet<String>,
    owner_ok: bool,
    pda_ok: bool,
}

impl<'ast> Visit<'ast> for Checks<'_> {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if owner_if_rejects(node, self.param) {
            self.owner_ok = true;
        }
        if pda_if_enforces(node, self.param, self.pdas) {
            self.pda_ok = true;
        }
        visit::visit_expr_if(self, node);
    }
}

fn owner_if_rejects(node: &syn::ExprIf, param: &str) -> bool {
    let Expr::Binary(bin) = &*node.cond else {
        return false;
    };
    if !matches!(bin.op, BinOp::Ne(_)) {
        return false;
    }
    is_param_owner(&bin.left, param)
        && is_system_program_id(&bin.right)
        && block_rejects(&node.then_branch)
}

fn pda_if_enforces(
    node: &syn::ExprIf,
    param: &str,
    pdas: &std::collections::HashSet<String>,
) -> bool {
    let Expr::Binary(bin) = &*node.cond else {
        return false;
    };
    if !matches!(bin.op, BinOp::Ne(_)) {
        return false;
    }
    let Expr::Path(path) = peel(&bin.right) else {
        return false;
    };
    if path.path.segments.len() != 1 {
        return false;
    }
    let name = path.path.segments[0].ident.to_string();
    is_param_key(&bin.left, param)
        && pdas.contains(&name)
        && (block_requires_signer(&node.then_branch, param) || block_rejects(&node.then_branch))
}

fn block_rejects(block: &syn::Block) -> bool {
    block.stmts.iter().any(stmt_rejects)
}

fn stmt_rejects(stmt: &syn::Stmt) -> bool {
    match stmt {
        Stmt::Expr(expr, _) => expr_rejects(expr),
        Stmt::Macro(mac) => macro_rejects(&mac.mac),
        _ => false,
    }
}

fn expr_rejects(expr: &Expr) -> bool {
    match expr {
        Expr::Return(_) | Expr::Try(_) => true,
        Expr::Macro(mac) => macro_rejects(&mac.mac),
        Expr::Block(block) => block_rejects(&block.block),
        _ => false,
    }
}

fn macro_rejects(mac: &syn::Macro) -> bool {
    let Some(name) = mac.path.segments.last() else {
        return false;
    };
    let name = name.ident.to_string();
    name == "err" || name.starts_with("require")
}

fn block_requires_signer(block: &syn::Block, param: &str) -> bool {
    block.stmts.iter().any(|stmt| match stmt {
        Stmt::Macro(mac) => macro_requires_signer(&mac.mac, param),
        Stmt::Expr(Expr::Macro(mac), _) => macro_requires_signer(&mac.mac, param),
        _ => false,
    })
}

fn macro_requires_signer(mac: &syn::Macro, param: &str) -> bool {
    let Some(name) = mac.path.segments.last() else {
        return false;
    };
    if !name.ident.to_string().starts_with("require") {
        return false;
    }
    let text = mac.tokens.to_string();
    text.contains(param) && text.contains("is_signer")
}

fn is_param_owner(expr: &Expr, param: &str) -> bool {
    let Expr::Field(field) = peel(expr) else {
        return false;
    };
    is_member(&field.member, "owner") && is_param_path(&field.base, param)
}

fn is_param_key(expr: &Expr, param: &str) -> bool {
    match peel(expr) {
        Expr::MethodCall(call) => call.method == "key" && is_param_path(&call.receiver, param),
        Expr::Field(field) => is_member(&field.member, "key") && is_param_path(&field.base, param),
        _ => false,
    }
}

fn is_param_path(expr: &Expr, param: &str) -> bool {
    let Expr::Path(path) = peel(expr) else {
        return false;
    };
    path.path.segments.len() == 1 && path.path.segments[0].ident == param
}

fn is_system_program_id(expr: &Expr) -> bool {
    match peel(expr) {
        Expr::Path(path) => {
            let segs: Vec<_> = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            let last = segs.last().map(String::as_str);
            let system = segs
                .iter()
                .any(|seg| seg == "system_program" || seg == "System");
            system && matches!(last, Some("ID") | Some("id"))
        }
        Expr::MethodCall(call) if call.method == "id" => match peel(&call.receiver) {
            Expr::Path(path) => path
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == "system_program" || segment.ident == "System"),
            _ => false,
        },
        _ => false,
    }
}

fn is_member(member: &syn::Member, name: &str) -> bool {
    matches!(member, syn::Member::Named(ident) if ident == name)
}

fn contains_address_derive(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => path.path.segments.iter().any(|segment| {
            segment.ident == "find_program_address" || segment.ident == "create_program_address"
        }),
        Expr::Call(call) => {
            contains_address_derive(&call.func) || call.args.iter().any(contains_address_derive)
        }
        Expr::MethodCall(call) => {
            contains_address_derive(&call.receiver) || call.args.iter().any(contains_address_derive)
        }
        Expr::Tuple(tuple) => tuple.elems.iter().any(contains_address_derive),
        Expr::Reference(reference) => contains_address_derive(&reference.expr),
        Expr::Paren(paren) => contains_address_derive(&paren.expr),
        Expr::Field(field) => contains_address_derive(&field.base),
        Expr::Try(try_expr) => contains_address_derive(&try_expr.expr),
        _ => false,
    }
}

fn first_binding(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        Pat::Tuple(tuple) => tuple.elems.first().and_then(first_binding),
        Pat::Type(typed) => first_binding(&typed.pat),
        Pat::Reference(reference) => first_binding(&reference.pat),
        _ => None,
    }
}

fn peel(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(reference) => peel(&reference.expr),
        Expr::Paren(paren) => peel(&paren.expr),
        Expr::Group(group) => peel(&group.expr),
        _ => expr,
    }
}

fn collect_field_calls(block: &syn::Block, field: &str, out: &mut Vec<(String, usize, usize)>) {
    struct Finder<'a> {
        field: &'a str,
        out: &'a mut Vec<(String, usize, usize)>,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Some(name) = call_name(node) {
                for (index, arg) in node.args.iter().enumerate() {
                    if field_passed(arg, self.field) {
                        self.out.push((name.clone(), index, node.args.len()));
                    }
                }
            }
            visit::visit_expr_call(self, node);
        }
    }
    Finder { field, out }.visit_block(block);
}

fn call_name(call: &syn::ExprCall) -> Option<String> {
    let Expr::Path(path) = peel(&call.func) else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn field_passed(expr: &Expr, field: &str) -> bool {
    match peel(expr) {
        Expr::MethodCall(call)
            if matches!(
                call.method.to_string().as_str(),
                "to_account_info" | "clone" | "into"
            ) =>
        {
            field_passed(&call.receiver, field)
        }
        Expr::Field(field_expr) => {
            is_member(&field_expr.member, field) && receiver_is_accounts(&field_expr.base)
        }
        _ => false,
    }
}

fn receiver_is_accounts(expr: &Expr) -> bool {
    match peel(expr) {
        Expr::Field(field) => is_member(&field.member, "accounts"),
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "accounts"),
        _ => false,
    }
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
    fn flags_account_info_without_owner_check() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                let data = ctx.accounts.vault.try_borrow_data()?;
                Ok(())
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW002");
    }

    #[test]
    fn does_not_flag_when_owner_constraint_present() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(owner = token::ID)]
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_when_owner_guard_in_instruction() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                require!(
                    ctx.accounts.vault.owner == &token::ID,
                    ErrorCode::InvalidOwner
                );
                Ok(())
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_address_constrained_account() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(address = some_known::ID)]
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_admin_stored_as_pubkey_only() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct CreateAmm<'info> {
                #[account(init, payer = payer, space = 8 + 64)]
                pub amm: Account<'info, Amm>,
                /// CHECK: Read only, delegatable creation
                pub admin: AccountInfo<'info>,
                #[account(mut)]
                pub payer: Signer<'info>,
                pub system_program: Program<'info, System>,
            }

            pub fn create_amm(ctx: Context<CreateAmm>) -> Result<()> {
                ctx.accounts.amm.admin = ctx.accounts.admin.key();
                Ok(())
            }

            #[account]
            pub struct Amm {
                pub admin: Pubkey,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "stored-pubkey admin must not be SW002: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_custom_key_equality_constraint() {
        // Odomart FP: payout destination pinned to stored pubkey — address identity.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct WithdrawTeamFees<'info> {
                pub team_config: Account<'info, TeamConfig>,
                #[account(
                    constraint = team_wallet.key() == team_config.team_wallet @ RiseError::InvalidTeamWallet
                )]
                pub team_wallet: UncheckedAccount<'info>,
            }

            #[account]
            pub struct TeamConfig {
                pub team_wallet: Pubkey,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "key() == stored pubkey must not be SW002: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_custom_owner_equality_constraint() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(constraint = vault.owner == &token_program.key())]
                pub vault: AccountInfo<'info>,
                pub token_program: AccountInfo<'info>,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "custom .owner == must not be SW002: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_mut_pubkey_only_identity() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Init<'info> {
                #[account(init, payer = payer, space = 8 + 32)]
                pub config: Account<'info, Config>,
                /// CHECK: pubkey stored in config only
                #[account(mut)]
                pub recipient: UncheckedAccount<'info>,
                #[account(mut)]
                pub payer: Signer<'info>,
                pub system_program: Program<'info, System>,
            }

            pub fn init(ctx: Context<Init>) -> Result<()> {
                ctx.accounts.config.recipient = ctx.accounts.recipient.key();
                Ok(())
            }

            #[account]
            pub struct Config {
                pub recipient: Pubkey,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "mut identity-only must not be SW002: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_seed_only_account() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct CreatePda<'info> {
                /// CHECK: only used as PDA seed
                pub to_owner: UncheckedAccount<'info>,
                #[account(
                    init,
                    payer = payer,
                    space = 8,
                    seeds = [b"pos", to_owner.key().as_ref()],
                    bump
                )]
                pub position: Account<'info, Position>,
                #[account(mut)]
                pub payer: Signer<'info>,
                pub system_program: Program<'info, System>,
            }

            pub fn create(ctx: Context<CreatePda>) -> Result<()> {
                Ok(())
            }

            #[account]
            pub struct Position {}
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "seed-only UncheckedAccount must not be SW002: {findings:?}"
        );
    }

    #[test]
    fn still_flags_mut_data_use_without_owner() {
        // ZK-bound recipient that is actually read as data still needs a visible check
        // for SW002 — proof binding is out of scope for AST.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                /// CHECK: bound in Groth16 public inputs (not visible to AST)
                #[account(mut)]
                pub recipient: UncheckedAccount<'info>,
            }

            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
                let _data = ctx.accounts.recipient.try_borrow_data()?;
                Ok(())
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings =
            rule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(
            findings.len(),
            1,
            "data use without owner must still flag: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_when_owner_guard_in_other_file_via_global() {
        use crate::global_index::GlobalIndex;

        let accounts = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Load<'info> {
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
            "#,
        );
        let handler = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn load(ctx: Context<Load>) -> Result<()> {
                require!(
                    ctx.accounts.vault.owner == &token::ID,
                    ErrorCode::InvalidOwner
                );
                let _data = ctx.accounts.vault.try_borrow_data()?;
                Ok(())
            }
            "#,
        );

        let global = GlobalIndex::from_syn_files(&[&accounts.syntax, &handler.syntax]);
        let files = [accounts, handler];
        let ctx = RuleContext::new(&files, &global);

        let findings = MissingOwnerCheckRule.match_file(&files[0], &ctx);
        assert!(
            findings.is_empty(),
            "cross-file owner guard via GlobalIndex must quiet SW002: {findings:?}"
        );
    }

    #[test]
    fn still_flags_when_other_file_has_no_owner_guard() {
        use crate::global_index::GlobalIndex;

        let accounts = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Load<'info> {
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
            "#,
        );
        let handler = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn load(ctx: Context<Load>) -> Result<()> {
                let _data = ctx.accounts.vault.try_borrow_data()?;
                Ok(())
            }
            "#,
        );

        let global = GlobalIndex::from_syn_files(&[&accounts.syntax, &handler.syntax]);
        let files = [accounts, handler];
        let ctx = RuleContext::new(&files, &global);

        let findings = MissingOwnerCheckRule.match_file(&files[0], &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW002");
    }

    fn proving_callee() -> &'static str {
        r#"
            pub fn open(account: &AccountInfo, mint: &AccountInfo) -> Result<()> {
                if account.owner != &system_program::ID {
                    return err!(ErrorCode::NotApproved);
                }
                let (expect_pda_address, _bump) = Pubkey::find_program_address(
                    &[b"pool", mint.key().as_ref()],
                    &crate::id(),
                );
                if account.key() != expect_pda_address {
                    require_eq!(account.is_signer, true);
                }
                Ok(())
            }
        "#
    }

    #[test]
    fn does_not_flag_when_direct_callee_checks_system_owner_and_pda_or_signer() {
        let body = proving_callee();
        let file = parse_file(&format!(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Example<'info> {{
                /// CHECK: created here
                pub vault: UncheckedAccount<'info>,
                pub mint: Signer<'info>,
            }}
            pub fn handler(ctx: Context<Example>) -> Result<()> {{
                open(
                    &ctx.accounts.vault.to_account_info(),
                    &ctx.accounts.mint.to_account_info(),
                )?;
                Ok(())
            }}
            {body}
            "#
        ));
        let findings = MissingOwnerCheckRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert!(
            findings.is_empty(),
            "callee system-owner and pda-or-signer check must quiet SW002: {findings:?}"
        );
    }

    #[test]
    fn still_flags_when_owner_and_pda_comparisons_are_ignored() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Example<'info> {
                pub vault: UncheckedAccount<'info>,
            }
            pub fn handler(ctx: Context<Example>) -> Result<()> {
                open(&ctx.accounts.vault.to_account_info())?;
                Ok(())
            }
            pub fn open(account: &AccountInfo) -> Result<()> {
                let _ = account.owner != &system_program::ID;
                let (expect_pda_address, _bump) =
                    Pubkey::find_program_address(&[b"pool"], &crate::id());
                let _ = account.key() != expect_pda_address;
                let _ = account.is_signer;
                Ok(())
            }
            "#,
        );
        let findings = MissingOwnerCheckRule
            .match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)));
        assert_eq!(
            findings.len(),
            1,
            "stored comparisons must not quiet SW002: {findings:?}"
        );
    }
}
