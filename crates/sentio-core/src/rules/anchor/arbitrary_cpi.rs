use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorFieldTypeKind};
use crate::finding::SourceLocation;
use crate::instruction_analysis::extract_context_accounts_struct;
use crate::instruction_analysis::{collect_instruction_index, CallKind};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use std::collections::HashMap;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, FnArg, Item, Member, Pat, UnOp};

#[derive(Debug, Default)]
pub struct ArbitraryCpiRule;

impl Rule for ArbitraryCpiRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW003",
            title: "Arbitrary CPI target",
            severity: RuleSeverity::Critical,
            description: "Detects CPI calls (invoke/invoke_signed) without prior program ID \
                validation. An attacker-supplied program can receive the transaction's signer \
                privileges (confused deputy): e.g. a marketplace CPI to a fake \"royalty\" \
                program that drains the buyer. Always validate program IDs or use \
                Program<'info, T> / an allowlist — never trust user-provided program addresses.",
            fix_guidance: "require!(program.key() == expected::ID, ...) or Program<'info, T> \
                before CPI. Prefer allowlists for optional external programs (royalties, hooks). \
                Never pass a Signer into a CPI whose program account is unvalidated.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_instruction_index(&file.syntax);
        let accounts = collect_anchor_accounts_index(&file.syntax);
        // Same-file Signers / Program fields (unit tests / co-located Accounts).
        let local_signers = collect_signer_field_names(&accounts);
        let local_typed_programs = collect_typed_program_field_names(&accounts);
        let local_unvalidated_programs = collect_unvalidated_program_field_names(&accounts);
        let mut findings = Vec::new();

        for function in &index.functions {
            let cpi_calls: Vec<_> = function
                .calls
                .iter()
                .filter(|c| c.kind == CallKind::Cpi && is_raw_invoke(&c.callee))
                .collect();

            if cpi_calls.is_empty() {
                continue;
            }

            // Union local fields with Accounts struct from other files via Context<T>.
            let mut signer_fields = local_signers.clone();
            let mut typed_programs = local_typed_programs.clone();
            let mut unvalidated_programs = local_unvalidated_programs.clone();
            if let Some(ref accounts_name) = function.accounts_struct {
                for name in ctx.global.signer_field_names_for(accounts_name) {
                    signer_fields.insert(name);
                }
                if let Some(remote) = ctx.global.accounts(accounts_name) {
                    for name in typed_program_names_from_struct(remote) {
                        typed_programs.insert(name);
                    }
                    for name in unvalidated_program_names_from_struct(remote) {
                        unvalidated_programs.insert(name);
                    }
                }
            }

            for cpi_call in cpi_calls {
                if has_program_validation_before(function, cpi_call.order) {
                    continue;
                }

                // Anchor already validates Program<'info, T> (ID + executable).
                // Raw invoke through that account is not an arbitrary CPI target.
                // Still flag if an unvalidated *program* AccountInfo/UncheckedAccount
                // also appears in the metas (confused-deputy / dual-program cases).
                if cpi_targets_anchor_typed_program(
                    &cpi_call.cpi_account_names,
                    &typed_programs,
                    &unvalidated_programs,
                ) {
                    continue;
                }

                // Helper has no Accounts struct. The program id is a parameter.
                // Quiet this invoke only when every call site in the crate passes
                // a Program<'info, T> field for that same parameter.
                if helper_program_param_is_typed_at_every_call_site(
                    ctx,
                    &file.syntax,
                    &function.name,
                    function.span.start_line,
                    cpi_call.span.start_line,
                ) {
                    continue;
                }

                let delegated_signers: Vec<&String> = cpi_call
                    .cpi_account_names
                    .iter()
                    .filter(|name| signer_fields.iter().any(|s| s.eq_ignore_ascii_case(name)))
                    .collect();

                let (message, help) = if !delegated_signers.is_empty() {
                    let names = delegated_signers
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    (
                        format!(
                            "CPI `{}` in `{}` has no program ID check and passes signer \
                             privilege(s) (`{names}`) into the callee — classic confused-deputy: \
                             a malicious program can act with those signers (e.g. extra transfers).",
                            cpi_call.callee, function.name
                        ),
                        "Validate the CPI program ID (require! / Program<'info, T> / allowlist) \
                         before invoke. Do not forward buyer/authority Signers to untrusted programs."
                            .to_string(),
                    )
                } else {
                    (
                        format!(
                            "CPI call `{}` in `{}` has no preceding program key validation; \
                             an attacker can supply a malicious CPI target.",
                            cpi_call.callee, function.name
                        ),
                        "Add require!(program.key() == expected::ID, ...) before the CPI, use \
                         Program<'info, T>, or an allowlist for external programs (royalties, hooks)."
                            .to_string(),
                    )
                };

                findings.push(RuleMatch {
                    rule_id: "SW003",
                    severity: RuleSeverity::Critical,
                    message,
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: cpi_call.span.start_line,
                        column: cpi_call.span.start_column,
                    },
                    help: Some(help),
                });
            }
        }

        findings
    }
}

fn is_raw_invoke(callee: &str) -> bool {
    let n = callee.trim();
    n == "invoke"
        || n == "invoke_signed"
        || n == "invoke_unchecked"
        || n.ends_with("::invoke")
        || n.ends_with("::invoke_signed")
        || n.ends_with("::invoke_unchecked")
}

fn has_program_validation_before(
    function: &crate::instruction_analysis::InstructionFunction,
    cpi_order: usize,
) -> bool {
    function.guards.iter().any(|g| {
        g.order < cpi_order
            && (g.references_key || guard_looks_like_program_allowlist(&g.expression))
    })
}

/// Broader than bare `.key()` — allowlist / program_id / ::ID comparisons in require!/if.
fn guard_looks_like_program_allowlist(expression: &str) -> bool {
    let compact: String = expression
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    compact.contains("program_id")
        || compact.contains("::id")
        || compact.contains("allowlist")
        || compact.contains("allowed_program")
        || compact.contains("approved_program")
        || (compact.contains("program") && compact.contains("key()") && compact.contains("=="))
}

fn collect_signer_field_names(
    accounts: &crate::anchor_accounts::AnchorAccountsIndex,
) -> HashSet<String> {
    let mut names = HashSet::new();
    for item in &accounts.structs {
        for field in &item.fields {
            let Some(name) = field.ast.name.clone() else {
                continue;
            };
            let is_signer_type = field.type_info.kind == AnchorFieldTypeKind::Signer;
            let has_signer_constraint = field.constraints.is_signer;
            if is_signer_type || has_signer_constraint {
                names.insert(name);
            }
        }
    }
    names
}

fn collect_typed_program_field_names(
    accounts: &crate::anchor_accounts::AnchorAccountsIndex,
) -> HashSet<String> {
    let mut names = HashSet::new();
    for item in &accounts.structs {
        names.extend(typed_program_names_from_struct(item));
    }
    names
}

fn collect_unvalidated_program_field_names(
    accounts: &crate::anchor_accounts::AnchorAccountsIndex,
) -> HashSet<String> {
    let mut names = HashSet::new();
    for item in &accounts.structs {
        names.extend(unvalidated_program_names_from_struct(item));
    }
    names
}

fn typed_program_names_from_struct(
    item: &crate::anchor_accounts::AnchorAccountsStruct,
) -> HashSet<String> {
    item.fields
        .iter()
        .filter(|f| f.type_info.kind == AnchorFieldTypeKind::Program)
        .filter_map(|f| f.ast.name.clone())
        .collect()
}

/// AccountInfo / UncheckedAccount fields whose names suggest a CPI program target.
fn unvalidated_program_names_from_struct(
    item: &crate::anchor_accounts::AnchorAccountsStruct,
) -> HashSet<String> {
    item.fields
        .iter()
        .filter(|f| {
            matches!(
                f.type_info.kind,
                AnchorFieldTypeKind::AccountInfo | AnchorFieldTypeKind::UncheckedAccount
            )
        })
        .filter_map(|f| f.ast.name.clone())
        .filter(|name| name.to_ascii_lowercase().contains("program"))
        .collect()
}

/// True when CPI account metas include an Anchor-typed `Program<'info, T>` and do not
/// also include an unvalidated `*program*` AccountInfo/UncheckedAccount.
fn cpi_targets_anchor_typed_program(
    cpi_account_names: &[String],
    typed_programs: &HashSet<String>,
    unvalidated_programs: &HashSet<String>,
) -> bool {
    let has_typed = cpi_account_names
        .iter()
        .any(|m| typed_programs.iter().any(|t| t.eq_ignore_ascii_case(m)));
    if !has_typed {
        return false;
    }
    let has_unvalidated = cpi_account_names.iter().any(|m| {
        unvalidated_programs
            .iter()
            .any(|u| u.eq_ignore_ascii_case(m))
    });
    !has_unvalidated
}

fn helper_program_param_is_typed_at_every_call_site(
    ctx: &RuleContext<'_>,
    file: &syn::File,
    function_name: &str,
    function_line: usize,
    invoke_line: usize,
) -> bool {
    let Some((sig, block)) = find_fn_at_line(&file.items, function_name, function_line) else {
        return false;
    };
    let params = param_names(sig);
    let mut finder = ProgramParamFinder {
        params: params.clone(),
        invoke_line,
        lets: HashMap::new(),
        found: None,
    };
    finder.visit_block(block);
    let Some(param) = finder.found else {
        return false;
    };
    let Some(index) = params
        .iter()
        .position(|name| name.as_deref() == Some(param.as_str()))
    else {
        return false;
    };
    let mut stack = HashSet::new();
    all_call_sites_pass(ctx, function_name, index, params.len(), &mut stack)
}

struct ProgramParamFinder {
    params: Vec<Option<String>>,
    invoke_line: usize,
    lets: HashMap<String, Expr>,
    found: Option<String>,
}

impl<'ast> Visit<'ast> for ProgramParamFinder {
    fn visit_block(&mut self, node: &'ast syn::Block) {
        let saved = self.lets.clone();
        visit::visit_block(self, node);
        self.lets = saved;
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        visit::visit_local(self, node);
        if let (Some(init), Some(name)) = (&node.init, simple_pat_ident(&node.pat)) {
            self.lets.insert(name, (*init.expr).clone());
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if self.found.is_none()
            && node.span().start().line == self.invoke_line
            && is_raw_invoke(&call_callee(node))
        {
            let found = node.args.first().and_then(|instruction| {
                program_param_from_expr(instruction, &node.args, &self.lets, &self.params, 0)
            });
            self.found = found;
        }
        visit::visit_expr_call(self, node);
    }
}

/// Program account of this invoke, if it is a parameter of the enclosing function.
///
/// Struct form: `program_id: *param.key`.
/// Builder form: the call's first argument is `param.key` (sync_native).
/// `param` must also be present in the invoke account list.
fn program_param_from_expr(
    expr: &Expr,
    invoke_args: &syn::punctuated::Punctuated<Expr, syn::Token![,]>,
    lets: &HashMap<String, Expr>,
    params: &[Option<String>],
    depth: usize,
) -> Option<String> {
    if depth > 8 {
        return None;
    }
    let peeled = peel(expr);
    if is_key_expr(peeled) {
        let param = param_root_of_key(peeled, lets, params, depth)?;
        return invoke_mentions_param(invoke_args, &param).then_some(param);
    }
    match peeled {
        Expr::Struct(struct_expr) => {
            let field = struct_expr
                .fields
                .iter()
                .find(|field| member_is(&field.member, "program_id"))?;
            program_param_from_expr(&field.expr, invoke_args, lets, params, depth + 1)
        }
        Expr::Call(call) => {
            let first = call.args.first()?;
            let first = peel(first);
            if is_key_expr(first) {
                return program_param_from_expr(first, invoke_args, lets, params, depth + 1);
            }
            let Expr::Path(path) = first else {
                return None;
            };
            if path.path.segments.len() != 1 {
                return None;
            }
            let name = path.path.segments[0].ident.to_string();
            let bound = lets.get(&name)?;
            program_param_from_expr(bound, invoke_args, lets, params, depth + 1)
        }
        Expr::Path(path) if path.path.segments.len() == 1 => {
            let name = path.path.segments[0].ident.to_string();
            let bound = lets.get(&name)?;
            program_param_from_expr(bound, invoke_args, lets, params, depth + 1)
        }
        _ => None,
    }
}

fn param_root_of_key(
    expr: &Expr,
    lets: &HashMap<String, Expr>,
    params: &[Option<String>],
    depth: usize,
) -> Option<String> {
    if depth > 8 {
        return None;
    }
    let base = match peel(expr) {
        Expr::Field(field) if member_is(&field.member, "key") => peel(&field.base),
        Expr::MethodCall(call) if call.method == "key" => peel(&call.receiver),
        _ => return None,
    };
    let base = strip_value_wrappers(base);
    let Expr::Path(path) = base else {
        return None;
    };
    if path.path.segments.len() != 1 {
        return None;
    }
    let name = path.path.segments[0].ident.to_string();
    if let Some(bound) = lets.get(&name) {
        if is_key_expr(peel(bound)) {
            return param_root_of_key(bound, lets, params, depth + 1);
        }
        let forwarded = forwarded_param_ident(bound)?;
        if forwarded != name && param_index(params, &forwarded).is_some() {
            return Some(forwarded);
        }
        return None;
    }
    param_index(params, &name).map(|_| name)
}

fn invoke_mentions_param(
    args: &syn::punctuated::Punctuated<Expr, syn::Token![,]>,
    param: &str,
) -> bool {
    args.iter()
        .skip(1)
        .any(|arg| expr_mentions_param(arg, param))
}

fn expr_mentions_param(expr: &Expr, param: &str) -> bool {
    match peel(expr) {
        Expr::Path(path) => path.path.segments.len() == 1 && path.path.segments[0].ident == param,
        Expr::MethodCall(call)
            if matches!(
                call.method.to_string().as_str(),
                "clone" | "into" | "to_account_info"
            ) =>
        {
            expr_mentions_param(&call.receiver, param)
        }
        Expr::Array(array) => array
            .elems
            .iter()
            .any(|elem| expr_mentions_param(elem, param)),
        Expr::Call(call) => call.args.iter().any(|arg| expr_mentions_param(arg, param)),
        _ => false,
    }
}

fn all_call_sites_pass(
    ctx: &RuleContext<'_>,
    callee: &str,
    param_index: usize,
    arity: usize,
    stack: &mut HashSet<(String, usize)>,
) -> bool {
    let key = (callee.to_string(), param_index);
    if !stack.insert(key.clone()) {
        return false;
    }
    let mut saw = false;
    let mut ok = true;
    let mut walker = CallSiteWalker {
        ctx,
        callee,
        param_index,
        arity,
        stack,
        saw: &mut saw,
        ok: &mut ok,
    };

    for file in ctx.files {
        walk_items_for_calls(&mut walker, &file.syntax.items);
    }
    stack.remove(&key);
    saw && ok
}

struct CallSiteWalker<'a, 'b> {
    ctx: &'a RuleContext<'b>,
    callee: &'a str,
    param_index: usize,
    arity: usize,
    stack: &'a mut HashSet<(String, usize)>,
    saw: &'a mut bool,
    ok: &'a mut bool,
}

fn walk_items_for_calls(walker: &mut CallSiteWalker<'_, '_>, items: &[Item]) {
    for item in items {
        match item {
            Item::Fn(func) => consider_fn(walker, &func.sig, &func.block, None),

            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    walk_items_for_calls(walker, nested);
                }
            }

            Item::Impl(impl_item) => {
                let impl_name = type_name_of(&impl_item.self_ty);

                for inner in &impl_item.items {
                    let syn::ImplItem::Fn(func) = inner else {
                        continue;
                    };

                    consider_fn(walker, &func.sig, &func.block, impl_name.clone());
                }
            }

            _ => {}
        }
    }
}

fn consider_fn(
    walker: &mut CallSiteWalker<'_, '_>,
    sig: &syn::Signature,
    block: &syn::Block,
    impl_name: Option<String>,
) {
    let params = param_names(sig);
    let accounts = extract_context_accounts_struct(sig).or(impl_name);

    let mut calls = Vec::new();
    collect_calls(block, &mut calls);

    for call in calls {
        let Some(name) = call_last_segment(call) else {
            continue;
        };

        if name != walker.callee
            || call.args.len() != walker.arity
            || walker.param_index >= call.args.len()
        {
            continue;
        }

        *walker.saw = true;

        let proven = argument_is_typed_program(
            walker.ctx,
            &call.args[walker.param_index],
            &params,
            accounts.as_deref(),
            &sig.ident.to_string(),
            walker.stack,
        );

        *walker.ok = *walker.ok && proven;
    }
}

fn argument_is_typed_program(
    ctx: &RuleContext<'_>,
    arg: &Expr,
    caller_params: &[Option<String>],
    accounts_struct: Option<&str>,
    caller_name: &str,
    stack: &mut HashSet<(String, usize)>,
) -> bool {
    if let Some(field) = accounts_field_name(arg) {
        let Some(struct_name) = accounts_struct else {
            return false;
        };
        return field_is_typed_program(ctx, struct_name, &field);
    }
    if let Some(ident) = forwarded_param_ident(arg) {
        if let Some(index) = param_index(caller_params, &ident) {
            return all_call_sites_pass(ctx, caller_name, index, caller_params.len(), stack);
        }
    }
    false
}

fn field_is_typed_program(ctx: &RuleContext<'_>, struct_name: &str, field: &str) -> bool {
    let mut found: Option<bool> = None;
    for file in ctx.files {
        let index = collect_anchor_accounts_index(&file.syntax);
        for item in &index.structs {
            if item.ast.name != struct_name {
                continue;
            }
            let is_program = item.fields.iter().any(|candidate| {
                candidate.ast.name.as_deref() == Some(field)
                    && candidate.type_info.kind == AnchorFieldTypeKind::Program
            });
            if found.is_some() {
                return false;
            }
            found = Some(is_program);
        }
    }
    if let Some(is_program) = found {
        return is_program;
    }
    if ctx
        .global
        .duplicate_accounts_names
        .iter()
        .any(|name| name == struct_name)
    {
        return false;
    }
    ctx.global.accounts(struct_name).is_some_and(|item| {
        item.fields.iter().any(|candidate| {
            candidate.ast.name.as_deref() == Some(field)
                && candidate.type_info.kind == AnchorFieldTypeKind::Program
        })
    })
}

fn find_fn_at_line<'a>(
    items: &'a [Item],
    name: &str,
    line: usize,
) -> Option<(&'a syn::Signature, &'a syn::Block)> {
    for item in items {
        match item {
            Item::Fn(func) if func.sig.ident == name && func.span().start().line == line => {
                return Some((&func.sig, &func.block));
            }
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    if let Some(found) = find_fn_at_line(nested, name, line) {
                        return Some(found);
                    }
                }
            }
            Item::Impl(impl_item) => {
                for inner in &impl_item.items {
                    let syn::ImplItem::Fn(func) = inner else {
                        continue;
                    };
                    if func.sig.ident == name && func.span().start().line == line {
                        return Some((&func.sig, &func.block));
                    }
                }
            }
            _ => {}
        }
    }
    None
}

struct CallCollector<'a, 'c> {
    calls: &'c mut Vec<&'a ExprCall>,
}

impl<'ast> Visit<'ast> for CallCollector<'ast, '_> {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        self.calls.push(node);
        visit::visit_expr_call(self, node);
    }
}

fn collect_calls<'a>(block: &'a syn::Block, calls: &mut Vec<&'a ExprCall>) {
    let mut collector = CallCollector { calls };
    collector.visit_block(block);
}

fn param_names(sig: &syn::Signature) -> Vec<Option<String>> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Receiver(_) => None,
            FnArg::Typed(typed) => Some(simple_pat_ident(&typed.pat)),
        })
        .collect()
}

fn param_index(params: &[Option<String>], name: &str) -> Option<usize> {
    params
        .iter()
        .position(|param| param.as_deref() == Some(name))
}

fn call_callee(call: &ExprCall) -> String {
    let Expr::Path(path) = peel(&call.func) else {
        return String::new();
    };
    path.path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn call_last_segment(call: &ExprCall) -> Option<String> {
    let Expr::Path(path) = peel(&call.func) else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn accounts_field_name(expr: &Expr) -> Option<String> {
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
            _ => break,
        }
    }
    let Expr::Field(field) = current else {
        return None;
    };
    let Member::Named(ident) = &field.member else {
        return None;
    };
    if is_accounts_receiver(&field.base) {
        Some(ident.to_string())
    } else {
        None
    }
}

fn is_accounts_receiver(expr: &Expr) -> bool {
    let expr = peel(expr);
    if is_path_ident(expr, "self") {
        return true;
    }
    let Expr::Field(field) = expr else {
        return false;
    };
    member_is(&field.member, "accounts")
        && (is_path_ident(&field.base, "ctx") || is_path_ident(&field.base, "self"))
}

fn forwarded_param_ident(expr: &Expr) -> Option<String> {
    let expr = strip_value_wrappers(peel(expr));
    let Expr::Path(path) = expr else {
        return None;
    };
    if path.path.segments.len() != 1 {
        return None;
    }
    Some(path.path.segments[0].ident.to_string())
}

fn strip_value_wrappers(expr: &Expr) -> &Expr {
    let mut current = peel(expr);
    loop {
        match current {
            Expr::MethodCall(call)
                if matches!(
                    call.method.to_string().as_str(),
                    "clone" | "into" | "to_account_info"
                ) =>
            {
                current = peel(&call.receiver);
            }
            _ => return current,
        }
    }
}

fn is_key_expr(expr: &Expr) -> bool {
    match peel(expr) {
        Expr::Field(field) => member_is(&field.member, "key"),
        Expr::MethodCall(call) => call.method == "key",
        _ => false,
    }
}

fn peel(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(reference) => peel(&reference.expr),
        Expr::Paren(paren) => peel(&paren.expr),
        Expr::Group(group) => peel(&group.expr),
        Expr::Try(try_expr) => peel(&try_expr.expr),
        Expr::Unary(unary) if matches!(unary.op, UnOp::Deref(_)) => peel(&unary.expr),
        _ => expr,
    }
}

fn member_is(member: &Member, name: &str) -> bool {
    match member {
        Member::Named(ident) => ident == name,
        Member::Unnamed(_) => false,
    }
}

fn is_path_ident(expr: &Expr, name: &str) -> bool {
    let Expr::Path(path) = peel(expr) else {
        return false;
    };
    path.path.segments.len() == 1 && path.path.segments[0].ident == name
}

fn simple_pat_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        Pat::Type(typed) => simple_pat_ident(&typed.pat),
        Pat::Reference(reference) => simple_pat_ident(&reference.pat),
        _ => None,
    }
}

fn type_name_of(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        syn::Type::Reference(reference) => type_name_of(&reference.elem),
        syn::Type::Paren(paren) => type_name_of(&paren.elem),
        syn::Type::Group(group) => type_name_of(&group.elem),
        _ => None,
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

    fn run(file: &ParsedFile) -> Vec<RuleMatch> {
        ArbitraryCpiRule.match_file(file, &RuleContext::files_only(std::slice::from_ref(file)))
    }
    fn run_files(files: &[ParsedFile], helper: usize) -> Vec<RuleMatch> {
        use crate::global_index::GlobalIndex;

        let syns: Vec<&syn::File> = files.iter().map(|file| &file.syntax).collect();
        let global = GlobalIndex::from_syn_files(&syns);
        let ctx = RuleContext::new(files, &global);
        ArbitraryCpiRule.match_file(&files[helper], &ctx)
    }

    #[test]
    fn flags_cpi_without_key_check() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke(
                    &instruction,
                    &[ctx.accounts.target_program.to_account_info()],
                )?;
                Ok(())
            }
        "#,
        );
        let findings = run(&file);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW003");
    }

    #[test]
    fn does_not_flag_cpi_with_key_check_before() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                require!(
                    ctx.accounts.target_program.key() == &expected_program::ID,
                    ErrorCode::InvalidProgram
                );
                invoke(
                    &instruction,
                    &[ctx.accounts.target_program.to_account_info()],
                )?;
                Ok(())
            }
        "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn does_not_flag_function_with_no_cpi() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                ctx.accounts.vault.balance = 100;
                Ok(())
            }
        "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn flags_confused_deputy_signer_passed_to_unvalidated_program() {
        // Marketplace-style: CPI to user-supplied royalty program with buyer as signer.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct Buy<'info> {
                pub buyer: Signer<'info>,
                /// CHECK: supposed royalty program — unvalidated
                pub royalty_program: AccountInfo<'info>,
                #[account(mut)]
                pub buyer_token: AccountInfo<'info>,
            }

            pub fn buy(ctx: Context<Buy>) -> Result<()> {
                let ix = solana_program::instruction::Instruction {
                    program_id: *ctx.accounts.royalty_program.key,
                    accounts: vec![],
                    data: vec![],
                };
                invoke(
                    &ix,
                    &[
                        ctx.accounts.buyer.to_account_info(),
                        ctx.accounts.buyer_token.to_account_info(),
                        ctx.accounts.royalty_program.to_account_info(),
                    ],
                )?;
                Ok(())
            }
        "#,
        );
        let findings = run(&file);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.to_lowercase().contains("signer")
                || findings[0].message.to_lowercase().contains("confused"),
            "expected confused-deputy messaging: {}",
            findings[0].message
        );
    }

    #[test]
    fn does_not_flag_when_program_validated_even_with_signer_in_metas() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct Buy<'info> {
                pub buyer: Signer<'info>,
                pub royalty_program: AccountInfo<'info>,
            }

            pub fn buy(ctx: Context<Buy>) -> Result<()> {
                require_keys_eq!(*ctx.accounts.royalty_program.key, royalty::ID);
                invoke(
                    &ix,
                    &[
                        ctx.accounts.buyer.to_account_info(),
                        ctx.accounts.royalty_program.to_account_info(),
                    ],
                )?;
                Ok(())
            }
        "#,
        );
        assert!(
            run(&file).is_empty(),
            "validated program ID must clear SW003 even with signer in metas: {:?}",
            run(&file)
        );
    }

    #[test]
    fn confused_deputy_when_signer_on_accounts_in_other_file() {
        use crate::global_index::GlobalIndex;

        let accounts = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Buy<'info> {
                pub buyer: Signer<'info>,
                /// CHECK: supposed royalty program — unvalidated
                pub royalty_program: AccountInfo<'info>,
            }
            "#,
        );
        let handler = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            pub fn buy(ctx: Context<Buy>) -> Result<()> {
                invoke(
                    &ix,
                    &[
                        ctx.accounts.buyer.to_account_info(),
                        ctx.accounts.royalty_program.to_account_info(),
                    ],
                )?;
                Ok(())
            }
            "#,
        );

        let global = GlobalIndex::from_syn_files(&[&accounts.syntax, &handler.syntax]);
        let files = [accounts, handler];
        let ctx = RuleContext::new(&files, &global);

        let findings = ArbitraryCpiRule.match_file(&files[1], &ctx);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.to_lowercase().contains("signer")
                || findings[0].message.to_lowercase().contains("confused"),
            "cross-file Signer must upgrade to confused-deputy: {}",
            findings[0].message
        );
    }

    #[test]
    fn does_not_flag_invoke_through_typed_program_account() {
        // Marinade-style: Program<'info, Stake> already pins the CPI target.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct StakeReserve<'info> {
                pub stake_program: Program<'info, Stake>,
                #[account(mut)]
                pub stake_account: AccountInfo<'info>,
                pub rent: Sysvar<'info, Rent>,
            }

            pub fn process(ctx: Context<StakeReserve>) -> Result<()> {
                invoke(
                    &ix,
                    &[
                        ctx.accounts.stake_program.to_account_info(),
                        ctx.accounts.stake_account.to_account_info(),
                        ctx.accounts.rent.to_account_info(),
                    ],
                )?;
                Ok(())
            }
            "#,
        );
        assert!(
            run(&file).is_empty(),
            "typed Program<'info, T> must quiet SW003: {:?}",
            run(&file)
        );
    }

    #[test]
    fn does_not_flag_invoke_via_self_field_on_impl() {
        // Real Marinade dialect: `impl StakeReserve { fn process(&mut self) { self.stake_program... } }`.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::{invoke, invoke_signed};

            #[derive(Accounts)]
            pub struct StakeReserve<'info> {
                pub stake_program: Program<'info, Stake>,
                #[account(mut)]
                pub stake_account: AccountInfo<'info>,
                /// CHECK: vote
                pub validator_vote: UncheckedAccount<'info>,
            }

            impl<'info> StakeReserve<'info> {
                pub fn process(&mut self) -> Result<()> {
                    invoke(
                        &ix,
                        &[
                            self.stake_program.to_account_info(),
                            self.stake_account.to_account_info(),
                        ],
                    )?;
                    invoke_signed(
                        &ix2,
                        &[
                            self.stake_program.to_account_info(),
                            self.stake_account.to_account_info(),
                            self.validator_vote.to_account_info(),
                        ],
                        &[],
                    )?;
                    Ok(())
                }
            }
            "#,
        );
        assert!(
            run(&file).is_empty(),
            "self.stake_program on impl must quiet SW003: {:?}",
            run(&file)
        );
    }

    #[test]
    fn still_flags_when_unvalidated_program_alongside_typed_program() {
        // token_program is typed, but royalty_program is the real (unvalidated) target.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct Buy<'info> {
                pub buyer: Signer<'info>,
                /// CHECK: attacker-controlled
                pub royalty_program: AccountInfo<'info>,
                pub token_program: Program<'info, Token>,
            }

            pub fn buy(ctx: Context<Buy>) -> Result<()> {
                invoke(
                    &ix,
                    &[
                        ctx.accounts.buyer.to_account_info(),
                        ctx.accounts.royalty_program.to_account_info(),
                        ctx.accounts.token_program.to_account_info(),
                    ],
                )?;
                Ok(())
            }
            "#,
        );
        let findings = run(&file);
        assert_eq!(
            findings.len(),
            1,
            "unvalidated *program* AccountInfo must still flag: {findings:?}"
        );
    }

    #[test]
    fn typed_program_on_other_file_quiets_handler_cpi() {
        use crate::global_index::GlobalIndex;

        let accounts = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct StakeReserve<'info> {
                pub stake_program: Program<'info, Stake>,
                #[account(mut)]
                pub stake_account: AccountInfo<'info>,
            }
            "#,
        );
        let handler = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn process(ctx: Context<StakeReserve>) -> Result<()> {
                invoke_signed(
                    &ix,
                    &[
                        ctx.accounts.stake_program.to_account_info(),
                        ctx.accounts.stake_account.to_account_info(),
                    ],
                    &[],
                )?;
                Ok(())
            }
            "#,
        );

        let global = GlobalIndex::from_syn_files(&[&accounts.syntax, &handler.syntax]);
        let files = [accounts, handler];
        let ctx = RuleContext::new(&files, &global);
        let findings = ArbitraryCpiRule.match_file(&files[1], &ctx);
        assert!(
            findings.is_empty(),
            "cross-file typed Program must quiet SW003: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_helper_when_every_call_site_passes_typed_program() {
        // Two hops, two files. The immediate caller only forwards the parameter.
        // Both instruction call sites pass Program<'info, T>.
        let helper = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn sweep(program: AccountInfo) -> Result<()> {
                inner(program)
            }

            pub fn inner(program: AccountInfo) -> Result<()> {
                let ix = Instruction {
                    program_id: *program.key,
                    accounts: vec![],
                    data: vec![],
                };
                invoke_signed(&ix, &[program], &[])?;
                Ok(())
            }
            "#,
        );
        let caller = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Collect<'info> {
                pub token_program: Program<'info, Token>,
                pub token_program_2022: Program<'info, Token2022>,
            }

            pub fn collect(ctx: Context<Collect>, flag: bool) -> Result<()> {
                if flag {
                    sweep(ctx.accounts.token_program.to_account_info())?;
                } else {
                    sweep(ctx.accounts.token_program_2022.to_account_info())?;
                }
                Ok(())
            }
            "#,
        );
        let files = [helper, caller];
        let findings = run_files(&files, 0);
        assert!(
            findings.is_empty(),
            "typed Program at every call site must quiet the helper: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_helper_when_builder_first_key_is_typed_program() {
        // sync_native shape: program id is the builder's first argument, not a
        // program_id field in this function.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct Collect<'info> {
                pub token_program: Program<'info, Token>,
            }

            pub fn collect(ctx: Context<Collect>) -> Result<()> {
                sweep(
                    ctx.accounts.token_program.to_account_info(),
                    ctx.accounts.token_program.to_account_info(),
                )
            }

            pub fn sweep(program: AccountInfo, source: AccountInfo) -> Result<()> {
                let sync_ix = sync_native(program.key, source.key)?;
                invoke(&sync_ix, &[source.clone(), program.clone()])?;
                Ok(())
            }
            "#,
        );
        assert!(
            run(&file).is_empty(),
            "builder whose first argument is the typed program must be quiet: {:?}",
            run(&file)
        );
    }

    #[test]
    fn still_flags_helper_when_any_call_site_is_unchecked() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            #[derive(Accounts)]
            pub struct Good<'info> {
                pub token_program: Program<'info, Token>,
            }

            #[derive(Accounts)]
            pub struct Bad<'info> {
                /// CHECK: attacker-controlled
                pub token_program: UncheckedAccount<'info>,
            }

            pub fn good(ctx: Context<Good>) -> Result<()> {
                sweep(ctx.accounts.token_program.to_account_info())
            }

            pub fn bad(ctx: Context<Bad>) -> Result<()> {
                sweep(ctx.accounts.token_program.to_account_info())
            }

            pub fn sweep(program: AccountInfo) -> Result<()> {
                inner(program)
            }

            pub fn inner(program: AccountInfo) -> Result<()> {
                let ix = Instruction {
                    program_id: *program.key,
                    accounts: vec![],
                    data: vec![],
                };
                invoke_signed(&ix, &[program], &[])?;
                Ok(())
            }
            "#,
        );
        let findings = run(&file);
        assert_eq!(
            findings.len(),
            1,
            "one UncheckedAccount call site keeps the helper finding: {findings:?}"
        );
    }

    #[test]
    fn still_flags_when_program_id_is_a_different_unchecked_parameter() {
        // The safe argument is named token_program and is Program<'info, T>.
        // program_id is the other parameter. The name must not quiet the invoke.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct Mix<'info> {
                pub token_program: Program<'info, Token>,
                /// CHECK: real CPI target
                pub other: UncheckedAccount<'info>,
            }

            pub fn handler(ctx: Context<Mix>) -> Result<()> {
                inner(
                    ctx.accounts.token_program.to_account_info(),
                    ctx.accounts.other.to_account_info(),
                )
            }

            pub fn inner(token_program: AccountInfo, other: AccountInfo) -> Result<()> {
                let ix = Instruction {
                    program_id: *other.key,
                    accounts: vec![],
                    data: vec![],
                };
                invoke(&ix, &[token_program, other])?;
                Ok(())
            }
            "#,
        );
        let findings = run(&file);
        assert_eq!(
            findings.len(),
            1,
            "typed token_program must not quiet a different program_id: {findings:?}"
        );
    }

    #[test]
    fn still_flags_helper_with_no_call_site() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn inner(token_program: AccountInfo) -> Result<()> {
                let ix = Instruction {
                    program_id: *token_program.key,
                    accounts: vec![],
                    data: vec![],
                };
                invoke_signed(&ix, &[token_program], &[])?;
                Ok(())
            }
            "#,
        );
        let findings = run(&file);
        assert_eq!(
            findings.len(),
            1,
            "no visible caller must keep the finding: {findings:?}"
        );
    }
}
