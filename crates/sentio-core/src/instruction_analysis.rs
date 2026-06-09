use crate::ast_index::{span_of, AstSpan};
use quote::ToTokens;
use serde::Serialize;
use std::collections::HashMap;
use syn::parse::Parser;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstructionIndex {
    pub functions: Vec<InstructionFunction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstructionFunction {
    pub name: String,
    pub qualified_name: String,
    pub span: AstSpan,
    pub guards: Vec<GuardEvidence>,
    pub calls: Vec<CallEvidence>,
    pub writes: Vec<WriteEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardEvidence {
    pub kind: GuardKind,
    pub expression: String,
    pub span: AstSpan,
    pub order: usize,
    pub references_owner: bool,
    pub references_signer: bool,
    pub references_key: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardKind {
    IfCondition,
    RequireMacro,
    AssertMacro,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallEvidence {
    pub kind: CallKind,
    pub callee: String,
    pub span: AstSpan,
    pub order: usize,
    /// Account names extracted from the CpiContext struct for this CPI call.
    /// Empty when the CPI accounts could not be resolved (raw invoke, unknown binding).
    pub cpi_account_names: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Deserialization,
    Cpi,
    Reload,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriteEvidence {
    pub target: String,
    pub span: AstSpan,
    pub order: usize,
}

pub fn collect_instruction_index(file: &syn::File) -> InstructionIndex {
    let mut collector = InstructionCollector::default();
    collector.visit_file(file);
    InstructionIndex {
        functions: collector.functions,
    }
}

#[derive(Default)]
struct InstructionCollector {
    functions: Vec<InstructionFunction>,
    module_stack: Vec<String>,
    impl_stack: Vec<String>,
}

impl<'ast> Visit<'ast> for InstructionCollector {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        self.module_stack.push(node.ident.to_string());

        if let Some((_, items)) = &node.content {
            for item in items {
                self.visit_item(item);
            }
        }

        self.module_stack.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        self.impl_stack.push(node.self_ty.to_token_stream().to_string());
        visit::visit_item_impl(self, node);
        self.impl_stack.pop();
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.collect_function(node.sig.ident.to_string(), node.span(), &node.block);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.collect_function(node.sig.ident.to_string(), node.span(), &node.block);
    }
}

impl InstructionCollector {
    fn collect_function(&mut self, name: String, span: proc_macro2::Span, block: &syn::Block) {
        let mut collector = FunctionBodyCollector::default();
        collector.visit_block(block);

        self.functions.push(InstructionFunction {
            qualified_name: self.qualified_name(&name),
            name,
            span: span_of(span),
            guards: collector.guards,
            calls: collector.calls,
            writes: collector.writes,
        });
    }

    fn qualified_name(&self, name: &str) -> String {
        let mut parts = self.module_stack.clone();
        if let Some(impl_name) = self.impl_stack.last() {
            parts.push(impl_name.clone());
        }
        parts.push(name.to_string());
        parts.join("::")
    }
}

#[derive(Default)]
struct FunctionBodyCollector {
    next_order: usize,
    guards: Vec<GuardEvidence>,
    calls: Vec<CallEvidence>,
    writes: Vec<WriteEvidence>,
    /// Maps local variable names to the account names found in the struct literal they were
    /// bound to (e.g. `let accounts = Transfer { from: ctx.accounts.vault, ... }` →
    /// `"accounts" → ["vault", ...]`). Used to resolve CpiContext args by name.
    let_bindings: HashMap<String, Vec<String>>,
}

impl FunctionBodyCollector {
    fn order(&mut self) -> usize {
        self.next_order += 1;
        self.next_order
    }

    fn push_guard(&mut self, kind: GuardKind, expression: syn::Expr) {
        let features = ExprFeatures::from_expr(&expression);
        self.push_guard_text(kind, expression.to_token_stream().to_string(), expression.span(), features);
    }

    fn push_guard_text(
        &mut self,
        kind: GuardKind,
        expression: String,
        span: proc_macro2::Span,
        features: ExprFeatures,
    ) {
        let order = self.order();
        self.guards.push(GuardEvidence {
            kind,
            expression,
            span: span_of(span),
            order,
            references_owner: features.references_owner,
            references_signer: features.references_signer,
            references_key: features.references_key,
        });
    }

    fn push_call(&mut self, callee: String, span: proc_macro2::Span, cpi_account_names: Vec<String>) {
        let order = self.order();
        self.calls.push(CallEvidence {
            kind: classify_call_kind(&callee),
            callee,
            span: span_of(span),
            order,
            cpi_account_names,
        });
    }

    /// Walk `expr` and return the account names it refers to, following variable
    /// bindings recorded in `self.let_bindings`. Handles:
    /// - struct literals: `Transfer { from: ctx.accounts.X, ... }` → `["X", ...]`
    /// - `CpiContext::new(prog, accounts_expr)` → recurse on accounts_expr
    /// - variable paths: look up in `let_bindings`
    /// - references `&expr`: strip and recurse
    fn extract_account_names_from_expr(&self, expr: &syn::Expr) -> Vec<String> {
        match expr {
            syn::Expr::Struct(s) => s
                .fields
                .iter()
                .filter_map(|f| {
                    let val = normalize_tokens(&f.expr.to_token_stream().to_string());
                    extract_account_name_from_str(&val)
                })
                .collect(),
            syn::Expr::Call(call) => {
                let func = normalize_tokens(&call.func.to_token_stream().to_string());
                if func.contains("CpiContext::new") {
                    if let Some(accounts_arg) = call.args.iter().nth(1) {
                        return self.extract_account_names_from_expr(accounts_arg);
                    }
                }
                vec![]
            }
            syn::Expr::Path(p) => {
                let var = p
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                self.let_bindings.get(&var).cloned().unwrap_or_default()
            }
            syn::Expr::Reference(r) => self.extract_account_names_from_expr(&r.expr),
            _ => vec![],
        }
    }

    fn push_write(&mut self, target: String, span: proc_macro2::Span) {
        let order = self.order();
        self.writes.push(WriteEvidence {
            target,
            span: span_of(span),
            order,
        });
    }

    fn record_guard_macro(
        &mut self,
        path: &syn::Path,
        tokens: &proc_macro2::TokenStream,
        span: proc_macro2::Span,
    ) {
        if let Some(kind) = classify_guard_macro(path) {
            if let Some((expression, features)) = macro_guard_payload(path, tokens) {
                self.push_guard_text(kind, expression, span, features);
            }
        }
    }
}

impl<'ast> Visit<'ast> for FunctionBodyCollector {
    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if let syn::Stmt::Macro(stmt) = node {
            self.record_guard_macro(&stmt.mac.path, &stmt.mac.tokens, stmt.mac.span());
        }

        visit::visit_stmt(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.push_guard(GuardKind::IfCondition, (*node.cond).clone());
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        self.record_guard_macro(&node.mac.path, &node.mac.tokens, node.span());

        visit::visit_expr_macro(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (Some(init), Some(var_name)) = (&node.init, get_simple_pat_ident(&node.pat)) {
            let names = self.extract_account_names_from_expr(&init.expr);
            if !names.is_empty() {
                self.let_bindings.insert(var_name, names);
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let callee = normalize_tokens(&node.func.to_token_stream().to_string());
        let cpi_account_names = if classify_call_kind(&callee) == CallKind::Cpi {
            let mut found = vec![];
            for arg in &node.args {
                let names = self.extract_account_names_from_expr(arg);
                if !names.is_empty() {
                    found = names;
                    break;
                }
            }
            found
        } else {
            vec![]
        };
        self.push_call(callee, node.span(), cpi_account_names);
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let receiver = normalize_tokens(&node.receiver.to_token_stream().to_string());
        let callee = format!("{receiver}.{}", node.method);
        self.push_call(callee, node.span(), vec![]);
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        self.push_write(normalize_tokens(&node.left.to_token_stream().to_string()), node.span());
        visit::visit_expr_assign(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if is_assign_op(&node.op) {
            self.push_write(normalize_tokens(&node.left.to_token_stream().to_string()), node.span());
        }

        visit::visit_expr_binary(self, node);
    }
}

#[derive(Default)]
struct ExprFeatures {
    references_owner: bool,
    references_signer: bool,
    references_key: bool,
}

impl ExprFeatures {
    fn from_expr(expr: &syn::Expr) -> Self {
        let mut collector = ExprFeatureCollector::default();
        collector.visit_expr(expr);
        collector.features
    }

    fn merge(self, other: Self) -> Self {
        Self {
            references_owner: self.references_owner || other.references_owner,
            references_signer: self.references_signer || other.references_signer,
            references_key: self.references_key || other.references_key,
        }
    }
}

#[derive(Default)]
struct ExprFeatureCollector {
    features: ExprFeatures,
}

impl<'ast> Visit<'ast> for ExprFeatureCollector {
    fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
        if let syn::Member::Named(member) = &node.member {
            self.record_ident(member);
        }
        visit::visit_expr_field(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.record_ident(&node.method);
        visit::visit_expr_method_call(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        for segment in &node.segments {
            self.record_ident(&segment.ident);
        }
        visit::visit_path(self, node);
    }
}

impl ExprFeatureCollector {
    fn record_ident(&mut self, ident: &syn::Ident) {
        match ident.to_string().as_str() {
            "owner" => self.features.references_owner = true,
            "is_signer" | "signer" => self.features.references_signer = true,
            "key" => self.features.references_key = true,
            _ => {}
        }
    }
}

fn classify_guard_macro(path: &syn::Path) -> Option<GuardKind> {
    let ident = path.segments.last()?.ident.to_string();
    if ident.starts_with("require") {
        Some(GuardKind::RequireMacro)
    } else if ident.starts_with("assert") {
        Some(GuardKind::AssertMacro)
    } else {
        None
    }
}

fn parse_macro_guard_args(tokens: &proc_macro2::TokenStream) -> Option<Vec<syn::Expr>> {
    let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
    let args = parser.parse2(tokens.clone()).ok()?;
    Some(args.into_iter().collect())
}

fn macro_guard_payload(path: &syn::Path, tokens: &proc_macro2::TokenStream) -> Option<(String, ExprFeatures)> {
    let args = parse_macro_guard_args(tokens)?;
    if args.is_empty() {
        return None;
    }

    let ident = path.segments.last()?.ident.to_string();
    if (ident.ends_with("_eq") || ident == "assert_eq") && args.len() >= 2 {
        let expression = format!(
            "{} == {}",
            args[0].to_token_stream(),
            args[1].to_token_stream()
        );
        let features = ExprFeatures::from_expr(&args[0]).merge(ExprFeatures::from_expr(&args[1]));
        return Some((expression, features));
    }

    if (ident.ends_with("_ne") || ident == "assert_ne") && args.len() >= 2 {
        let expression = format!(
            "{} != {}",
            args[0].to_token_stream(),
            args[1].to_token_stream()
        );
        let features = ExprFeatures::from_expr(&args[0]).merge(ExprFeatures::from_expr(&args[1]));
        return Some((expression, features));
    }

    let first = args.into_iter().next()?;
    let features = ExprFeatures::from_expr(&first);
    Some((first.to_token_stream().to_string(), features))
}

fn classify_call_kind(callee: &str) -> CallKind {
    let normalized = normalize_tokens(callee);
    let lower = normalized.to_lowercase();

    if normalized.ends_with(".reload") || normalized.ends_with("::reload") {
        return CallKind::Reload;
    }

    if lower.contains("try_deserialize")
        || normalized.ends_with("::try_from")
        || normalized.ends_with("::from_account_info")
        || normalized.ends_with(".load")
        || normalized.ends_with(".load_mut")
    {
        return CallKind::Deserialization;
    }

    if normalized == "invoke"
        || normalized == "invoke_signed"
        || normalized.ends_with("::invoke")
        || normalized.ends_with("::invoke_signed")
        || normalized.contains("CpiContext::new")
        || normalized.contains("CpiContext::new_with_signer")
        || normalized.starts_with("token::")
        || normalized.contains("anchor_spl::token::")
    {
        return CallKind::Cpi;
    }

    CallKind::Other
}

fn is_assign_op(op: &syn::BinOp) -> bool {
    matches!(
        op,
        syn::BinOp::AddAssign(_)
            | syn::BinOp::SubAssign(_)
            | syn::BinOp::MulAssign(_)
            | syn::BinOp::DivAssign(_)
            | syn::BinOp::RemAssign(_)
            | syn::BinOp::BitXorAssign(_)
            | syn::BinOp::BitAndAssign(_)
            | syn::BinOp::BitOrAssign(_)
            | syn::BinOp::ShlAssign(_)
            | syn::BinOp::ShrAssign(_)
    )
}

fn normalize_tokens(tokens: &str) -> String {
    tokens.split_whitespace().collect()
}

fn get_simple_pat_ident(pat: &syn::Pat) -> Option<String> {
    if let syn::Pat::Ident(p) = pat {
        Some(p.ident.to_string())
    } else {
        None
    }
}

/// Extract an account name from an expression string by looking for `.accounts.IDENT`.
/// Returns `None` when the expression doesn't reference `ctx.accounts`.
fn extract_account_name_from_str(s: &str) -> Option<String> {
    let pos = s.find(".accounts.")?;
    let after = &s[pos + ".accounts.".len()..];
    let ident: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() { None } else { Some(ident) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_file(source: &str) -> syn::File {
        syn::parse_file(source).expect("source should parse")
    }

    #[test]
    fn collects_functions_from_modules_and_impls() {
        let file = parse_file(
            r#"
            mod instructions {
                pub fn process() {}
            }

            impl Processor {
                pub fn handle() {}
            }
            "#,
        );

        let index = collect_instruction_index(&file);
        assert_eq!(index.functions.len(), 2);
        assert_eq!(index.functions[0].qualified_name, "instructions::process");
        assert_eq!(index.functions[1].qualified_name, "Processor::handle");
    }

    #[test]
    fn models_guards_calls_and_writes_in_order() {
        let file = parse_file(
            r#"
            pub fn process(mut state: Account<'info, Vault>, authority: Signer<'info>) -> Result<()> {
                if state.owner != authority.key() {
                    return Err(ErrorCode::Unauthorized.into());
                }

                require!(authority.is_signer, ErrorCode::Unauthorized);

                let account = Vault::try_deserialize(&mut data)?;
                invoke_signed(&ix, &accounts, signer_seeds)?;
                state.reload()?;
                state.counter += account.amount;
                state.authority = authority.key();
                Ok(())
            }
            "#,
        );

        let index = collect_instruction_index(&file);
        assert_eq!(index.functions.len(), 1);

        let function = &index.functions[0];
        assert_eq!(function.qualified_name, "process");
        assert_eq!(function.guards.len(), 2);
        assert!(function.guards.iter().any(|guard| guard.references_owner));
        assert!(function.guards.iter().any(|guard| guard.references_signer));
        assert!(function.guards.iter().any(|guard| guard.references_key));

        assert!(function.calls.iter().any(|call| {
            call.kind == CallKind::Deserialization
                && call.callee.contains("Vault::try_deserialize")
        }));
        assert!(function.calls.iter().any(|call| {
            call.kind == CallKind::Cpi && call.callee.contains("invoke_signed")
        }));
        assert!(function.calls.iter().any(|call| {
            call.kind == CallKind::Reload && call.callee.contains("state.reload")
        }));

        assert!(function
            .writes
            .iter()
            .any(|write| write.target == "state.counter"));
        assert!(function
            .writes
            .iter()
            .any(|write| write.target == "state.authority"));

        let cpi_order = function
            .calls
            .iter()
            .find(|call| call.kind == CallKind::Cpi)
            .expect("cpi call should be recorded")
            .order;
        let reload_order = function
            .calls
            .iter()
            .find(|call| call.kind == CallKind::Reload)
            .expect("reload call should be recorded")
            .order;
        let write_order = function
            .writes
            .iter()
            .find(|write| write.target == "state.counter")
            .expect("counter write should be recorded")
            .order;

        assert!(cpi_order < reload_order);
        assert!(reload_order < write_order);
    }

    #[test]
    fn models_eq_style_guard_macros_with_both_operands() {
        let file = parse_file(
            r#"
            pub fn process(account: AccountInfo<'info>, authority: Signer<'info>) -> Result<()> {
                require_keys_eq!(account.owner, authority.key(), ErrorCode::Unauthorized);
                Ok(())
            }
            "#,
        );

        let index = collect_instruction_index(&file);
        let function = &index.functions[0];
        let guard = function
            .guards
            .iter()
            .find(|guard| guard.kind == GuardKind::RequireMacro)
            .expect("require macro guard should be recorded");

        assert!(guard.expression.contains("=="));
        assert!(guard.references_owner);
        assert!(guard.references_key);
    }
}
