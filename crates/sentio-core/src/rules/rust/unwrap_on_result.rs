use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use std::collections::HashMap;
use syn::parse::Parser;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Block, Expr, ExprBinary, ExprMethodCall, ImplItemFn, Item, ItemFn, ItemMod, Lit, Macro,
    PatIdent, Stmt,
};

#[derive(Debug, Default)]
pub struct UnwrapOnResultRule;

impl Rule for UnwrapOnResultRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW025",
            title: "unwrap() / expect() in instruction handler",
            severity: RuleSeverity::Low,
            description: "Detects .unwrap() and .expect() calls in instruction handlers. \
                          In Solana programs these cause a runtime panic, which fails the \
                          transaction with a generic error and can be triggered by crafting \
                          inputs that produce None or Err, making it a potential DoS vector. \
                          Unwraps that cannot panic — proven Some by same-block is_some / \
                          is_none checks, or in-bounds by a same-file length require — are \
                          not reported.",
            fix_guidance: "Replace .unwrap() with ? to propagate the error as an Anchor \
                           ErrorCode, or use .ok_or(ErrorCode::Foo)? to return a meaningful \
                           program error instead of panicking.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let len_floor = file_len_require_floor(&file.syntax);
        let mut collector = UnwrapCollector {
            findings: Vec::new(),
            in_test: false,
            panic_nesting: 0,
            guards: Vec::new(),
            len_floor,
        };
        visit::visit_file(&mut collector, &file.syntax);

        collector
            .findings
            .into_iter()
            .map(|(message, line, column)| RuleMatch {
                rule_id: "SW025",
                severity: RuleSeverity::Low,
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

/// Proof that a base is `Some`.
enum ScopeGuard {
    /// Holds unconditionally for the rest of the block.
    Always(String),
    /// Established by `require!(key.is_some(), …)` inside `if cond { … }`;
    /// holds only where the same condition is re-checked, and only until `cond`
    /// or `key` is mutated.
    While { cond: String, key: String },
    /// A `let` / pattern binding re-used the name: within this scope the outer
    /// proofs no longer describe the value behind it.
    Shadowed(String),
}

struct UnwrapCollector {
    findings: Vec<(String, usize, usize)>,
    in_test: bool,
    /// Depth of nested `.unwrap()` / `.expect()` while walking receivers.
    /// Only the outermost call in a chain is reported (avoids double-counting
    /// `checked_mul(...).unwrap().checked_div(...).unwrap()`).
    panic_nesting: usize,
    /// Stack of scopes; each holds base paths proven `Some` for the statements
    /// that follow in the same block / branch.
    guards: Vec<Vec<ScopeGuard>>,
    /// Smallest bound proven by a same-file `require!(x.len() >= … + CONST)`:
    /// `.get(N)` with `N < len_floor` and `.last()` on such slices cannot panic.
    len_floor: Option<u64>,
}

impl UnwrapCollector {
    fn push_scope(&mut self) {
        self.guards.push(Vec::new());
    }

    fn pop_scope(&mut self) {
        self.guards.pop();
    }

    fn add_guard(&mut self, key: String) {
        if let Some(scope) = self.guards.last_mut() {
            // A fresh proof describes the current binding; retire the shadow.
            scope.retain(|guard| !matches!(guard, ScopeGuard::Shadowed(s) if *s == key));
            scope.push(ScopeGuard::Always(key));
        }
    }

    fn is_shadowed(&self, key: &str) -> bool {
        self.guards.iter().any(|scope| {
            scope
                .iter()
                .any(|guard| matches!(guard, ScopeGuard::Shadowed(s) if s == key))
        })
    }

    fn is_guarded(&self, key: &str) -> bool {
        // Innermost first: a shadow in an enclosing scope blocks every proof
        // above it — until that scope ends and the outer name is visible again.
        for scope in self.guards.iter().rev() {
            if scope
                .iter()
                .any(|guard| matches!(guard, ScopeGuard::Shadowed(s) if s == key))
            {
                return false;
            }
            if scope
                .iter()
                .any(|guard| matches!(guard, ScopeGuard::Always(g) if g == key))
            {
                return true;
            }
        }
        false
    }

    /// Conditional proofs whose condition matches `cond` exactly — used to
    /// quiet `if C { require!(x.is_some()) }` … `if C { x.unwrap() }`.
    fn conditional_keys(&self, cond: &str) -> Vec<String> {
        self.guards
            .iter()
            .flatten()
            .filter_map(|guard| match guard {
                ScopeGuard::While { cond: g, key } if g == cond && !self.is_shadowed(key) => {
                    Some(key.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// After visiting a statement: carry the proofs it establishes for the rest
    /// of the block, then drop any guard it invalidates (assignment, shadowing
    /// `let`, `take` / `replace` / `swap`).
    fn absorb_stmt(&mut self, stmt: &Stmt) {
        for key in stmt_persistent_guards(stmt) {
            self.add_guard(key);
        }
        if let Stmt::Expr(Expr::If(if_expr), _) = stmt {
            let cond = token_key(&if_expr.cond);
            for inner in &if_expr.then_branch.stmts {
                for key in stmt_require_guards(inner) {
                    if let Some(scope) = self.guards.last_mut() {
                        scope
                            .retain(|guard| !matches!(guard, ScopeGuard::Shadowed(s) if *s == key));
                        scope.push(ScopeGuard::While {
                            cond: cond.clone(),
                            key,
                        });
                    }
                }
            }
        }
        let clobbers = clobbered_keys(stmt);
        // Mutations hit the value behind the name everywhere; bindings only
        // re-bind inside their own block, so they come from this statement's
        // own `let` pattern only — a `let` nested deeper is absorbed when that
        // inner block visits it.
        if !clobbers.mutations.is_empty() {
            for scope in &mut self.guards {
                scope.retain(|guard| match guard {
                    ScopeGuard::Always(guard_key) => !clobbers
                        .mutations
                        .iter()
                        .any(|key| guard_clobbered_by(guard_key, key)),
                    ScopeGuard::While {
                        cond,
                        key: guard_key,
                    } => {
                        !clobbers
                            .mutations
                            .iter()
                            .any(|key| guard_clobbered_by(guard_key, key))
                            && !clobbers
                                .mutations
                                .iter()
                                .any(|key| cond_mentions_ident(cond, key))
                    }
                    ScopeGuard::Shadowed(_) => true,
                });
            }
        }
        if let Stmt::Local(local) = stmt {
            for binding in local_pat_bindings(&local.pat) {
                if let Some(scope) = self.guards.last_mut() {
                    scope.push(ScopeGuard::Shadowed(binding));
                }
            }
        }
    }

    fn quiet_by_slice_bound(&self, receiver: &Expr) -> bool {
        match slice_access(receiver) {
            SliceAccess::Get(index) => self.len_floor.is_some_and(|floor| index < floor),
            SliceAccess::Last => self.len_floor.is_some_and(|floor| floor >= 1),
            SliceAccess::None => false,
        }
    }
}

impl<'ast> Visit<'ast> for UnwrapCollector {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        // Skip functions marked #[test] to avoid noise from test utilities.
        let was_in_test = self.in_test;
        if node
            .attrs
            .iter()
            .any(|a| a.path().is_ident("test") || attr_cfg_enables_test(a))
        {
            self.in_test = true;
        }
        // A nested fn never captures the enclosing scope: same-named locals must
        // not inherit the outer function's proofs.
        let outer_guards = std::mem::take(&mut self.guards);
        visit::visit_item_fn(self, node);
        self.guards = outer_guards;
        self.in_test = was_in_test;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let outer_guards = std::mem::take(&mut self.guards);
        visit::visit_impl_item_fn(self, node);
        self.guards = outer_guards;
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        let was_in_test = self.in_test;
        if node.attrs.iter().any(attr_cfg_enables_test) {
            self.in_test = true;
        }
        visit::visit_item_mod(self, node);
        self.in_test = was_in_test;
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        // Closures run after the surrounding code may have mutated the receiver;
        // surrounding guards do not carry into the body.
        let outer_guards = std::mem::take(&mut self.guards);
        visit::visit_expr_closure(self, node);
        self.guards = outer_guards;
    }

    fn visit_block(&mut self, node: &'ast Block) {
        self.push_scope();
        for stmt in &node.stmts {
            self.visit_stmt(stmt);
            self.absorb_stmt(stmt);
        }
        self.pop_scope();
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.push_scope();
        self.visit_expr(&node.cond);
        for key in truth_implies_some(&node.cond) {
            self.add_guard(key);
        }
        let cond = token_key(&node.cond);
        for key in self.conditional_keys(&cond) {
            self.add_guard(key);
        }
        self.visit_block(&node.then_branch);
        if let Some(scope) = self.guards.last_mut() {
            scope.clear();
        }
        if let Some((_, else_expr)) = &node.else_branch {
            for key in falsity_implies_some(&node.cond) {
                self.add_guard(key);
            }
            match else_expr.as_ref() {
                Expr::Block(b) => self.visit_block(&b.block),
                other => self.visit_expr(other),
            }
            if let Some(scope) = self.guards.last_mut() {
                scope.clear();
            }
        }
        self.pop_scope();
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if matches!(node.op, syn::BinOp::And(_)) {
            // Short-circuit: every later operand only evaluates when all earlier
            // ones are true, so `is_some()` proofs hold for them.
            self.push_scope();
            let mut operands = Vec::new();
            flatten_and_operand(&node.left, &mut operands);
            flatten_and_operand(&node.right, &mut operands);
            for operand in operands {
                self.visit_expr(operand);
                for key in truth_implies_some(operand) {
                    self.add_guard(key);
                }
            }
            self.pop_scope();
        } else if matches!(node.op, syn::BinOp::Or(_)) {
            // Later operands only evaluate when all earlier ones are false:
            // `is_none()` proves `Some` for them.
            self.push_scope();
            let mut operands = Vec::new();
            flatten_or_operand(&node.left, &mut operands);
            flatten_or_operand(&node.right, &mut operands);
            for operand in operands {
                self.visit_expr(operand);
                for key in falsity_implies_some(operand) {
                    self.add_guard(key);
                }
            }
            self.pop_scope();
        } else {
            visit::visit_expr_binary(self, node);
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        let is_panic = method == "unwrap" || method == "expect";

        if is_panic {
            self.panic_nesting += 1;
        }

        // Walk children first so nested panics bump nesting before we decide.
        self.visit_expr(&node.receiver);
        for arg in &node.args {
            self.visit_expr(arg);
        }

        if is_panic {
            if !self.in_test && self.panic_nesting == 1 {
                let receiver = node.receiver.to_token_stream().to_string();
                let receiver_compact = receiver.split_whitespace().collect::<Vec<_>>().join(" ");
                // Production Anchor dialects often unwrap infallible PDA / borsh helpers.
                // Keep flagging user-influenced Results (try_into, checked_*, CPI, account data).
                if !is_benign_unwrap_receiver(&receiver_compact)
                    && !self.is_guarded(&unwrap_base_key(&node.receiver))
                    && !self.quiet_by_slice_bound(&node.receiver)
                {
                    let loc = node.span().start();
                    self.findings.push((
                        format!(
                            "`.{method}()` on `{receiver_compact}` will panic on None/Err; use `?` or \
                             `.ok_or(ErrorCode::...)?` instead"
                        ),
                        loc.line,
                        loc.column + 1,
                    ));
                }
            }
            self.panic_nesting -= 1;
        }
    }
}

/// Receivers that are noise on mature protocols, not attacker-chosen Options.
fn is_benign_unwrap_receiver(receiver: &str) -> bool {
    let compact: String = receiver.chars().filter(|c| !c.is_whitespace()).collect();
    let lower = compact.to_ascii_lowercase();

    // Pubkey::create_program_address / create_with_seed / find_program_address
    // (and associated helpers that wrap those calls).
    if lower.contains("create_program_address")
        || lower.contains("create_with_seed")
        || lower.contains("find_program_address")
    {
        return true;
    }

    // Fixed-layout borsh of Default / zeroed placeholders — effectively infallible size helpers.
    // e.g. `ValidatorRecord::default().try_to_vec()` or `MaybeUninit::zeroed().assume_init().try_to_vec()`.
    if lower.contains("try_to_vec")
        && (lower.contains("::default()")
            || lower.contains(".default()")
            || lower.contains("assume_init")
            || lower.contains("zeroed"))
    {
        return true;
    }

    false
}

/// `#[cfg(test)]`, `#[cfg(all(test, ...))]`, `#[cfg(any(test, ...))]`.
/// `#[cfg(not(test))]` does not count: that item is the production build.
fn attr_cfg_enables_test(attr: &syn::Attribute) -> bool {
    let syn::Meta::List(list) = &attr.meta else {
        return false;
    };
    if !list.path.is_ident("cfg") {
        return false;
    }
    let Ok(meta) = syn::parse2::<syn::Meta>(list.tokens.clone()) else {
        return false;
    };
    cfg_meta_enables_test(&meta)
}

fn cfg_meta_enables_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("not") => false,
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let Ok(nested) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return false;
            };
            nested.iter().any(cfg_meta_enables_test)
        }
        _ => false,
    }
}

// --- Guard analysis -----------------------------------------------------------
//
// A base path is proven `Some` when every path reaching the current statement
// has passed a check that fails on `None`. Proofs are collected per block scope
// and dropped when the statement re-binds or mutates the receiver.

fn token_key<T: ToTokens>(tokens: &T) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .split_whitespace()
        .collect()
}

/// Strip Option-preserving accessors from the outside of a receiver chain so
/// `x.as_ref().unwrap()` matches a guard on `x`. Opaque calls stay opaque:
/// `x.load().unwrap()` must not match a guard on `x` (the `Err` case remains).
fn strip_option_accessors(mut expr: &Expr) -> &Expr {
    while let Expr::MethodCall(m) = expr {
        if m.args.is_empty() && (m.method == "as_ref" || m.method == "as_mut") {
            expr = &m.receiver;
        } else {
            break;
        }
    }
    expr
}

fn unwrap_base_key(receiver: &Expr) -> String {
    token_key(strip_option_accessors(receiver))
}

/// Key for a guard — only stable paths/field chains qualify. A guard on
/// `foo()` says nothing about a later call to `foo()`.
fn guarded_key(checkee: &Expr) -> Option<String> {
    let stripped = strip_option_accessors(checkee);
    is_stable_path(stripped).then(|| token_key(stripped))
}

fn is_stable_path(expr: &Expr) -> bool {
    match expr {
        Expr::Path(_) => true,
        Expr::Field(f) => is_stable_path(&f.base),
        Expr::Index(i) => is_stable_path(&i.expr),
        Expr::Paren(p) => is_stable_path(&p.expr),
        Expr::Group(g) => is_stable_path(&g.expr),
        Expr::Reference(r) => is_stable_path(&r.expr),
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => is_stable_path(&u.expr),
        _ => false,
    }
}

fn is_some_object(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Paren(p) => is_some_object(&p.expr),
        Expr::MethodCall(m) if m.args.is_empty() && m.method == "is_some" => {
            guarded_key(&m.receiver)
        }
        _ => None,
    }
}

fn is_none_object(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Paren(p) => is_none_object(&p.expr),
        Expr::MethodCall(m) if m.args.is_empty() && m.method == "is_none" => {
            guarded_key(&m.receiver)
        }
        _ => None,
    }
}

/// Bases proven `Some` when `expr` evaluates to true.
fn truth_implies_some(expr: &Expr) -> Vec<String> {
    match expr {
        Expr::Paren(p) => truth_implies_some(&p.expr),
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Not(_)) => falsity_implies_some(&u.expr),
        _ => {
            if let Some(key) = is_some_object(expr) {
                return vec![key];
            }
            if let Expr::Binary(b) = expr {
                if matches!(b.op, syn::BinOp::And(_)) {
                    let mut operands = Vec::new();
                    flatten_and_operand(expr, &mut operands);
                    return operands
                        .iter()
                        .flat_map(|op| truth_implies_some(op))
                        .collect();
                }
            }
            Vec::new()
        }
    }
}

/// Bases proven `Some` when `expr` evaluates to false.
fn falsity_implies_some(expr: &Expr) -> Vec<String> {
    match expr {
        Expr::Paren(p) => falsity_implies_some(&p.expr),
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Not(_)) => truth_implies_some(&u.expr),
        _ => {
            if let Some(key) = is_none_object(expr) {
                return vec![key];
            }
            if let Expr::Binary(b) = expr {
                if matches!(b.op, syn::BinOp::Or(_)) {
                    let mut operands = Vec::new();
                    flatten_or_operand(expr, &mut operands);
                    return operands
                        .iter()
                        .flat_map(|op| falsity_implies_some(op))
                        .collect();
                }
            }
            Vec::new()
        }
    }
}

fn flatten_and_operand<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    match expr {
        Expr::Paren(p) => flatten_and_operand(&p.expr, out),
        Expr::Binary(b) if matches!(b.op, syn::BinOp::And(_)) => {
            flatten_and_operand(&b.left, out);
            flatten_and_operand(&b.right, out);
        }
        other => out.push(other),
    }
}

fn flatten_or_operand<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    match expr {
        Expr::Paren(p) => flatten_or_operand(&p.expr, out),
        Expr::Binary(b) if matches!(b.op, syn::BinOp::Or(_)) => {
            flatten_or_operand(&b.left, out);
            flatten_or_operand(&b.right, out);
        }
        other => out.push(other),
    }
}

/// Proofs a statement establishes for the statements after it:
/// - `require!(x.is_some(), …)` / `assert!(…)` — returning means the cond held;
/// - a then-branch that always diverges — reaching the next statement means the
///   condition was false (`is_none()` in an `||` chain therefore proves `Some`).
fn stmt_persistent_guards(stmt: &Stmt) -> Vec<String> {
    match stmt {
        Stmt::Macro(sm) => require_style_guards(&sm.mac),
        Stmt::Expr(Expr::Macro(m), _) => require_style_guards(&m.mac),
        Stmt::Expr(Expr::If(i), _) => {
            let mut keys = Vec::new();
            if block_diverges(&i.then_branch) {
                keys.extend(falsity_implies_some(&i.cond));
            }
            if let Some((_, else_expr)) = &i.else_branch {
                if expr_diverges(else_expr) {
                    keys.extend(truth_implies_some(&i.cond));
                }
            }
            keys
        }
        _ => Vec::new(),
    }
}

fn stmt_require_guards(stmt: &Stmt) -> Vec<String> {
    match stmt {
        Stmt::Macro(sm) => require_style_guards(&sm.mac),
        Stmt::Expr(Expr::Macro(m), _) => require_style_guards(&m.mac),
        _ => Vec::new(),
    }
}

fn require_style_guards(mac: &Macro) -> Vec<String> {
    let Some(ident) = mac.path.segments.last().map(|s| s.ident.to_string()) else {
        return Vec::new();
    };
    if !(ident.starts_with("require") || ident.starts_with("assert")) {
        return Vec::new();
    }
    macro_expr_args(&mac.tokens)
        .and_then(|args| args.first().map(truth_implies_some))
        .unwrap_or_default()
}

// --- Divergence ---------------------------------------------------------------
// Conservative: only proof-carrying shapes count. Anything unsure returns false,
// which keeps the unwrap flagged.

fn block_diverges(block: &Block) -> bool {
    block.stmts.iter().any(stmt_diverges)
}

fn stmt_diverges(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr(expr, _) => expr_diverges(expr),
        _ => false,
    }
}

fn expr_diverges(expr: &Expr) -> bool {
    match expr {
        Expr::Return(_) | Expr::Break(_) | Expr::Continue(_) => true,
        Expr::Block(b) => block_diverges(&b.block),
        Expr::Paren(p) => expr_diverges(&p.expr),
        Expr::If(i) => {
            block_diverges(&i.then_branch)
                && i.else_branch
                    .as_ref()
                    .is_some_and(|(_, else_expr)| expr_diverges(else_expr))
        }
        Expr::Try(t) => expr_is_err(&t.expr),
        Expr::Macro(m) => m.mac.path.segments.last().is_some_and(|seg| {
            matches!(
                seg.ident.to_string().as_str(),
                "panic" | "unreachable" | "todo" | "unimplemented" | "bail"
            )
        }),
        _ => false,
    }
}

/// `Err(…)` — the constructor itself never returns `Ok`.
fn expr_is_err(expr: &Expr) -> bool {
    match expr {
        Expr::Call(c) => {
            let callee = token_key(&c.func);
            callee == "Err" || callee.ends_with("::Err")
        }
        Expr::Paren(p) => expr_is_err(&p.expr),
        _ => false,
    }
}

// --- Statement clobbers -------------------------------------------------------

#[derive(Default)]
struct ClobberCollector {
    mutations: Vec<String>,
}

impl<'ast> Visit<'ast> for ClobberCollector {
    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        self.mutations.push(mutation_key(&node.left));
        visit::visit_expr_assign(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if is_assign_op(&node.op) {
            self.mutations.push(mutation_key(&node.left));
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if matches!(
            node.method.to_string().as_str(),
            "take" | "replace" | "swap"
        ) {
            self.mutations.push(mutation_key(&node.receiver));
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_reference(&mut self, node: &'ast syn::ExprReference) {
        // Any `&mut x` passed to a callee can write through the borrow —
        // covers `normalize(&mut rate)` and `mem::take(&mut rate)` alike.
        if node.mutability.is_some() {
            self.mutations.push(mutation_key(&node.expr));
        }
        visit::visit_expr_reference(self, node);
    }
}

/// Base path a write lands on: strips parens / groups / derefs / references
/// outside-in, then the Option accessors, so `*rate = None`, `(*rate) = None`
/// and `rate.as_mut()` all key as `rate`.
fn mutation_key(expr: &Expr) -> String {
    let mut expr = expr;
    loop {
        match expr {
            Expr::Paren(p) => expr = &p.expr,
            Expr::Group(g) => expr = &g.expr,
            Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => expr = &u.expr,
            Expr::Reference(r) => expr = &r.expr,
            Expr::MethodCall(m)
                if m.args.is_empty() && (m.method == "as_ref" || m.method == "as_mut") =>
            {
                expr = &m.receiver
            }
            _ => break,
        }
    }
    token_key(expr)
}

struct Clobbers {
    mutations: Vec<String>,
}

fn clobbered_keys(stmt: &Stmt) -> Clobbers {
    let mut collector = ClobberCollector::default();
    collector.visit_stmt(stmt);
    Clobbers {
        mutations: collector.mutations,
    }
}

/// Names a `let` statement rebinds in its own block.
fn local_pat_bindings(pat: &syn::Pat) -> Vec<String> {
    struct Collector {
        keys: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Collector {
        fn visit_pat_ident(&mut self, node: &'ast PatIdent) {
            self.keys.push(node.ident.to_string());
            visit::visit_pat_ident(self, node);
        }
    }
    let mut collector = Collector { keys: Vec::new() };
    collector.visit_pat(pat);
    collector.keys
}

/// The guard `k` is dead after anything that clobbers `key`: exact match, or a
/// prefix mutation (`self.inner = …` invalidates a guard on `self.inner.fee`).
fn guard_clobbered_by(guard: &str, key: &str) -> bool {
    guard == key
        || guard
            .strip_prefix(key)
            .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('['))
}

/// Whether a mutation of `key` can affect `cond` — `key` must appear as a
/// whole binding in it. `amount` never matches inside `commission_amount`;
/// `rate` never matches inside `self.rate` (field vs local). But `config`
/// matches in `config.fee` — rebinding `config` changes that path too.
fn cond_mentions_ident(cond: &str, key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    cond.match_indices(key).any(|(at, _)| {
        let before = cond[..at].chars().next_back();
        let after = cond[at + key.len()..].chars().next();
        let before_ok = !before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.');
        let after_ok = !after.is_some_and(|c| c.is_alphanumeric() || c == '_');
        before_ok && after_ok
    })
}

fn is_assign_op(op: &syn::BinOp) -> bool {
    use syn::BinOp::*;
    matches!(
        op,
        AddAssign(_)
            | SubAssign(_)
            | MulAssign(_)
            | DivAssign(_)
            | RemAssign(_)
            | BitXorAssign(_)
            | BitAndAssign(_)
            | BitOrAssign(_)
            | ShlAssign(_)
            | ShrAssign(_)
    )
}

// --- Slice length bounds ------------------------------------------------------
//
// `.get(N).unwrap()` / `.last().unwrap()` on a slice whose length the file
// already requires cannot panic when `N` is below every required bound.
// Bounds are collected per FILE, not per variable: Anchor code usually
// requires `remaining.len()` once and indexes the slice later under another
// name or in another function, so one bound vouches for every `.get`/`.last`
// in the file. The smallest require wins — a stronger bound never quiets an
// index past a weaker one, so `N >= floor` stays flagged (past-end indexes
// included). Known tradeoff: an independent, shorter slice in the same file
// shares the floor, and `N < floor` on it is quieted without proof on that
// variable (docs/LIMITATIONS.md).

enum SliceAccess {
    Get(u64),
    Last,
    None,
}

fn slice_access(receiver: &Expr) -> SliceAccess {
    let Expr::MethodCall(m) = receiver else {
        return SliceAccess::None;
    };
    match m.method.to_string().as_str() {
        "last" if m.args.is_empty() => SliceAccess::Last,
        "get" => {
            let mut args = m.args.iter();
            let (
                Some(Expr::Lit(syn::ExprLit {
                    lit: Lit::Int(index),
                    ..
                })),
                None,
            ) = (args.next(), args.next())
            else {
                return SliceAccess::None;
            };
            index
                .base10_parse::<u64>()
                .ok()
                .map(SliceAccess::Get)
                .unwrap_or(SliceAccess::None)
        }
        _ => SliceAccess::None,
    }
}

fn file_len_require_floor(file: &syn::File) -> Option<u64> {
    let consts = collect_file_consts(&file.items);
    let mut collector = LenFloorCollector {
        floor: None,
        consts: &consts,
    };
    visit::visit_file(&mut collector, file);
    collector.floor
}

fn collect_file_consts(items: &[Item]) -> HashMap<String, Expr> {
    fn walk(items: &[Item], out: &mut HashMap<String, Expr>) {
        for item in items {
            match item {
                Item::Const(c) => {
                    out.insert(c.ident.to_string(), (*c.expr).clone());
                }
                Item::Mod(m) => {
                    if let Some((_, nested)) = &m.content {
                        walk(nested, out);
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = HashMap::new();
    walk(items, &mut out);
    out
}

struct LenFloorCollector<'a> {
    floor: Option<u64>,
    consts: &'a HashMap<String, Expr>,
}

impl LenFloorCollector<'_> {
    fn consider(&mut self, mac: &Macro) {
        let Some(ident) = mac.path.segments.last().map(|s| s.ident.to_string()) else {
            return;
        };
        if !(ident.starts_with("require") || ident.starts_with("assert")) {
            return;
        }
        let Some(args) = macro_expr_args(&mac.tokens) else {
            return;
        };
        let Some(cond) = args.first() else {
            return;
        };
        if let Some(bound) = find_len_bound(cond, self.consts, 0) {
            self.floor = Some(match self.floor {
                Some(existing) => existing.min(bound),
                None => bound,
            });
        }
    }
}

impl<'ast, 'a> Visit<'ast> for LenFloorCollector<'a> {
    fn visit_stmt(&mut self, node: &'ast Stmt) {
        if let Stmt::Macro(sm) = node {
            self.consider(&sm.mac);
        }
        visit::visit_stmt(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        self.consider(&node.mac);
        visit::visit_expr_macro(self, node);
    }
}

fn macro_expr_args(tokens: &proc_macro2::TokenStream) -> Option<Vec<Expr>> {
    let parser = syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated;
    let args = parser.parse2(tokens.clone()).ok()?;
    Some(args.into_iter().collect())
}

/// Sound lower bound of `cond`: a value the caller must have proven `>=` for
/// `cond` to hold. `||` yields nothing — the bound may be the operand that was
/// false.
fn find_len_bound(cond: &Expr, consts: &HashMap<String, Expr>, depth: u32) -> Option<u64> {
    if depth > 8 {
        return None;
    }
    match cond {
        Expr::Paren(p) => find_len_bound(&p.expr, consts, depth + 1),
        Expr::Binary(b) => match &b.op {
            syn::BinOp::Ge(_) | syn::BinOp::Gt(_) => {
                if is_len_call(&b.left) {
                    return resolve_usize(&b.right, consts, depth + 1);
                }
                if is_len_call(&b.right) {
                    return resolve_usize(&b.left, consts, depth + 1);
                }
                find_len_bound(&b.left, consts, depth + 1)
                    .or_else(|| find_len_bound(&b.right, consts, depth + 1))
            }
            syn::BinOp::And(_) => find_len_bound(&b.left, consts, depth + 1)
                .or_else(|| find_len_bound(&b.right, consts, depth + 1)),
            _ => None,
        },
        _ => None,
    }
}

fn is_len_call(expr: &Expr) -> bool {
    matches!(expr, Expr::MethodCall(m) if m.args.is_empty() && m.method == "len")
}

fn resolve_usize(expr: &Expr, consts: &HashMap<String, Expr>, depth: u32) -> Option<u64> {
    if depth > 8 {
        return None;
    }
    match expr {
        Expr::Lit(syn::ExprLit {
            lit: Lit::Int(int), ..
        }) => int.base10_parse().ok(),
        Expr::Cast(c) => resolve_usize(&c.expr, consts, depth + 1),
        Expr::Paren(p) => resolve_usize(&p.expr, consts, depth + 1),
        Expr::Path(p) => {
            let ident = p.path.get_ident()?;
            consts
                .get(&ident.to_string())
                .and_then(|value| resolve_usize(value, consts, depth + 1))
        }
        // `len >= *offset + ACCOUNTS_LEN`: every usize operand is ≥ 0, so
        // dropping an unresolvable one only weakens the bound — still sound.
        // Subtraction must not drop its right side (`len >= A - B` says nothing
        // about `A`), so only `+` is folded.
        Expr::Binary(b) if matches!(b.op, syn::BinOp::Add(_)) => {
            let left = resolve_usize(&b.left, consts, depth + 1);
            let right = resolve_usize(&b.right, consts, depth + 1);
            match (left, right) {
                (Some(a), Some(b)) => a.checked_add(b),
                (Some(a), None) | (None, Some(a)) => Some(a),
                (None, None) => None,
            }
        }
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

    fn findings_in(source: &str) -> Vec<RuleMatch> {
        let file = parse_file(source);
        UnwrapOnResultRule.match_file(&file, &RuleContext::files_only(std::slice::from_ref(&file)))
    }

    #[test]
    fn flags_unwrap_in_instruction() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, raw: &[u8]) -> Result<()> {
                let val: u64 = raw.try_into().unwrap();
                Ok(())
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW025");
    }

    #[test]
    fn flags_expect_in_instruction() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, amount: u64) -> Result<()> {
                let val = ctx.accounts.vault.amount.checked_add(amount).expect("overflow");
                Ok(())
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW025");
    }

    #[test]
    fn does_not_flag_unwrap_inside_test_fn() {
        let findings = findings_in(
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
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_question_mark_propagation() {
        let findings = findings_in(
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
        assert!(findings.is_empty());
    }

    #[test]
    fn dedupes_nested_unwrap_chain_to_one_finding() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, amount: u64) -> Result<()> {
                let amount_a = (amount as u128)
                    .checked_mul(ctx.accounts.pool.amount as u128)
                    .unwrap()
                    .checked_div(ctx.accounts.mint.supply as u128 + 100)
                    .unwrap() as u64;
                let _ = amount_a;
                Ok(())
            }
            "#,
        );
        assert_eq!(
            findings.len(),
            1,
            "one finding for the whole unwrap chain, got: {findings:?}"
        );
    }

    #[test]
    fn still_flags_separate_unwrap_statements() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Foo>, a: u64, b: u64) -> Result<()> {
                let x = a.checked_add(1).unwrap();
                let y = b.checked_mul(2).unwrap();
                let _ = (x, y);
                Ok(())
            }
            "#,
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn does_not_flag_pubkey_create_program_address_unwrap() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn helper(state: &Pubkey) -> Pubkey {
                Pubkey::create_program_address(&[state.as_ref(), b"reserve"], &crate::ID).unwrap()
            }
            "#,
        );
        assert!(
            findings.is_empty(),
            "Pubkey::create_* unwrap must be quiet: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_create_with_seed_unwrap() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn default_msol_leg(state: &Pubkey) -> Pubkey {
                Pubkey::create_with_seed(state, b"leg", &spl_token::ID).unwrap()
            }
            "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn does_not_flag_default_try_to_vec_unwrap() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Default)]
            pub struct ValidatorRecord { pub x: u64 }
            pub fn size() -> usize {
                ValidatorRecord::default().try_to_vec().unwrap().len()
            }
            "#,
        );
        assert!(
            findings.is_empty(),
            "default().try_to_vec() unwrap must be quiet: {findings:?}"
        );
    }

    #[test]
    fn still_flags_user_input_try_into_unwrap() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn process(raw: Vec<u8>) -> Result<()> {
                let amount = u64::from_le_bytes(raw.try_into().unwrap());
                let _ = amount;
                Ok(())
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_unwrap_in_cfg_test_helper() {
        let findings = findings_in(
            r#"
            #[cfg(test)]
            pub mod test {
                pub fn check_curve_value_from_swap(amount: u128) -> u128 {
                    amount.checked_add(1).unwrap()
                }
            }
            "#,
        );
        assert!(
            findings.is_empty(),
            "#[cfg(test)] helpers are not in the program: {findings:?}"
        );
    }

    #[test]
    fn still_flags_unwrap_under_cfg_not_test() {
        let findings = findings_in(
            r#"
            #[cfg(not(test))]
            pub fn handler(amount: u64) -> u64 {
                amount.checked_add(1).unwrap()
            }
            "#,
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    // --- Guard awareness (issue #30) ------------------------------------------

    #[test]
    fn quiets_unwrap_after_require_is_some() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(commission: Option<u64>) -> Result<()> {
                require!(commission.is_some(), ErrorCode::CommissionIsNone);
                let c = commission.as_ref().unwrap();
                msg!("{}", c);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { CommissionIsNone }
            "#,
        );
        assert!(findings.is_empty(), "require! dominates: {findings:?}");
    }

    #[test]
    fn quiets_unwrap_after_is_none_early_exit() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(rate: Option<u64>) -> Result<()> {
                if rate.is_none() || rate.unwrap() == 0 {
                    return Ok(());
                }
                msg!("{}", rate.unwrap());
                Ok(())
            }
            "#,
        );
        assert!(
            findings.is_empty(),
            "is_none early-exit dominates the rest: {findings:?}"
        );
    }

    #[test]
    fn quiets_unwrap_in_else_of_is_none() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(seeds: Option<Vec<Vec<u8>>>) -> Result<()> {
                if seeds.is_none() {
                    msg!("missing seeds");
                } else {
                    invoke_signed_with(seeds.unwrap());
                }
                Ok(())
            }
            fn invoke_signed_with(_s: Vec<Vec<u8>>) {}
            "#,
        );
        assert!(
            findings.is_empty(),
            "else of is_none means Some: {findings:?}"
        );
    }

    #[test]
    fn quiets_unwrap_behind_is_some_short_circuit() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(fee: Option<u64>, authority: Pubkey) -> Result<()> {
                if fee.is_some() && fee.as_ref().unwrap() == &authority.to_bytes()[0] as u64 {
                    msg!("match");
                }
                Ok(())
            }
            "#,
        );
        assert!(
            findings.is_empty(),
            "is_some() && … short-circuits into the unwrap: {findings:?}"
        );
    }

    #[test]
    fn quiets_unwrap_in_nested_block_after_guard() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(commission: Option<u64>) -> Result<()> {
                require!(commission.is_some(), ErrorCode::Missing);
                if true {
                    let c = commission.as_ref().unwrap();
                    msg!("{}", c);
                }
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { Missing }
            "#,
        );
        assert!(
            findings.is_empty(),
            "guards inherit into blocks: {findings:?}"
        );
    }

    #[test]
    fn still_flags_unwrap_when_guard_uses_different_variable() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(commission: Option<u64>, other: Option<u64>) -> Result<()> {
                require!(commission.is_some(), ErrorCode::Missing);
                let v = other.unwrap();
                msg!("{}", v);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { Missing }
            "#,
        );
        assert_eq!(
            findings.len(),
            1,
            "proof on commission says nothing about other"
        );
    }

    #[test]
    fn still_flags_unwrap_after_reassignment_clobbers_guard() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler() -> Result<()> {
                let mut rate: Option<u64> = Some(1);
                require!(rate.is_some(), ErrorCode::Missing);
                rate = None;
                let v = rate.unwrap();
                msg!("{}", v);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { Missing }
            "#,
        );
        assert_eq!(
            findings.len(),
            1,
            "assignment invalidates the guard: {findings:?}"
        );
    }

    #[test]
    fn still_flags_unwrap_after_take_clobbers_guard() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler() -> Result<()> {
                let mut rate: Option<u64> = Some(1);
                require!(rate.is_some(), ErrorCode::Missing);
                rate.take();
                let v = rate.unwrap();
                msg!("{}", v);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { Missing }
            "#,
        );
        assert_eq!(findings.len(), 1, "Option::take invalidates: {findings:?}");
    }

    #[test]
    fn still_flags_unwraps_after_mem_swap_clobbers_both_guards() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(mut a: Option<u64>, mut b: Option<u64>) -> Result<()> {
                require!(a.is_some(), ErrorCode::Missing);
                require!(b.is_some(), ErrorCode::Missing);
                std::mem::swap(&mut a, &mut b);
                let x = a.unwrap();
                let y = b.unwrap();
                msg!("{} {}", x, y);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { Missing }
            "#,
        );
        assert_eq!(
            findings.len(),
            2,
            "swap writes through both &mut args, killing both guards: {findings:?}"
        );
    }

    #[test]
    fn still_flags_unwrap_after_mem_take_clobbers_guard() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler() -> Result<()> {
                let mut rate: Option<u64> = Some(1);
                require!(rate.is_some(), ErrorCode::Missing);
                std::mem::take(&mut rate);
                let v = rate.unwrap();
                msg!("{}", v);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { Missing }
            "#,
        );
        assert_eq!(
            findings.len(),
            1,
            "mem::take(&mut x) invalidates: {findings:?}"
        );
    }

    #[test]
    fn still_flags_unwrap_when_is_none_exit_is_not_unconditional() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(rate: Option<u64>, fast: bool) -> Result<()> {
                if rate.is_none() && fast {
                    return Ok(());
                }
                let v = rate.unwrap();
                msg!("{}", v);
                Ok(())
            }
            "#,
        );
        assert_eq!(
            findings.len(),
            1,
            "`x.is_none() && y` can fall through with x == None: {findings:?}"
        );
    }

    #[test]
    fn still_flags_unwrap_when_is_some_proof_is_from_call() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            fn load() -> Option<u64> { None }
            pub fn handler() -> Result<()> {
                require!(load().is_some(), ErrorCode::Missing);
                let v = load().unwrap();
                msg!("{}", v);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { Missing }
            "#,
        );
        assert_eq!(
            findings.len(),
            1,
            "a proof about one call does not cover the next: {findings:?}"
        );
    }

    #[test]
    fn quiets_unwrap_behind_matching_conditional_require() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(commission_amount: u64, commission_account: Option<u64>) -> Result<()> {
                if commission_amount > 0 {
                    require!(commission_account.is_some(), ErrorCode::CommissionIsNone);
                }
                if true {
                    if commission_amount > 0 {
                        let c = commission_account.as_ref().unwrap();
                        msg!("{}", c);
                    }
                }
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { CommissionIsNone }
            "#,
        );
        assert!(
            findings.is_empty(),
            "same condition re-checked: {findings:?}"
        );
    }

    #[test]
    fn still_flags_conditional_require_under_different_condition() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(commission_amount: u64, other: u64, commission_account: Option<u64>) -> Result<()> {
                if commission_amount > 0 {
                    require!(commission_account.is_some(), ErrorCode::CommissionIsNone);
                }
                if other > 0 {
                    let c = commission_account.as_ref().unwrap();
                    msg!("{}", c);
                }
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { CommissionIsNone }
            "#,
        );
        assert_eq!(findings.len(), 1, "different condition: {findings:?}");
    }

    #[test]
    fn quiets_conditional_unwrap_even_when_sibling_block_shadows_the_name() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(commission_amount: u64, commission_account: Option<u64>) -> Result<()> {
                if commission_amount > 0 {
                    require!(commission_account.is_some(), ErrorCode::CommissionIsNone);
                }
                if commission_amount > 0 {
                    let commission_account = commission_account.as_ref().unwrap();
                    msg!("{}", commission_account);
                }
                if commission_amount > 0 {
                    let c = commission_account.as_ref().unwrap();
                    msg!("{}", c);
                }
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { CommissionIsNone }
            "#,
        );
        assert!(
            findings.is_empty(),
            "shadow ends with its own block: {findings:?}"
        );
    }

    #[test]
    fn still_flags_conditional_unwrap_when_name_shadowed_in_same_block() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(commission_amount: u64, commission_account: Option<u64>) -> Result<()> {
                if commission_amount > 0 {
                    require!(commission_account.is_some(), ErrorCode::CommissionIsNone);
                }
                if commission_amount > 0 {
                    let commission_account = commission_account.as_ref().unwrap();
                    let c = commission_account.as_ref().unwrap();
                    msg!("{}", c);
                }
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { CommissionIsNone }
            "#,
        );
        assert_eq!(
            findings.len(),
            1,
            "after the rebinding the old proof must not apply: {findings:?}"
        );
    }

    #[test]
    fn still_flags_conditional_require_after_condition_variable_mutated() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(mut commission_amount: u64, commission_account: Option<u64>) -> Result<()> {
                if commission_amount > 0 {
                    require!(commission_account.is_some(), ErrorCode::CommissionIsNone);
                }
                commission_amount = 0;
                if commission_amount > 0 {
                    let c = commission_account.as_ref().unwrap();
                    msg!("{}", c);
                }
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { CommissionIsNone }
            "#,
        );
        assert_eq!(
            findings.len(),
            1,
            "mutating the condition invalidates the conditional proof: {findings:?}"
        );
    }

    #[test]
    fn flags_unwrap_after_mut_reference_pass() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            fn normalize(rate: &mut Option<u64>) {
                *rate = None;
            }
            pub fn handler(mut rate: Option<u64>) -> Result<()> {
                require!(rate.is_some(), ErrorCode::MissingRate);
                normalize(&mut rate);
                let c = rate.as_ref().unwrap();
                msg!("{}", c);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { MissingRate }
            "#,
        );
        assert_eq!(
            findings.len(),
            1,
            "&mut pass can reset the value: {findings:?}"
        );
    }

    #[test]
    fn flags_unwrap_after_deref_assignment() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(rate: &mut Option<u64>) -> Result<()> {
                require!(rate.is_some(), ErrorCode::MissingRate);
                *rate = None;
                let c = rate.as_ref().unwrap();
                msg!("{}", c);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { MissingRate }
            "#,
        );
        assert_eq!(
            findings.len(),
            1,
            "`*rate = None` invalidates the proof: {findings:?}"
        );
    }

    #[test]
    fn quiets_when_mut_reference_passes_a_different_binding() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            fn bump(counter: &mut u64) {
                *counter += 1;
            }
            pub fn handler(rate: Option<u64>, mut counter: u64) -> Result<()> {
                require!(rate.is_some(), ErrorCode::MissingRate);
                bump(&mut counter);
                let c = rate.as_ref().unwrap();
                msg!("{}", c);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { MissingRate }
            "#,
        );
        assert!(
            findings.is_empty(),
            "&mut on another binding says nothing about rate: {findings:?}"
        );
    }

    #[test]
    fn quiets_conditional_unwrap_when_only_name_prefix_of_condition_mutated() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(mut commission_amount: u64, amount: u64, commission_account: Option<u64>) -> Result<()> {
                if commission_amount > 0 {
                    require!(commission_account.is_some(), ErrorCode::CommissionIsNone);
                }
                let mut amount = amount;
                amount = 0;
                if commission_amount > 0 {
                    let c = commission_account.as_ref().unwrap();
                    msg!("{}", c);
                }
                let _ = amount;
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { CommissionIsNone }
            "#,
        );
        assert!(
            findings.is_empty(),
            "mutating `amount` must not invalidate a condition on `commission_amount`: {findings:?}"
        );
    }

    #[test]
    fn quiets_get_within_same_file_len_require() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            const ACCOUNTS_LEN: usize = 16;
            pub fn swap(remaining: &[AccountInfo], offset: &mut usize) -> Result<()> {
                require!(
                    remaining.len() >= *offset + ACCOUNTS_LEN,
                    ErrorCode::InvalidAccountsLength
                );
                Ok(())
            }
            pub fn hook(accounts: &[AccountInfo]) -> Result<()> {
                let payer = accounts.get(6).unwrap();
                msg!("{}", payer.key);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { InvalidAccountsLength }
            "#,
        );
        assert!(findings.is_empty(), "6 < ACCOUNTS_LEN: {findings:?}");
    }

    #[test]
    fn quiets_last_within_same_file_len_require() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            const ACCOUNTS_LEN: usize = 4;
            pub fn swap(remaining: &[AccountInfo]) -> Result<()> {
                require!(remaining.len() >= ACCOUNTS_LEN, ErrorCode::InvalidAccountsLength);
                Ok(())
            }
            pub fn hook(accounts: &[AccountInfo]) -> Result<()> {
                let payer = accounts.last().unwrap();
                msg!("{}", payer.key);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { InvalidAccountsLength }
            "#,
        );
        assert!(findings.is_empty(), "len >= 4 proves index 0: {findings:?}");
    }

    #[test]
    fn still_flags_get_at_or_past_len_require() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            const ACCOUNTS_LEN: usize = 16;
            pub fn swap(remaining: &[AccountInfo], offset: &mut usize) -> Result<()> {
                require!(
                    remaining.len() >= *offset + ACCOUNTS_LEN,
                    ErrorCode::InvalidAccountsLength
                );
                Ok(())
            }
            pub fn hook(accounts: &[AccountInfo]) -> Result<()> {
                let payer = accounts.get(16).unwrap();
                msg!("{}", payer.key);
                Ok(())
            }
            #[error_code]
            pub enum ErrorCode { InvalidAccountsLength }
            "#,
        );
        assert_eq!(
            findings.len(),
            1,
            "index == floor is not proven in-bounds: {findings:?}"
        );
    }

    #[test]
    fn still_flags_get_without_len_require() {
        let findings = findings_in(
            r#"
            use anchor_lang::prelude::*;
            pub fn hook(accounts: &[AccountInfo]) -> Result<()> {
                let payer = accounts.get(6).unwrap();
                msg!("{}", payer.key);
                Ok(())
            }
            "#,
        );
        assert_eq!(findings.len(), 1, "no length proof in file: {findings:?}");
    }
}
