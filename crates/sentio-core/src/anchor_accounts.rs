use quote::ToTokens;
use serde::Serialize;
use syn::meta::ParseNestedMeta;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Attribute, Fields, GenericArgument, Path, PathArguments, Token, Type, TypePath};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorAccountsIndex {
    pub structs: Vec<AnchorAccountsStruct>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorAccountsStruct {
    pub name: String,
    pub span: AnchorSpan,
    pub fields: Vec<AnchorAccountsField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorAccountsField {
    pub name: String,
    pub ty: String,
    pub type_info: AnchorFieldType,
    pub constraints: AnchorFieldConstraints,
    pub span: AnchorSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorFieldType {
    pub kind: AnchorFieldTypeKind,
    pub display: String,
    pub wrappers: Vec<AnchorTypeWrapper>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorFieldTypeKind {
    Account,
    AccountInfo,
    AccountLoader,
    InterfaceAccount,
    Program,
    Signer,
    SystemAccount,
    UncheckedAccount,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorTypeWrapper {
    pub kind: AnchorTypeWrapperKind,
    pub inner: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorTypeWrapperKind {
    Box,
    Ref,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct AnchorFieldConstraints {
    pub items: Vec<AnchorConstraint>,
    pub is_signer: bool,
    pub is_mut: bool,
    pub has_one: Vec<String>,
    pub has_constraint: bool,
    pub has_seeds: bool,
    pub has_bump: bool,
    pub owner: bool,
    pub address: bool,
    pub token_mint: bool,
    pub token_authority: bool,
    pub init: bool,
    pub init_if_needed: bool,
    pub realloc: bool,
    pub realloc_zero: bool,
    pub close: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorConstraint {
    pub path: String,
    pub kind: AnchorConstraintKind,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorConstraintKind {
    Signer,
    Mut,
    HasOne,
    Constraint,
    Seeds,
    Bump,
    Owner,
    Address,
    TokenMint,
    TokenAuthority,
    Init,
    InitIfNeeded,
    Realloc,
    ReallocZero,
    Close,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AnchorSpan {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

pub fn collect_anchor_accounts_index(file: &syn::File) -> AnchorAccountsIndex {
    let mut structs = Vec::new();
    collect_from_items(&file.items, &mut structs);

    AnchorAccountsIndex { structs }
}

fn collect_from_items(items: &[syn::Item], structs: &mut Vec<AnchorAccountsStruct>) {
    for item in items {
        match item {
            syn::Item::Struct(item) => collect_struct(item, structs),
            syn::Item::Mod(module) => {
                if let Some((_, nested_items)) = &module.content {
                    collect_from_items(nested_items, structs);
                }
            }
            _ => {}
        }
    }
}

fn collect_struct(item: &syn::ItemStruct, structs: &mut Vec<AnchorAccountsStruct>) {
    if !has_anchor_accounts_derive(&item.attrs) {
        return;
    }

    let mut fields = Vec::new();
    if let Fields::Named(named) = &item.fields {
        for field in &named.named {
            let Some(name) = field.ident.as_ref().map(|ident| ident.to_string()) else {
                continue;
            };

            fields.push(AnchorAccountsField {
                name,
                ty: type_to_string(&field.ty),
                type_info: classify_field_type(&field.ty),
                constraints: collect_field_constraints(&field.attrs),
                span: span_of(field.span()),
            });
        }
    }

    structs.push(AnchorAccountsStruct {
        name: item.ident.to_string(),
        span: span_of(item.ident.span()),
        fields,
    });
}

fn has_anchor_accounts_derive(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }

        attr.parse_args_with(Punctuated::<Path, Token![,]>::parse_terminated)
            .map(|paths| paths.iter().any(|path| path.is_ident("Accounts")))
            .unwrap_or(false)
    })
}

fn collect_field_constraints(attrs: &[Attribute]) -> AnchorFieldConstraints {
    let mut constraints = AnchorFieldConstraints::default();

    for attr in attrs {
        if !attr.path().is_ident("account") {
            continue;
        }

        let _ = attr.parse_nested_meta(|meta| {
            let path = path_to_string(&meta.path);
            let value = if meta.input.peek(Token![=]) {
                Some(parse_nested_value(&meta)?)
            } else {
                None
            };
            let constraint = AnchorConstraint {
                kind: constraint_kind(&meta.path),
                path,
                value,
            };
            constraints.push(constraint);
            Ok(())
        });
    }

    constraints
}

impl AnchorFieldConstraints {
    fn push(&mut self, constraint: AnchorConstraint) {
        match &constraint.kind {
            AnchorConstraintKind::Signer => self.is_signer = true,
            AnchorConstraintKind::Mut => self.is_mut = true,
            AnchorConstraintKind::HasOne => {
                if let Some(value) = constraint.value.clone() {
                    self.has_one.push(value);
                }
            }
            AnchorConstraintKind::Constraint => self.has_constraint = true,
            AnchorConstraintKind::Seeds => self.has_seeds = true,
            AnchorConstraintKind::Bump => self.has_bump = true,
            AnchorConstraintKind::Owner => self.owner = true,
            AnchorConstraintKind::Address => self.address = true,
            AnchorConstraintKind::TokenMint => self.token_mint = true,
            AnchorConstraintKind::TokenAuthority => self.token_authority = true,
            AnchorConstraintKind::Init => self.init = true,
            AnchorConstraintKind::InitIfNeeded => self.init_if_needed = true,
            AnchorConstraintKind::Realloc => self.realloc = true,
            AnchorConstraintKind::ReallocZero => self.realloc_zero = true,
            AnchorConstraintKind::Close => self.close = true,
            AnchorConstraintKind::Custom => {
                // Keep custom constraints in the index for future rule work.
            }
        }

        self.items.push(constraint);
    }
}

fn parse_nested_value(meta: &ParseNestedMeta<'_>) -> syn::Result<String> {
    let value_stream = meta.value()?;
    let mut tokens = proc_macro2::TokenStream::new();

    while !value_stream.is_empty() && !value_stream.peek(Token![,]) {
        let token_tree: proc_macro2::TokenTree = value_stream.parse()?;
        tokens.extend(std::iter::once(token_tree));
    }

    Ok(tokens.to_string())
}

fn constraint_kind(path: &Path) -> AnchorConstraintKind {
    if path.is_ident("signer") {
        AnchorConstraintKind::Signer
    } else if path.is_ident("mut") {
        AnchorConstraintKind::Mut
    } else if path.is_ident("has_one") {
        AnchorConstraintKind::HasOne
    } else if path.is_ident("constraint") {
        AnchorConstraintKind::Constraint
    } else if path.is_ident("seeds") {
        AnchorConstraintKind::Seeds
    } else if path.is_ident("bump") {
        AnchorConstraintKind::Bump
    } else if path.is_ident("owner") {
        AnchorConstraintKind::Owner
    } else if path.is_ident("address") {
        AnchorConstraintKind::Address
    } else if path_matches(path, &["token", "mint"]) {
        AnchorConstraintKind::TokenMint
    } else if path_matches(path, &["token", "authority"]) {
        AnchorConstraintKind::TokenAuthority
    } else if path.is_ident("init") {
        AnchorConstraintKind::Init
    } else if path.is_ident("init_if_needed") {
        AnchorConstraintKind::InitIfNeeded
    } else if path.is_ident("realloc") {
        AnchorConstraintKind::Realloc
    } else if path_matches(path, &["realloc", "zero"]) {
        AnchorConstraintKind::ReallocZero
    } else if path.is_ident("close") {
        AnchorConstraintKind::Close
    } else {
        AnchorConstraintKind::Custom
    }
}

fn path_matches(path: &Path, expected: &[&str]) -> bool {
    path.segments.len() == expected.len()
        && path
            .segments
            .iter()
            .zip(expected.iter())
            .all(|(segment, expected)| segment.ident == *expected)
}

fn classify_field_type(ty: &Type) -> AnchorFieldType {
    let display = type_to_string(ty);
    let (kind, wrappers) = classify_field_type_inner(ty);

    AnchorFieldType {
        kind,
        display,
        wrappers,
    }
}

fn classify_field_type_inner(ty: &Type) -> (AnchorFieldTypeKind, Vec<AnchorTypeWrapper>) {
    match ty {
        Type::Reference(reference) => {
            let inner_display = type_to_string(&reference.elem);
            let (kind, mut wrappers) = classify_field_type_inner(&reference.elem);
            wrappers.insert(
                0,
                AnchorTypeWrapper {
                    kind: AnchorTypeWrapperKind::Ref,
                    inner: inner_display,
                },
            );
            (kind, wrappers)
        }
        Type::Paren(paren) => classify_field_type_inner(&paren.elem),
        Type::Group(group) => classify_field_type_inner(&group.elem),
        Type::Path(type_path) => classify_type_path(type_path),
        _ => (AnchorFieldTypeKind::Other, Vec::new()),
    }
}

fn classify_type_path(type_path: &TypePath) -> (AnchorFieldTypeKind, Vec<AnchorTypeWrapper>) {
    let Some(segment) = type_path.path.segments.last() else {
        return (AnchorFieldTypeKind::Other, Vec::new());
    };

    let ident = segment.ident.to_string();
    if ident == "Box" {
        if let Some(inner_ty) = first_type_argument(&segment.arguments) {
            let inner_display = type_to_string(inner_ty);
            let (kind, mut wrappers) = classify_field_type_inner(inner_ty);
            wrappers.insert(
                0,
                AnchorTypeWrapper {
                    kind: AnchorTypeWrapperKind::Box,
                    inner: inner_display,
                },
            );
            return (kind, wrappers);
        }

        return (AnchorFieldTypeKind::Other, Vec::new());
    }

    let kind = match ident.as_str() {
        "Account" => AnchorFieldTypeKind::Account,
        "AccountInfo" => AnchorFieldTypeKind::AccountInfo,
        "AccountLoader" => AnchorFieldTypeKind::AccountLoader,
        "InterfaceAccount" => AnchorFieldTypeKind::InterfaceAccount,
        "Program" => AnchorFieldTypeKind::Program,
        "Signer" => AnchorFieldTypeKind::Signer,
        "SystemAccount" => AnchorFieldTypeKind::SystemAccount,
        "UncheckedAccount" => AnchorFieldTypeKind::UncheckedAccount,
        _ => AnchorFieldTypeKind::Other,
    };

    (kind, Vec::new())
}

fn first_type_argument(arguments: &PathArguments) -> Option<&Type> {
    let PathArguments::AngleBracketed(args) = arguments else {
        return None;
    };

    args.args.iter().find_map(|arg| match arg {
        GenericArgument::Type(ty) => Some(ty),
        _ => None,
    })
}

fn path_to_string(path: &Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string().trim_start_matches("r#").to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn type_to_string(ty: &Type) -> String {
    ty.to_token_stream().to_string()
}

fn span_of(span: proc_macro2::Span) -> AnchorSpan {
    let start = span.start();
    let end = span.end();

    AnchorSpan {
        start_line: start.line,
        start_column: start.column,
        end_line: end.line,
        end_column: end.column,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_file(source: &str) -> syn::File {
        syn::parse_file(source).expect("source should parse")
    }

    #[test]
    fn extracts_accounts_structs_only() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Update<'info> {
                pub authority: Signer<'info>,
            }

            pub struct Ignored {
                pub value: u64,
            }
            "#,
        );

        let index = collect_anchor_accounts_index(&file);
        assert_eq!(index.structs.len(), 1);
        assert_eq!(index.structs[0].name, "Update");
        assert_eq!(index.structs[0].fields.len(), 1);
    }

    #[test]
    fn classifies_field_types_and_wrappers() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Types<'info> {
                pub a: Account<'info, Data>,
                pub b: AccountLoader<'info, Data>,
                pub c: InterfaceAccount<'info, Data>,
                pub d: Program<'info, System>,
                pub e: Signer<'info>,
                pub f: SystemAccount<'info>,
                pub g: UncheckedAccount<'info>,
                pub h: Box<Account<'info, Data>>,
                pub i: &'info AccountInfo<'info>,
            }
            "#,
        );

        let index = collect_anchor_accounts_index(&file);
        let fields = &index.structs[0].fields;

        assert_eq!(fields[0].type_info.kind, AnchorFieldTypeKind::Account);
        assert_eq!(fields[1].type_info.kind, AnchorFieldTypeKind::AccountLoader);
        assert_eq!(fields[2].type_info.kind, AnchorFieldTypeKind::InterfaceAccount);
        assert_eq!(fields[3].type_info.kind, AnchorFieldTypeKind::Program);
        assert_eq!(fields[4].type_info.kind, AnchorFieldTypeKind::Signer);
        assert_eq!(fields[5].type_info.kind, AnchorFieldTypeKind::SystemAccount);
        assert_eq!(fields[6].type_info.kind, AnchorFieldTypeKind::UncheckedAccount);
        assert_eq!(fields[7].type_info.kind, AnchorFieldTypeKind::Account);
        assert_eq!(fields[7].type_info.wrappers[0].kind, AnchorTypeWrapperKind::Box);
        assert_eq!(fields[8].type_info.kind, AnchorFieldTypeKind::AccountInfo);
        assert_eq!(fields[8].type_info.wrappers[0].kind, AnchorTypeWrapperKind::Ref);
    }

    #[test]
    fn parses_account_constraints() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Constraints<'info> {
                #[account(mut, signer, has_one = authority, constraint = vault.data_len() > 0, seeds = [b"vault"], bump, owner = program.key(), address = account.key(), token::mint = mint.key(), token::authority = authority.key(), init, init_if_needed, realloc = 128, realloc::zero = true, close = authority)]
                pub vault: Account<'info, Vault>,
            }
            "#,
        );

        let index = collect_anchor_accounts_index(&file);
        let constraints = &index.structs[0].fields[0].constraints;

        assert!(constraints.is_mut);
        assert!(constraints.is_signer);
        assert_eq!(constraints.has_one, vec!["authority"]);
        assert!(constraints.has_constraint);
        assert!(constraints.has_seeds);
        assert!(constraints.has_bump);
        assert!(constraints.owner);
        assert!(constraints.address);
        assert!(constraints.token_mint);
        assert!(constraints.token_authority);
        assert!(constraints.init);
        assert!(constraints.init_if_needed);
        assert!(constraints.realloc);
        assert!(constraints.realloc_zero);
        assert!(constraints.close);
        assert!(constraints.items.iter().any(|item| item.kind == AnchorConstraintKind::Mut));
        assert!(constraints.items.iter().any(|item| {
            item.path == "constraint"
                && item
                    .value
                    .as_deref()
                    .is_some_and(|value| value.contains("data_len"))
        }));
        assert!(constraints
            .items
            .iter()
            .any(|item| item.path == "has_one" && item.value.as_deref() == Some("authority")));
        assert!(constraints.items.iter().any(|item| item.path == "realloc::zero"));
    }
}
