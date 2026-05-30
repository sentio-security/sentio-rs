use crate::ast_index::{ast_field_from_syn, ast_struct_from_syn, AstField, AstStruct};
use quote::ToTokens;
use serde::Serialize;
use syn::ext::IdentExt;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Attribute, Expr, GenericArgument, Item, ItemStruct, Path, PathArguments, Type, TypePath};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorAccountsIndex {
    pub structs: Vec<AnchorAccountsStruct>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorAccountsStruct {
    pub ast: AstStruct,
    pub fields: Vec<AnchorAccountsField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorAccountsField {
    pub ast: AstField,
    pub type_info: AnchorFieldType,
    pub constraints: AnchorFieldConstraints,
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

pub fn collect_anchor_accounts_index(file: &syn::File) -> AnchorAccountsIndex {
    let mut structs = Vec::new();
    collect_accounts_structs(&file.items, &mut structs);

    AnchorAccountsIndex { structs }
}

fn collect_accounts_structs(items: &[Item], structs: &mut Vec<AnchorAccountsStruct>) {
    for item in items {
        match item {
            Item::Struct(item_struct) => {
                if has_anchor_accounts_derive(&item_struct.attrs) {
                    structs.push(collect_accounts_struct(item_struct));
                }
            }
            Item::Mod(module) => {
                if let Some((_, nested_items)) = &module.content {
                    collect_accounts_structs(nested_items, structs);
                }
            }
            _ => {}
        }
    }
}

fn collect_accounts_struct(item: &ItemStruct) -> AnchorAccountsStruct {
    let ast = ast_struct_from_syn(item);

    let fields = item
        .fields
        .iter()
        .filter(|field| field.ident.is_some())
        .map(collect_anchor_field)
        .collect();

    AnchorAccountsStruct { ast, fields }
}

fn collect_anchor_field(field: &syn::Field) -> AnchorAccountsField {
    let ast = ast_field_from_syn(field);
    let type_info = classify_field_type(&ast.ty);
    let constraints = collect_field_constraints(&field.attrs);

    AnchorAccountsField {
        ast,
        type_info,
        constraints,
    }
}

fn has_anchor_accounts_derive(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }

        let mut found = false;
        let _ = attr.parse_nested_meta(|meta| {
            if normalize_syn_path(&meta.path) == "Accounts" {
                found = true;
            }
            Ok(())
        });
        found
    })
}

fn collect_field_constraints(attrs: &[Attribute]) -> AnchorFieldConstraints {
    let mut constraints = AnchorFieldConstraints::default();

    for attr in attrs {
        if !attr.path().is_ident("account") {
            continue;
        }

        let parser = Punctuated::<ParsedConstraintEntry, syn::Token![,]>::parse_terminated;
        let Ok(entries) = attr.parse_args_with(parser) else {
            continue;
        };

        for entry in entries {
            let constraint = AnchorConstraint {
                kind: constraint_kind(&entry.path),
                path: entry.path,
                value: entry.value.map(|expr| expr.to_token_stream().to_string()),
            };
            constraints.push(constraint);
        }
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
            AnchorConstraintKind::Custom => {}
        }

        self.items.push(constraint);
    }
}

fn constraint_kind(path: &str) -> AnchorConstraintKind {
    if path == "signer" {
        AnchorConstraintKind::Signer
    } else if path == "mut" {
        AnchorConstraintKind::Mut
    } else if path == "has_one" {
        AnchorConstraintKind::HasOne
    } else if path == "constraint" {
        AnchorConstraintKind::Constraint
    } else if path == "seeds" {
        AnchorConstraintKind::Seeds
    } else if path == "bump" {
        AnchorConstraintKind::Bump
    } else if path == "owner" {
        AnchorConstraintKind::Owner
    } else if path == "address" {
        AnchorConstraintKind::Address
    } else if path == "token::mint" {
        AnchorConstraintKind::TokenMint
    } else if path == "token::authority" {
        AnchorConstraintKind::TokenAuthority
    } else if path == "init" {
        AnchorConstraintKind::Init
    } else if path == "init_if_needed" {
        AnchorConstraintKind::InitIfNeeded
    } else if path == "realloc" {
        AnchorConstraintKind::Realloc
    } else if path == "realloc::zero" {
        AnchorConstraintKind::ReallocZero
    } else if path == "close" {
        AnchorConstraintKind::Close
    } else {
        AnchorConstraintKind::Custom
    }
}

fn classify_field_type(ty: &str) -> AnchorFieldType {
    match syn::parse_str::<Type>(ty) {
        Ok(ty) => classify_field_type_syn(&ty),
        Err(_) => AnchorFieldType {
            kind: AnchorFieldTypeKind::Other,
            display: ty.to_string(),
            wrappers: Vec::new(),
        },
    }
}

fn classify_field_type_syn(ty: &Type) -> AnchorFieldType {
    let display = ty.to_token_stream().to_string();
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

fn normalize_path(path: &str) -> String {
    let compact: String = path.split_whitespace().collect();
    compact
        .split("::")
        .map(|segment| segment.strip_prefix("r#").unwrap_or(segment))
        .collect::<Vec<_>>()
        .join("::")
}

fn normalize_syn_path(path: &Path) -> String {
    normalize_path(&path.to_token_stream().to_string())
}

fn type_to_string(ty: &Type) -> String {
    ty.to_token_stream().to_string()
}

struct ParsedConstraintEntry {
    path: String,
    value: Option<Expr>,
}

impl Parse for ParsedConstraintEntry {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let path = parse_constraint_path(input)?;
        let value = if input.peek(syn::Token![=]) {
            input.parse::<syn::Token![=]>()?;
            Some(input.parse::<Expr>()?)
        } else {
            None
        };

        Ok(Self { path, value })
    }
}

fn parse_constraint_path(input: ParseStream<'_>) -> syn::Result<String> {
    let mut segments = Vec::new();

    loop {
        let ident = input.call(syn::Ident::parse_any)?;
        segments.push(ident.to_string());

        if !input.peek(syn::Token![::]) {
            break;
        }

        input.parse::<syn::Token![::]>()?;
    }

    Ok(normalize_path(&segments.join("::")))
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
        assert_eq!(index.structs[0].ast.name, "Update");
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
