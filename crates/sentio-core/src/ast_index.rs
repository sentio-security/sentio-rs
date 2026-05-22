use quote::ToTokens;
use serde::Serialize;
use syn::spanned::Spanned;
use syn::{Attribute, Fields};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AstIndex {
    pub structs: Vec<AstStruct>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AstStruct {
    pub name: String,
    pub attrs: Vec<AstAttr>,
    pub fields: Vec<AstField>,
    pub span: AstSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AstField {
    pub name: Option<String>,
    pub ty: String,
    pub attrs: Vec<AstAttr>,
    pub span: AstSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AstAttr {
    pub path: String,
    pub tokens: Option<String>,
    pub span: AstSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AstSpan {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

pub fn collect_ast_index(file: &syn::File) -> AstIndex {
    let mut structs = Vec::new();
    collect_from_items(&file.items, &mut structs);
    AstIndex { structs }
}

fn collect_from_items(items: &[syn::Item], structs: &mut Vec<AstStruct>) {
    for item in items {
        match item {
            syn::Item::Struct(item) => structs.push(collect_struct(item)),
            syn::Item::Mod(module) => {
                if let Some((_, nested_items)) = &module.content {
                    collect_from_items(nested_items, structs);
                }
            }
            _ => {}
        }
    }
}

fn collect_struct(item: &syn::ItemStruct) -> AstStruct {
    let fields = match &item.fields {
        Fields::Named(named) => named.named.iter().map(collect_field).collect(),
        Fields::Unnamed(unnamed) => unnamed.unnamed.iter().map(collect_field).collect(),
        Fields::Unit => Vec::new(),
    };

    AstStruct {
        name: item.ident.to_string(),
        attrs: collect_attrs(&item.attrs),
        fields,
        span: span_of(item.span()),
    }
}

fn collect_field(field: &syn::Field) -> AstField {
    AstField {
        name: field.ident.as_ref().map(|ident| ident.to_string()),
        ty: field.ty.to_token_stream().to_string(),
        attrs: collect_attrs(&field.attrs),
        span: span_of(field.span()),
    }
}

fn collect_attrs(attrs: &[Attribute]) -> Vec<AstAttr> {
    attrs
        .iter()
        .map(|attr| AstAttr {
            path: attr.path().to_token_stream().to_string(),
            tokens: attr_tokens(attr),
            span: span_of(attr.span()),
        })
        .collect()
}

fn attr_tokens(attr: &Attribute) -> Option<String> {
    match &attr.meta {
        syn::Meta::Path(_) => None,
        syn::Meta::List(list) => Some(list.tokens.to_string()),
        syn::Meta::NameValue(name_value) => Some(name_value.value.to_token_stream().to_string()),
    }
}

fn span_of(span: proc_macro2::Span) -> AstSpan {
    let start = span.start();
    let end = span.end();

    AstSpan {
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
    fn collects_struct_fields_attrs_and_spans() {
        let file = parse_file(
            r#"
            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(mut, signer)]
                pub authority: Signer<'info>,
                pub count: u64,
            }
            "#,
        );

        let index = collect_ast_index(&file);
        assert_eq!(index.structs.len(), 1);

        let item = &index.structs[0];
        assert_eq!(item.name, "Example");
        assert_eq!(item.attrs.len(), 1);
        assert_eq!(item.attrs[0].path, "derive");
        assert_eq!(item.fields.len(), 2);
        assert_eq!(item.fields[0].name.as_deref(), Some("authority"));
        assert_eq!(item.fields[0].attrs.len(), 1);
        assert_eq!(item.fields[0].attrs[0].path, "account");
    }
}
