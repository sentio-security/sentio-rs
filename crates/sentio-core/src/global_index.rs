//! Cross-file foundation: link `Context<Deposit>` handlers to `#[derive(Accounts)]`
//! structs defined in other files. Not full cross-program CPI analysis.

use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorAccountsStruct};
use crate::instruction_analysis::{collect_instruction_index, InstructionFunction};
use crate::syntax::ParsedFile;
use std::collections::HashMap;

/// Merged view of all scanned files for cross-file rule queries.
#[derive(Debug, Clone, Default)]
pub struct GlobalIndex {
    /// `#[derive(Accounts)]` structs keyed by type name (last path segment).
    /// On duplicate names across files, the **first** insertion wins (stable, predictable).
    pub accounts_by_name: HashMap<String, AnchorAccountsStruct>,
    /// Handlers that take `Context<Name>`, keyed by that accounts struct name.
    pub functions_by_accounts_struct: HashMap<String, Vec<InstructionFunction>>,
    /// Struct names seen more than once (ambiguous merge).
    pub duplicate_accounts_names: Vec<String>,
}

impl GlobalIndex {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build from already-parsed files (normal scan path).
    pub fn from_parsed_files(files: &[ParsedFile]) -> Self {
        let mut index = Self::empty();
        for file in files {
            index.ingest_syn_file(&file.syntax);
        }
        index
    }

    /// Build from raw `syn::File`s (unit tests without disk I/O).
    pub fn from_syn_files(files: &[&syn::File]) -> Self {
        let mut index = Self::empty();
        for file in files {
            index.ingest_syn_file(file);
        }
        index
    }

    fn ingest_syn_file(&mut self, file: &syn::File) {
        let accounts = collect_anchor_accounts_index(file);
        for accounts_struct in accounts.structs {
            let name = accounts_struct.ast.name.clone();
            if self.accounts_by_name.contains_key(&name) {
                if !self.duplicate_accounts_names.iter().any(|n| n == &name) {
                    self.duplicate_accounts_names.push(name.clone());
                }
                // Keep first definition; do not overwrite.
                continue;
            }
            self.accounts_by_name.insert(name, accounts_struct);
        }

        let instructions = collect_instruction_index(file);
        for function in instructions.functions {
            let Some(ref accounts_name) = function.accounts_struct else {
                continue;
            };
            self.functions_by_accounts_struct
                .entry(accounts_name.clone())
                .or_default()
                .push(function);
        }
    }

    pub fn accounts(&self, name: &str) -> Option<&AnchorAccountsStruct> {
        self.accounts_by_name.get(name)
    }

    pub fn functions_for_accounts(&self, name: &str) -> &[InstructionFunction] {
        self.functions_by_accounts_struct
            .get(name)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// All signer-referencing guard tokens across handlers for an accounts struct.
    pub fn signer_guard_tokens_for(&self, accounts_name: &str) -> Vec<String> {
        self.functions_for_accounts(accounts_name)
            .iter()
            .flat_map(|f| f.guards.iter())
            .filter(|g| g.references_signer)
            .flat_map(|g| {
                g.expression
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub fn owner_guard_tokens_for(&self, accounts_name: &str) -> Vec<String> {
        self.functions_for_accounts(accounts_name)
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
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> syn::File {
        syn::parse_file(source).expect("parse")
    }

    #[test]
    fn merges_accounts_and_handlers_across_files() {
        let accounts_file = parse(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Deposit<'info> {
                pub authority: AccountInfo<'info>,
            }
            "#,
        );
        let handler_file = parse(
            r#"
            use anchor_lang::prelude::*;
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
                Ok(())
            }
            "#,
        );

        let index = GlobalIndex::from_syn_files(&[&accounts_file, &handler_file]);

        assert!(index.accounts("Deposit").is_some());
        let fns = index.functions_for_accounts("Deposit");
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "deposit");
        assert!(fns[0].guards.iter().any(|g| g.references_signer));

        let tokens = index.signer_guard_tokens_for("Deposit");
        assert!(tokens.iter().any(|t| t == "authority" || t == "is_signer"));
    }

    #[test]
    fn skips_functions_without_context_param() {
        let file = parse(
            r#"
            pub fn helper(x: u64) -> Result<()> { Ok(()) }
            pub fn deposit(ctx: Context<Deposit>) -> Result<()> { Ok(()) }
            "#,
        );
        let index = GlobalIndex::from_syn_files(&[&file]);
        assert_eq!(index.functions_for_accounts("Deposit").len(), 1);
        assert!(!index.functions_by_accounts_struct.contains_key("Helper"));
    }

    #[test]
    fn duplicate_accounts_struct_keeps_first() {
        let a = parse(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Deposit<'info> {
                pub authority: AccountInfo<'info>,
            }
            "#,
        );
        let b = parse(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Deposit<'info> {
                pub authority: Signer<'info>,
            }
            "#,
        );
        let index = GlobalIndex::from_syn_files(&[&a, &b]);
        assert!(index
            .duplicate_accounts_names
            .iter()
            .any(|n| n == "Deposit"));
        let dep = index.accounts("Deposit").expect("Deposit");
        // First file: AccountInfo, not Signer
        assert_eq!(dep.fields.len(), 1);
        assert!(matches!(
            dep.fields[0].type_info.kind,
            crate::anchor_accounts::AnchorFieldTypeKind::AccountInfo
        ));
    }

    #[test]
    fn empty_index_from_no_files() {
        let index = GlobalIndex::from_syn_files(&[]);
        assert!(index.accounts_by_name.is_empty());
        assert!(index.functions_by_accounts_struct.is_empty());
    }
}
