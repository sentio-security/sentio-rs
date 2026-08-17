//! Manual lamport drain without close constraint.
use anchor_lang::prelude::*;
use super::accounts::CloseVault;

pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
    let vault = &ctx.accounts.vault;
    let authority = &ctx.accounts.authority;
    let lamports = vault.to_account_info().lamports();
    **vault.to_account_info().lamports.borrow_mut() = 0;
    **authority.lamports.borrow_mut() += lamports;
    Ok(())
}
