//! Handler uses vault data without owner guard.
use anchor_lang::prelude::*;
use super::accounts::Load;

pub fn load(ctx: Context<Load>) -> Result<()> {
    let _data = ctx.accounts.vault.try_borrow_data()?;
    Ok(())
}
