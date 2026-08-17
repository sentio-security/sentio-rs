//! Handler with explicit owner guard — must quiet SW002 cross-file.
use anchor_lang::prelude::*;
use super::accounts::Load;

pub fn load(ctx: Context<Load>) -> Result<()> {
    require!(
        ctx.accounts.vault.owner == &token::ID,
        ErrorCode::InvalidOwner
    );
    let _data = ctx.accounts.vault.try_borrow_data()?;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    InvalidOwner,
}
