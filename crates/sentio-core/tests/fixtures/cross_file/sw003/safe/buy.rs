//! Program ID checked before CPI — no SW003.
use anchor_lang::prelude::*;
use solana_program::program::invoke;
use super::accounts::Buy;

pub fn buy(ctx: Context<Buy>) -> Result<()> {
    require!(
        ctx.accounts.royalty_program.key() == &royalty::ID,
        ErrorCode::InvalidProgram
    );
    invoke(
        &ix,
        &[
            ctx.accounts.buyer.to_account_info(),
            ctx.accounts.royalty_program.to_account_info(),
        ],
    )?;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    InvalidProgram,
}
