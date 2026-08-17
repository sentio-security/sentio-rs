//! CPI to unvalidated program with buyer Signer in metas.
use anchor_lang::prelude::*;
use solana_program::program::invoke;
use super::accounts::Buy;

pub fn buy(ctx: Context<Buy>) -> Result<()> {
    invoke(
        &ix,
        &[
            ctx.accounts.buyer.to_account_info(),
            ctx.accounts.royalty_program.to_account_info(),
        ],
    )?;
    Ok(())
}
