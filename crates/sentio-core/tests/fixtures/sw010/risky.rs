use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, TokenAccount};

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut, token::mint = mint)]
    pub from: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    pub authority: Signer<'info>,
}

pub fn handler(_ctx: Context<Transfer>, _amount: u64) -> Result<()> {
    Ok(())
}
