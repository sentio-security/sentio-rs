use anchor_lang::prelude::*;
use anchor_spl::token::TokenAccount;

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)] // sentio-ignore SW009
    pub from: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}

pub fn handler(_ctx: Context<Transfer>, _amount: u64) -> Result<()> {
    Ok(())
}
