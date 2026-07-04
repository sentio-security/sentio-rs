use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(mut, close = authority)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

pub fn close_vault(_ctx: Context<CloseVault>) -> Result<()> {
    Ok(())
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub amount: u64,
}
