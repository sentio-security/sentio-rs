use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct UseVault<'info> {
    #[account(seeds = [b"vault"], bump = bump_seed)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

pub fn handler(_ctx: Context<UseVault>, _bump_seed: u8) -> Result<()> {
    Ok(())
}

#[account]
pub struct Vault {
    pub balance: u64,
    pub bump: u8,
}
