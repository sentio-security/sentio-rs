use anchor_lang::prelude::*;

/// Safe: no explicit bump — Anchor derives the canonical bump automatically.
#[derive(Accounts)]
pub struct CreateVault<'info> {
    #[account(init, seeds = [b"vault"], bump, payer = authority, space = 8 + 8 + 1)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// Safe: bump read from the stored field on the account (canonical bump reuse).
#[derive(Accounts)]
pub struct UseVault<'info> {
    #[account(seeds = [b"vault"], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

pub fn handler_create(_ctx: Context<CreateVault>) -> Result<()> {
    Ok(())
}

pub fn handler_use(_ctx: Context<UseVault>) -> Result<()> {
    Ok(())
}

#[account]
pub struct Vault {
    pub balance: u64,
    pub bump: u8,
}
