//! Cross-file SW022 risky: no close constraint on Accounts.
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
