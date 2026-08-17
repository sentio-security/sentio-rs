//! Cross-file SW022 safe: close constraint on Accounts file.
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(mut, close = authority)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
