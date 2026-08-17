//! Cross-file fixture: Accounts struct lives apart from the handler.
//! Risky: authority is AccountInfo with no signer constraint.
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: should be a signer — intentionally unchecked for SW001
    pub authority: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
