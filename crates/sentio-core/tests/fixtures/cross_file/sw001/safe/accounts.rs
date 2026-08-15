//! Cross-file fixture: same split layout as risky; authority remains AccountInfo
//! (signer guard lives in the handler file).
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: validated as signer in deposit handler
    pub authority: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
