use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Risky<'info> {
    #[account(seeds = [b"vault"])]
    pub vault: Account<'info, Vault>,
}
