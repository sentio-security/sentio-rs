use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Suppressed<'info> {
    #[account(seeds = [b"vault"])] // sentio-ignore SW012
    pub vault: Account<'info, Vault>, // sentio-ignore SW012
}
