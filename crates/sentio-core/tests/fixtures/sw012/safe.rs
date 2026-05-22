use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Safe<'info> {
    #[account(seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
}
