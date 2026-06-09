use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CreateVault<'info> {
    #[account(init, payer = authority, space = 8 + 64)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
