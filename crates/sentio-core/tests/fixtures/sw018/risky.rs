use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ResizeVault<'info> {
    #[account(mut, realloc = 512, realloc_authority = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
