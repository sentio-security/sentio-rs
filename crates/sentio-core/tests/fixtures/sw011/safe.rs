use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CreateVault<'info> {
    #[account(init, payer = authority, space = 8 + 64)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// Safe: AccountInfo + seeds/bump is a PDA address authority, not untyped program data.
#[derive(Accounts)]
pub struct PdaAuthority<'info> {
    /// CHECK: Read-only pool authority
    #[account(seeds = [b"authority", mint.key().as_ref()], bump)]
    pub pool_authority: AccountInfo<'info>,
    pub mint: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
