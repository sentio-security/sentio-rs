use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Risky<'info> {
    #[account(init_if_needed, payer = authority, space = 8 + Vault::LEN)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
