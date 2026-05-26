use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Suppressed<'info> {
    #[account(init_if_needed, payer = authority, space = 8 + Vault::LEN)] // sentio-ignore SW016
    pub vault: Account<'info, Vault>, // sentio-ignore SW016
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
