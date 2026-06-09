use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CreateVault<'info> {
    #[account(init, payer = authority, space = 8 + 64)]
    pub vault: AccountInfo<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
