use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CreatePool<'info> {
    #[account(init, seeds = [name.as_bytes(), symbol.as_bytes()], bump, payer = authority, space = 8 + 64)] // sentio-ignore SW021
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn handler(_ctx: Context<CreatePool>, _name: String, _symbol: String) -> Result<()> {
    Ok(())
}

#[account]
pub struct Pool {
    pub balance: u64,
}
