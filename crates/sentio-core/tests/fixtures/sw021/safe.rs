use anchor_lang::prelude::*;

/// Safe: a fixed-length byte literal separates the two variable-length seeds.
#[derive(Accounts)]
pub struct CreatePool<'info> {
    #[account(init, seeds = [name.as_bytes(), b"::", symbol.as_bytes()], bump, payer = authority, space = 8 + 64)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// Safe: only one variable-length seed, preceded by a fixed-length Pubkey seed.
#[derive(Accounts)]
pub struct UseVault<'info> {
    #[account(seeds = [b"vault", authority.key().as_ref(), name.as_bytes()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

pub fn handler_create(_ctx: Context<CreatePool>, _name: String, _symbol: String) -> Result<()> {
    Ok(())
}

pub fn handler_use(_ctx: Context<UseVault>, _name: String) -> Result<()> {
    Ok(())
}

#[account]
pub struct Pool {
    pub balance: u64,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
