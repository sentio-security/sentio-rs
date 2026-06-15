use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CreateVault<'info> {
    /// CHECK: used as PDA seed but not validated
    pub user: AccountInfo<'info>,
    #[account(seeds = [b"vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

pub fn handler(_ctx: Context<CreateVault>) -> Result<()> {
    Ok(())
}

#[account]
pub struct Vault {
    pub balance: u64,
}
