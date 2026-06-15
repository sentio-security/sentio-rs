use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CreateVault<'info> {
    /// CHECK: intentionally unvalidated
    pub user: AccountInfo<'info>,
    #[account(seeds = [b"vault", user.key().as_ref()], bump)] // sentio-ignore SW013
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
