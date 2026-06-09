use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)] // sentio-ignore SW001
    pub authority: AccountInfo<'info>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
}

pub fn handler(ctx: Context<Initialize>, amount: u64) -> Result<()> {
    ctx.accounts.vault.balance += amount;
    Ok(())
}

#[account]
pub struct Vault {
    pub balance: u64,
}
