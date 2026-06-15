use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    ctx.accounts.vault.balance += amount; // sentio-ignore SW005
    Ok(())
}

#[account]
pub struct Vault {
    pub balance: u64,
}
