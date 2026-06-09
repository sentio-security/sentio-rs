use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub vault: AccountInfo<'info>, // sentio-ignore SW002
    #[account(mut)]
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<Withdraw>) -> Result<()> {
    let lamports = ctx.accounts.vault.lamports();
    Ok(())
}
