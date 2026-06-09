use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(owner = vault_program::ID)]
    pub vault: AccountInfo<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<Withdraw>) -> Result<()> {
    let lamports = ctx.accounts.vault.lamports();
    msg!("vault lamports: {}", lamports);
    Ok(())
}
