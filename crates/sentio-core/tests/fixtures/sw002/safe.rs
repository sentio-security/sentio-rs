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

/// Safe: AccountInfo only used via `.key()` to store a pubkey — owner is irrelevant.
#[derive(Accounts)]
pub struct CreateConfig<'info> {
    #[account(init, payer = payer, space = 8 + 32)]
    pub config: Account<'info, Config>,
    /// CHECK: Read only — key copied into config
    pub admin: AccountInfo<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn create_config(ctx: Context<CreateConfig>) -> Result<()> {
    ctx.accounts.config.admin = ctx.accounts.admin.key();
    Ok(())
}

#[account]
pub struct Config {
    pub admin: Pubkey,
}
