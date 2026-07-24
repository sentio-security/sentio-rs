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

/// Safe: custom constraint pins UncheckedAccount to a stored pubkey (address identity).
#[derive(Accounts)]
pub struct WithdrawTeamFees<'info> {
    pub team_config: Account<'info, TeamConfig>,
    #[account(
        constraint = team_wallet.key() == team_config.team_wallet @ ErrorCode::InvalidTeamWallet
    )]
    pub team_wallet: UncheckedAccount<'info>,
}

#[account]
pub struct TeamConfig {
    pub team_wallet: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    InvalidTeamWallet,
}
