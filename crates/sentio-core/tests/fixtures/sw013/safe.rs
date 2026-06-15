use anchor_lang::prelude::*;

/// Safe: seed uses a Signer — cannot be attacker-controlled.
#[derive(Accounts)]
pub struct CreateWithSigner<'info> {
    pub authority: Signer<'info>,
    #[account(seeds = [b"vault", authority.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
}

/// Safe: seed uses a typed Account<T> — owner validated by Anchor.
#[derive(Accounts)]
pub struct CreateWithTypedAccount<'info> {
    pub user: Account<'info, UserProfile>,
    #[account(seeds = [b"vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

/// Safe: seed account has explicit owner constraint.
#[derive(Accounts)]
pub struct CreateWithOwnerCheck<'info> {
    #[account(owner = crate::ID)]
    pub user: AccountInfo<'info>,
    #[account(seeds = [b"vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

/// Safe: only literal seeds — no account reference to validate.
#[derive(Accounts)]
pub struct CreateGlobalConfig<'info> {
    #[account(seeds = [b"global-config"], bump)]
    pub config: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

pub fn handler(_ctx: Context<CreateWithSigner>) -> Result<()> {
    Ok(())
}

#[account]
pub struct Vault {
    pub balance: u64,
}

#[account]
pub struct UserProfile {
    pub owner: Pubkey,
}
