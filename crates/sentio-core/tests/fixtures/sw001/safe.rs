use anchor_lang::prelude::*;

/// Safe: authority uses Signer<'info> — framework enforces the check automatically.
#[derive(Accounts)]
pub struct WithSignerType<'info> {
    pub authority: Signer<'info>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
}

/// Safe: authority uses AccountInfo but has the explicit signer constraint.
#[derive(Accounts)]
pub struct WithSignerConstraint<'info> {
    #[account(mut, signer)]
    pub authority: AccountInfo<'info>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
}

/// Safe: authority checked via require!(authority.is_signer, ...) in the handler.
#[derive(Accounts)]
pub struct WithSignerGuard<'info> {
    #[account(mut)]
    pub authority: AccountInfo<'info>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
}

pub fn handler_with_guard(ctx: Context<WithSignerGuard>, amount: u64) -> Result<()> {
    require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
    ctx.accounts.vault.balance += amount;
    Ok(())
}

/// Safe: AccountInfo not named after an authority role — out of SW001 scope.
#[derive(Accounts)]
pub struct WithTreasury<'info> {
    pub treasury: AccountInfo<'info>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    Unauthorized,
}
