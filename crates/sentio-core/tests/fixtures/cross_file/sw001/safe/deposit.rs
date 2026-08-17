//! Handler with explicit is_signer guard — must quiet SW001 once cross-file (Phase 4).
use anchor_lang::prelude::*;
use super::accounts::Deposit;

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    require!(
        ctx.accounts.authority.is_signer,
        ErrorCode::Unauthorized
    );
    ctx.accounts.vault.balance = ctx.accounts.vault.balance.saturating_add(amount);
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    Unauthorized,
}
