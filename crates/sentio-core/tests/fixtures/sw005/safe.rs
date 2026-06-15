use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

/// Safe: checked_add propagates the error on overflow.
pub fn handler_checked(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    ctx.accounts.vault.balance = ctx.accounts.vault.balance
        .checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;
    Ok(())
}

/// Safe: saturating_add caps at u64::MAX instead of wrapping.
pub fn handler_saturating(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    ctx.accounts.vault.balance = ctx.accounts.vault.balance.saturating_add(amount);
    Ok(())
}

/// Safe: arithmetic on local variables only — no account field involved.
pub fn handler_local(_ctx: Context<Deposit>, amount: u64, fee: u64) -> Result<()> {
    let total = amount + fee;
    let _ = total;
    Ok(())
}

/// Safe: loop counter has no field access.
pub fn handler_loop(_ctx: Context<Deposit>) -> Result<()> {
    let mut i = 0u64;
    i += 1;
    let _ = i;
    Ok(())
}

#[account]
pub struct Vault {
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    Overflow,
}
