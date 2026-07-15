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

/// Safe: account fields cast to u128 before arithmetic (standard overflow pattern).
pub fn handler_u128_widen(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let _ = (amount as u128)
        .checked_mul(ctx.accounts.vault.balance as u128)
        .unwrap()
        .checked_div(ctx.accounts.vault.balance as u128 + 100u128)
        .unwrap() as u64;
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
