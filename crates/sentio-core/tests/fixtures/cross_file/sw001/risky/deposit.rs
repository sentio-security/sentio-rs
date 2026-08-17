//! Handler in a separate file from `Deposit` accounts (no is_signer guard).
use anchor_lang::prelude::*;
use super::accounts::Deposit;

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    ctx.accounts.vault.balance = ctx.accounts.vault.balance.saturating_add(amount);
    Ok(())
}
