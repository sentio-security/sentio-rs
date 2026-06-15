use anchor_lang::prelude::*;

/// Safe: typed Account<'info, T> — Anchor verifies the discriminator automatically.
#[derive(Accounts)]
pub struct ProcessTyped<'info> {
    pub vault: Account<'info, VaultData>,
    pub authority: Signer<'info>,
}

pub fn handler_typed(ctx: Context<ProcessTyped>) -> Result<()> {
    msg!("balance: {}", ctx.accounts.vault.balance);
    Ok(())
}

/// Safe: try_from_slice with [8..] to skip the 8-byte discriminator.
#[derive(Accounts)]
pub struct ProcessRaw<'info> {
    /// CHECK: discriminator validated manually below
    pub raw_account: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

pub fn handler_raw(ctx: Context<ProcessRaw>) -> Result<()> {
    let data = VaultData::try_from_slice(&ctx.accounts.raw_account.data.borrow()[8..])?;
    msg!("balance: {}", data.balance);
    Ok(())
}

/// Safe: Anchor's try_deserialize checks the discriminator internally.
pub fn handler_deserialize(ctx: Context<ProcessRaw>) -> Result<()> {
    let mut raw: &[u8] = &ctx.accounts.raw_account.data.borrow();
    let data = VaultData::try_deserialize(&mut raw)?;
    msg!("balance: {}", data.balance);
    Ok(())
}

#[account]
pub struct VaultData {
    pub balance: u64,
}
