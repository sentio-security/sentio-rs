use anchor_lang::prelude::*;
use solana_program::program::invoke_signed;

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<Stake>, amount: u64) -> Result<()> {
    let seeds: &[&[u8]] = &[b"vault", &[ctx.bumps.vault]];
    invoke_signed(&transfer_ix, &accounts, &[seeds])?; // sentio-ignore SW008
    ctx.accounts.vault.staked_amount += amount;
    Ok(())
}

#[account]
pub struct Vault {
    pub staked_amount: u64,
}
