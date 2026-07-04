use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CalcFee<'info> {
    pub config: Account<'info, Config>,
}

pub fn calc_fee(ctx: Context<CalcFee>, amount: u64) -> Result<u64> {
    // rate comes from account data — could be zero if misconfigured
    let fee = amount / ctx.accounts.config.rate;
    Ok(fee)
}

#[account]
pub struct Config {
    pub rate: u64,
}
