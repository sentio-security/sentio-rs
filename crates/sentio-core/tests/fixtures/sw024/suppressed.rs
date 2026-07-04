use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CalcFee<'info> {
    pub config: Account<'info, Config>,
}

// sentio-ignore-fn SW024
pub fn calc_fee(ctx: Context<CalcFee>, amount: u64) -> Result<u64> {
    let fee = amount / ctx.accounts.config.rate;
    Ok(fee)
}

#[account]
pub struct Config {
    pub rate: u64,
}
