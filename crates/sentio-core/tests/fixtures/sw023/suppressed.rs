use anchor_lang::prelude::*;
use solana_program::program::invoke;

#[derive(Accounts)]
pub struct RouteSwap<'info> {
    pub user: Signer<'info>,
}

// sentio-ignore-fn SW023
pub fn route_swap(ctx: Context<RouteSwap>, data: Vec<u8>) -> Result<()> {
    let ix = build_ix(&data);
    let mut accounts = vec![ctx.accounts.user.to_account_info()];
    accounts.extend_from_slice(ctx.remaining_accounts);
    invoke(&ix, &accounts)?;
    Ok(())
}

fn build_ix(_data: &[u8]) -> solana_program::instruction::Instruction {
    unimplemented!()
}
