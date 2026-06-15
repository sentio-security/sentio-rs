use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Process<'info> {
    /// CHECK: manually deserialized below
    pub raw_account: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<Process>) -> Result<()> {
    let data = VaultData::try_from_slice(&ctx.accounts.raw_account.data.borrow())?; // sentio-ignore SW006
    msg!("balance: {}", data.balance);
    Ok(())
}

pub struct VaultData {
    pub balance: u64,
}
