use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ProcessData<'info> {
    pub authority: Signer<'info>,
}

// sentio-ignore-fn SW025
pub fn process(_ctx: Context<ProcessData>, raw: Vec<u8>) -> Result<()> {
    let amount = u64::from_le_bytes(raw.try_into().unwrap());
    msg!("amount: {}", amount);
    Ok(())
}
