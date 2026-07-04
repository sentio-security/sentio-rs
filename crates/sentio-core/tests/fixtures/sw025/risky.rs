use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ProcessData<'info> {
    pub authority: Signer<'info>,
}

pub fn process(ctx: Context<ProcessData>, raw: Vec<u8>) -> Result<()> {
    // unwrap on user-supplied bytes — panics if slice is wrong length
    let amount = u64::from_le_bytes(raw.try_into().unwrap());
    msg!("amount: {}", amount);
    Ok(())
}
