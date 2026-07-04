use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ProcessData<'info> {
    pub authority: Signer<'info>,
}

pub fn process(_ctx: Context<ProcessData>, raw: Vec<u8>) -> Result<()> {
    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| error!(ErrorCode::InvalidInput))?;
    let amount = u64::from_le_bytes(bytes);
    msg!("amount: {}", amount);
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    InvalidInput,
}
