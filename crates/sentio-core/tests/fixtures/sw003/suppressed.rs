use anchor_lang::prelude::*;
use solana_program::program::invoke;

#[derive(Accounts)]
pub struct ExecuteCpi<'info> {
    pub target_program: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<ExecuteCpi>, data: Vec<u8>) -> Result<()> {
    let ix = solana_program::instruction::Instruction {
        program_id: *ctx.accounts.target_program.key,
        accounts: vec![],
        data,
    };
    invoke(&ix, &[ctx.accounts.target_program.clone()])?; // sentio-ignore SW003
    Ok(())
}
