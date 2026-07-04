use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct UpdateVault<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

// sentio-ignore-fn SW027
pub fn update_vault(ctx: Context<UpdateVault>, new_value: u64) -> Result<()> {
    ctx.accounts.vault.value = new_value;
    Ok(())
}

#[account]
pub struct Vault {
    pub value: u64,
}
