use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

// sentio-ignore-fn SW022
pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
    let vault = &ctx.accounts.vault;
    let authority = &ctx.accounts.authority;
    let lamports = vault.to_account_info().lamports();
    **vault.to_account_info().lamports.borrow_mut() = 0;
    **authority.lamports.borrow_mut() += lamports;
    Ok(())
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub amount: u64,
}
