//! Cross-file SW002 safe: vault owner checked in handler file.
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Load<'info> {
    /// CHECK: owner validated in load handler
    pub vault: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
