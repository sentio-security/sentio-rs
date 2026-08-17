//! Cross-file SW003 safe: same Accounts; program validated in handler.
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Buy<'info> {
    pub buyer: Signer<'info>,
    /// CHECK: key checked in buy handler
    pub royalty_program: AccountInfo<'info>,
}
