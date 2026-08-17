//! Cross-file SW003: Buyer is Signer; royalty_program unvalidated.
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Buy<'info> {
    pub buyer: Signer<'info>,
    /// CHECK: supposed royalty program — unvalidated
    pub royalty_program: AccountInfo<'info>,
}
