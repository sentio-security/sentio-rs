//! Cross-file SW002 risky: vault is AccountInfo with no owner constraint.
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Load<'info> {
    /// CHECK: should check owner — intentionally unchecked for SW002
    pub vault: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
