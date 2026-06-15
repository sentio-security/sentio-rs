use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, TokenAccount};

/// Safe: explicit token::mint constraint.
#[derive(Accounts)]
pub struct TransferChecked<'info> {
    #[account(mut, token::mint = mint, token::authority = authority)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut, token::mint = mint)]
    pub to: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    pub authority: Signer<'info>,
}

/// Safe: associated_token covers both mint and authority.
#[derive(Accounts)]
pub struct TransferAssociated<'info> {
    #[account(mut, associated_token::mint = mint, associated_token::authority = authority)]
    pub from: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    pub authority: Signer<'info>,
}

/// Safe: read-only token account — not mutable, no transfer risk.
#[derive(Accounts)]
pub struct ReadBalance<'info> {
    pub token_account: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}

pub fn handler_checked(_ctx: Context<TransferChecked>, _amount: u64) -> Result<()> {
    Ok(())
}
