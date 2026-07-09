use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, TokenAccount};

/// Safe: explicit token::mint + token::authority.
#[derive(Accounts)]
pub struct TransferFull<'info> {
    #[account(mut, token::mint = mint, token::authority = authority)]
    pub from: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    pub authority: Signer<'info>,
}

/// Safe: associated_token::authority satisfies the owner check.
#[derive(Accounts)]
pub struct TransferAssociated<'info> {
    #[account(mut, associated_token::mint = mint, associated_token::authority = authority)]
    pub from: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    pub authority: Signer<'info>,
}

/// Safe: has_one = authority on the token account validates the owner sub-field.
#[derive(Accounts)]
pub struct TransferHasOne<'info> {
    #[account(mut, token::mint = mint, has_one = authority)]
    pub from: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    pub authority: Signer<'info>,
}

/// Safe: read-only — not flagged.
#[derive(Accounts)]
pub struct ReadBalance<'info> {
    pub token_account: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}

/// Safe: custom constraint pins TokenAccount.owner (authority).
#[derive(Accounts)]
pub struct TransferCustomOwner<'info> {
    pub user: Signer<'info>,
    pub market: Account<'info, Market>,
    #[account(
        mut,
        constraint = user_token_account.owner == user.key(),
        constraint = user_token_account.mint == market.mint,
    )]
    pub user_token_account: Account<'info, TokenAccount>,
}

#[account]
pub struct Market {
    pub mint: Pubkey,
}

pub fn handler(_ctx: Context<TransferFull>, _amount: u64) -> Result<()> {
    Ok(())
}
