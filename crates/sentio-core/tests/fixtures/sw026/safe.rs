use solana_program::pubkey::Pubkey;

pub fn derive_pda(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
    // find_program_address always returns the canonical (highest valid) bump
    Pubkey::find_program_address(seeds, program_id)
}
