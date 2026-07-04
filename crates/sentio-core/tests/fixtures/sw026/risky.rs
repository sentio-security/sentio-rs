use solana_program::pubkey::Pubkey;

pub fn verify_pda(seeds: &[&[u8]], program_id: &Pubkey, bump: u8) -> bool {
    let bump_seed = [bump];
    let mut full_seeds: Vec<&[u8]> = seeds.to_vec();
    full_seeds.push(&bump_seed);
    // create_program_address accepts any bump — non-canonical bumps produce different valid PDAs
    let derived = Pubkey::create_program_address(&full_seeds, program_id)
        .expect("invalid seeds");
    derived == *program_id
}
