use solana_program::pubkey::Pubkey;

// sentio-ignore-fn SW026
pub fn verify_pda(seeds: &[&[u8]], program_id: &Pubkey, bump: u8) -> bool {
    let bump_seed = [bump];
    let mut full_seeds: Vec<&[u8]> = seeds.to_vec();
    full_seeds.push(&bump_seed);
    let derived = Pubkey::create_program_address(&full_seeds, program_id)
        .expect("invalid seeds");
    derived == *program_id
}
