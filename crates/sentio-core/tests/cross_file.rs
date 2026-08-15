//! Phase 0+1 cross-file analysis foundations.
//!
//! Fixtures under `fixtures/cross_file/sw001/{risky,safe}/` split
//! `#[derive(Accounts)]` and `pub fn deposit(ctx: Context<Deposit>, …)` across files.
//! Full SW001 quiet-on-safe is Phase 4; here we lock extraction + fixture layout.

mod common;

use sentio_core::instruction_analysis::collect_instruction_index;
use sentio_core::syntax::parse_rust_file;
use std::fs;

#[test]
fn phase0_risky_fixture_files_exist() {
    let base = common::fixture_path("cross_file/sw001/risky");
    assert!(base.join("accounts.rs").is_file());
    assert!(base.join("deposit.rs").is_file());
}

#[test]
fn phase0_safe_fixture_files_exist() {
    let base = common::fixture_path("cross_file/sw001/safe");
    assert!(base.join("accounts.rs").is_file());
    assert!(base.join("deposit.rs").is_file());
}

#[test]
fn phase1_deposit_handler_extracts_accounts_struct() {
    let path = common::fixture_path("cross_file/sw001/risky/deposit.rs");
    // Fixture uses `super::accounts::Deposit` — may not parse as standalone if
    // unresolved paths are fine for syn (they are: syn does not resolve).
    let source = fs::read_to_string(&path).expect("read deposit.rs");
    // Strip `use super::...` for standalone parse if needed — syn accepts it.
    let file = parse_rust_file(&path).expect("deposit.rs should parse");
    let index = collect_instruction_index(&file.syntax);
    let deposit = index
        .functions
        .iter()
        .find(|f| f.name == "deposit")
        .expect("deposit fn");
    assert_eq!(
        deposit.accounts_struct.as_deref(),
        Some("Deposit"),
        "Phase 1: Context<Deposit> → accounts_struct"
    );
    let _ = source;
}

#[test]
fn phase1_safe_deposit_also_links_to_deposit_struct() {
    let path = common::fixture_path("cross_file/sw001/safe/deposit.rs");
    let file = parse_rust_file(&path).expect("safe deposit.rs should parse");
    let index = collect_instruction_index(&file.syntax);
    let deposit = index
        .functions
        .iter()
        .find(|f| f.name == "deposit")
        .expect("deposit fn");
    assert_eq!(deposit.accounts_struct.as_deref(), Some("Deposit"));
    assert!(
        deposit.guards.iter().any(|g| g.references_signer),
        "safe handler must carry is_signer guard evidence for Phase 4"
    );
}

/// Documents the Phase 4 goal. Today SW001 is per-file, so the Accounts file still
/// flags without seeing the handler guard — this test is ignored until GlobalIndex
/// is wired into SW001.
#[test]
#[ignore = "phase 4: SW001 cross-file GlobalIndex"]
fn phase4_goal_safe_split_file_no_sw001() {
    let result = common::scan_fixture("cross_file/sw001/safe", "SW001");
    assert!(
        result.findings.is_empty(),
        "cross-file is_signer guard must quiet SW001: {:?}",
        result.findings
    );
}

#[test]
fn phase0_risky_split_still_flags_sw001_on_accounts_file() {
    // Current per-file behavior: Accounts struct alone is enough to flag.
    let result = common::scan_fixture("cross_file/sw001/risky", "SW001");
    assert!(
        !result.findings.is_empty(),
        "risky fixture must produce SW001 today"
    );
    assert!(result.findings.iter().all(|f| f.rule_id == "SW001"));
}
