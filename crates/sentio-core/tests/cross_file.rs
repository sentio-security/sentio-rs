//! Cross-file analysis foundations.
//!
//! Fixtures under `fixtures/cross_file/sw001/{risky,safe}/` split
//! `#[derive(Accounts)]` and `pub fn deposit(ctx: Context<Deposit>, …)` across files.
//!
//! Today we lock `Context<T>` → `accounts_struct` extraction and fixture layout.
//! Full SW001 quiet-on-safe (handler guard in another file) lands when GlobalIndex
//! is wired into the rule.

mod common;

use sentio_core::instruction_analysis::collect_instruction_index;
use sentio_core::syntax::parse_rust_file;

#[test]
fn risky_fixture_files_exist() {
    let base = common::fixture_path("cross_file/sw001/risky");
    assert!(base.join("accounts.rs").is_file());
    assert!(base.join("deposit.rs").is_file());
}

#[test]
fn safe_fixture_files_exist() {
    let base = common::fixture_path("cross_file/sw001/safe");
    assert!(base.join("accounts.rs").is_file());
    assert!(base.join("deposit.rs").is_file());
}

#[test]
fn deposit_handler_extracts_accounts_struct() {
    let path = common::fixture_path("cross_file/sw001/risky/deposit.rs");
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
        "Context<Deposit> → accounts_struct"
    );
}

#[test]
fn safe_deposit_links_struct_and_has_signer_guard() {
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
        "safe handler must carry is_signer guard evidence"
    );
}

/// Goal test: Accounts in one file, `is_signer` guard in another → no SW001.
/// Ignored until GlobalIndex is wired into SW001.
#[test]
#[ignore = "cross-file: SW001 GlobalIndex not wired yet"]
fn safe_split_file_no_sw001() {
    let result = common::scan_fixture("cross_file/sw001/safe", "SW001");
    assert!(
        result.findings.is_empty(),
        "cross-file is_signer guard must quiet SW001: {:?}",
        result.findings
    );
}

#[test]
fn risky_split_flags_sw001() {
    // Per-file behavior: Accounts struct alone is enough to flag today.
    let result = common::scan_fixture("cross_file/sw001/risky", "SW001");
    assert!(
        !result.findings.is_empty(),
        "risky fixture must produce SW001"
    );
    assert!(result.findings.iter().all(|f| f.rule_id == "SW001"));
}
