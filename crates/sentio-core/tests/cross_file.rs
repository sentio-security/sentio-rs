//! Cross-file analysis foundations.
//!
//! Fixtures under `fixtures/cross_file/sw001/{risky,safe}/` split
//! `#[derive(Accounts)]` and `pub fn deposit(ctx: Context<Deposit>, …)` across files.
//!
//! - Phase 1: `Context<T>` → `accounts_struct` extraction
//! - Phase 2/3: `GlobalIndex` merge + `RuleContext.global` (scanner builds once)
//! - Phase 4: SW001 consumes `ctx.global` (un-ignore `safe_split_file_no_sw001`)

mod common;

use sentio_core::instruction_analysis::collect_instruction_index;
use sentio_core::syntax::{parse_rust_file, parse_rust_files};
use sentio_core::GlobalIndex;

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

/// Phase 2/3: GlobalIndex links Accounts struct file ↔ handler file.
#[test]
fn global_index_links_split_safe_fixture() {
    let base = common::fixture_path("cross_file/sw001/safe");
    let report = parse_rust_files([base.join("accounts.rs"), base.join("deposit.rs")]);
    assert_eq!(report.files.len(), 2, "both fixture files must parse");

    let index = GlobalIndex::from_parsed_files(&report.files);
    assert!(
        index.accounts("Deposit").is_some(),
        "Accounts struct from accounts.rs"
    );
    let fns = index.functions_for_accounts("Deposit");
    assert_eq!(fns.len(), 1);
    assert_eq!(fns[0].name, "deposit");
    assert!(
        fns[0].guards.iter().any(|g| g.references_signer),
        "handler is_signer guard must be indexed"
    );
    let tokens = index.signer_guard_tokens_for("Deposit");
    assert!(
        tokens.iter().any(|t| t == "authority"),
        "signer guard tokens should include authority: {tokens:?}"
    );
}

/// Goal test: Accounts in one file, `is_signer` guard in another → no SW001.
/// Ignored until SW001 reads `ctx.global` (Phase 4).
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
