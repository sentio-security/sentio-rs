//! Cross-file analysis: Accounts ↔ handler linking via `GlobalIndex`.
//!
//! Fixtures under `fixtures/cross_file/sw00{1,2,3,22}/{risky,safe}/` split
//! `#[derive(Accounts)]` from instruction handlers.
//!
//! Migrated rules: SW001 (signer), SW002 (owner), SW003 (CPI signers), SW022 (close).

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
#[test]
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
    // Handler has no is_signer guard — SW001 must still fire on Accounts file.
    let result = common::scan_fixture("cross_file/sw001/risky", "SW001");
    assert!(
        !result.findings.is_empty(),
        "risky fixture must produce SW001"
    );
    assert!(result.findings.iter().all(|f| f.rule_id == "SW001"));
}

// ── SW002 ───────────────────────────────────────────────────────────────────

#[test]
fn safe_split_file_no_sw002() {
    let result = common::scan_fixture("cross_file/sw002/safe", "SW002");
    assert!(
        result.findings.is_empty(),
        "cross-file owner guard must quiet SW002: {:?}",
        result.findings
    );
}

#[test]
fn risky_split_flags_sw002() {
    let result = common::scan_fixture("cross_file/sw002/risky", "SW002");
    assert!(
        !result.findings.is_empty(),
        "risky fixture must produce SW002"
    );
    assert!(result.findings.iter().all(|f| f.rule_id == "SW002"));
}

// ── SW003 ───────────────────────────────────────────────────────────────────

#[test]
fn risky_split_flags_sw003_confused_deputy() {
    let result = common::scan_fixture("cross_file/sw003/risky", "SW003");
    assert!(
        !result.findings.is_empty(),
        "split-file unvalidated CPI with Signer must flag SW003"
    );
    assert!(result.findings.iter().all(|f| f.rule_id == "SW003"));
    assert!(
        result.findings.iter().any(|f| {
            let m = f.message.to_lowercase();
            m.contains("signer") || m.contains("confused")
        }),
        "must use confused-deputy messaging when Signer is on Accounts file: {:?}",
        result.findings
    );
}

#[test]
fn safe_split_file_no_sw003() {
    let result = common::scan_fixture("cross_file/sw003/safe", "SW003");
    assert!(
        result.findings.is_empty(),
        "program key check must quiet SW003: {:?}",
        result.findings
    );
}

// ── SW022 ───────────────────────────────────────────────────────────────────

#[test]
fn safe_split_file_no_sw022() {
    let result = common::scan_fixture("cross_file/sw022/safe", "SW022");
    assert!(
        result.findings.is_empty(),
        "close on Accounts file must quiet SW022 drain in handler: {:?}",
        result.findings
    );
}

#[test]
fn risky_split_flags_sw022() {
    let result = common::scan_fixture("cross_file/sw022/risky", "SW022");
    assert!(
        !result.findings.is_empty(),
        "manual drain without close must flag SW022"
    );
    assert!(result.findings.iter().all(|f| f.rule_id == "SW022"));
}
