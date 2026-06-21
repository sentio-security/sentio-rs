# sentio

**AST-based security scanner for Anchor programs.**

sentio scans Rust source files for common Solana vulnerability patterns using [`syn`](https://docs.rs/syn) — Rust's macro-safe AST parser. It understands Anchor account constraints, instruction logic, and CPI call graphs to produce high-signal findings with minimal false positives.

---

## Quick Start

```bash
# Install
cargo install sentio-cli

# Scan your program
sentio scan /path/to/your/anchor-program

# Scan with JSON output (for CI pipelines)
sentio scan . --format json

# Export findings to a JSON file (pipe to AI or tooling)
sentio scan . --format json --output report.json

# Run only one specific rule
sentio scan . --rule SW003

# List all available rules
sentio rules list
```

---

## CLI Reference

```
sentio <COMMAND>

Commands:
  scan    Scan a Solana program directory or file for vulnerabilities
  rules   Manage and inspect the built-in rule set

sentio scan [OPTIONS] [PATH]

Arguments:
  [PATH]              Directory or .rs file to scan [default: .]

Options:
  --format <FORMAT>   Output format: human (default) | json
  --output <FILE>     Write JSON output to a file (requires --format json)
  --rule <RULE_ID>    Run only a specific rule, e.g. --rule SW003
  --include-tests     Include test files (excluded by default to reduce noise)
  -h, --help          Print help

sentio rules list     Print all rule IDs and titles
```

**Exit codes**

| Code | Meaning |
|------|---------|
| `0`  | No findings |
| `1`  | One or more findings |
| `2`  | Parse error in one or more files |

---

## Example Output

```
$ sentio scan ./programs/my-program
```

```
==============FINDING 1: SW001 Missing signer check==============
Severity: critical
Location: src/instructions/update.rs:14:1

Rule:
  Detects AccountInfo or UncheckedAccount fields whose names suggest an
  authority role but have no signer constraint and no is_signer guard.

Matched Because:
  Account `authority` appears to be an authority but has no signer constraint
  and no is_signer guard; an attacker can pass an unsigned account.

Source:
  12|     pub vault: Account<'info, Vault>,
  13|
 >14|     #[account(mut)]
    | ^
  15|     pub authority: AccountInfo<'info>,
  16|

Guidance:
  Use Signer<'info> as the field type, add #[account(signer)], or add
  require!(account.is_signer, ...) in the instruction handler.

==============FINDING 2: SW003 Arbitrary CPI target==============
Severity: critical
Location: src/instructions/transfer.rs:29:5

Rule:
  Detects CPI calls where no key or program ID check precedes the invocation,
  allowing an attacker to supply a malicious program as the CPI target.

Matched Because:
  CPI call `invoke` in `handler` has no preceding program key validation.

Source:
  27|     let ix = build_instruction(&ctx);
  28|
 >29|     invoke(&ix, &[ctx.accounts.target_program.to_account_info()])?;
    | ^
  30|     Ok(())
  31|

Guidance:
  Add require!(program.key() == expected::ID, ...) before the CPI, or use
  Program<'info, T> to enforce program ID validation at the account level.

-------- Summary --------
Total findings: 2
Critical: 2
High: 0
Medium: 0
Low: 0

By rule:
  1  SW001 Missing signer check
  1  SW003 Arbitrary CPI target
```

---

## Rules

| ID | Title | Severity | What it catches |
|----|-------|----------|-----------------|
| SW001 | Missing signer check | Critical | `AccountInfo`/`UncheckedAccount` named as authority with no `#[account(signer)]` and no `is_signer` guard |
| SW002 | Missing owner check | Critical | `AccountInfo`/`UncheckedAccount` with no `owner` or `address` constraint and no owner guard in handler |
| SW003 | Arbitrary CPI target | Critical | Raw `invoke`/`invoke_signed` calls with no preceding program key validation |
| SW005 | Unchecked arithmetic | High | `+`, `-`, `*`, `+=`, `-=`, `*=` on account fields with no checked math; can overflow in release builds |
| SW006 | Type cosplay | Critical | `try_from_slice` without a discriminator check; a malicious account type can be deserialized as another |
| SW008 | Missing post-CPI reload | High | Account written after a CPI that may have mutated it, without an intervening `reload()` |
| SW009 | Missing token mint check | High | Mutable `TokenAccount` with no `token::mint` constraint and no `associated_token`, allowing wrong-mint deposits |
| SW010 | Missing token owner check | High | Mutable `TokenAccount` with no `token::authority` or authority `has_one`, allowing unauthorized withdrawals |
| SW011 | AccountInfo as data account | Medium | `AccountInfo` used where a typed `Account<'info, T>` is needed (init/has_one/seeds constraints present) |
| SW012 | Missing seeds + bump on PDA | High | PDA accounts with `seeds` but no `bump`, skipping bump verification |
| SW013 | PDA seed unvalidated account | High | PDA seeds reference an `AccountInfo`/`UncheckedAccount` sibling with no `owner`, `address`, or `signer` constraint |
| SW014 | PDA bump not canonical | Medium | `bump = <bare_identifier>` uses a caller-supplied bump instead of Anchor's canonical derivation |
| SW016 | init_if_needed usage | Medium | `init_if_needed` accounts that can be silently re-initialized, resetting state |
| SW018 | Missing realloc::zero | Medium | `realloc` without `realloc::zero = true`, leaving stale data in reallocated memory |
| SW020 | AccountInfo as CPI program | Medium | `AccountInfo` used as a CPI program account instead of typed `Program<'info, T>` |
| SW021 | PDA seed collision risk | High | Adjacent variable-length seeds (e.g. `name.as_bytes()` next to `symbol.as_bytes()`) with no fixed-length seed between them, allowing different inputs to derive the same PDA |

### Inline Suppressions

Suppress a finding on the same line:

```rust
#[account(mut)] // sentio-ignore SW001
pub authority: AccountInfo<'info>,
```

Suppress a finding on the next line:

```rust
// sentio-ignore-next-line SW001
#[account(mut)]
pub authority: AccountInfo<'info>,
```

Both forms accept a comma-separated list of rule IDs: `// sentio-ignore SW001, SW002`.

---

## How It Works

sentio's precision comes from a two-layer analysis pipeline built on top of `syn`, Rust's macro-safe AST parser. Every rule operates on the actual structure of the code — typed AST nodes, not source text.

### Layer 1 — Anchor Account Index

For every `#[derive(Accounts)]` struct, sentio extracts a typed model of each field:

```
AccountInfo named "authority"
  type_info   → kind: AccountInfo, wrappers: []
  constraints → is_signer: false, owner: false, address: false,
                init: false, seeds: false, bump: false, ...
```

This is built by `anchor_accounts.rs`, which uses `syn`'s meta parser to read every key inside `#[account(...)]` into a strongly-typed `AnchorFieldConstraints` struct. Every constraint — `mut`, `signer`, `has_one`, `seeds`, `bump`, `owner`, `address`, `init`, `init_if_needed`, `realloc`, `realloc::zero`, `close` — is parsed from the AST token stream into a typed field on the struct.

### Layer 2 — Instruction Analysis Index

For every function in the file, sentio builds an ordered model of three things:

**Guards** — `if` conditions, `require!`, `assert!` macros. Each guard records which semantic properties it references:

```rust
require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
// → GuardEvidence { references_signer: true, references_key: false, order: 1 }
```

**Calls** — function and method calls, classified as `Cpi`, `Reload`, `Deserialization`, or `Other`. CPI calls also carry a `cpi_account_names` list — the actual account names resolved from the `CpiContext` struct:

```rust
let cpi_accounts = Transfer {
    from: ctx.accounts.vault.to_account_info(),
    to: ctx.accounts.dest.to_account_info(),
    authority: ctx.accounts.authority.to_account_info(),
};
token::transfer(CpiContext::new(token_prog, cpi_accounts), amount)?;
// → CallEvidence { kind: Cpi, cpi_account_names: ["vault", "dest", "authority"], order: 3 }
```

**Writes** — assignment expressions (`=`, `+=`, `-=`, etc.) with the target captured as a string:

```rust
ctx.accounts.game.status = GameStatus::Resolved;
// → WriteEvidence { target: "ctx.accounts.game.status", order: 4 }
```

All three are tagged with a sequential `order` counter so rules can reason about what happened before and after what.

### Cross-Reference Analysis (SW008)

The post-CPI reload rule is the most sophisticated. Without cross-reference tracking, any write after a CPI would produce a finding — including writing `game.status = Resolved` after a token transfer, which is a false positive because `game` wasn't part of the transfer at all.

sentio tracks variable bindings across statements to solve this:

1. `let cpi_accounts = Transfer { from: ctx.accounts.vault, ... }` → sentio records `cpi_accounts → ["vault", "dest", "authority"]` in a binding map.
2. `let cpi_ctx = CpiContext::new(prog, cpi_accounts)` → sentio resolves `cpi_accounts` through the binding map, forwarding the names to `cpi_ctx`.
3. `token::transfer(cpi_ctx, amount)` → sentio resolves `cpi_ctx`, giving the call `cpi_account_names: ["vault", "dest", "authority"]`.
4. After the CPI: `game.status = Resolved` → sentio extracts account name `game`, checks it against `["vault", "dest", "authority"]` → not found → no finding.
5. After the CPI: `vault.amount -= fee` → sentio extracts `vault` → found → finding.

The inline pattern (`token::transfer(CpiContext::new(prog, Transfer { from: ..., to: ..., authority: ... }), amount)`) is also handled — sentio traverses into the nested call expression to extract the struct fields directly.

### Rule Execution

Each rule receives the `AnchorAccountsIndex` and the `InstructionIndex` for the file and combines them with boolean logic:

```
SW001: field.type ∈ {AccountInfo, UncheckedAccount}
       && field.name contains "authority" | "admin" | "signer" | "initializer"
       && !constraints.is_signer
       && !constraints.address
       && no guard references_signer && mentions field_name
       → flag
```

No heuristic scoring. No ML. Just structured data and typed predicates.

### Suppression Pass

After all rule matches are collected, sentio runs a suppression pass. For each finding, it looks up the source line and checks whether it contains `// sentio-ignore SWXXX`. Suppressed matches are dropped before results are returned or printed.

---

## Workspace Layout

```
sentio-rs/
├── crates/
│   ├── sentio-core/
│   │   ├── src/
│   │   │   ├── anchor_accounts.rs       # Anchor #[account(...)] constraint parser
│   │   │   ├── instruction_analysis.rs  # Guard / call / write extractor with CPI cross-reference
│   │   │   ├── rules/
│   │   │   │   └── anchor/              # One module per rule (SW001–SW020)
│   │   │   ├── scanner.rs               # File walker + suppression pass
│   │   │   └── syntax.rs                # syn parsing wrapper
│   │   └── tests/
│   │       ├── common/mod.rs            # Shared fixture helpers
│   │       ├── fixtures/swXXX/          # risky.rs / safe.rs / suppressed.rs per rule
│   │       └── rules_swXXX.rs           # Integration test per rule
│   └── sentio-cli/
│       ├── src/
│       │   ├── lib.rs                   # Public formatter API (render_human_report, etc.)
│       │   └── main.rs                  # CLI entry point (clap)
│       └── tests/
│           └── human_output.rs          # Formatter integration tests
```

---

## Design Philosophy

**Structured analysis.** sentio parses Rust source with `syn` — the same parser used by procedural macros — so every constraint, guard, and expression is a typed AST node. Rules ask "does this field have a `seeds` constraint with no `bump`?" against a structured model, not against source text.

**Anchor-aware.** sentio models Anchor's `#[derive(Accounts)]` structs and their full constraint vocabulary — `signer`, `owner`, `address`, `has_one`, `seeds`, `bump`, `init_if_needed`, `realloc::zero`, and more. It also understands Anchor CPI patterns including `CpiContext::new` and account struct resolution.

**Precision over recall.** A false positive wastes an auditor's time and erodes trust in the tool. Every rule ships with a real-program validation pass. When precision cannot be guaranteed, rules are flagged as `manual review` rather than treated as confirmed vulnerabilities.

**No compiler dependency.** sentio works on raw `.rs` source files. No `rustc_private`, no proc-macro expansion, no `cargo build` needed. Point it at any Solana program directory and it works.

---

## Status

sentio is under active development. The rule set is growing; the AST infrastructure is stable.

**16 rules ship today** covering the most common Solana/Anchor vulnerability classes. Native Solana (non-Anchor) rule support is on the roadmap.
