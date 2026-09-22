# sentio

<p align="center">
  <img src="https://avatars.githubusercontent.com/u/282654001?s=200&v=4" alt="sentio" width="120" />
</p>

<div align="center">
  <p>
    <a href="https://crates.io/crates/sentio-core"><img src="https://img.shields.io/crates/v/sentio-core?color=2C1810&label=sentio" alt="sentio version" /></a>
    <a href="https://github.com/sentio-security/sentio-rs/blob/main/LICENSE"><img src="https://img.shields.io/crates/l/sentio-cli" alt="license" /></a>
  </p>
</div>

<p align="center"><strong>Local pre-audit for Anchor programs. No build. No source upload.</strong></p>

---

## 2 steps · 1 minute

```bash
cargo install sentio-cli
sentio scan .
```

That's it. Run from your Anchor workspace root (where `Anchor.toml` lives).

**MSRV:** Rust **1.85+** (`rust-version` in `Cargo.toml`; required by `ureq` 3.3 and our toolchain choices).

<p align="center">
  <img src="assets/demo.gif" alt="sentio scan demo" width="720" />
</p>

---

## More commands

```bash
sentio version

# CI: fail on high/critical, emit SARIF for Code Scanning
sentio scan . --format sarif --output sentio.sarif --fail-on high

# JSON for tooling / agents
sentio scan . --format json --output report.json

# Markdown for docs / Discord / Notion
sentio scan . --format markdown --output report.md

# One rule only
sentio scan . --rule SW003

sentio rules list
```

Copy [`sentio.example.toml`](./sentio.example.toml) to `sentio.toml` for excludes, fail thresholds, and per-rule overrides.

**Contribute:** [CONTRIBUTING.md](./CONTRIBUTING.md) — fork → branch → PR.  
**Changelog** (severities, rules, releases): [CHANGELOG.md](./CHANGELOG.md).  
**Limits (ZK, cross-program, AST):** [docs/LIMITATIONS.md](./docs/LIMITATIONS.md).

---

## CLI Reference

```
sentio <COMMAND>

Commands:
  scan      Scan a Solana program directory or file for vulnerabilities
  rules     Manage and inspect the built-in rule set
  version   Print the installed sentio version and check for updates

sentio scan [OPTIONS] [PATH]

Arguments:
  [PATH]                    Directory or .rs file to scan [default: .]

Options:
  --format <FORMAT>         human (default) | json | sarif | markdown
  --output <FILE>           Write json/sarif/markdown output to a file
  --rule <RULE_ID>          Run only a specific rule, e.g. --rule SW003
  --include-tests           Include test files (excluded by default)
  --config <FILE>           Path to sentio.toml
  --fail-on <LEVEL>         off | low | medium | high | critical
  --baseline <FILE>         Hide findings present in this baseline JSON
  --update-baseline <FILE>  Write current findings to a baseline file
  -h, --help                Print help

sentio rules list             Print all rule IDs and titles
sentio version, -V, --version Print the installed version and check for a newer release
```

`sentio version` (and `-V`/`--version`) make a brief network call to check for updates. A random anonymous ID is generated on first run and stored at `~/.config/sentio/telemetry_id` so repeated checks from the same machine don't get counted more than once. Set `SENTIO_NO_TELEMETRY=1` to disable this entirely. **No source code, file paths, or scan results ever leave your machine** — `scan` never makes network calls. That is intentional: unlike cloud auto-auditors, sentio is a local pre-audit gate.

**Exit codes**

| Code | Meaning |
| ---- | ------- |
| `0`  | Clean, or only findings below `--fail-on` |
| `1`  | One or more findings at or above `--fail-on` |
| `2`  | Parse error in one or more files |

---

## Configuration (`sentio.toml`)

Place `sentio.toml` in the scan root (or pass `--config`). CLI flags always override the file.

```toml
[scan]
exclude = ["migrations", "idls"]
include_tests = false
fail_on = "high"          # recommended for CI

[rules.SW027]
enabled = false           # hygiene: report locally, don't gate PRs

[rules.SW016]
severity = "low"          # demote noisy-but-useful rules
```

See [`sentio.example.toml`](./sentio.example.toml) for a full annotated example.

### Fail thresholds

| `--fail-on` | Exit 1 when… |
| ----------- | ------------ |
| `off`       | Never (parse errors still exit 2) |
| `low`       | Any finding (default, preserves historical CLI behavior) |
| `medium`    | Medium, high, or critical |
| `high`      | High or critical (good CI default) |
| `critical`  | Critical only |

### Baseline (only-new findings)

Adopt sentio without boiling the ocean on day one:

```bash
# Capture current findings as accepted debt
sentio scan . --update-baseline .sentio/baseline.json

# Later: only surface regressions
sentio scan . --baseline .sentio/baseline.json --fail-on high
```

Baseline identity is `rule_id + path + message` (line numbers are ignored so small refactors do not re-open accepted findings).

### SARIF / GitHub Code Scanning

```bash
sentio scan . --format sarif --output sentio.sarif --fail-on high
```

Upload `sentio.sarif` with [`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action). A ready-to-copy workflow lives in [`examples/github-workflow.yml`](./examples/github-workflow.yml). A composite Action is under [`action/`](./action/).

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

Severities follow an audit rubric: **Critical** = direct value loss / compromise with minimal preconditions; **High** = value loss or corruption with one clear precondition; **Medium** = needs chaining; **Low** = hygiene.

| ID | Title | Severity |
| --- | --- | --- |
| SW001 | Missing signer check | Critical |
| SW002 | Missing owner check | Critical |
| SW003 | Arbitrary CPI target | Critical |
| SW005 | Unchecked arithmetic | High |
| SW006 | Type cosplay — missing discriminator check | Critical |
| SW008 | Missing post-CPI account reload | High |
| SW009 | Missing token account mint check | High |
| SW010 | Missing token account owner check | Critical |
| SW011 | AccountInfo used as data account | High |
| SW012 | Missing seeds + bump on PDA | High |
| SW013 | PDA seed references unvalidated account | High |
| SW014 | PDA bump may not be canonical | High |
| SW016 | init_if_needed usage (manual review) | High |
| SW018 | Missing realloc::zero = true | Low |
| SW020 | AccountInfo used as CPI target program | Critical |
| SW021 | PDA seed collision risk | High |
| SW022 | Manual account closure without close constraint | High |
| SW023 | Unvalidated remaining_accounts forwarded to CPI | Critical |
| SW024 | Division by zero | High |
| SW025 | unwrap() / expect() in instruction handler | Medium |
| SW026 | create_program_address used instead of find_program_address | High |
| SW027 | Missing event emission on state change | Low |

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

Suppress all findings of a rule within an entire function (useful for intentionally permissionless instructions):

```rust
// sentio-ignore-fn SW007
pub fn permissionless_ix(ctx: Context<MyAccounts>) -> Result<()> {
    // all SW007 findings inside this function are suppressed
    Ok(())
}
```

All forms accept a comma-separated list of rule IDs: `// sentio-ignore SW001, SW002`.

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
├── action/                              # Composite GitHub Action
├── examples/github-workflow.yml         # Drop-in CI workflow
├── sentio.example.toml                  # Annotated project config
├── crates/
│   ├── sentio-core/
│   │   ├── src/
│   │   │   ├── anchor_accounts.rs       # Anchor #[account(...)] constraint parser
│   │   │   ├── instruction_analysis.rs  # Guard / call / write extractor with CPI cross-reference
│   │   │   ├── config.rs                # sentio.toml loader + fail-on
│   │   │   ├── baseline.rs              # Only-new findings baseline
│   │   │   ├── sarif.rs                 # SARIF 2.1.0 export
│   │   │   ├── rules/                   # One module per rule
│   │   │   ├── scanner.rs               # File walker + suppression pass
│   │   │   └── syntax.rs                # syn parsing wrapper
│   │   └── tests/
│   │       ├── fixtures/swXXX/          # risky.rs / safe.rs / suppressed.rs per rule
│   │       └── rules_swXXX.rs           # Integration test per rule
│   └── sentio-cli/
│       └── src/                         # CLI entry point + human formatter
```

---

## Design Philosophy

**Structured analysis.** sentio parses Rust source with `syn` — the same parser used by procedural macros — so every constraint, guard, and expression is a typed AST node. Rules ask "does this field have a `seeds` constraint with no `bump`?" against a structured model, not against source text.

**Anchor-aware.** sentio models Anchor's `#[derive(Accounts)]` structs and their full constraint vocabulary — `signer`, `owner`, `address`, `has_one`, `seeds`, `bump`, `init_if_needed`, `realloc::zero`, and more. It also understands Anchor CPI patterns including `CpiContext::new` and account struct resolution.

**Precision over recall.** A false positive wastes an auditor's time and erodes trust in the tool. Every rule ships with a real-program validation pass. When precision cannot be guaranteed, rules are flagged as `manual review` rather than treated as confirmed vulnerabilities.

**No compiler dependency.** sentio works on raw `.rs` source files. No `rustc_private`, no proc-macro expansion, no `cargo build` needed. Point it at any Solana program directory and it works.
