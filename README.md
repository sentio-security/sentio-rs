# sentio-rs

Rust-based CLI scanner for common Solana program vulnerability patterns.

`sentio-rs` is the Rust implementation of Sentio's pre-audit security scanner for
Anchor and native Solana programs. The current focus is a stable CLI, a reusable
AST index, inline suppressions, and the first high-signal Anchor rules.

## Scope

- Scan Rust source files in Solana programs
- Report findings with severity, rule ID, location, and remediation guidance
- Support human and JSON output modes
- Support rule filtering and inline suppressions
- Ignore tests by default to reduce false positives
- Anchor-aware AST extraction for future rules
- First shipped rule: `SW012` missing seeds + bump on PDA

## Planned CLI

```bash
sentio-rs scan .
sentio-rs scan . --format json
sentio-rs scan . --rule SW017
sentio-rs scan . --include-tests
sentio-rs rules list
```

## Current Status

- `scan <path>` works
- `--format human|json` works
- `--rule SW###` is wired
- `--include-tests` works
- inline suppressions work
- `SW012` is implemented and tested
- `SW018` is next

## Workspace Layout

- `crates/sentio-core`: scanner engine, finding model, rule registry
- `crates/sentio-cli`: command-line interface and reporters

## Design Direction

This repository intentionally starts as a standalone scanner, not a
`rustc_private` lint. The initial goal is fast delivery, stable distribution, and
high-signal Solana checks. Type-aware compiler integration can be explored later
for rules that truly need semantic analysis.
# sentio-rs
