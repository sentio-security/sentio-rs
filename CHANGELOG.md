# Changelog

All notable changes to Sentio are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Sentio versions use [SemVer](https://semver.org/).

**Why this matters:** rule **severity** feeds `--fail-on` / `fail_on` in CI. Pinning a crates.io version without a changelog makes severity shifts invisible.

Rule IDs are stable (`SW001`…`SW027`). Gaps in numbering (no SW004, SW007, …) are intentional reserved slots, not missing history.

---

## [Unreleased]

Changes on `main` since **0.3.2** (not yet cut as a crates.io release):

### Added
- CONTRIBUTING — verified commits, pre-push `fmt` / `clippy` / `test` / `audit`

### Fixed
- **GlobalIndex** scoped per Anchor program (same-named Accounts across programs no longer merge) — [#8](https://github.com/sentio-security/sentio-rs/issues/8)
- **`sentio-ignore-fn`** uses AST function spans; ignore markers only in real `//` comments — [#9](https://github.com/sentio-security/sentio-rs/issues/9)
- Human report write errors propagated; `BrokenPipe` treated as success — [#11](https://github.com/sentio-security/sentio-rs/issues/11)
- MSRV pinned to **Rust 1.85** — [#10](https://github.com/sentio-security/sentio-rs/issues/10)
- `rustls` ≥ 0.23.45 (RUSTSEC-2026-0285)

### Changed
- Precision / FP reductions (in git; upgrade from crates.io 0.3.2 via git/`main` until the next release):
  - **SW003** — quiet CPI when target is typed `Program<'info, T>` (still flags unvalidated `*program*` AccountInfo)
  - **SW025** — quiet `Pubkey::create_*` / fixed-layout `try_to_vec` unwraps
  - **SW010** — quiet user mint/burn endpoints when mint is pinned (vault/`from` still flagged)

---

## [0.3.2] — 2026-08

### Added
- **Cross-file analysis:** workspace `GlobalIndex` links `#[derive(Accounts)]` ↔ `Context<T>` handlers across modules
  - **SW001** — cross-file `is_signer` guards
  - **SW002** — cross-file owner guards
  - **SW003** — confused-deputy when Signers live on Accounts in another file
  - **SW022** — quiet manual close when `close = …` is on linked Accounts

### Changed
- Integration tests: `phase_a` → `scan_config`

---

## [0.3.1] — 2026-08

### Added
- Markdown report export: `--format markdown`
- `CONTRIBUTING.md`, `docs/LIMITATIONS.md`

### Fixed
- **SW024** — non-zero const divisors (including casts) no longer false-positive
- **SW027** — `msg!` counts as observability alongside `emit!`
- **SW002** — skip identity-only accounts (`.key()` / PDA seed use); ZK / cross-program still out of scope

### Changed — rule severity reclassification

Severities follow an audit rubric (also documented in the README):

| Severity | Meaning |
|----------|---------|
| Critical | Direct value loss / compromise with minimal preconditions |
| High | Value loss or corruption with one clear precondition |
| Medium | Needs chaining / more context |
| Low | Hygiene / observability |

Notable **severity** moves (affects `--fail-on`):

| Rule | Previous | New |
|------|----------|-----|
| SW010 | High | **Critical** |
| SW011 | Medium | **High** |
| SW014 | Medium | **High** |
| SW016 | Medium | **High** |
| SW018 | Medium | **Low** |
| SW020 | Medium | **Critical** |
| SW023 | High | **Critical** |

Unchanged at Critical: SW001, SW002, SW003, SW006.  
SW025 remains Medium; SW027 remains Low.

---

## Earlier

Pre-0.3.1 history introduced the Anchor/Rust rule set (SW001–SW027, with intentional ID gaps), CLI formats (human / JSON / SARIF), config, baseline, suppressions, and the GitHub Action. See git history and GitHub Releases for detail.

---

[Unreleased]: https://github.com/sentio-security/sentio-rs/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/sentio-security/sentio-rs/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/sentio-security/sentio-rs/releases/tag/v0.3.1
