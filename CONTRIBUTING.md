# Contributing

## Workflow

1. **Fork** this repo (or use a branch with write access).
2. **Branch** from `main` (`git checkout -b fix/sw024-const` or `feat/...`).
3. **Change** code + tests.
4. **PR** into `main` of `sentio-security/sentio-rs`.

Do not commit directly to `main`. One PR ≈ one focused change.

## GitHub norms

- **Verified commits** — sign commits (SSH or GPG) so GitHub shows them as **Verified**.  
  - SSH: [Signing commits with SSH keys](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)  
  - Enable “Vigilant mode” / require verified commits on your account if you can.
- **Conventional, clear messages** — e.g. `fix(SW003): …`, `feat: …`, `chore: bump rustls…`. Explain *why* in the body when non-obvious.
- **Link issues** — use `Closes #N` / `Fixes #N` in the PR description (or commit body) so issues auto-close on merge.
- **PR description** — what changed, how you tested, screenshots/logs only if useful. Keep the diff focused.
- **Don’t force-push to `main`**; force-push on your feature branch only when rewriting history before review (or after addressing review, if agreed).
- **Respond to review** — push follow-up commits (or a clean rebase if the reviewer prefers); don’t leave threads hanging.
- **No secrets** in the repo (tokens, private keys, `.env`).

## Before you push / open a PR

Run this from the repo root (all must pass):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo audit
```

To auto-format before the check:

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo audit
```

| Command | Why |
|---------|-----|
| `cargo fmt` | Consistent style |
| `cargo clippy -D warnings` | No new lint debt |
| `cargo test --all` | Unit + integration green |
| `cargo audit` | No known vulnerable deps in `Cargo.lock` |

Install audit once: `cargo install cargo-audit --locked`.

If `cargo audit` fails on a transitive crate, prefer `cargo update -p <crate>` (or a compatible bump) and include the `Cargo.lock` change in the PR.

## Rules (sentio-core)

| Do | Don't |
|----|--------|
| Add/update fixtures under `crates/sentio-core/tests/fixtures/swXXX/` | Ship a rule with no tests |
| Keep `risky.rs` / `safe.rs` / `suppressed.rs` in sync | Flag style that is already safe (precision > recall) |
| Register new rules in `RuleRegistry::baseline()` | Reuse an existing SW id |

New rule id: next free `SWxxx`. Match existing rule modules for structure.

## False positives

Open a GitHub issue with:

- rule id (e.g. `SW024`)
- short code snippet
- why it is safe

PRs that fix FPs with a regression test are preferred.

## Security bugs in Sentio

Vulnerabilities **in Sentio itself** (not scan FPs) → see [SECURITY.md](./SECURITY.md). Do not file those as public issues.

## Larger contributions

- Prefer high-signal security / precision fixes and evaluation harness work (e.g. corpus / `sentio-bench`).
- Discuss large features or architecture changes in an **issue first** — don’t open a mega-PR rewrite without agreement.
- See [docs/LIMITATIONS.md](./docs/LIMITATIONS.md). Sentio is AST-first: **no ZK proof verification, no cross-program trust graphs** unless explicitly scoped.

## Questions

Use Discord or a GitHub issue. Keep security reports responsible (no exploit dumps against third parties).
