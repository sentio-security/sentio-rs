# Security policy

This document covers two different things:

1. **Bugs in Sentio itself** (the scanner)
2. **Responsible use** of Sentio findings against other people’s programs

False positives / false negatives from a scan are **not** security reports for Sentio. Use [GitHub Issues](https://github.com/sentio-security/sentio-rs/issues) or see [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## 1. Reporting a vulnerability in Sentio

Report security vulnerabilities **in Sentio** (`sentio-cli` / `sentio-core`, releases, or the GitHub Action).

Please **do not** open a public GitHub issue for exploitable bugs in Sentio.

Prefer one of:

1. **GitHub Private Vulnerability Reporting**  
   Repo → **Security** → **Advisories** → **Report a vulnerability**  
   https://github.com/sentio-security/sentio-rs/security/advisories/new

2. If private reporting is unavailable, email the maintainers via the addresses on the [GitHub org](https://github.com/sentio-security) / latest release, and mark the message clearly as a security report.

### Please include

- Affected version (`sentio version` / crates.io version / commit)
- Description of the issue and impact (e.g. crash, unexpected code execution, path escape, secret leak)
- Steps to reproduce (minimal PoC if possible)
- Whether the issue is already public

We will acknowledge reports as soon as we can and coordinate a fix and disclosure timeline.

### Scope (examples)

In scope when it affects Sentio users or maintainers:

- Remote or local code execution via malicious or malformed program input Sentio parses
- Path traversal / writing outside the intended scan tree when scanning untrusted trees
- Leakage of secrets that Sentio should never collect (Sentio is designed for **local** analysis with **no source upload**)
- Compromised release artifacts or CI supply-chain issues in this repository

Out of scope for *this* section:

- Findings Sentio produces about third-party Anchor programs (tool working as designed, or an FP/FN report — see below for how to handle real vulns you discover that way)
- Denial of service from scanning extremely large trees unless there is a clear, practical fix
- Issues only in unmaintained forks of Sentio

### Safe harbor (reports about Sentio)

If you report in good faith, avoid privacy violations and destruction of data, and give us a reasonable chance to fix before public disclosure, we will not pursue legal action related to the report.

### Preferred disclosure (Sentio)

We aim to fix confirmed issues promptly and publish a GitHub Security Advisory (and crates.io yank/release if needed) before or together with public discussion.

---

## 2. Responsible use

Sentio is a **detection tool**. A finding is not permission to exploit, ransom, or dump a vulnerability in public without giving the affected project a fair chance to fix it.

If you scan **someone else’s** codebase (open source or otherwise) and believe you have found a **real** security issue:

1. **Do not** exploit it, threaten disclosure for payment, or post a full PoC publicly as a first step.
2. **Contact the project** through their `SECURITY.md`, security contact, GitHub private vulnerability reporting, or another documented channel.
3. Follow **coordinated / responsible disclosure** norms: share enough detail for them to reproduce and fix, agree on a timeline when possible, and only publish after a fix or an agreed date.
4. If there is no security contact, use the maintainers’ public channels carefully and still avoid weaponized detail until they can respond.

You are responsible for how you act on Sentio’s output. Sentio’s authors are not a party to your disclosure of third-party bugs and do not endorse misuse of findings.

Scanning **your own** programs (or programs you are authorized to test) and fixing issues internally is always fine.
