# Security & Responsible-Use Policy

The 0xRay Hunt Harness is offensive-security tooling. Read this before you run it.

## Authorized use only
Run the harness **only** against targets you own or are explicitly authorized to test
(in-scope bug-bounty assets, or a signed engagement with rules of engagement).
Unauthorized testing may be illegal.

## The safety contract (do not weaken)
- **Read-only by default.** The only write action is guardrail-gated test-account creation on
  in-scope targets (capped by `HUNT_MAX_ACCOUNTS`, fully audited).
- **In-scope only** — recon and hunting are filtered to scope at every boundary.
- **No brute force / password cracking** — refused by policy.
- **Stop at draft** — findings are published and emailed but **never submitted** without
  explicit, per-report human approval.
- **Evidence-only** — claim exactly what was proven; no "could potentially".

## Secret hygiene
- **Never commit `.env`.** It is gitignored; use `harness/.env.example` as the template and
  `chmod 600` your real `.env`.
- Rotate the bridge token and the SMTP app password periodically.
- The CI **secret-scan** runs on every push and pull request (`make secret-scan`) — do not bypass it.
- If you believe a secret was committed, rotate it immediately and purge it from history.

## Reporting a vulnerability in the harness itself
Open a private issue or contact the maintainer directly. Please do not disclose publicly
until a fix is available.
