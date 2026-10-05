# Changelog

All notable changes to the 0xRay Hunt Harness. Format based on
[Keep a Changelog](https://keepachangelog.com/); releases are date-based.

## [0.6.0] - 2026-10-05
### Added — authenticated & advanced hunting (the "find more bugs" upgrade)
- **Authenticated sessions** (`authn.py`): per-target operator-provided sessions (cookie/bearer/headers)
  with two identities **A + B**, stored outside the repo (`<base>/_auth/<slug>.json`). Recon and the agent
  reach the behind-login surface via `netget … --as A/B`.
- **Cross-account IDOR/BOLA diff** (`authz.py`): replay a request as A vs B and flag where B reads
  A-owned data — triage for OWASP #1 (Broken Access Control), the best-paying class. Read-only; two-account
  PoC still required before drafting.
- **Headless-browser capture** (`browser.py`, Playwright): render a SPA (optionally authenticated) and
  capture the **real XHR/fetch/GraphQL API** that curl-based recon misses — the biggest discovery win.
- **Coverage matrix + leads** (`coverage.py`): per-class tested/total + an interesting-leads queue, so
  "0 findings" is backed by visible coverage instead of a black box.
- **APK → API surface** (`apkmap.py`, jadx/apktool): pull hosts/endpoints/secrets from an app even when
  the live API is geo/IP-gated (e.g. meleclerc).
- Engine wiring: authenticated recon when a session exists; the agent ROE + capabilities now surface
  `netget --as`, `browser.py`, `authz.py`, `apkmap.py`, and the two-account IDOR workflow. All additive +
  guarded (other targets unchanged); everything stays per-target/dynamic (no hardcoding).
- `selfcheck` extended to **66/66** (adds authn/authz/coverage/apkmap selftests).

## [0.5.0] - 2026-10-05
### Added
- Engine support for **path-scoped API programs** (e.g. a mobile backend with documented routes on one
  host). New per-target scope fields, all additive + backward-compatible:
  - `user_agent` — a required SOC-tag UA, applied to recon (`osint`/`recon` via `HUNT_USER_AGENT`) and
    injected into the agent rules-of-engagement so every request carries it.
  - `endpoints` — documented API routes seeded directly into the hunt worklist (when recon can't crawl).
  - `roe_extra` — program-specific rules appended to the ROE.
  - `skip_param_mining` — disable gau/katana crawling for "no automated scanners" programs.
  - `proxy` + `impersonate` — route recon AND the hunt agent through an egress proxy with a curl_cffi
    TLS fingerprint (new `netget` helper) for targets whose edge resets by source-IP / TLS (e.g. a mobile
    API that only accepts its app's origin). The agent is instructed to use `netget` instead of curl.

## [0.4.0] - 2026-10-05
### Added
- **`hunt-mcp`** — Model Context Protocol attacks (OWASP MCP Top 10 2025 / Agentic Apps 2026): tool
  poisoning, full-schema poisoning, rug-pull / silent redefinition, tool-response injection, context
  injection & over-sharing, and confused-deputy / token passthrough (e.g. a server reusing a DB
  `service_role` to bypass RLS). Grounded in 2025-2026 in-the-wild incidents.
- **`hunt-baas`** — Backend-as-a-Service misconfig (Firebase / Supabase / PocketBase / Appwrite /
  Nhost): open Firestore/RTDB/Storage rules and Supabase RLS-off / `USING(true)` tables readable with
  the public anon key (UpGuard: 16k+ exposed Supabase DBs; CVE-2025-48757).
- Registered `mcp` / `baas` classes + starter probes in `skill_map.py`; linked `hunt-mcp` into `llm-ai`.

### Changed
- `hunt-llm-ai` refreshed for 2026: MCP cross-reference, RAG up/down exfiltration, and
  context-privilege-escalation (M-CPE / X-CPE).
- Skills count **78 -> 80**. The earlier-authored `hunt-webhook` / `hunt-jwt` / `hunt-api-owasp` plus
  the two new skills are now installed into the live engine (`~/.claude/skills`) so running hunts use them.

## [0.3.0] - 2026-10-05
### Fixed
- **Email CC now works.** `notify.py` never read `SMTP_CC`, so Cc recipients were silently dropped on
  every email (findings, status, monitor alerts). `cfg`/`build`/`send`/`send_safe` now honor
  `SMTP_CC` (and a new `SMTP_BCC`) from one place; the bridge `/notify` also accepts `cc`/`html`.
- **n8n "Send Email credentials not set".** The novelty-monitor's `emailSend` node (which needed a
  manually-created n8n SMTP credential) is replaced by an `httpRequest` to the bridge `/notify`. No
  n8n credential is required; recipients come from `.env`, so an edit there reflects everywhere at once.

### Changed
- CI is now **manual** (`workflow_dispatch`) — GitHub Actions requires account billing; the same gates
  run locally via `make secret-scan` / `make skills-lint`, or a `make hooks` pre-push hook.
- `.env.example` documents `SMTP_CC` / `SMTP_BCC`; `import-workflow.sh` note updated (no creds needed).

## [0.2.0] - 2026-10-05
### Added
- **Full engine vendored from the live working tree** — previously only the engine's committed
  subset shipped, which omitted the core runtime. Now included: `orchestrator.py`, `bridge.py`,
  and every module (`dedup`, `novelty`, `yieldrank`, `targets`, `notify`, `guardrails`, `identity`,
  `sms`, `websearch`, `learn`, `jsdiff`, `observe`, `scopefetch`, `authsession`) plus the test
  scripts (`selfcheck`, `e2e`, `watchdog`).
- Two previously-missing referenced skills: `changed-js-deepdive`, `dedup-novelty`.
- Two desktop hunt skills: `hunt-desktop-macos`, `hunt-desktop-windows`.
- Three new authored skills — `hunt-webhook`, `hunt-jwt`, `hunt-api-owasp` — registered in
  `skill_map.py` (new `webhook`, `jwt`, `api` classes + starter probes).
- Repo scaffolding: `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `.editorconfig`,
  `Makefile`, GitHub issue/PR templates, and CI (`secret-scan` + `skills-lint`).

### Changed
- Hunt skills synced to their **edited** versions (the dedup-gate footer across the `hunt-*` set).
- README expanded with a full **skills catalog** and a `make`-based setup.
- The skills linter now skips the `learned/` container.

### Security
- Re-scrubbed: no real `.env` values, tokens, or client/engagement identifiers in the tree.
- Learned-skill drafts sanitized to remove hunt-target program names.

## [0.1.0] - 2026-10-05
### Added
- Initial harness: n8n novelty monitor, host bridge, Cursor agents + rules, `MANUAL.md`, and the
  engine (committed subset).
