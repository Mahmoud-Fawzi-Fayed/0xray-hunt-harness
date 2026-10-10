# Changelog

All notable changes to the 0xRay Hunt Harness. Format based on
[Keep a Changelog](https://keepachangelog.com/); releases are date-based.

## [0.10.0] - 2026-10-10
### Added — destatic hunt + auto-relogin
- **No product/class path catalog in the engine.** Rank, skill map, and session probes use this
  program's live surface and the operator paste. `HUNT_DEEP=1` runs one analysis-driven agent per
  URL instead of spraying an OWASP class list.
- **Creds vault auto-relogin** (`authsession.save_login` / `relogin`) — password POST or cookie GET
  against the stored `login_url`. JWT `exp` on headers *and* cookies marks a session dead; reviewer
  and hunt refresh it. Header names are case-preserved (some APIs are case-sensitive).
- **Reviewer 60s heal** — revive false-dead logins, coerce leftover class items to deep, wake
  hunts onto current code, publish `_review/live.json` to the panel.
- **`brain.py`** — per-program hunt memory so the next agent does not repeat the same empty test.

### Changed
- `hunt-dispatch` loads matching skills from disk (cap 8), not a hardcoded army.
- Yield rank uses this journal only (no global class-weight table).

## [0.9.1] - 2026-10-06
### Added — RTFS / Informative protection (generic, every program)
- **`verify.py` now runs the `disposition.py` RTFS/Informative gate** plus a generic
  **precondition check** — the #1 closure cause: impact that assumes obtaining a victim's session /
  transaction-id / token the PoC never demonstrates. Such findings now return DO_NOT_SUBMIT with the
  exact reason, instead of being green-lit and closed as RTFS.
- **New skill `triage-rtfs`** — the methodology: the precondition ladder (own-session / asserted-leak /
  capability-URL → RTFS/Informative; in-scope oracle / enumerable id / reproduced XSS-CSRF / write-past-
  terminal-lock → VALID), a pre-draft self-check, and how to rescue a held finding. Registered as a
  default skill so it's loaded on every hunt. Skills 80 → 81.
- Proven against the two real closures: own-session 2FA-disable ATO and asserted-leak checkout rewrite
  both → DO_NOT_SUBMIT; a valid cross-account enumerable IDOR stays READY. selfcheck 70/70.

## [0.9.0] - 2026-10-06
### Added — guarded session management (never auto-deletes)
- **`sessions.py`** — the single sanctioned way to manage Cursor sessions. **Dry-run by default**;
  deletion only with an explicit `--confirm`. Clears only **orphaned** chat dirs (never a session in a
  running target's pool); `reset --slug` refuses to touch a running target. `list` shows the inventory.
- **Bridge** `/sessions/clear` + `/sessions/reset` (confirm-gated) and a `sessions.orphaned_chats` count
  in `/capabilities`.
- **Panel** — a "Cursor sessions" box on the Capabilities tab: shows chats on disk + orphaned count, a
  **Preview clear** (dry-run) and a confirm-gated **Clear orphaned chats** button.
- `selfcheck` → **70/70** (adds sessions + disposition).

## [0.8.1] - 2026-10-06
### Added
- **File upload** on the Verify-finding tab — attach the report + evidence (screenshots, HAR,
  request/response, .md/.json/.txt). Text files are merged into the checks; images count as evidence.
- **Combined expert verdict** — with deep triage on, the final trigger is the STRICTER of the
  deterministic gate and the LLM expert security review.
### Security (upload intake hardening — it's an upload on our own site)
- basename-only filenames (path-traversal safe: `../../evil.md` → `evil.md`, kept inside the dir),
  extension allow-list (text + images + pdf; scripts/executables like `.php`/`.sh`/`.exe` rejected),
  per-file (8 MB) + total (24 MB) caps, path-escape guard, `chmod 600`, stored in the engagement dir
  (never web-served or executed). Per-path body cap preserves the general 2 MB DoS limit; only `/verify`
  accepts large (32 MB) uploads. Covered by `verify.py` selftest (traversal / bad-type / oversized) + selfcheck 68/68.

## [0.8.0] - 2026-10-06
### Added — "Verify finding" gate on the dashboard
- **`verify.py`** — submit a draft finding (class, severity, URL, steps, PoC, evidence, impact) and get a
  verdict: **READY / NEEDS_FIXES / DO_NOT_SUBMIT**, with a per-check list, what's missing, a readiness
  score, and a dedup check. Enforces per-class PoC minimums, the always-rejected list, scope, the
  program's qualifying/non-qualifying lists, and severity honesty. Optional deep LLM triager opinion.
- **Bridge `/verify`** + a **"Verify finding"** tab on the panel (fill the form → get the verdict).
- `selfcheck` → **68/68** (adds verify).

### Fixed
- `/activity` read every engine log in full on each ~8s poll → slow/timeout as logs grew. Now it tails
  128 KB per log and caches for 15s (miss ~2.4s, cached hit ~2ms).
- Bridge swallows client-disconnects quietly (no more `BrokenPipe` tracebacks).
- Public-suffix-aware apexes (`x.vwfs.co.za → vwfs.co.za`, not `co.za`) so the monitor doesn't observe
  bogus TLD apexes.

## [0.7.0] - 2026-10-06
### Added — add a target by PASTING the program page
- **`scopeparse.py`** — paste a YesWeHack / HackerOne / Bugcrowd program page and it auto-extracts
  in/out-of-scope hosts, the mandatory User-Agent suffix, qualifying + non-qualifying vuln classes
  (mapped to hunt classes), the reward grid, and the rules-of-engagement → a full dynamic scope +
  a human-readable `program.md`. No hand-editing.
- **Bridge `/targets/ingest`** — POST the pasted page → parsed + registered (guards an empty paste).
- **Panel** — a new "Add by pasting the program page" box on the Targets tab (textarea + *Parse & add*).
  The panel source is now version-controlled at [`harness/panel/index.html`](harness/panel/index.html).
- Registered **Paddle** via this flow (12 in-scope, 2 out-of-scope, UA + `BugBounty`, 13 classes).
- `selfcheck` → **67/67** (adds scopeparse).

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
