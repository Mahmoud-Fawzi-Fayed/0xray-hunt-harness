# 0xRay Hunt Harness

![skills](https://img.shields.io/badge/skills-78-blue)
![engine modules](https://img.shields.io/badge/engine%20modules-23-blue)
![posture](https://img.shields.io/badge/posture-read--only%20·%20stops%20at%20draft-brightgreen)
![license](https://img.shields.io/badge/license-Proprietary-red)

Autonomous, **anti-duplicate** bug-hunting harness. It runs on **Cursor agents**, hunts
**read-only by default**, and **stops at draft — it never submits without a human**.

The harness wires three things together:

- an **engine** ([`engine/`](engine/)) — recon, yield-ranking, dedup/novelty oracles, the hunt
  orchestrator, the host bridge, notify/publish, guardrails, self-learning, and **78 skills**;
- an **n8n** workflow (novelty monitor) that watches target surface and triggers hunts on change;
- the **host bridge** + **Cursor agents/rules** that drive the LLM hunting loop.

> **Scope note:** this repo is the reusable *framework* only. Per-target recon, findings, evidence,
> and anything touching real programs are deliberately **excluded** (see [`.gitignore`](.gitignore)).

## Contents
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [The pipeline](#the-pipeline)
- [Cursor agents & rules](#cursor-agents--rules)
- [Engine](#engine)
- [Skills catalog](#skills-catalog)
- [Autonomous capabilities](#autonomous-capabilities)
- [Safety contract](#safety-contract)
- [Testing & CI](#testing--ci)
- [Project docs](#project-docs)

## Architecture

```
            ┌────────────────────────────────────────────────────────┐
            │                      YOU / Cursor chat                   │
            │   drives hunts, spawns subagents (.cursor/agents/*.md)   │
            └───────────────┬────────────────────────────────────────┘
                            │
  n8n (novelty-monitor) ──► │ POST /hunt            ┌─────────────────┐
  diffs target surface      ▼                        │  78 skills      │
                    ┌───────────────┐   dispatches   │  engine/skills  │
                    │  host bridge  │───────────────►│  (hunt-* + …)   │
                    │  :8899 (token)│                 └─────────────────┘
                    └───────┬───────┘
                            │ orchestrator --persist (pm2, crash-safe)
                            ▼
      novelty → recon → rank → map → hunt → validate → DRAFT-GATE → STOP
                                                            │
                                         publish finding + email (never submit)
```

## Repository layout

| Path | What |
|------|------|
| [`harness/`](harness/) | the glue: n8n `docker-compose`, the novelty-monitor workflow, and the `hunt-run` / `hunt-bridge-start` / `import-workflow` scripts |
| [`harness/.env.example`](harness/.env.example) | every config key documented — copy to `.env` and fill in |
| [`.cursor/agents/`](.cursor/agents/) | the 5 subagents: `hunt-orchestrator`, `recon-novelty`, `vuln-hunter`, `dedup-oracle`, `report-drafter` |
| [`.cursor/rules/`](.cursor/rules/) | the always-on hunt rules: SOP, dedup/novelty discipline, triager-grade reporting |
| [`engine/`](engine/) | the full engine (23 modules) + 78 skills — see [Engine](#engine) |
| [`MANUAL.md`](MANUAL.md) | the full operator manual (dashboard, sessions, ops, troubleshooting) |
| [`Makefile`](Makefile) | one-command setup, run, and the CI gates |

## Quick start

Prerequisites: Linux + Docker (`docker compose`), Python 3.10+, `pm2` (`npm i -g pm2`), and
`cursor-agent` installed and logged in.

```bash
make setup        # cp harness/.env.example -> harness/.env  (then edit it)
#   set HUNT_BRIDGE_TOKEN (openssl rand -hex 32), SMTP_*, CURSOR_HUNT_MODELS …

make n8n-up       # start the isolated hunting n8n container
make import       # import the novelty-monitor workflow (injects the bridge token/url)
make bridge       # start the token-gated host bridge on :8899 under pm2

# start a hunt on a target (scope JSON from the engine), 3h loop, crash-safe
cd harness && pm2 start ./hunt-run.sh --name hunt-acme -- /path/to/acme.scope.json 10800
pm2 logs hunt-acme
```

Run `make` with no target for the full list.

> **Paths:** the launcher scripts reference the original deployment layout
> (`/root/Claude-BugHunter` for the engine, `/root/BugHunting_0xRay/harness` for config). The
> vendored [`engine/`](engine/) mirrors that engine — point the scripts at wherever you place it,
> or keep the same paths. Skills are read at runtime from `~/.claude/skills`; install the engine's
> `skills/` there (or symlink it).

## The pipeline

`novelty → recon → rank → map → hunt → validate → DRAFT-GATE → STOP`

1. **Novelty first** — diff the target's surface vs the last snapshot; new/changed surface is hunted first.
2. **Recon** — service/tech fingerprint, platform discovery, JS endpoint+secret mining, param mining (cached per target so it doesn't re-hammer the target).
3. **Rank** — cover all vuln classes, most-findable first; known-issue surface is down-ranked (dedup-aware).
4. **Hunt** — Cursor agents test each `(endpoint, class)` with the matching skill, curl-first, and only claim a vuln with **demonstrated impact** (never reflection/error-only).
5. **Validate** — an adversarial second pass; defaults to false-positive unless proven.
6. **Dedup gate** — every confirmed finding is scored; `LIKELY_DUP` is held, `NOVEL`/`REVIEW` is drafted.
7. **STOP** — drafts + an `approval.md` are written and the finding is **published + emailed** (to `SMTP_TO`, Cc `SMTP_CC` from `.env` — set once, honored everywhere). Nothing is submitted.

Hunting rotates **only** across the approved pool in `CURSOR_HUNT_MODELS`; an off-pool model can never
be used (enforced in code).

## Cursor agents & rules

- **Agents** ([`.cursor/agents/`](.cursor/agents/)) — spawnable subagents for each stage of the hunt.
- **Rules** ([`.cursor/rules/`](.cursor/rules/)) — always-applied discipline:
  - `hunt-harness` — the standard operating procedure for every target;
  - `dedup-novelty` — mandatory pre-hunt (novelty-first) and pre-submit (dedup oracle) gates;
  - `ywh-triager-grade-reports` — claim exactly what was proven; per-class PoC minimums.

## Engine

[`engine/`](engine/) is the full engine. The runtime modules under [`engine/engine/`](engine/engine/):

`orchestrator` · `bridge` · `agent` · `recon` · `osint` · `scope` · `scopefetch` · `targets` ·
`novelty` · `jsdiff` · `observe` · `yieldrank` · `skill_map` · `dedup` · `guardrails` · `identity` ·
`sms` · `authsession` · `websearch` · `learn` · `notify` · `state` · `engine`

Helpers: [`engine/scripts/`](engine/scripts/) (`selfcheck`, `e2e`, `watchdog`, `lint_skills`) and
the operator commands under [`engine/commands/`](engine/commands/). The engine is vendored from
[elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter); to refresh the
public portion: `git -C /path/to/Claude-BugHunter archive HEAD | tar -x -C engine`.

## Skills catalog

78 skills live under [`engine/skills/`](engine/skills/) (plus auto-authored drafts in
`engine/skills/learned/`). New in this release: ✨ `hunt-webhook`, `hunt-jwt`, `hunt-api-owasp`,
`hunt-desktop-macos`, `hunt-desktop-windows`.

**Recon & novelty** — `web2-recon` · `offensive-osint` · `osint-methodology` · `hunt-subdomain` ·
`hunt-source-leak` · `changed-js-deepdive` · `hunt-ntlm-info` · `supply-chain-attack-recon`

**Injection & server-side** — `hunt-sqli` · `hunt-nosqli` · `hunt-ssrf` · `hunt-rce` · `hunt-lfi` ·
`hunt-ssti` · `hunt-xxe` · `hunt-deserialization` · `hunt-ldap` · ✨`hunt-webhook`

**Client-side** — `hunt-xss` · `hunt-dom` · `hunt-cors` · `hunt-csrf` · `hunt-open-redirect` ·
`hunt-cache-poison`

**Access control & logic** — `hunt-idor` · `hunt-business-logic` · `hunt-race-condition` ·
`hunt-file-upload` · `hunt-host-header` · `hunt-http-smuggling`

**Auth · identity · session** — `hunt-auth-bypass` · `hunt-oauth` · `hunt-saml` · `hunt-mfa-bypass` ·
`hunt-ato` · `hunt-session` · ✨`hunt-jwt` · `hunt-brute-force`

**API** — ✨`hunt-api-owasp` · `hunt-api-misconfig` · `hunt-graphql` · `hunt-grpc` · `hunt-websocket`

**Framework / stack-specific** — `hunt-nextjs` · `hunt-nodejs` · `hunt-laravel` · `hunt-springboot` ·
`hunt-aspnet` · `hunt-sharepoint`

**Cloud · infra · appliances** — `hunt-cloud-misconfig` · `cloud-iam-deep` · `hunt-k8s` · `hunt-cicd` ·
`hunt-tls-network` · `enterprise-vpn-attack` · `vmware-vcenter-attack`

**Identity providers (enterprise)** — `m365-entra-attack` · `okta-attack`

**Desktop / mobile** — ✨`hunt-desktop-macos` · ✨`hunt-desktop-windows` · `apk-redteam-pipeline`

**AI / LLM** — `hunt-llm-ai`

**Web3 / crypto** — `web3-audit` · `meme-coin-audit`

**Methodology · dedup · triage · reporting** — `bb-methodology` · `bug-bounty` · `bb-local-toolkit` ·
`dedup-novelty` · `triage-validation` · `redteam-mindset` · `mid-engagement-ir-detection` ·
`evidence-hygiene` · `report-writing` · `bugcrowd-reporting` · `redteam-report-template` ·
`security-arsenal` · `hunt-dispatch` · `hunt-misc`

Each `hunt-*` skill follows the same house structure: *what actually pays (and what doesn't)*,
detection, **PoC minimums**, a **dedup-gate** footer, and cross-references. See
[CONTRIBUTING.md](CONTRIBUTING.md) to add one.

## Autonomous capabilities (all guardrail-gated)

Driven mid-hunt when a finding needs them: **web search** (confirm a CVE before claiming impact),
**test identities** (disposable mail.tm accounts for IDOR/auth), **phone/SMS OTP** (optional, off
unless configured), and **self-learning** (research an unknown stack and draft a new skill into
`engine/skills/learned/`). Every account/login/SMS action passes `engine/engine/guardrails.py`.

## Safety contract

- **Read-only by default** — the only "write" is guardrail-gated test-account creation on in-scope
  targets (capped by `HUNT_MAX_ACCOUNTS`, audited).
- **No brute force / password cracking** — refused by policy.
- **In-scope only** — recon + hunt are filtered to scope at every boundary.
- **Stop at draft** — nothing is ever submitted without explicit, per-report human approval.
- **Evidence-only** — findings claim exactly what was proven; no "could potentially".

See [SECURITY.md](SECURITY.md) for the full responsible-use policy.

## Testing & CI

```bash
make selfcheck     # engine crash/loop/hostile-input gauntlet + live bridge
make e2e           # end-to-end: env→models→bridge→n8n→skills→pipeline→dedup→notify→publish
make skills-lint   # frontmatter, naming, secret + client-identifier scan over all skills
make secret-scan   # fail if obvious secrets are present in the tree
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs **secret-scan** and **skills-lint**.
GitHub Actions needs billing enabled on the account; while it's off the workflow is **manual**
(`workflow_dispatch`) so pushes never show a failed run. Run the same gates locally with `make`,
or install them as a pre-push hook once: `make hooks`.

## Project docs

[`MANUAL.md`](MANUAL.md) · [`SECURITY.md`](SECURITY.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) ·
[`CHANGELOG.md`](CHANGELOG.md) · [`LICENSE`](LICENSE)

---

*Harness branding: 0xRay. Engine © its authors (see [`engine/LICENSE`](engine/LICENSE)).*
