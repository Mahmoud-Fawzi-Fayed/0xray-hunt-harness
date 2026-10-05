# 0xRay Hunt Harness

Autonomous, **anti-duplicate** bug-hunting harness. It runs on **Cursor agents**, hunts
**read-only by default**, and **stops at draft — it never submits without a human**.

The harness wires three things together:

- an **engine** (vendored in [`engine/`](engine/)) — recon, yield-ranking, dedup/novelty oracles,
  the hunt orchestrator, notify/publish, guardrails, and **71 hunt skills**;
- an **n8n** workflow (novelty monitor) that watches target surface and triggers hunts on change;
- a **host bridge** + **Cursor agents/rules** that drive the LLM hunting loop.

> **Scope note:** this repo is the reusable *framework* only. Per-target recon, findings, evidence,
> and anything touching real programs are deliberately **excluded** (see [`.gitignore`](.gitignore)).

---

## Architecture

```
            ┌────────────────────────────────────────────────────────┐
            │                      YOU / Cursor chat                   │
            │   drives hunts, spawns subagents (.cursor/agents/*.md)   │
            └───────────────┬────────────────────────────────────────┘
                            │
  n8n (novelty-monitor) ──► │ POST /hunt            ┌─────────────────┐
  diffs target surface      ▼                        │  hunt skills    │
                    ┌───────────────┐   dispatches   │  engine/skills  │
                    │  host bridge  │───────────────►│  (71 hunt-*)    │
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
| [`engine/`](engine/) | **vendored** engine + 71 hunt skills (see *Engine* below) |
| [`MANUAL.md`](MANUAL.md) | the full operator manual (dashboard, sessions, ops, troubleshooting) |

---

## Prerequisites

- Linux host with Docker + `docker compose`
- Python 3.10+
- `pm2` (`npm i -g pm2`) to keep the bridge + hunts alive
- `cursor-agent` installed and logged in (the harness dispatches LLM work through it)

## Quick start

```bash
# 1) configure
cp harness/.env.example harness/.env && chmod 600 harness/.env
#    edit harness/.env — set HUNT_BRIDGE_TOKEN (openssl rand -hex 32), SMTP_*, model pool…

# 2) start the hunting n8n (isolated container/network/volume)
cd harness
docker compose -f docker-compose.hunt-n8n.yml --env-file .env up -d

# 3) import the novelty-monitor workflow (injects the bridge token/url)
./import-workflow.sh workflows/novelty-monitor.json

# 4) start the host bridge (token-gated control plane on :8899), kept alive by pm2
pm2 start ./hunt-bridge-start.sh --name hunt-bridge

# 5) start a hunt on a target (scope JSON from the engine), 3h loop, crash-safe
pm2 start ./hunt-run.sh --name hunt-acme -- /path/to/acme.scope.json 10800
pm2 logs hunt-acme
```

> **Paths:** the launcher scripts reference the original deployment layout
> (`/root/Claude-BugHunter` for the engine, `/root/BugHunting_0xRay/harness` for config).
> The vendored [`engine/`](engine/) mirrors that engine — point the scripts at wherever you
> place it, or keep the same paths.

---

## The pipeline

`novelty → recon → rank → map → hunt → validate → DRAFT-GATE → STOP`

1. **Novelty first** — diff the target's surface vs the last snapshot; new/changed surface is hunted first.
2. **Recon** — service/tech fingerprint, platform discovery, JS endpoint+secret mining, param mining (cached per target so it doesn't re-hammer the target).
3. **Rank** — cover all vuln classes, most-findable first; known-issue surface is down-ranked (dedup-aware).
4. **Hunt** — Cursor agents test each `(endpoint, class)` with the matching `hunt-*` skill, curl-first, and only claim a vuln with **demonstrated impact** (never reflection/error-only).
5. **Validate** — an adversarial second pass; defaults to false-positive unless proven.
6. **Dedup gate** — every confirmed finding is scored; `LIKELY_DUP` is held, `NOVEL`/`REVIEW` is drafted.
7. **STOP** — drafts + an `approval.md` are written and the finding is **published + emailed**. Nothing is submitted.

## Models

Hunting rotates **only** across the approved pool in `CURSOR_HUNT_MODELS`. An off-pool model can never be
used (enforced in code). Default pool: `kimi-k3-max`, `cursor-grok-4.6-high`, `grok-4.7-high`,
`claude-fable-5-1-high`.

## Cursor agents & rules ("skills")

- **Agents** ([`.cursor/agents/`](.cursor/agents/)) — spawnable subagents for each stage of the hunt.
- **Rules** ([`.cursor/rules/`](.cursor/rules/)) — always-applied discipline:
  - `hunt-harness` — the standard operating procedure for every target;
  - `dedup-novelty` — mandatory pre-hunt (novelty-first) and pre-submit (dedup oracle) gates;
  - `ywh-triager-grade-reports` — claim exactly what was proven; per-class PoC minimums.

## Engine

[`engine/`](engine/) is **vendored** from [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
(committed content only — no scratch files or secrets). It provides the orchestrator, recon,
`yieldrank`, `dedup`/`novelty`, `notify`/publish, `guardrails`, identity/SMS/self-learning, the
bridge, and the **71 hunt skills** under [`engine/skills/`](engine/skills/). To refresh it:

```bash
git -C /path/to/Claude-BugHunter archive HEAD | tar -x -C engine
```

## Autonomous capabilities (all guardrail-gated)

Driven mid-hunt when a finding needs them: **web search** (confirm a CVE before claiming impact),
**test identities** (disposable mail.tm accounts for IDOR/auth), **phone/SMS OTP** (optional, off unless
configured), and **self-learning** (research an unknown stack and draft a new skill). Every
account/login/SMS action passes `engine/guardrails.py`.

## Safety contract

- **Read-only by default** — the only "write" is guardrail-gated test-account creation on in-scope
  targets (capped + audited).
- **No brute force / password cracking** — refused by policy.
- **In-scope only** — recon + hunt are filtered to scope at every boundary.
- **Stop at draft** — nothing is ever submitted without explicit, per-report human approval.
- **Evidence-only** — findings claim exactly what was proven; no "could potentially".

## Testing

```bash
python3 engine/scripts/selfcheck.py   # crash/loop/hostile-input gauntlet + live bridge
python3 engine/scripts/e2e.py         # end-to-end: env→models→bridge→n8n→skills→pipeline→dedup→notify→publish
python3 engine/scripts/e2e.py --ping  # also live-ping each model
```

See [`MANUAL.md`](MANUAL.md) for the dashboard, session management, operations, and troubleshooting.

---

*Harness branding: 0xRay. Engine © its authors (see [`engine/LICENSE`](engine/LICENSE)).*
