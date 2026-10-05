# 0xRay Hunt Harness — Operator Manual

Autonomous, **anti-duplicate** bug-hunting harness. Runs on **Cursor agents** (not Claude), hunts
read-only by default, and **stops at draft — it never submits without you**.

- **Engine:** `/root/Claude-BugHunter/engine`  ·  **Config/secrets:** `/root/BugHunting_0xRay/harness/.env`
- **Dashboard:** https://finding.redtracefai.com/panel/  (Basic-Auth)
- **Findings viewer + email:** `finding.redtracefai.com` · `x00xrayx00x@gmail.com`
- **Runtime models (pool):** `kimi-k3-max`, `cursor-grok-4.6-high`, `grok-4.7-high`, `claude-fable-5-1-high`

---

## 1. Quick start

Everything is already running under `pm2` and survives reboots/crashes.

```bash
pm2 list                                  # hunt-bridge + hunt-<target> processes
python3 /root/Claude-BugHunter/scripts/e2e.py        # one-command health check (14 stages)
```

Open the **dashboard** and watch: Overview (KPIs), Activity (model + skills per step), Findings,
Capabilities (tools + sessions + learning + account audit), Live logs.

---

## 2. The dashboard (panel)

`https://finding.redtracefai.com/panel/` — Basic-Auth (user `ray`). The browser never sees the bridge
token; nginx injects it. The panel polls every 8s and is served `no-store` (no stale JS).

| Tab | Shows |
|-----|-------|
| Overview | targets, running hunts, findings, alerts; hunt-steps, models rotating, learned skills, tools ready; **System & guardrails** (runtime, chat sessions, model pool, capabilities) |
| Targets | add / start / stop / remove targets |
| Activity | every hunt/validate step with its **model + skills**, and model-usage bars |
| Findings | published finding pages (also emailed) |
| Capabilities | web-search / identity / SMS / self-learning status, learning journal, **account & write-action audit** |
| Live logs | the running hunt's engine log (defaults to the active hunt) |

---

## 3. Managing targets

Three ways: the **Targets tab**, the **bridge API**, or the **CLI**. All resolve a target to a
canonical slug (lowercase; `DrAnsay` → `dransay`) used for its dir, logs, sessions, and pm2 name.

### Add a target
- **Panel:** Targets → "Add / update target" → program name + in-scope hosts (one per line, wildcards ok).
- **API:** `POST /targets/add {"program":"acme","hosts":"*.acme.com\napi.acme.com"}`
- **CLI (full platform scope):** fetch scope via the `bb-platforms` MCP, then:
  ```bash
  python3 engine/targets.py add --program acme --scope-file acme.json   # any H1/Bugcrowd/YWH shape
  ```
  Seeds **all concrete in-scope hosts** (not just the first few), so sandboxes/vendor portals are hunted too.

### Start / stop / rerun / remove
| Action | Panel | API | Effect |
|--------|-------|-----|--------|
| Start | "Start" | `POST /hunt {"program":"acme","interval":10800}` | runs under pm2 (`hunt-acme`), 3h loop |
| Stop | "Stop" | `POST /hunt/stop {"program":"acme"}` | **kills the hunt + all its agent sessions**; **keeps session state** so a rerun resumes |
| Rerun | "Start" again | `POST /hunt` | **resumes the same sessions** from the per-target state (no new chats) |
| Remove | "Remove" | `POST /targets/remove {"program":"acme"}` | kills sessions, **purges its session state + its chats**, deletes the scope |

Change the schedule with the `interval` seconds on `/hunt` (default 3h = `10800`).

---

## 4. How a hunt works (the pipeline)

`novelty → recon → rank → map → hunt → validate → DRAFT-GATE → STOP`

1. **Novelty first** — diff the target's surface vs the last snapshot; new/changed surface is hunted first.
2. **Recon** — service/tech fingerprint, platform (.well-known/OAuth), JS endpoint+secret mining, and
   `gau`+`katana` param mining (**cached per target for 6h** so it doesn't re-hammer the target each round).
3. **Rank (yield + dedup)** — cover all classes, most-findable first; known-issue surface is down-ranked.
4. **Hunt** — Cursor agents test each `(endpoint, class)`; they `cat` the matching `hunt-*` skills, use
   curl, and only claim a vuln with **demonstrated impact** (never reflection/error-only).
5. **Validate** — an adversarial second pass; defaults to false-positive unless proven.
6. **Dedup gate** — every confirmed finding is scored; `LIKELY_DUP` is held, `NOVEL`/`REVIEW` is drafted.
7. **STOP** — drafts + an `approval.md` are written, the finding is **published + emailed**. Nothing is
   submitted. "No finding this round" is a **status, not a stop** — it re-recons and rotates classes.

---

## 5. Models

Hunting rotates **only** across the approved pool in `CURSOR_HUNT_MODELS`. An off-pool model (e.g. a
stale default) is forced back into the pool in code — it can never be used. Verify each live:

```bash
python3 scripts/e2e.py --ping          # pings each pool model once
```

---

## 6. Sessions (minimal chat churn)

The harness keeps a **small pooled set of cursor-agent sessions per target** and **resumes** them across
every step, phase, and round — instead of opening a new chat per step.

- **Pool size:** `HUNT_SESSION_POOL` (default 3, matches parallelism).
- **Refresh:** after `HUNT_SESSION_MAX_USES` turns (default 25) or on error/limit (then it rotates model).
- **Per-target state:** `~/.bughunter-engagements/_sessions/<slug>/state.json` — the last session ids.
- **Stop** keeps that state → **rerun resumes**; **remove** purges it (and the chats).
- Watch the count on the panel: *Capabilities → System → Chat sessions*.

If a resumed session was pruned by Cursor, the harness self-heals by opening a fresh one.

---

## 7. Autonomous capabilities (all guardrail-gated)

The agent may drive these mid-hunt when a finding needs them:

- **Web search** — `python3 engine/websearch.py search "<q>"` / `fetch <url>`: confirm a CVE / known bug
  before claiming impact.
- **Test identities** — `engine/identity.py new --program <p>` mints a disposable mail.tm account with a
  live inbox; `identity.py poll ...` reads the verification link/code. For IDOR/auth that need real users.
- **Phone / SMS OTP** — `engine/sms.py`: **disabled** until `SMS_PROVIDER` + `SMS_API_KEY` are set
  (5sim / sms-activate). Phone-gated signups are skipped while disabled.
- **Self-learning** — on an unknown stack, `engine/learn.py auto --kind tech --name "<X>"` researches it
  and drafts `skills/learned/<x>/SKILL.md`, which the next hunt reads. Outcomes (confirmed / false-positive
  / duplicate / error) feed `yieldrank`, so class ranking improves over time.

### Guardrails (`engine/guardrails.py`)
In-scope hosts **only** · ≤ `HUNT_MAX_ACCOUNTS` (default 3) test accounts per target · **no bruteforce**
(refused by policy) · every write action audited (`/accounts` endpoint, Capabilities panel). Turn off
account creation for a program by setting `self_register_ok: false` in its scope json.

---

## 8. Authenticated hunting

The deepest surface (dashboards, authenticated APIs) is behind login. With `HUNT_AUTH=1`, each round the
harness provisions a disposable session **once** (`engine/authsession.py`): mint identity → register on the
best in-scope auth host (sandbox-login/vendors/portal) → verify via inbox → capture the session → inject it
into authenticated hunt steps.

- Works automatically on targets with **open self-service signup**.
- If a target has **no open signup** (e.g. approval-only vendor accounts), provisioning fails fast and a
  **6h cooldown** is set; the hunt continues unauthenticated. To go deeper there, provide credentials
  (store a session manually) or hunt a target that allows signup.

---

## 9. Notifications & findings

- Verified + drafted findings are **published** to `finding.redtracefai.com` and **emailed** (Gmail SMTP
  in `.env`). Test the email render + send: `python3 scripts/e2e.py --email`.
- Each finding page + the email carry the **0xRay** branding and say *draft — not submitted*.
- To submit an approved draft (a human step): re-check dedup, then use the `bb-platforms` MCP
  `draft_* / submit_*` (hard-gated by `BB_ALLOW_SUBMIT` + per-report approval).

---

## 10. Configuration (`harness/.env`)

| Key | Meaning |
|-----|---------|
| `HUNT_BRIDGE_TOKEN` / `BRIDGE_PORT` / `HUNT_BRIDGE_HOST` | host bridge auth + bind |
| `CURSOR_HUNT_MODELS` | the approved model pool (comma list) |
| `HUNT_SESSION_POOL` / `HUNT_SESSION_MAX_USES` | sessions per target / turns before refresh |
| `HUNT_AGENT_TIMEOUT` | per-step agent timeout (default 300s) |
| `HUNT_MAX_HUNTS` | items tested per round (default 24) |
| `HUNT_PARAMS_TTL` | param-mining cache TTL (default 6h) |
| `HUNT_MAX_ACCOUNTS` | test-account cap per target (default 3) |
| `HUNT_AUTH` | `1` = attempt authenticated hunting |
| `SMS_PROVIDER` / `SMS_API_KEY` / `SMS_COUNTRY` | enable phone-gated signups |
| `SMTP_*` | email (Gmail app password) |
| `HUNT_PUBLIC_URL` / `HUNT_WEB_DIR` | findings viewer URL + web root |

`.env` is gitignored and `chmod 600`. Rotate the Gmail app password periodically.

---

## 11. Testing

```bash
python3 scripts/selfcheck.py     # 62 cases: crash/loop/hostile-input gauntlet + live bridge
python3 scripts/e2e.py           # 16 stages end-to-end (env→models→bridge→n8n→skills→pipeline→
                                 #   dedup→notify→publish→capabilities→guardrails→learning→resilience)
python3 scripts/e2e.py --ping    # also live-ping each model
python3 scripts/e2e.py --email   # also send a branded test email
```
Run both before trusting any change. Each engine module also has `python3 engine/<mod>.py selftest`.

---

## 12. Operations

- **Processes:** `pm2 list` · `pm2 logs hunt-<slug>` · `pm2 restart hunt-bridge`. Hunts auto-restart on
  crash and resume from saved state.
- **Bridge:** host service on `127.0.0.1:8899`, token-authed; nginx proxies `/panel/api/` to it.
- **n8n:** `hunt-n8n` container (`:5690`) runs the novelty monitor.
- **nginx:** terminates TLS, serves the panel + findings, injects the bridge token, rate-limits.

---

## 13. Troubleshooting

| Symptom | Cause / fix |
|--------|-------------|
| Panel "bridge offline" / empty | bridge down → `pm2 restart hunt-bridge`; hard-refresh the panel |
| No activity for a while | the hunt is in its 3h sleep between rounds (by design), or in a long recon |
| Target `[429]` in logs | the target is rate-limiting recon; backoff + the 6h params cache handle it; it recovers next round |
| Chats piling up | shouldn't — the pool bounds them; a restart leaves a few that prune on their own. Check *Capabilities → Chat sessions* |
| "no finding" on a target | expected on hardened/unauthenticated surface — the harness won't fabricate. Enable `HUNT_AUTH` / provide creds, or pick a target with more surface |
| Model shows something off-pool | can't happen now (enforced); if `CURSOR_HUNT_MODELS` is empty, set it in `.env` |

---

## 14. Safety contract

- **Read-only by default**; the only "write" is **guardrail-gated test-account creation** on in-scope
  targets (capped + audited).
- **No bruteforce / password cracking** — refused by policy.
- **In-scope only** — recon + hunt are filtered to the scope at every boundary.
- **Stop at draft** — nothing is ever submitted without your explicit, per-report approval.
- **Evidence-only** — findings claim exactly what was proven; no "could potentially".
