# Engagement engine

A **decision-support engine**, not an autonomous robot. It maps a target's attack surface using
function profiles and trust dimensions, hunts based on observed behavior, **shows you each stage
live** — so you spend your expert 20% where the 80% automation points. Active hunting runs
automatically through the full 10-phase pipeline.

## Design principles
1. **Deterministic-first.** Breadth (recon, parameter discovery, secret scanning, service
   fingerprint) is plain Python + passive tooling — **`$0`, no agents, no rate-limit burn**.
   The AI runtime is reserved for judgment calls in hunt/validate/chain.
2. **Behavior-driven, not class-driven.** No hardcoded vulnerability lists or class-based skill
   routing. The AI forms hypotheses from observed target behavior, function profiles, and trust
   dimensions. Classification happens only after evidence supports it.
3. **Dynamic tool discovery.** Recon tools are discovered at runtime via a capability registry
   (8 categories, 11 tools). New tools added to PATH are picked up without code changes.
4. **Show every stage.** Each phase logs what it found, live, so you always know where to focus.
5. **Safe by construction.** Scope is a deterministic allowlist; agents run **read-only by
   default** with hard rules-of-engagement; a deterministic scope-audit flags any out-of-scope PoC.
   Agent subprocesses receive a filtered environment (secrets denied).

```
  recon → discover → explore → rank → map → plan → hunt → validate → chain → report
    │        │          │        │      │      │      │        │         │       │
    │        │          │        │      │      │      │        │         │       └ dedup + draft
    │        │          │        │      │      │      │        │         └ attack-path chaining
    │        │          │        │      │      │      │        └ live retest + LLM skeptic + disposition
    │        │          │        │      │      │      └ per-function deep analysis, trust dimensions
    │        │          │        │      │      └ behavior-based test cases + auth bootstrap
    │        │          │        │      └ arsenal.md with function profiles
    │        │          │        └ yield-based ranking (dedup-downranked)
    │        │          └ functional analysis, app model
    │        └ exhaustive surface: OpenAPI + JS mining + browser + GraphQL
    └ subdomains, seeds, params (dynamic tool registry)
```

## Modules (55)

| Piece | What it is |
|---|---|
| `scope.py` | deterministic allowlist (apex/wildcard/CIDR/regex; deny-wins; default-deny). Enforced at recon **and** hunt. |
| `recon.py` | **deterministic recon** — per target: service/tech (JS markers), JS-bundle endpoint mining, **JS secret scanning**, and **all input parameters** via dynamic tool registry (gau, waybackurls, katana, or any tool on PATH). Noise-filtered, scope-filtered. No LLM in the find-step. |
| `discovery.py` | **exhaustive surface mapping** — OpenAPI probing (11 paths), JS bundle mining, browser capture, GraphQL introspection. Multi-round expansion with convergence detection and residual tracking. Provenance normalized to structured dicts. |
| `skill_map.py` | **behavior-driven matching** — skills matched by tech stack and analysis content, never by URL patterns or vulnerability class names. `for_hypothesis()` gates references behind case-linked evidence. |
| `function_profile.py` | **protocol-neutral function profiles** — action, resource, actors, inputs, outputs, effects, state, sensitivity, trust dimensions. Provenance normalized at input boundary. |
| `target_adapters.py` | **live-target and artifact adapters** — cloud, LLM, Android, iOS, desktop, infrastructure, contract artifacts. All provenance structured. |
| `coverage.py` | **dimensional coverage** — per-operation, per-identity, per-trust-dimension evidence. Trust dimensions primary, class coverage secondary. |
| `testplan.py` | **behavior-based test cases** — dimensional outcomes, not class checklists. Cases carry function profiles and trust dimensions. |
| `yieldrank.py` | **yield-based ranking** — observed impact and unresolved trust, not URL or vulnerability names. Dedup-downranks known issues. |
| `osint.py` | **per-target recon** — subdomain enumeration via dynamic tool loop (subfinder, assetfinder, crt.sh, or any available). dnsx validation. |
| `state.py` | persistent, resumable engagement store (`state.json` + `evidence/` + `engine.log` + `arsenal.md` + `report.md`). |
| `agent.py` | AI runtime dispatch via `HUNT_AGENT_CMD` + JSON extraction. Preflight ping, model pool enforcement, session management, timeout failover. **Environment filtered** — secrets denied from subprocess. |
| `engine.py` | the orchestrator: 10 phases, scope enforcement, circuit breaker, budget gate, auth refresh, parallel hunt/validate, candidate→confirm, report. |
| `learn.py` | **self-learning** — auto-researches unknown stacks, drafts behavior-driven skill templates (no OWASP checklists). Evolves skills from hunt outcomes. |
| `vulncatalog.py` | **dedup normalization** — 60+ class aliases for corpus matching. No class→skill routing (SKILLS dict removed). |
| `verify.py` | **triager-grade verification** — 60 class-specific proof rules (post-evidence quality gates), live retest, reproduction requirement. |
| `browser.py` | **Playwright headless** — XHR/fetch/WebSocket capture, scope-filtered deepening. No consent auto-click, no hardcoded parameter names. |
| `jsminer.py` | **JS bundle analysis** — API paths, GraphQL ops, auth patterns, routes, hidden endpoints, source map mining. |

## The pipeline

The full 10-phase pipeline runs automatically. Each phase feeds the next:

```bash
# Run the full pipeline:
python3 engine/engine.py --scope engagement.json

# Run specific phases:
python3 engine/engine.py --scope engagement.json --phases hunt,validate,report

# Dry-run with mock agents:
python3 engine/engine.py --scope engine/engagement.example.json --base /tmp/eng --mock --hunt
```

Key flags: `--phases a,b,c` (explicit override) · `--parallel N` (concurrent agents, default 3) ·
`--mock` (synthetic fixtures, no AI budget).

## Safety
- **Read-only by default** — all testing is non-destructive unless guardrails explicitly approve a write action.
- **Deterministic scope-audit** — every confirmed finding is checked for out-of-scope hosts in its PoC.
- **Calibrated severity** — the adversarial validator's severity (not the hunt's raw guess) is what's stored.
- **Agent isolation** — subprocess environment filtered: `_TOKEN`, `_PASS`, `_KEY`, `_SECRET`, `SMTP_*` denied.
- **No brute force** — refused by policy at the guardrails layer.
- **Stop at draft** — nothing is ever submitted without explicit, per-report human approval.

## Test suites

```bash
python3 scripts/selfcheck.py          # 63/63 — crash/loop/hostile-input gauntlet
python3 tests/test_dynamic_harness.py  # 27/27 — evidence pipeline, dimensional coverage, skill gating
python3 tests/test_behavior_lab.py     # 9/9  — function profiles, chain verification, yield metrics
python3 scripts/e2e.py                 # 13/16 — end-to-end pipeline trace (2 WARN infra, 0 FAIL)
```
