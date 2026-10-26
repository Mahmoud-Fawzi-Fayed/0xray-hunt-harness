# 0xRay Hunt Harness

Engine: `~/0xray-hunt-harness/engine/engine/` (49 modules).
Skills: `~/0xray-hunt-harness/engine/skills/` (96 skills, 68 hunt-*).
Agents: `.claude/agents/` (6 agents). Commands: 22.
Config/secrets: `~/0xray-hunt-harness/harness/.env`.
Engagement state: `~/.bughunter-engagements/<program>/`.
Identity store: `~/.bughunter-engagements/_identity/<program>.json`.
Dedup corpus: `~/.bughunter-engagements/_dedup/corpus/<program>.jsonl`.
Recon tools: `~/go/bin/` (auto-added to PATH by engine.py).

## Core Principles

1. **Everything dynamic** — no static target data, no hardcoded vuln lists, no program-specific patterns in engine code. Every module works for ANY target by reading live responses.
2. **Verify before claim** — never report a vulnerability without full proof. Every claim backed by exact HTTP request/response evidence.
3. **Pipeline is law** — every phase runs in order. No skipping discovery. No hunting without surface. No drafting without dedup.
4. **Autonomy stops at draft** — the harness does everything up to the report draft. Submission requires explicit per-report human approval. No exceptions.

## Auto-Start

When a new conversation opens and a target is provided (program URL, domain, or "hunt X"):
1. Run the full pipeline — no waiting for explicit phase commands
2. Start with intake if scope isn't loaded, then every phase in order through deliver
3. If no target is given, ask once: "What program are we hunting today?"
4. Between phases, never pause to ask "should I continue?" — the pipeline is continuous
5. Hard stops: (a) scope ambiguity, (b) auth-wall blocking >50% surface, (c) draft approval before submission

## Model Routing

| Model | Agent | Use |
|-------|-------|-----|
| Opus (`claude-opus-4-6`) | vuln-hunter, report-drafter, hunt-orchestrator, discovery-agent | Deep reasoning, quality writing, thorough mapping |
| Fable (`claude-fable-5-1`) | (creative bypass) | Hypothesis generation, creative bypass, novel attack paths |
| Sonnet (`claude-sonnet-5-5`) | recon-novelty, dedup-oracle | Fast recon, pattern matching, dedup scoring |

Route to Fable when standard techniques fail and lateral thinking is needed. Route to Sonnet for high-volume low-depth work. Default to Opus for anything requiring judgment.

## Pipeline

Every target, in order. Runs automatically via `engine.py run()`.

The engine's actual phase list: `recon → discover → explore → rank → map → plan → hunt → validate → chain → report`

Before the engine runs, intake and scope setup happen via CLI:

### Pre-engine: Intake & Scope
```
intake.py start <program-url>     # H1/Bugcrowd/YWH URL → scope.json → engagement
targets.py show --program <p>     # load/fetch scope via bb-platforms MCP
```

### Phase 1: Recon (`engine.recon()`)
Subdomain enumeration, seed probing, parameter gathering. Uses go/bin tools (subfinder, httpx, gau, katana). Feeds surface to the engine worklist.

### Phase 2: Discover (`engine.discover()`)
Exhaustive surface mapping — runs `discovery.py` which auto-detects program type and adapts methods.

**HARD GATE**: if coverage <80%, hunt phase will BLOCK (set `HUNT_SKIP_COVERAGE_GATE=1` to override).

Discovery auto-detects program type (SPA, pure API, mobile API, GraphQL, WordPress, traditional web) and prioritizes methods accordingly:
- OpenAPI/Swagger parsing
- JS bundle mining (`jsminer.py`)
- Browser capture (headless SPA walk)
- GraphQL introspection
- Admin/internal probing
- API resource probing
- Error-based discovery (405/404 mining)
- Response mining (follow JSON links)
- Dynamic tech fingerprinting (`knowledge.detect_tech()`)

What to discover (coverage checklist — 11 categories):
- `ui_features` — buttons, forms, modals, tabs, workflows
- `api_endpoints` — REST, GraphQL, WebSocket, gRPC, internal
- `user_roles` — admin, member, viewer, guest, service account
- `auth_mechanisms` — cookies, JWT, OAuth, API keys, SAML, MFA
- `org_boundaries` — orgs, projects, teams, workspaces, permissions
- `sharing_flows` — sharing, transfers, invitations, collaboration
- `integration_points` — webhooks, OAuth apps, imports/exports
- `storage_operations` — CRUD, file upload/download
- `admin_endpoints` — actuator, debug, metrics, health, internal
- `billing_flows` — subscriptions, usage limits, spending
- `credential_management` — API keys, tokens, secrets, connection strings

### Phase 3: Explore (`engine.explore()`)
Functional analysis — `explorer.py` builds app model from state, identifies API surface patterns.

### Phase 4: Rank (`engine.rank()`)
Yield-based ranking via `yieldrank.py`. Dedup-downranks known issues. Prioritizes by dynamic signals.

### Phase 5: Map (`engine.map()`)
Knowledge-to-skill mapping. Generates `arsenal.md` with per-endpoint skill recommendations.

### Phase 6: Plan (`engine.plan()`)
`testplan.py` generates signal-based test plan. `authbootstrap.py` analyzes auth needs.

**HARD GATE**: if >50% of surface needs auth and no session exists, hunt phase will BLOCK (set `HUNT_SKIP_AUTH_GATE=1` to override).

Auth provisioning:
- Automated: `authsession.py provision --program <p>`
- Manual: `authbootstrap.py inject --program <p> --cookie '...' --ident A`

### Phase 7: Hunt (`engine.hunt()`)
Knowledge-driven per-endpoint analysis with test-plan-driven dispatch:
1. FETCH — read every byte (status, headers, body, IDs, roles, links, errors, timing)
2. UNDERSTAND — resource, action, auth model, boundaries
3. HYPOTHESIZE — knowledge patterns as starting points, adapt to live behavior
4. TEST — one precise request per hypothesis
5. ITERATE — new hypotheses from observations
6. PROVE — impact with in-scope actions only

Requirements:
- Unique markers in every test request (header with H1 username)
- Body-diff for response comparison (not just status codes)
- n>=10 for timing-based tests
- OOB via Burp Collaborator for blind vulns
- Two distinct identities for any cross-account test

### Phase 8: Validate (`engine.validate()`)
`verify.py check` — triager-grade verification gate. Per-class PoC minimums enforced for 15+ vuln classes.

Per-finding checklist (ALL must pass):
1. Full exploit chain with HTTP requests/responses
2. Cross-account impact with two distinct identities
3. Not documented/expected behavior
4. Working PoC with reproducible steps
5. CVSS scored to match ACTUAL demonstrated impact
6. Evidence saved with redacted credentials

### Phase 9: Chain (`engine.chain()`)
Chains related findings into higher-impact attack paths where possible.

### Phase 10: Report (`engine.report()`)
Dedup check (`dedup.py check`) + report generation. Writes `report.md`.

Dedup verdicts:
- `NOVEL` — proceed to draft
- `REVIEW` — draft with "why this is different" paragraph
- `LIKELY_DUP` — **STOP. Do not draft.**

**HARD STOP: never submit without explicit per-report approval.**

Self-verdict on every draft: `READY` / `NEEDS_FIXES` / `DO_NOT_SUBMIT`.
Findings publish to `https://finding.redtracefai.com` + email `x00xrayx00x@gmail.com`.

## Knowledge-Driven Dynamic Hunting

Three-layer system. Everything is dynamic — works for any target without static data.

### Layer 1: Signal Detection (`testplan.py`)
Each endpoint is profiled by what it DOES:
- `handles_identity` — params contain id/uid/user_id/account_id/org_id
- `accepts_file` — file/upload/attachment/image/avatar params
- `accepts_url` — url/uri/redirect/callback/dest params
- `accepts_freetext` — search/query/filter/comment/template params
- `auth_flow` — login/signup/oauth/token/password/reset paths
- `elevated_privilege` — admin/manage/dashboard/internal paths
- `financial` — payment/billing/order/checkout/subscribe paths
- `state_changing` — create/update/delete/modify/approve paths + POST/PUT/PATCH/DELETE methods

### Layer 2: Knowledge Patterns (`knowledge.py`)
Signals map to historical vuln patterns — "when you see X, here's what has gone wrong before":
- `handles_identity + state_changing` → cross-account mutation, bulk endpoint auth bypass
- `financial + state_changing` → price manipulation, race conditions, discount abuse
- `auth_flow` → token predictability, host header poisoning, OAuth state CSRF
- Tech-detected patterns: `graphql` → introspection leak, depth attack; `jwt` → alg confusion; `rails` → mass assignment; `remix` → loader data exposure; `nextjs` → middleware bypass
- `detect_tech(headers, body, url)` fingerprints tech stack from live HTTP responses — NEVER from static config

### Layer 3: Hypothesis-Driven Hunt (`engine.py`)
Agent receives knowledge-driven guidance and hunts adaptively. No scripted checklist — live reasoning from observed behavior.

### Supporting Capabilities
- **Auth bootstrap** (`authbootstrap.py`): auto-analyzes what accounts are needed post-discovery
- **JS bundle mining** (`jsminer.py`): extracts API paths, GraphQL ops, auth patterns, routes, hidden endpoints, tokens, fetch calls from client JS
- **Knowledge-to-skill bridge** (`skill_map.py`): signals auto-recommend relevant hunt-* skills as reference
- **Coverage tracking** (`coverage.py show --slug <p>`): tested vs untested surface
- **Creative bypass via Fable**: when standard techniques fail, route to Fable for lateral thinking
- **Retry resilience**: failed endpoints retry up to 3x with different models/timeouts

## Self-Learning System (`learn.py`)

The harness teaches itself. When the hunter meets something it has no playbook for, it records the gap, researches it, and drafts a skill so the NEXT hunt already knows how.

### How it works
1. **Gap detection** — engine records gaps automatically:
   - Unknown tech in `map()` → `record_gap("tech", name)`
   - Hunt timeout/double-timeout → `record_gap("bypass", "timeout-<class>")`
   - Hunt max retries exceeded → `record_gap("bypass", "retry-fail-<class>")`
   - Discovery finds nothing → `record_gap("bypass", "empty-discovery-<program>")`
   - Hunt failure details → `learn_from_hunt_failure(program, url, type, error, tech)`

2. **Auto-learning** — `autolearn(kind, name, context)`:
   - Checks if a skill exists → skips if yes
   - Researches the topic (web search, 4 queries max)
   - Drafts a new `SKILL.md` in `engine/skills/learned/<slug>/`
   - Caps: 5 calls/session, 12h cooldown per topic, 120-line max

3. **Outcome recording** — `record_outcome(program, class, result, note)`:
   - Confirmed findings → `confirmed`
   - False positives → `false-positive`
   - Duplicates → `duplicate`
   - Feeds into yieldrank (class ranking learns over time)

4. **Skill evolution** — `evolve_skill(name)`:
   - After 5+ outcomes, auto-evolves the skill
   - Appends confirmed vectors, false-positive patterns, duplicate patterns
   - Skills sharpen over time from real hunt data

5. **Post-hunt gap learning** — after validate(), engine:
   - Reviews all gaps from this engagement
   - Auto-learns skills for up to 3 unresolved gaps
   - Evolves all learned skills with accumulated outcomes

### CLI
```bash
python3 engine/engine/learn.py auto --kind <tech|vuln|bypass|program> --name "X" --context "why"
python3 engine/engine/learn.py evolve --name "X"    # evolve one skill
python3 engine/engine/learn.py evolve               # evolve all
python3 engine/engine/learn.py gaps                  # show all gaps
python3 engine/engine/learn.py diagnose [--program X]  # prioritized gap analysis
python3 engine/engine/learn.py skills                # list learned skills
```

### Learning kinds
- `tech` — unknown framework/stack (e.g., "RedwoodJS", "Supabase")
- `vuln` — unknown vulnerability class (e.g., "prototype-pollution", "CRLF")
- `bypass` — evasion technique needed (e.g., "WAF bypass", "Cloudflare auth")
- `program` — program-specific intel (e.g., "Shopify Collabs architecture")

## Module Reference

### Core Pipeline
| Module | Purpose | CLI |
|--------|---------|-----|
| `engine.py` | Orchestrator: scope→recon→rank→hunt→validate→report | `--scope <file> [--phases X,Y]` |
| `intake.py` | Program URL → scope.json → engagement | `start <url>` |
| `scope.py` | Scope boundary enforcement (wildcard-aware) | (library) |
| `scopefetch.py` | Fetch scope from bb-platforms MCP | (library) |
| `scopeparse.py` | Parse program rules, ROE, qualifying/non-qualifying | (library) |
| `targets.py` | Show/manage target scope | `show --program <p>` |
| `state.py` | Engagement state persistence (resumable) | (library) |

### Discovery & Recon
| Module | Purpose | CLI |
|--------|---------|-----|
| `discovery.py` | Exhaustive surface mapping (9 phases) | `discover --slug <p>` |
| `jsminer.py` | JS bundle API surface extraction | `--url <seed>` or `selftest` |
| `jsdiff.py` | JS bundle change detection | (library) |
| `recon.py` | Subdomain/asset recon | (library) |
| `osint.py` | OSINT data gathering | (library) |
| `novelty.py` | New/changed surface detection | `watch` |
| `featuremap.py` | Feature-to-endpoint mapping | (library) |
| `explorer.py` | Authenticated app exploration | (library) |
| `browser.py` | Headless browser capture | (library) |
| `websearch.py` | Web search integration | (library) |

### Analysis & Planning
| Module | Purpose | CLI |
|--------|---------|-----|
| `knowledge.py` | Signal→pattern library + `detect_tech()` | `selftest` |
| `testplan.py` | Signal-based test plan generation | `plan --scope <file>` |
| `yieldrank.py` | Yield-based endpoint ranking | `rank --tech <stack>` |
| `brain.py` | LLM reasoning interface | (library) |
| `bridge.py` | Knowledge-to-skill recommendation | (library) |
| `skill_map.py` | Skill lookup and routing | (library) |

### Auth & Identity
| Module | Purpose | CLI |
|--------|---------|-----|
| `authn.py` | Per-target session storage | `set/show --slug <p>` |
| `authsession.py` | Session provisioning & validation | `provision/show --program <p>` |
| `authbootstrap.py` | Auth needs analysis + manual inject | `plan/inject --program <p>` |
| `authz.py` | Authorization boundary testing | (library) |
| `identity.py` | Disposable test account management | (library) |

### Hunting & Validation
| Module | Purpose | CLI |
|--------|---------|-----|
| `agent.py` | Hunt agent dispatch | (library) |
| `orchestrator.py` | Multi-agent coordination | (library) |
| `modelroute.py` | Model selection routing | (library) |
| `netget.py` | HTTP client (TLS impersonation, proxy, rate-limit) | `GET/POST <url>` |
| `oob.py` | Out-of-band interaction tracking | (library) |
| `burp.py` | Burp Suite MCP integration | `setup` |
| `coverage.py` | Surface coverage tracking | (library) |
| `observe.py` | Response observation & diffing | (library) |

### Quality Gates
| Module | Purpose | CLI |
|--------|---------|-----|
| `verify.py` | Triager-grade finding verification | `check --file <f> [--deep]` |
| `dedup.py` | Duplicate avoidance oracle | `check/ingest/stats --program <p>` |
| `guardrails.py` | Write-action safety gate (scope, caps, audit) | `check/audit --program <p>` |
| `reviewer.py` | Finding quality review | (library) |
| `disposition.py` | Finding triage disposition | (library) |

### Reporting & Output
| Module | Purpose | CLI |
|--------|---------|-----|
| `report.py` | Report generation | (library) |
| `findings.py` | Finding storage & management | (library) |
| `notify.py` | Notification dispatch | (library) |
| `learn.py` | Auto-research unknown stacks, draft skills | `auto` |
| `sessions.py` | Session management | (library) |
| `fixchat.py` | Chat transcript repair | (library) |

### Network & Infrastructure
| Module | Purpose | CLI |
|--------|---------|-----|
| `netget.py` | Returns `(status_code:int, text:str, headers:dict)` | `GET/POST <url> [body]` |
| `sms.py` | SMS OTP (DISABLED unless `SMS_PROVIDER` + `SMS_API_KEY` set) | (library) |

## Agents

| Agent | Model | Effort | Role |
|-------|-------|--------|------|
| `hunt-orchestrator` | Opus | xhigh | Top-level pipeline coordinator |
| `vuln-hunter` | Opus | xhigh | Single-endpoint deep hunter |
| `discovery-agent` | Opus | high | Exhaustive surface mapper |
| `recon-novelty` | Sonnet | high | Recon + novelty delta scout |
| `dedup-oracle` | Sonnet | high | Duplicate-risk gate |
| `report-drafter` | Opus | high | Triager-grade draft writer |

## Guardrails

All write actions (account creation, login attempts, SMS) go through `guardrails.py`:
- **Scope enforcement** — action's host must be in-scope, not out-of-scope
- **Self-register gate** — per-target `self_register_ok` flag
- **Account cap** — max `HUNT_MAX_ACCOUNTS` (default 3) per program
- **No brute force** — password/OTP/token brute loops refused outright
- **Audit trail** — every allowed/refused action logged

`netget.py` enforces:
- **Scope guard** — set by engine init, blocks requests to out-of-scope hosts
- **Adaptive rate limiter** — per-host backoff, 5min pause after 5 consecutive 403s
- **Connection pooling** — reuses TCP connections
- **TLS impersonation** — curl_cffi with real browser fingerprints for WAF bypass

## Burp Suite MCP

When Burp Pro is running with MCP BApp (port 9876):
- `mcp__burp__send_http1_request` / `send_http2_request` — requests in proxy history
- `mcp__burp__generate_collaborator_payload` / `get_collaborator_interactions` — OOB testing
- `mcp__burp__get_scan_issues` — passive/active scanner findings
- `netget.py` auto-routes through Burp proxy (127.0.0.1:8080) when MCP is reachable
- Setup: `python3 engine/engine/burp.py setup`

## Research Routing (ContextPilot)

For external research (web pages, docs, GitHub issues/PRs, PDFs):
1. Discover with `contextpilot_search` — pass the error text or question as `query`
2. Read URLs with `contextpilot_research` (several URLs or a GitHub issue/PR) or `contextpilot_fetch` (single URL) — pass `focus`
3. Recover omitted detail with `contextpilot_expand({ evidence_id })` — do NOT re-fetch
4. If gateway returns `ok:false`, fall back to native WebFetch/WebSearch

## Hard Rules

### Scope & Safety
1. **In-scope only** — never touch hosts, domains, or resources outside the program's scope definition
2. **Read-only by default** — all testing is non-destructive unless guardrails explicitly approve a write action
3. **No brute force** — never password-spray, credential-stuff, or OTP-brute. The harness blocks these at the guardrails layer
4. **Rate-limit respect** — `netget.py` handles adaptive rate limiting. If you get 429s, back off. Never bypass rate limits
5. **Unique identification** — every test request carries a header with the H1 username so SOC teams can identify authorized testing
6. **ROE compliance** — read and follow each program's Rules of Engagement. Example: Shopify requires testing only against stores you created with your H1-registered email

### Quality Standards
7. **Triager-grade only** — claim exactly what was proven. Never inflate severity, never add theoretical impact
8. **Two-identity minimum** — any cross-account finding requires two distinct authenticated identities proving the boundary violation
9. **Body-diff, not status-diff** — a 200 status is not proof. Compare response bodies to show what data actually leaked or what state actually changed
10. **Timing requires n>=10** — timing-based attacks need at least 10 samples with statistical significance
11. **OOB requires proof** — blind SSRF/XXE needs actual Collaborator/OOB interaction, not just a DNS pingback

### Pipeline Gates
12. **Discovery before hunting** — never test an endpoint that wasn't found in discovery. If you find new surface during hunting, add it to the inventory first
13. **Auth before auth-walled testing** — if >50% of surface needs auth and you don't have sessions, STOP and solve auth first
14. **Dedup is mandatory** — no draft without `dedup.py check`. `LIKELY_DUP` means STOP, not "draft anyway with a caveat"
15. **Verify before draft** — every finding runs through `verify.py check` before report generation
16. **Draft before submit** — autonomy stops at the draft. Never call submit functions. Submission requires explicit per-report human approval

### Dynamic Behavior
17. **No static target data in engine code** — `knowledge.py`, `testplan.py`, and all modules must work for ANY program without program-specific patterns, vuln lists, or hardcoded target info
18. **Detect, don't assume** — use `knowledge.detect_tech()` to fingerprint tech from live HTTP responses. Never assume a target's stack
19. **Adapt to what you see** — hypotheses come from observed behavior, not from a static checklist. If the target doesn't match a pattern, invent new tests from what you actually observe
20. **Learn from failures** — when a hypothesis fails, record WHY and adjust. Don't repeat the same test with different formatting

### Reporting Standards
21. **Evidence hygiene** — redact session tokens in screenshots, black-bar PII, sanitize HAR files
22. **CVSS honesty** — score what the evidence supports, never what the vuln class theoretically allows
23. **No boilerplate** — every sentence in a report must be specific to THIS finding. No copy-paste padding
24. **Findings publish to** `https://finding.redtracefai.com` + email `x00xrayx00x@gmail.com`

## Lessons Learned (Applied Automatically)

These are distilled from real engagement experience. The harness applies them without operator intervention.

- **Incomplete discovery = wasted hunt** — the Neon audit found 0 bounty-eligible findings because initial discovery missed entire feature categories (orgs, transfers, credentials). Discovery must be exhaustive before hunting begins.
- **Auth blockers kill momentum** — Shopify audit: 13/26 endpoints untested because Cloudflare blocked automated signup. Detect auth walls early, solve them before testing.
- **Hardened targets need creativity** — extremely hardened targets (modern WAF, tight CORS, proper auth boundaries) need Fable-routed creative bypass, not brute repetition of standard checks.
- **Static data rots** — any hardcoded target-specific pattern becomes wrong when the target changes. Dynamic detection from live responses is the only reliable approach.
- **Dedup saves reputation** — reporting a known issue burns triager goodwill and wastes time. The dedup corpus is as important as the finding itself.

## Testing

```bash
python3 ~/0xray-hunt-harness/engine/scripts/selfcheck.py    # crash/loop/hostile-input gauntlet
python3 ~/0xray-hunt-harness/engine/scripts/e2e.py           # end-to-end pipeline trace
python3 ~/0xray-hunt-harness/engine/engine/<module>.py selftest  # per-module selftest
```

## Quick Reference

```bash
# Start a hunt
python3 engine/engine/intake.py start <program-url>

# Check scope
python3 engine/engine/targets.py show --program <p>

# Run discovery
python3 engine/engine/discovery.py discover --slug <p>

# Generate test plan
python3 engine/engine/testplan.py plan --scope scope.json

# Auth bootstrap
python3 engine/engine/authbootstrap.py plan --program <p>
python3 engine/engine/authbootstrap.py inject --program <p> --cookie '...' --ident A

# Check for duplicates
python3 engine/engine/dedup.py check --program <p> --class <c> --url <u> --title "..."

# Verify finding
python3 engine/engine/verify.py check --file finding.json --program <p>

# Run engine
python3 engine/engine/engine.py --scope engagement.json [--phases hunt,validate,report]
```
