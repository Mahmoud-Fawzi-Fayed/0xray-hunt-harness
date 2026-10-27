# 0xRay Hunt Harness

Engine: `~/0xray-hunt-harness/engine/engine/` (55 modules).
Skills: `~/0xray-hunt-harness/engine/skills/` (95 skills, 68 hunt-*).
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

`HUNT_AGENT_CMD` is the only AI runtime command. Its optional `{task}`, `{model}`, and `{resume}` placeholders support argv prompts and model/session labels; without `{task}`, the prompt goes to stdin. `HUNT_MODELS` is an optional pool of opaque labels, and an empty pool uses the active host's default. There are no provider tiers, model-prefix rules, or fallback CLIs. If no command is configured, AI stages fail closed while deterministic stages remain available.

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
Iterative function and relationship inventory through `discovery.py`. No schema or target category is required: observed seeds, nested JSON relationships, HTML forms, event data, response headers, client execution, and available document parsers can all contribute operations.

**HARD GATE**: hunt requires validated in-scope operations. Guessed paths remain leads; failed or unavailable sources and unparsed relationships remain explicit residuals (set `HUNT_SKIP_COVERAGE_GATE=1` only for an intentional operator override).

Discovery attempts safe protocol parsers and browser/client observation when applicable, then expands only from observed behavior for up to six rounds or its budget. Two stable rounds stop expansion. It records source attempts, validated operations, protocol-neutral function profiles, convergence, and residuals; convergence is not a claim that every function was found. No OpenAPI, GraphQL schema, framework name, URL convention, or fixed function checklist is required.

Coverage is dimensional rather than categorical: source/operation validation, function profiles, actor and ownership boundaries, input/parser behavior, state and sequence, external effects, relationships, workflow invariants, confidentiality, and unresolved residuals are reported independently.

### Phase 3: Explore (`engine.explore()`)
Functional analysis — `explorer.py` builds app model from state, identifies API surface patterns.

### Phase 4: Rank (`engine.rank()`)
Yield-based ranking via `yieldrank.py`. Dedup-downranks known issues. Prioritizes by dynamic signals.

### Phase 5: Map (`engine.map()`)
Generates `arsenal.md` with protocol-neutral function profiles and trust dimensions. Vulnerability references are not attached before live evidence and a concrete hypothesis.

### Phase 6: Plan (`engine.plan()`)
`testplan.py` generates behavior-based cases with independent dimensional outcomes. `authbootstrap.py` analyzes auth needs.

**HARD GATE**: if >50% of surface needs auth and no session exists, hunt phase will BLOCK (set `HUNT_SKIP_AUTH_GATE=1` to override).

Auth provisioning:
- Automated: `authsession.py provision --program <p>`
- Manual: `authbootstrap.py inject --program <p> --cookie '...' --ident A`

### Phase 7: Hunt (`engine.hunt()`)
Evidence-driven per-function analysis with test-plan-driven dispatch:
1. FETCH — read every byte and retain baseline observation IDs
2. UNDERSTAND — resource, action, auth model, effects, and trust boundaries
3. HYPOTHESIZE — derive one testable assumption from those observations, then select optional references
4. TEST — one precise request per hypothesis and trust dimension
5. ITERATE — new hypotheses from observations; leave untested dimensions unresolved
6. PROVE — impact with in-scope actions and case-linked evidence only

Requirements:
- Unique markers in every test request (header with H1 username)
- Body-diff for response comparison (not just status codes)
- n>=10 for timing-based tests
- OOB via Burp Collaborator for blind vulns
- Two distinct identities for any cross-account test

### Phase 8: Validate (`engine.validate()`)
`verify.py check` — triager-grade verification gate with canonical class-specific proof rules and independent reproduction. LLM-only or similarity-only claims stay in manual review.

Per-finding checklist (ALL must pass):
1. Full exploit chain with HTTP requests/responses and linked observation IDs
2. Cross-account impact with two distinct identities and an A-owned unique marker plus controls
3. Not documented/expected behavior
4. Independently reproduced PoC with reproducible steps
5. CVSS scored to match ACTUAL demonstrated impact
6. Evidence saved with redacted credentials and private, size-bounded request/response excerpts

### Phase 9: Chain (`engine.chain()`)
Chains related findings into higher-impact attack paths where possible.

### Phase 10: Report (`engine.report()`)
Dedup check (`dedup.py check`) + report generation. Writes `report.md`.

Dedup verdicts:
- `NOVEL` — eligible only after reproduction and report-ready checks pass
- `REVIEW` — requires a concrete differentiator; otherwise HELD
- `UNKNOWN` — **HELD. Empty corpus is not novelty.**
- `LIKELY_DUP` — **STOP. Do not draft.**

**HARD STOP: never submit without explicit per-report approval.**

Self-verdict on every draft: `READY` / `NEEDS_FIXES` / `DO_NOT_SUBMIT`.
Findings publish to `https://finding.redtracefai.com` + email `x00xrayx00x@gmail.com`.

## Evidence-Driven Dynamic Hunting

Three-layer system. Target behavior comes from live inputs and supplied artifacts, not a vulnerability checklist.

### Layer 1: Function Profiles (`function_profile.py`, `target_adapters.py`)
Each operation is described by its protocol, action, resource, actors, inputs, outputs, effects, state, sensitivity, and provenance. Profiles expose trust dimensions including actor variation, ownership/tenant boundaries, input and parser variation, state/sequence, external effects, file handling, role transitions, and protocol behavior. Ranking uses observed impact and unresolved trust, not URL or vulnerability names.

### Layer 2: Evidence-Late References (`skill_map.py`)
The agent first fetches a baseline and retains its case-linked observation IDs. Only after forming a concrete hypothesis may it request matching hunt-* references with those IDs. Missing, forged, or cross-case evidence returns methodology only. Technology and class-specific references remain valid later during validation and reporting, after the relevant fact is established.

### Layer 3: Dimensional Hunt and Coverage (`engine.py`, `testplan.py`, `coverage.py`)
Each hypothesis result names one trust dimension, an outcome, evidence, and observation IDs. A terminal result resolves only that dimension. Pending, blocked, inconclusive, and unknown dimensions stay visible; a tested endpoint or legacy plan never blanket-covers the operation.

### Supporting Capabilities
- **Auth bootstrap** (`authbootstrap.py`): auto-analyzes what accounts are needed post-discovery
- **JS bundle mining** (`jsminer.py`): extracts API paths, GraphQL ops, auth patterns, routes, hidden endpoints, tokens, fetch calls from client JS
- **Target/artifact matrix** (`eval/run_dynamic_matrix.py`): verifies live HTTP, schema, browser, schema-less JSON/form/event/workflow inputs and cloud, LLM/MCP, infrastructure, desktop, contract, Android, and IPA artifacts end to end; artifact-only results are not runtime claims
- **Coverage tracking** (`coverage.py show --slug <p>`): per-operation, per-identity, per-dimension evidence and blind spots
- **Creative retry on the active host**: when standard techniques fail, increase effort or rotate an approved opaque label without changing runtime
- **Retry resilience**: failed endpoints retry up to 3x with different labels/timeouts on the same configured command

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

3. **Outcome recording** — `record_outcome(program, class, result, note, trust_dimension=...)`:
   - Confirmed findings → `confirmed`
   - False positives → `false-positive`
   - Duplicates → `duplicate`
   - Feeds into yieldrank using observed trust dimensions and profile IDs; legacy class names do not influence target selection

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
| `function_profile.py` | Protocol-neutral functions, trust dimensions, impact ranking | (library) |
| `target_adapters.py` | Live-target and artifact adapters | (library) |
| `testplan.py` | Behavior-based cases and dimensional outcomes | `plan --scope <file>` |
| `yieldrank.py` | Yield-based endpoint ranking | `rank --tech <stack>` |
| `brain.py` | LLM reasoning interface | (library) |
| `skill_map.py` | Evidence-gated hypothesis references and post-finding skills | (library) |

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
| `hunt-orchestrator` | active host | xhigh | Top-level pipeline coordinator |
| `vuln-hunter` | active host | xhigh | Single-endpoint deep hunter |
| `discovery-agent` | active host | high | Exhaustive surface mapper |
| `recon-novelty` | active host | high | Recon + novelty delta scout |
| `dedup-oracle` | active host | high | Duplicate-risk gate |
| `report-drafter` | active host | high | Triager-grade draft writer |

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
- **Hardened targets need creativity** — extremely hardened targets need observation-driven hypotheses and creative retries on the active host, not brute repetition or a provider-specific fallback.
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
