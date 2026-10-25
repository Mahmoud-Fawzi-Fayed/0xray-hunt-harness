# Architecture and Threat Model

## Component Map (45 modules in `engine/engine/`)

### Intake and Scope
| Module | Role |
|---|---|
| `intake.py` | Fetches program scope from H1/Bugcrowd/YWH URL, creates engagement directory |
| `scopefetch.py` | Converts platform scope blobs to normalized host/path lists |
| `scopeparse.py` | Parses raw scope text into structured entries |
| `scope.py` | Canonical scope matcher — exact host, `*.` wildcard, `=` exact, CIDR, `re:` regex, path allow/deny |
| `targets.py` | Manages `_targets/<slug>.json` files, lists engagements |

### Network and Transport
| Module | Role |
|---|---|
| `netget.py` | Central HTTP client (curl_cffi/requests). Process-global scope guard, redirect validation, request counting |
| `recon.py` | HTTP recon — fetches pages, extracts JS/API/form endpoints, auth enforcement sweep. Per-hop redirect scope check |
| `browser.py` | Playwright headless browser — captures XHR/fetch/form/button requests. Route-level scope blocker (fail-closed) |
| `observe.py` | Passive observation — subdomain enum, JS analysis, tech detection. Uses `curl`/`httpx` subprocesses (known egress gap) |
| `oob.py` | Out-of-band interaction via Burp Collaborator payloads |
| `burp.py` | Burp MCP bridge setup and capability detection |

### Identity and Auth
| Module | Role |
|---|---|
| `identity.py` | Disposable test account creation (guardrail-gated, capped) |
| `authn.py` | Manages auth sessions — loads/saves cookies/headers per identity (A/B) |
| `authsession.py` | Session lifecycle — login, token refresh, session validation |
| `authz.py` | Two-account authorization diff — compares A vs B responses for IDOR/BOLA |
| `sms.py` | SMS/OTP handling for phone-gated signups (disabled unless configured) |
| `sessions.py` | Session state persistence |

### Planning and Execution
| Module | Role |
|---|---|
| `engine.py` | Main orchestrator — phases: recon → explore → map → plan → hunt → validate → report |
| `orchestrator.py` | Higher-level orchestration, draft publishing, approval gates |
| `testplan.py` | Test case generation, state tracking, evidence validation, plan coverage |
| `yieldrank.py` | Ranks vuln classes by findability for the target stack |
| `explorer.py` | Analyzes browser captures into app model (pages, API, features, hidden paths) |
| `featuremap.py` | Builds feature-operation-parameter inventory from all sources |

### Agent and Model
| Module | Role |
|---|---|
| `agent.py` | Dispatches tasks to Claude Code / OpenCode / Kimi CLI. Parses JSON results from agent output |
| `modelroute.py` | Routes tasks to models: Opus (deep), Fable (creative), Sonnet (fast). Escalation ladder |
| `skill_map.py` | Filesystem-based skill discovery — matches `hunt-*` directories to vuln classes |
| `brain.py` | Per-program memory — stores/retrieves context for agent prompts |
| `learn.py` | Auto-drafts new skills for unknown stacks/vulns |

### Verification and Reporting
| Module | Role |
|---|---|
| `verify.py` | 42 PER_CLASS verification rules, ALWAYS_REJECT patterns, evidence quality checks |
| `dedup.py` | Deduplication gate — LIKELY_DUP stops the pipeline |
| `disposition.py` | Finding disposition (own-session OAuth, self-XSS, etc.) |
| `reviewer.py` | Multi-model review panel for findings |
| `report.py` | Finding report generation and formatting |
| `findings.py` | Finding lifecycle state management |
| `notify.py` | Finding notification (email, webhook) |
| `coverage.py` | Coverage matrix — per method/URL/class/param/role with blind spot detection |

### Supporting
| Module | Role |
|---|---|
| `state.py` | Engagement state persistence — surface, tested, worklist, candidates |
| `guardrails.py` | Write-action gate — scope check, brute-force refusal, account caps, audit trail |
| `novelty.py` | Monitors for new/changed surface |
| `jsdiff.py` | JavaScript bundle diff for redeployed code |
| `osint.py` | Open-source intelligence gathering |
| `apkmap.py` | Android APK API surface extraction |
| `websearch.py` | Web search for CVE/disclosure context |
| `fixchat.py` | Chat/session repair utilities |
| `bridge.py` | Inter-process bridge for agent communication |

## Trust Boundaries

```
Program URL
    │
    ▼
┌─────────────────────────────────────────────┐
│  INTAKE (scopefetch → scope.json)           │
│  Trust boundary: program platform → local   │
└──────────────┬──────────────────────────────┘
               │ canonical scope.json
               ▼
┌─────────────────────────────────────────────┐
│  SCOPE ENFORCEMENT (5 layers)               │
│                                             │
│  1. scope.py::in_scope_host()               │
│     - Exact host / *.wildcard / CIDR / re:  │
│     - Path allow + path deny lists          │
│     - Deny wins over allow                  │
│                                             │
│  2. netget.py scope guard                   │
│     - Pre-request host check                │
│     - Post-redirect validation              │
│     - Request counting                      │
│                                             │
│  3. browser.py route blocker                │
│     - Playwright route handler              │
│     - Fail-closed (abort on exception)      │
│                                             │
│  4. observe.py (PARTIAL — subprocess gap)   │
│     - JS URL filtering uses scope           │
│     - curl -sL / httpx bypass scope guard   │
│                                             │
│  5. guardrails.py                           │
│     - All URL-bearing actions scope-checked │
│     - Fail-closed on scope module failure   │
│     - Brute-force actions always refused    │
│     - Account creation capped + audited     │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  AGENT EXECUTION                            │
│                                             │
│  modelroute.py selects model:               │
│    Opus  → deep reasoning, report drafts    │
│    Fable → hypothesis, creative bypass      │
│    Sonnet → recon, dedup, fast tasks        │
│                                             │
│  agent.py dispatches to runtime:            │
│    Claude Code CLI / OpenCode / Kimi        │
│    Timeout + turn limits (advisory)         │
│    JSON result extraction                   │
│                                             │
│  Agents can invoke engine tools:            │
│    netget.py, identity.py, browser.py,      │
│    authz.py, learn.py, websearch.py         │
│    All gated by guardrails + scope          │
│                                             │
│  TRUST: Agent prompts are NOT containment.  │
│  Network containment = scope guard code.    │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  VERIFICATION + REPORTING                   │
│                                             │
│  verify.py — 42 class rules + ALWAYS_REJECT │
│  dedup.py  — mandatory before any draft     │
│  report.py — draft only, never auto-submit  │
│  Human approval required before submission  │
└─────────────────────────────────────────────┘
```

## Known Egress Gaps

1. **observe.py**: `curl -sL` and `httpx` subprocesses bypass the scope guard. Mitigation: scope-filter results post-hoc.
2. **Agent tools**: Agents can invoke shell commands. Mitigation: guardrails.py gates write actions; scope.py gates URLs. But a creative agent could theoretically invoke an unguarded binary.
3. **Port-based scope**: `scope.py` matches hostnames, not ports. Two services on the same host at different ports cannot be independently scoped.
4. **DNS rebinding**: No protection against DNS changes between scope check and request.
