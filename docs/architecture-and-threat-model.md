# Architecture and Threat Model

## Component Map (55 modules in `engine/engine/`)

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
| `engine.py` | Main orchestrator — phases: recon → discover → explore → rank → map → plan → hunt → validate → chain → report |
| `orchestrator.py` | Higher-level orchestration, draft publishing, approval gates |
| `testplan.py` | Test case generation, state tracking, evidence validation, plan coverage |
| `yieldrank.py` | Ranks endpoints by observed impact and unresolved trust dimensions |
| `explorer.py` | Analyzes browser captures into app model (pages, API, features, hidden paths) |
| `featuremap.py` | Builds feature-operation-parameter inventory from all sources |

### Agent and Model
| Module | Role |
|---|---|
| `agent.py` | Dispatches tasks only to the configured active command. Parses plain/JSON/JSONL output by content |
| `modelroute.py` | Routes tasks to the configured model pool via opaque labels. Budget gate |
| `skill_map.py` | Behavior-driven skill matching — matches `hunt-*` directories by tech stack and analysis content, not by URL patterns or vuln class names |
| `brain.py` | Per-program memory — stores/retrieves context for agent prompts |
| `learn.py` | Auto-drafts new skills for unknown stacks/vulns |

### Verification and Reporting
| Module | Role |
|---|---|
| `verify.py` | 60 PER_CLASS post-evidence verification rules, ALWAYS_REJECT patterns, evidence quality checks |
| `dedup.py` | Deduplication gate — LIKELY_DUP stops the pipeline |
| `disposition.py` | Finding disposition (own-session OAuth, self-XSS, etc.) |
| `reviewer.py` | Multi-model review panel for findings |
| `report.py` | Finding report generation and formatting |
| `findings.py` | Finding lifecycle state management |
| `notify.py` | Finding notification (email, webhook) |
| `coverage.py` | Dimensional coverage — per-operation, per-identity, per-trust-dimension evidence. Trust dimensions primary, class coverage secondary |

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
│  4. observe.py + recon transports           │
│     - netget scope/redirect enforcement     │
│     - uncontained active crawler disabled   │
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
│  modelroute.py selects an opaque pool label │
│  or delegates to the host default; effort   │
│  follows observed task complexity.          │
│                                             │
│  agent.py dispatches only to the configured │
│  active command; no fallback runtime.       │
│    Timeout + process-group cleanup          │
│    Plain/JSON/JSONL result extraction       │
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

## Residual Egress Risks

1. **Agent tools**: Agents can invoke shell commands. Built-in target fetches use netget, dangerous flags are refused, and uncontained active crawling is disabled, but this is not OS-level network containment. Use an OS sandbox for untrusted agents.
2. **Port-based scope**: Explicit `host:port` and wildcard-port rules are enforced; portless scope entries intentionally allow any port.
3. **DNS rebinding**: No protection against DNS changes between scope check and request.
