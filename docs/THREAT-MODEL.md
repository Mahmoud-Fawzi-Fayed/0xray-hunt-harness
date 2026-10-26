# Threat Model — 0xRay Hunt Harness

Threat model for the harness itself, not the targets it hunts.

## Assets

| Asset | Location | Sensitivity |
|-------|----------|-------------|
| Engagement data | `~/.bughunter-engagements/<program>/` | High — target surface, test results |
| Auth credentials | `_identity/<slug>-creds.json`, `authn/<slug>-<ident>.json` | Critical — session cookies, tokens |
| Scope policies | `_targets/<slug>.json`, `<program>/scope.json` | High — defines attack boundary |
| Evidence | `<program>/evidence/observations.jsonl` | High — transport-recorded proof |
| Findings | `<program>/state.json`, report drafts | High — unreported vulnerabilities |
| Dedup corpus | `_dedup/corpus/<program>.jsonl` | Medium — known public issues |
| Learned skills | `engine/skills/learned/` | Low — publicly derivable |

## Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| Misconfigured agent | Filesystem + network, runs as engine user | Drift from intended behavior |
| Compromised dependency | Code execution via pip package | Supply chain attack |
| Stale scope | Outdated scope allows decommissioned/transferred hosts | Accidental OOS testing |
| DNS rebinding | Target resolves to internal IP after scope check | Bypass scope guard |
| Malicious redirect | In-scope host returns 3xx to attacker-controlled host | Credential exfiltration |

## Trust Boundaries

### 1. Scope Boundary (Critical)

**What**: Every outbound HTTP request must be authorized against the loaded scope policy.

**Enforcement points**:
- `netget.py`: Process-global `_SCOPE_GUARD` checked before every request. CLI mode loads scope from `--scope-file`/`--slug` — exits nonzero if missing.
- `browser.py`: Playwright route-level blocker intercepts all requests. CLI exits nonzero without `--scope`/`--slug`.
- `guardrails.py`: Write actions validated against scope before execution.
- `follow_redirects()`: Each redirect hop re-authorized. Credentials stripped on origin change.

**Fail mode**: Closed. Missing scope = no request executes (except localhost).

**Residual risk**: `recon.py` shells out to external tools (`subfinder`, `httpx`, `gau`) that bypass `netget.py`. Mitigation: tools only receive in-scope targets as arguments.

### 2. Engine-to-Agent Subprocess

**What**: LLM agents execute with filesystem and network access in their own sessions.

**Enforcement points**:
- `agent.py`: Dangerous flags (`--dangerously-skip-permissions`, `--no-verify`, `--yolo`) trigger stderr warnings.
- Task prompts include scope context so sub-agents load policy.
- Session pool limits concurrent instances per target.

**Residual risk**: Agent with filesystem access can read/modify engine code. Network-layer sandboxing (iptables/firewall) is not enforced by the harness.

### 3. Engine-to-Browser

**What**: Headless Playwright browser executes JS from target pages.

**Enforcement points**:
- Route-level scope blocker intercepts requests before they leave the browser.
- Navigation limited to in-scope origins.

**Residual risk**: Browser JS can attempt WebSocket/WebRTC connections that bypass the route blocker.

### 4. Engine-to-Burp MCP

**What**: Burp Suite MCP provides proxy, collaborator, and scanner via JSON-RPC (localhost:9876).

**Enforcement points**:
- MCP is localhost-only.
- `oob.py` validates collaborator payload format.

**Residual risk**: Any process on localhost can connect to the MCP port.

### 5. Engine-to-Target

**What**: Test requests sent to authorized in-scope hosts.

**Enforcement points**:
- `netget.py` scope guard, rate limiter, budget counter.
- `guardrails.py` write-action gate, account cap, brute-force refusal.
- Unique User-Agent / header identifying the tester.

**Residual risk**: A testing request may trigger a destructive side-effect on the target. Mitigation: read-only by default, write actions require explicit guardrails approval.

## Attack Surfaces

### netget.py CLI (subprocess invocation)
- **Vector**: Agent constructs a subprocess call to netget.py with attacker-influenced URL/headers.
- **Mitigation**: Scope guard re-loaded from disk before first request. Shell injection mitigated by using argument lists, not shell strings.

### browser.py CLI
- **Vector**: Agent drives headless browser to a URL that redirects to internal services.
- **Mitigation**: Route-level blocker enforces scope on every network request. CLI requires `--scope`/`--slug`.

### Redirect following
- **Vector**: In-scope server 302s to attacker-controlled host, leaking Authorization header.
- **Mitigation**: `follow_redirects()` checks each hop against scope. Credentials stripped on origin change. Max hops enforced (default 5).

### Scope file loading
- **Vector**: Tampered scope.json broadens the allowed host set.
- **Mitigation**: Scope files are written at intake time from program metadata. File mode 644. No dynamic modification by agents.

### Identity storage
- **Vector**: Agent reads another identity's session file to cross-contaminate A/B tests.
- **Mitigation**: Identity files stored per-slug per-ident with 600 permissions. Engine injects credentials per-request, not via shared environment.

## Mitigations Implemented

| Mitigation | Module | Description |
|------------|--------|-------------|
| Fail-closed scope guard | `netget.py`, `browser.py` | No scope = no requests |
| Transport-only evidence | `evidence.py` | Only real HTTP observations count as proof |
| Atomic state writes | `state.py` | `checkpoint()` writes to temp then renames |
| Rate limiting | `netget.py` | Per-host adaptive backoff, 5-min pause after 5x 403 |
| Budget enforcement | `netget.py`, `guardrails.py` | `HUNT_MAX_REQUESTS` (default 5000), per-program account cap |
| Credential redaction | `evidence.py` | Sensitive headers regex-redacted in stored observations |
| Credential stripping | `netget.py` | Auth/Cookie/API-key headers removed on redirect origin change |
| Brute-force refusal | `guardrails.py` | Password-spray, OTP-brute, etc. refused outright |
| Submission gate | `engine.py` | Pipeline stops at draft, no auto-submit |

## Residual Risks

| Risk | Severity | Notes |
|------|----------|-------|
| Agent shell commands not network-sandboxed | Medium | Agents can make arbitrary HTTP calls outside `netget.py`. Requires OS-level firewall. |
| Cross-process budget is in-process only | Low | `_request_count` resets on process restart. Per-engagement budget not enforced across CLI invocations. |
| DNS rebinding | Medium | Scope checks hostname at call time. If DNS changes between check and connect, a different IP may be reached. Mitigation: re-resolve and re-check is not implemented. |
| Recon tool egress | Medium | `subfinder`, `httpx`, `gau` bypass `netget.py` scope guard. Only mitigated by passing in-scope args. |
| Browser WebRTC/WebSocket | Low | May bypass route-level blocker in edge cases. |

## Non-Negotiables

1. **Zero OOS requests** in the adversarial test suite (E2E test T10.1).
2. **No `allow_redirects=True`** anywhere in transport code.
3. **No agent-text-as-evidence** — only HttpObservation with `resp_status != 0` counts.
4. **No auto-submit** — pipeline stops at report draft, always.

## Threat Scenarios

### T1: Out-of-Scope Request
**Attack**: Engine sends HTTP request to host not in program scope.
**Mitigations**: Scope guard in netget.py, route blocker in browser.py, hop-by-hop redirect check.
**Test**: E2E test T10.1 verifies zero OOS sink requests.

### T2: Credential Cross-Contamination
**Attack**: Identity A's cookies leak into Identity B's requests.
**Mitigations**: `authn.py` stores A/B separately. `_hunt_deep()` injects identity per test plan item.
**Test**: authsession.py selftest verifies isolation.

### T3: Evidence Fabrication
**Attack**: Agent claims a vulnerability without transport proof.
**Mitigations**: `validate_evidence()` rejects cases with zero real observations.
**Test**: Evidence pipeline tests verify invalid result for zero-observation cases.

### T4: Duplicate Report
**Attack**: Engine reports a vulnerability already public or previously reported.
**Mitigations**: `dedup.py` corpus scoring. `LIKELY_DUP` is a hard stop.
**Test**: Dedup selftest covers threshold transitions.

### T5: Redirect-Based Scope Escape
**Attack**: In-scope server 302s to out-of-scope host.
**Mitigations**: `allow_redirects=False` hardcoded. `follow_redirects()` re-authorizes each hop.
**Test**: E2E test T3.3 verifies zero OOS requests via redirect.

### T6: Budget Exhaustion Denial-of-Service
**Attack**: Agent burns the request budget on low-value endpoints.
**Mitigations**: `HUNT_MAX_REQUESTS` budget counter. Yield-based ranking prioritizes high-value targets.
**Test**: Budget exhaustion raises `BudgetExhausted` exception.
