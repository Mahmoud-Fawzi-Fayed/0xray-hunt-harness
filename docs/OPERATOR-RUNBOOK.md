# Operator Runbook

## Quick Start

```bash
# 1. Start engagement
python3 engine/engine/intake.py start <program-url>

# 2. Verify scope loaded
python3 engine/engine/targets.py show --program <slug>

# 3. Run full pipeline
python3 engine/engine/engine.py --scope <engagement>/scope.json

# 4. Check coverage
python3 engine/engine/coverage.py show --slug <slug>

# 5. Review findings (always stop here — never auto-submit)
cat ~/.bughunter-engagements/<slug>/report.md
```

## Prerequisites

- Python 3.11+
- `pip install requests playwright`
- `python3 -m playwright install chromium`
- Optional: Burp Suite Pro with MCP BApp (port 9876)
- Optional: Go recon tools in `~/go/bin/` (subfinder, httpx, gau, katana)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BUGHUNTER_BASE` | `~/.bughunter-engagements` | Base directory for all engagements |
| `HUNT_USER_AGENT` | (required) | SOC-tagging User-Agent header for all requests |
| `HUNT_PROXY` | unset | HTTP(S)/SOCKS5 proxy URL for egress |
| `HUNT_IMPERSONATE` | `safari_ios` | curl_cffi TLS impersonation profile |
| `HUNT_MAX_REQUESTS` | `5000` | Per-engagement request budget |
| `HUNT_REQUESTS_PER_SECOND` | `10` | Rate limit (requests per second) |
| `HUNT_REQUEST_TIMEOUT` | `30` | Default request timeout in seconds |
| `HUNT_MAX_REDIRECTS` | `5` | Maximum redirect hops for `follow_redirects()` |
| `HUNT_RETEST_HOURS` | `48` | Re-hunt window (hours since last test) |
| `HUNT_MAX_ACCOUNTS` | `3` | Max accounts created per program |
| `HUNT_SKIP_COVERAGE_GATE` | unset | Set to `1` for an intentional operator override of discovery readiness |
| `HUNT_SKIP_AUTH_GATE` | unset | Set to `1` to bypass auth-wall gate |
| `HUNT_SESSION_POOL` | `3` | Reused agent sessions per target |
| `HUNT_SESSION_MAX_USES` | `25` | Max turns before session refresh |
| `HUNT_SESSION_MAX_AGE_MIN` | `360` | Session retirement age in minutes |
| `SESSION_MAX_AGE_SEC` | `3600` | Auth session expiry in seconds |

## Pipeline Gates

### Coverage Gate (Phase: Discover → Hunt)

- Requirement: validated in-scope operations with source attempts and unparsed residuals retained
- Guessed paths are leads only; source, operation, workflow, and trust-dimensional coverage are independent
- No schema, URL convention, or target category is required; unavailable capabilities stay visible
- Override: `HUNT_SKIP_COVERAGE_GATE=1` for an intentional operator decision
- If triggered: inspect residuals, supply missing identities/artifacts, and rerun observed-response, client, and applicable parser discovery

### Auth Gate (Phase: Plan → Hunt)

- Threshold: >50% surface requires authentication
- Override: `HUNT_SKIP_AUTH_GATE=1`
- Resolution: `python3 engine/engine/authsession.py provision --program <slug>`
- Manual: `python3 engine/engine/authbootstrap.py inject --program <slug> --cookie '...' --ident A`

### Dedup Gate (Phase: Report)

- Verdict `LIKELY_DUP`: HARD STOP — do not draft
- Verdict `UNKNOWN`: HELD — an empty corpus is not novelty
- Verdict `REVIEW`: requires a concrete differentiator; otherwise HELD
- Verdict `NOVEL`: eligible for the report-ready check
- Check: `python3 engine/engine/dedup.py check --program <slug> --class <c> --url <u> --title "..."`

### Verify Gate (Phase: Validate → Report)

- Every finding must be independently reproduced and pass `verify.py check --file <finding.json> --program <slug>`
- High/Critical findings require two independent reproduction tools/transports; another model's opinion is not one
- Similarity-only BOLA, reflection-only XSS, and SQL-error-only SQLi are detection signals, not reproduction
- Self-verdict: `READY` / `NEEDS_FIXES` / `DO_NOT_SUBMIT`
- `DO_NOT_SUBMIT` is a hard stop — fix or discard

## Phase States

| Status | Meaning |
|--------|---------|
| `NOT_STARTED` | Phase has not begun |
| `RUNNING` | Phase is actively executing |
| `PASS` | Phase completed successfully |
| `BLOCKED` | Phase blocked by a gate condition |
| `FAILED` | Phase encountered an error |
| `CANCELLED` | Phase skipped by operator |
| `PARTIAL` | Phase partially completed |

Phase dependencies enforced: a phase cannot proceed if its prerequisite failed or is blocked.

## Auth Session Management

```bash
# Provision automated session
python3 engine/engine/authsession.py provision --program <slug>

# Check session status
python3 engine/engine/authsession.py show --program <slug>

# Manual session injection
python3 engine/engine/authbootstrap.py inject --program <slug> \
  --cookie 'session=abc123' --ident A

# Second identity for A/B testing
python3 engine/engine/authbootstrap.py inject --program <slug> \
  --cookie 'session=def456' --ident B
```

Sessions expire after `SESSION_MAX_AGE_SEC` (default 1 hour). Relogin is automatic if credentials are stored.

## Testing

```bash
# Full selfcheck (all 49 modules)
python3 engine/scripts/selfcheck.py

# Comprehensive E2E (27 tests)
python3 engine/tests/test_e2e_comprehensive.py

# Policy egress tests
python3 engine/tests/test_policy_egress.py

# Evidence pipeline tests
python3 engine/tests/test_evidence_pipeline.py

# Individual module selftest
python3 engine/engine/<module>.py selftest
```

## CLI Reference

### netget.py — HTTP client
```bash
python3 engine/engine/netget.py GET "https://host/path" --scope-file scope.json
python3 engine/engine/netget.py POST "https://host/path" '{"k":"v"}' --slug <target>
python3 engine/engine/netget.py selftest
```

### browser.py — headless browser capture
```bash
python3 engine/engine/browser.py --url "https://host" --slug <target>
python3 engine/engine/browser.py --url "https://host" --scope host1 host2
```

### engine.py — orchestrator
```bash
python3 engine/engine/engine.py --scope engagement.json
python3 engine/engine/engine.py --scope engagement.json --phases hunt,validate,report
```

### discovery.py — surface mapping
```bash
python3 engine/engine/discovery.py discover --slug <target>
```

### verify.py — finding verification
```bash
python3 engine/engine/verify.py check --file finding.json --program <slug>
python3 engine/engine/verify.py check --file finding.json --program <slug> --deep
```

### dedup.py — duplicate checking
```bash
python3 engine/engine/dedup.py check --program <slug> --class <c> --url <u> --title "..."
python3 engine/engine/dedup.py ingest --program <slug>
python3 engine/engine/dedup.py stats --program <slug>
```

### coverage.py — dimensional coverage tracking
```bash
python3 engine/engine/coverage.py show --slug <target>
python3 engine/engine/coverage.py show --slug <target> --json
python3 engine/engine/coverage.py all
```

Coverage is counted independently for each operation, actor/ownership context, and trust dimension. A tested endpoint does not close all of its dimensions. Pending, blocked, inconclusive, and legacy/unknown results remain unresolved; only `tested`, `confirmed`, or `disproved` dimensional results with matching transport observations count as covered. `dimension_details` contains the observation IDs and identity context for each result. Legacy class coverage remains compatibility output, not the completeness metric.

### Dynamic target and model validation

```bash
make dynamic         # generic runtime, evidence, adapter, and coverage regressions
make matrix          # schema-less/live workflows + real app/tool/infra/contract artifacts
make model-families  # opt-in live checks; consumes model tokens
make assess          # evidence-weighted score from the recorded gate artifacts
```

The matrix distinguishes `live-target` from `artifact-only` and writes `artifacts/release-validation/dynamic-matrix-results.json`. Model checks exercise every configured `HUNT_MODELS` label, or one host-default case, against the single `HUNT_AGENT_CMD` runtime with an isolated engagement and evidence directory per attempt. No alternate AI command is used. Claimed reflected XSS is independently reproduced in a browser; a model claim or reflection alone is not a pass. Unsupported target types and unavailable runtimes remain explicit rather than becoming passes. `make assess` gives artifact-only rows half the weight of live-target rows and reports an engineering-validation score, not vulnerability yield, production coverage, or proof of arbitrary live AI hosts.

### learn.py — self-learning
```bash
python3 engine/engine/learn.py auto --kind tech --name "X" --context "why"
python3 engine/engine/learn.py evolve --name "X"
python3 engine/engine/learn.py gaps
python3 engine/engine/learn.py diagnose
```

### evidence.py — evidence pipeline
```bash
python3 engine/engine/evidence.py show --slug <target>
python3 engine/engine/evidence.py show --slug <target> --case <case_id>
```

## Safety Mechanisms

- **Scope guard** — fail-closed in `netget.py` and `browser.py`, re-checked per redirect hop
- **Rate limiter** — per-host adaptive backoff, 5-min pause after 5 consecutive 403s
- **Request budget** — `HUNT_MAX_REQUESTS` (default 5000) hard cap per engagement
- **Account cap** — `HUNT_MAX_ACCOUNTS` (default 3) per program
- **Brute-force refusal** — password-spray, OTP-brute, credential-stuffing refused outright
- **Audit trail** — every guardrails decision logged to audit file
- **Submission gate** — pipeline always stops at draft, no auto-submit

## Doctor Check

Before running an engagement, verify:

1. **Scope loaded**: `python3 engine/engine/targets.py show --program <slug>` returns scope data
2. **Selftests pass**: `python3 engine/scripts/selfcheck.py` — expect 44+ PASS
3. **Auth ready** (if needed): `python3 engine/engine/authsession.py show --program <slug>`
4. **Dedup corpus current**: `python3 engine/engine/dedup.py stats --program <slug>`
5. **Burp MCP** (if needed): `python3 engine/engine/burp.py setup` — check connectivity
6. **Go tools** (for recon): `which subfinder httpx gau katana` — all found in PATH
7. **Browser**: `python3 -m playwright install chromium` — installed
8. **Environment**: `HUNT_USER_AGENT` is set to your H1 username identifier

## Troubleshooting

### "ERROR: scope file not found" (netget.py CLI)
The `--scope-file` path doesn't exist. Check the engagement directory.

### "ERROR: no scope file found for slug" (netget.py CLI)
No scope.json found at `<BUGHUNTER_BASE>/_targets/<slug>.json` or `<BUGHUNTER_BASE>/<slug>/scope.json`.

### "ERROR: no --scope or --slug — browser capture requires a scope policy"
Browser.py requires explicit scope. Pass `--slug <target>` or `--scope <host>`.

### Coverage gate blocks hunt
Run `python3 engine/engine/discovery.py discover --slug <slug>` to improve coverage. Check which categories are missing with `python3 engine/engine/coverage.py show --slug <slug>`.

### Agent session "rate-limited" errors
Reduce `HUNT_SESSION_POOL` or increase timeout between rounds. Check if the LLM provider is throttling.

### Redirect following stopped
`allow_redirects` is hardcoded False. Use `follow_redirects()` for safe redirect handling with per-hop scope authorization.
