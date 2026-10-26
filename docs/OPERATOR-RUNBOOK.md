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

- Python 3.12+
- `pip install requests playwright`
- `python3 -m playwright install chromium`
- Optional: Burp Suite Pro with MCP BApp (port 9876)
- Optional: Go recon tools in `~/go/bin/` (subfinder, httpx, gau, katana)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BUGHUNTER_BASE` | `~/.bughunter-engagements` | Base directory for all engagements |
| `HUNT_MAX_ACCOUNTS` | `3` | Max accounts created per program |
| `HUNT_SKIP_COVERAGE_GATE` | unset | Set to `1` to bypass 80% coverage gate |
| `HUNT_SKIP_AUTH_GATE` | unset | Set to `1` to bypass auth-wall gate |
| `HUNT_SESSION_POOL` | `3` | Reused agent sessions per target |
| `HUNT_SESSION_MAX_USES` | `25` | Max turns before session refresh |
| `HUNT_SESSION_MAX_AGE_MIN` | `360` | Session retirement age in minutes |
| `SESSION_MAX_AGE_SEC` | `3600` | Auth session expiry in seconds |

## Pipeline Gates

### Coverage Gate (Phase: Discover → Hunt)

- Threshold: 80% depth coverage
- Formula: `min(100, 0.9 * depth_score + breadth_bonus)`
- Override: `HUNT_SKIP_COVERAGE_GATE=1`
- If triggered: Run more discovery methods, check for missed endpoint categories

### Auth Gate (Phase: Plan → Hunt)

- Threshold: >50% surface requires authentication
- Override: `HUNT_SKIP_AUTH_GATE=1`
- Resolution: `python3 engine/engine/authsession.py provision --program <slug>`
- Manual: `python3 engine/engine/authbootstrap.py inject --program <slug> --cookie '...' --ident A`

### Dedup Gate (Phase: Report)

- Verdict `LIKELY_DUP`: HARD STOP — do not draft
- Verdict `REVIEW`: Draft with "why this is different" paragraph
- Verdict `NOVEL`: Proceed to draft
- Check: `python3 engine/engine/dedup.py check --program <slug> --class <c> --url <u> --title "..."`

### Verify Gate (Phase: Validate → Report)

- Every finding must pass `verify.py check --file <finding.json> --program <slug>`
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
