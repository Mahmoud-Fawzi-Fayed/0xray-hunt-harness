# Authorized Testing Runbook

## Safe Defaults

- **Read-only by default** — no mutations without explicit operator approval
- **Never auto-submit** — findings stop at draft, require human review
- **Dedup is mandatory** — `LIKELY_DUP` is a hard stop
- **In-scope only** — every request validated against canonical scope
- **Account creation capped** — max 5 per program (configurable via `HUNT_MAX_ACCOUNTS`)
- **No brute force** — OTP/credential brute-force actions are always refused

## Prerequisites

```bash
# Python 3.12+
python3 --version

# Core dependencies
pip install requests playwright
python3 -m playwright install chromium

# Optional: Burp Suite Pro with MCP BApp extension (port 9876)
# Optional: Go recon tools in ~/go/bin/
```

## Running Tests

### Unit + Self-Tests (61 modules)

```bash
python3 engine/scripts/selfcheck.py
# Expected: 61/61 passed, 0 failed
```

### Local E2E (basic pipeline)

```bash
python3 engine/tests/test_e2e_local.py
# Starts vuln_app on port 19876
# Tests: scope → intake → guardrails → netget → explore → plan → coverage → dedup
```

### Comprehensive E2E (full validation)

```bash
python3 engine/tests/test_e2e_comprehensive.py
# Starts vuln_app + OOS sink
# Tests: scope enforcement (exact/wildcard/CIDR/regex/path/userinfo),
#        guardrails, netget, explorer, test planner, coverage tracking,
#        dedup, browser discovery (Playwright), verify, OOS sink zero-request check
# Outputs: artifacts/release-validation/e2e-comprehensive-results.json
```

### Secret Scan

```bash
make secret-scan
# Verifies no credentials/tokens committed
```

### Skills Lint

```bash
make skills-lint
# Checks 90 skills for naming, structure, broken references
```

## ROE Intake — Starting an Engagement

```bash
# From a bug bounty program URL
python3 engine/engine/intake.py start https://hackerone.com/example

# This creates:
#   ~/.bughunter-engagements/example/scope.json    (canonical scope)
#   ~/.bughunter-engagements/_targets/example.json  (target registration)
```

### Manual Scope Creation

```json
{
  "name": "example",
  "in_scope": ["*.example.com"],
  "out_of_scope": ["admin.example.com"],
  "seeds": ["https://www.example.com"],
  "self_register_ok": true,
  "path_restrictions": {"*.example.com": ["/api"]},
  "out_path_restrictions": {"*.example.com": ["/api/internal"]},
  "rate_limit": 10,
  "prohibited_actions": ["file-upload", "payment"],
  "required_headers": {"X-Bug-Bounty": "authorized"},
  "roe_extra": "No testing during business hours UTC"
}
```

### Scope Pattern Reference

| Pattern | Matches |
|---|---|
| `example.com` | Exact host only |
| `*.example.com` | Any subdomain + the apex |
| `=api.example.com` | That exact host (explicit) |
| `10.0.0.0/8` | Any IP in the CIDR range |
| `re:^staging[0-9]+\.example\.com$` | Regex fullmatch |

## Local Test Lab

```bash
# Start the intentionally vulnerable test app
python3 engine/tests/vuln_app.py --port 9999

# Users: alice@test.local (admin, tenant 1), bob@test.local (user, tenant 1)
#        carol@test.local (admin, tenant 2), dave@test.local (user, tenant 2)
# Sessions: Cookie: sid=session-alice / session-bob / session-carol / session-dave
# Known vulns: IDOR, XSS, info disclosure, missing auth, CSRF, open redirect
# Known protections: /api/users/:id?fields=public, /api/admin/config (admin+CSRF)
```

## Burp Suite Integration (Optional)

```bash
# Setup Burp MCP bridge
python3 engine/engine/burp.py setup

# Verify connection
python3 engine/engine/burp.py selftest

# When Burp is running:
# - netget.py auto-routes through proxy (127.0.0.1:8080)
# - Collaborator payloads available for OOB testing
# - Passive scanner findings integrated into surface
```

## Running a Supervised Hunt

```bash
# 1. Verify scope
python3 engine/engine/targets.py show --program example

# 2. Profile the target
python3 engine/engine/brain.py profile --program example

# 3. Run the engine (supervised)
python3 engine/engine/engine.py run --program example --max-hunts 10

# 4. Review findings (NEVER auto-submitted)
python3 engine/engine/findings.py list --program example

# 5. Check coverage
python3 engine/engine/coverage.py show --slug example
```

## Hard Rules (Non-Negotiable)

1. **In-scope + read-only by default** — no brute force
2. **Triager-grade only** — claim exactly what was proven
3. **Dedup gate is mandatory** — no draft without a check
4. **LIKELY_DUP is a stop**, not a suggestion
5. **Autonomy stops at draft** — never submit without explicit per-report approval
6. **Never automatically trigger destructive or sensitive operations**
7. **Never invent endpoints or claim untested functionality is secure**
