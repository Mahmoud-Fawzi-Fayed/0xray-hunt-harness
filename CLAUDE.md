# 0xRay Hunt Harness

Engine: `~/0xray-hunt-harness/engine/engine/`. Config/secrets: `~/0xray-hunt-harness/harness/.env`.
Recon tools: `~/go/bin/` (add to PATH). Skills: `~/0xray-hunt-harness/engine/skills/` (89 skills).
Findings publish to `https://finding.redtracefai.com` + email `x00xrayx00x@gmail.com`. STOP at draft.

## Model routing

- **Opus** (`claude-opus-4-6`): vuln-hunter (deep reasoning), report-drafter (quality writing)
- **Fable** (`claude-fable-5-1`): hypothesis generation, creative bypass discovery
- **Sonnet** (`claude-sonnet-5-5`): recon-novelty (fast, cheap), dedup-oracle (pattern matching)

## Pipeline (every target, in order)

1. **Scope** — `targets.py show --program <p>`. Fetch via `bb-platforms` MCP if not registered.
2. **Profile** — `/profile target.com`. Understand app, roles, crown jewels, API surface before hunting.
3. **Novelty** — `novelty.py watch`. Hunt new/changed surface first. `jsdiff.py` on redeployed bundles.
4. **Yield** — `yieldrank.py rank --tech <stack>`. Cover ALL classes, most-findable first.
5. **Hunt** — walk matching `hunt-*` skills; prove real impact; unique markers; body-diff; n>=10 timing; OOB for blind.
6. **Dedup** — `dedup.py check` before drafting ANY finding. `LIKELY_DUP` = stop.
7. **Deliver** — publish finding page + email. **STOP at draft — never submit without explicit approval.**

## Autonomous capabilities (guardrail-gated)

- `identity.py` — disposable test accounts (capped, in-scope, audited)
- `sms.py` — DISABLED unless `SMS_PROVIDER` + `SMS_API_KEY` set
- `learn.py auto` — researches unknown stacks, drafts skills

## Burp Suite MCP

When Burp Pro is running with the MCP BApp extension (port 9876), agents automatically get:
- `mcp__burp__send_http1_request` / `send_http2_request` — requests captured in proxy history
- `mcp__burp__generate_collaborator_payload` / `get_collaborator_interactions` — OOB testing
- `mcp__burp__get_scan_issues` — passive/active scanner findings
- `netget.py` auto-routes through Burp proxy (127.0.0.1:8080) when MCP is reachable
- Setup: `python3 engine/engine/burp.py setup` registers in Claude Code + OpenCode

## Hard rules

- In-scope + read-only by default; no brute force.
- Triager-grade only: claim exactly what was proven.
- Dedup gate is mandatory. No draft without a `check`.
- `LIKELY_DUP` is a stop, not a suggestion.
- Autonomy stops at draft: never submit without explicit per-report approval.

## Testing

```bash
python3 ~/0xray-hunt-harness/scripts/selfcheck.py    # crash/loop/hostile-input gauntlet
python3 ~/0xray-hunt-harness/scripts/e2e.py           # end-to-end pipeline trace
```
