---
name: autopilot
description: Run autonomous hunt loop on a target — scope check → recon → rank surface → hunt → validate → report with configurable checkpoints. Usage: /autopilot target.com [--paranoid|--normal|--yolo]
---

# /autopilot

Autonomous hunt loop with deterministic scope safety and configurable checkpoints.

## Usage

```
/autopilot target.com                    # default: --paranoid mode
/autopilot target.com --normal           # batch checkpoint after validation
/autopilot target.com --yolo             # minimal checkpoints (still requires report approval)
/autopilot target.com --quick            # fast surface scan, fewer checks, lower token use
/autopilot targets.txt                   # multiple targets — one domain per line in the file
```

## Session Isolation (Important)

**Start a fresh Claude Code session per target.** Claude accumulates context across a session —
testing multiple targets in one session causes cross-contamination where findings, payloads,
and tech stack assumptions from target A bleed into target B.

Best practice:
```bash
# Terminal 1: target A
claude  →  /autopilot targetA.com

# Terminal 2: target B (separate process)
claude  →  /autopilot targetB.com
```

If you must test multiple targets in one session, run `/pickup target.com` at the start of
each target switch to reload the correct context.

## Token Optimization

Use `--quick` for faster, lower-cost scans (skips deep fuzzing and extended nuclei templates):
```
/autopilot target.com --quick    # ~40% fewer tokens, covers main attack surface
/hunt target.com --vuln-class idor   # single bug class — lowest token use
```

For long hunts, run `/compact` (Claude Code built-in) periodically to compress context
without losing findings.

## What This Does

Runs the full anti-duplicate hunt cycle without stopping for approval at each step — until draft:

```
1.  SCOPE       Load and confirm program scope
2.  SYNC        /dedup sync — build the known-issue corpus (your reports + public H1/Bugcrowd disclosures)
3.  RECON       Run recon (or use cached if < 7 days old)
4.  NOVELTY     /dedup watch — diff the surface; hunt the fresh/changed surface (lowest dup-risk) FIRST
5.  RANK        /yield — cover ALL classes, ordered by find-likelihood + your learned dup rate
6.  HUNT        Test prioritized surface systematically (novelty delta first)
7.  VALIDATE    7-Question Gate on findings
8.  DEDUP GATE  /dedup check — NOVEL -> draft; LIKELY_DUP -> HELD (not drafted) unless a differentiator
9.  DRAFT       Draft reports for novel validated findings
10. CHECKPOINT  Present to human; STOP before any submit
```

One-shot engine version (same stop-at-draft contract, deterministic control flow):

```
python3 engine/orchestrator.py --scope <scope.json> --hunt
```

Or delegate to the Cursor subagent `hunt-orchestrator`, which sequences `recon-novelty` ->
`vuln-hunter` -> `dedup-oracle` -> `report-drafter` and stops at draft.

## Safety Guarantees

- **Every URL** is checked against the scope allowlist before any request
- **Every request** is logged to `hunt-memory/audit.jsonl`
- **Reports are NEVER auto-submitted** — always requires explicit approval
- **Duplicates are HELD, not drafted** — the dedup gate scores every finding before drafting; a LIKELY_DUP is held with its matching disclosure link until you prove a differentiator
- **PUT/DELETE/PATCH** require human approval in --yolo mode (safe methods only)
- **Circuit breaker** stops hammering if 5 consecutive 403/429/timeout on same host
- **Rate limited** at 1 req/sec (testing) and 10 req/sec (recon)

## Checkpoint Modes

| Mode | When it stops | Best for |
|---|---|---|
| `--paranoid` | Every finding + partial signal | New targets, learning the surface |
| `--normal` | After validation batch | Systematic coverage |
| `--yolo` | After full surface exhausted | Familiar targets, experienced hunters |

## After Autopilot

- Run `/remember` to log successful patterns to hunt memory
- Run `/pickup target.com` next time to pick up where you left off
- Check `hunt-memory/audit.jsonl` for a full request log
