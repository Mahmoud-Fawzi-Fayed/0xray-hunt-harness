---
name: dedup-novelty
description: Avoid duplicate bug-bounty reports and hunt where the crowd has not. Use BEFORE picking what to hunt (novelty-first targeting on changed surface) and BEFORE drafting or submitting any finding (dedup gate against public disclosures + your own past reports). Trigger whenever starting a target, choosing a surface to attack, or about to write a report. Wraps engine/dedup.py (corpus + similarity oracle) and engine/novelty.py (surface change detection), fed from the bb-platforms MCP (own YesWeHack reports) and WebFetch (public HackerOne Hacktivity / Bugcrowd crowdstream).
---

# dedup-novelty — don't report what's already known; hunt what's new

Everyone has AI and the same skill packs now. Automation converges on the same obvious
surface, so the scanner-style finding is a duplicate before you even submit it. The edge is
**novelty**: hunt surface the crowd has not picked over, and never spend a report slot on a bug
that is already public or that you already filed. This skill is the discipline + the tooling for
both halves.

Two gates, both mandatory:

1. **Pre-hunt (novelty targeting)** — point effort at surface that just *changed* and at
   classes nobody has reported on this program.
2. **Pre-submit (dedup gate)** — score every candidate finding against a corpus of known
   issues before drafting. `LIKELY_DUP` without a documented differentiator = kill it.

The engine is offline and deterministic; YOU (the agent) acquire the corpus via MCP + WebFetch
and pipe it in. Nothing is auto-fetched.

---

## 1. Build / refresh the corpus (acquisition — you do this)

Pull known issues for the program and ingest them. Produce records in this exact shape
(any subset of fields works; more fields = sharper verdict):

```json
{"source":"h1-public","program":"<slug>","title":"...","vuln_class":"idor",
 "url":"https://.../api/...","status":"resolved","severity":"high","date":"2026-01-02",
 "link":"https://hackerone.com/reports/123"}
```

Sources, in priority order:

| Source | How to get it | ingest `--source` |
|---|---|---|
| **Your own YesWeHack reports** | `list_yeswehack_reports(program=...)` then `get_yeswehack_report(report_id)` for the title/bug_type/scope/endpoint of each | `ywh-own` |
| **Public HackerOne Hacktivity** | `WebFetch` the program's hacktivity (disclosed reports) — pull title, weakness, severity, report URL | `h1-public` |
| **Public Bugcrowd crowdstream** | `WebFetch` the program's public disclosures | `bugcrowd-public` |
| **Public YesWeHack reports** | `WebFetch` the program's public report list, if any | `ywh-public` |
| **Public Intigriti disclosures** | `WebFetch` the program's disclosed reports | `intigriti-public` |
| **Your hunt-memory** | read `hunt-memory/journal.jsonl` (confirmed findings) if present | `own-memory` |

Ingest (idempotent — re-running only adds new ids):

```bash
# own YesWeHack reports (after you've assembled them into reports.json)
python3 engine/dedup.py ingest --program acme --source ywh-own --file reports.json

# public disclosures you extracted with WebFetch, piped straight in
echo "$H1_JSON" | python3 engine/dedup.py ingest --program acme --source h1-public --stdin

python3 engine/dedup.py stats --program acme     # confirm the corpus has records
```

> If network blocks a public source, ingest what you can (own reports always work via MCP) and
> note the gap — a partial corpus still catches your own dups and the disclosed big ones.

---

## 2. Pre-hunt: novelty-first targeting

Feed each recon pass into `novelty.py` and hunt the delta FIRST. New/changed surface is both
higher-signal (new code = fresh bugs) and lower-dup-risk (nobody has reported it yet).

Build an observation JSON from recon (`recon/<target>/`): `subdomains`, `hosts`
(`{url,status,title,tech}`), `js` (`{url,hash}` — hash the bundle bytes), `endpoints`, `params`.

```bash
python3 engine/novelty.py watch --target acme.com --file obs.json   # diff vs last, then advance baseline
```

`watch` returns `new_subdomains`, `new_hosts`, `new_js`, `changed_js` (a redeploy of an existing
bundle — read the diff for new routes/secrets), `new_endpoints`, `new_params`. **Hunt these before
anything else.** A `changed_js` on an auth/payment bundle is the single highest-value novelty signal.

Use `diff` (no baseline advance) when you just want to look; use `watch` when this is the run of
record. The n8n hunting monitor calls `watch` on a schedule and alerts on any non-empty delta.

---

## 3. Pre-submit: the dedup gate (never skip)

Before drafting ANY report, score the candidate:

```bash
python3 engine/dedup.py check --program acme --class idor \
  --url "https://acme.com/api/v2/users/5/orders" \
  --title "Access another user's orders via v2 users orders API"
```

Verdicts (based on the top-match similarity score):

| Verdict | Score | Meaning | Action |
|---|---|---|---|
| ✅ `NOVEL` | < 0.45 | No close match in a non-empty corpus | Proceed to `/validate` → draft |
| ⚠ `REVIEW` | 0.45–0.72 | Overlaps a known issue (same class, related area) | Draft ONLY with an explicit "why this is not the known issue" paragraph citing the match link |
| ⛔ `LIKELY_DUP` | ≥ 0.72 | Almost certainly already known | **Do NOT draft** unless you can prove a concrete differentiator (different endpoint/parameter, different impact, bypass of the deployed fix). Otherwise kill it and move on. |
| ❔ `UNKNOWN` | n/a | Corpus for this program is empty | **Not a NOVEL.** Ingest at least one source, or run the manual three-axis check below and write that verdict. `dedup.py` returns `UNKNOWN` on an empty corpus so a missing corpus cannot look like a new bug. |

The score blends vuln-class match, endpoint path/param overlap (volatile ids like `/5/` and UUIDs
are normalized so a different victim id still matches), and title-token overlap. A reworded title
on the same endpoint still scores as a dup — that is the point.

**An incomplete-patch bypass is NOT a dup.** If the match is `resolved` and you reproduce it
anyway, that's a *new* finding (regression / incomplete fix) — say so in the report and link the
original.

**Sibling hosts on a wildcard program usually are a dup.** Same class + same control on
`a.target.com` after you (or someone) already filed it on `b.target.com` scores `LIKELY_DUP`
unless you write a differentiator (different parameter, different impact, or a fix-bypass). A
new subdomain is novelty for *hunting*, not automatic novelty for *reporting*.

**If `engine/dedup.py` is unavailable, dedup manually — never skip the gate.** Pull disclosed
reports (H1 Hacktivity / Bugcrowd crowdstream / program changelog via WebFetch) + your own prior
reports, then compare the candidate on three axes: (1) vuln class, (2) normalised endpoint/param
(strip volatile ids/UUIDs), (3) impact. A match on all three = treat as `LIKELY_DUP`; a clear
difference on any one (different param, different impact, or a bypass of a deployed fix) = proceed
and document the differentiator. Record the manual verdict in your hunt notes exactly as you would
the tool's.

---

## 4. Automatic integration points

- `engine/engine.py` **rank** down-ranks surface whose `(class,url)` scores `LIKELY_DUP` against
  the corpus, so agents spend budget on novel surface (no-op when no corpus exists).
- `engine/engine.py` **report** annotates every confirmed finding with its dedup verdict +
  nearest match, so a dup is visible before you ever open the platform.
- `/dedup` command — one entry point for sync / check / watch.
- `/validate` — the 7-Question Gate includes "is this a duplicate?"; run `check` to answer it.

---

## Hard rules

1. **No draft without a `check`.** The dedup verdict goes in your hunt notes next to the finding.
2. **`LIKELY_DUP` is a stop** unless you write the differentiator down. "Feels different" is not a
   differentiator — a different endpoint, parameter, impact, or a fix-bypass is.
3. **Refresh the corpus at session start** for the target. Stale corpus = false "NOVEL".
4. **Novelty delta is the default worklist.** If you're hunting the apex login page everyone
   scans instead of the subdomain that appeared yesterday, you're farming dups.
5. The oracle is an *advisor on dup-risk*, not a validity check. A `NOVEL` verdict still has to
   pass `/validate` and prove real impact.

---

## Related Skills & Chains

- **`bb-methodology`** — Phase 1 (Recon) feeds `novelty.py`; Phase 5 (Validate & Report) runs the
  dedup gate before `/report`. This skill supplies the "is it new / is it a dup" answers that
  methodology's phases assume.
- **`triage-validation`** — the 7-Question Gate's duplicate question is answered by
  `dedup.py check`; run this before `/validate` finalizes a finding.
- **`report-writing`** / **`bugcrowd-reporting`** — only draft after a `NOVEL` (or a `REVIEW`/dup
  with a written differentiator). A `LIKELY_DUP` report wastes the slot and your reputation.
- **`web2-recon`** / **`offensive-osint`** — produce the subdomain / host / JS / endpoint lists
  that become the `novelty.py` observation. Re-run them to generate the next delta.
- **`changed-js-deepdive`** — a `changed_js` / `new_js` delta is the trigger to diff the bundle
  (`engine/jsdiff.py`) for new routes, params, secrets, and server-action ids. `hunt-source-leak`
  is the follow-up when that diff also names a `.map`, `.env`, or spec file.
