---
name: dedup
description: Duplicate-avoidance + novelty engine. Sync a program's known-issue corpus (your YesWeHack reports + public HackerOne/Bugcrowd disclosures), check a candidate finding before you draft, or watch a target's surface for fresh (low-dup) changes. Usage: /dedup sync <program> | /dedup check | /dedup watch <target> | /dedup stats
---

# /dedup

Stop shipping duplicates. One entry point over `engine/dedup.py` (corpus + similarity oracle)
and `engine/novelty.py` (surface change detection). Load the `dedup-novelty` skill for the full
methodology; this command is the muscle memory.

## /dedup sync <program>

Build or refresh the known-issue corpus for a program. You acquire the data, the engine stores it.

1. **Your own YesWeHack reports** (always available via MCP):
   - `list_yeswehack_reports(program="<program>")` → for each, `get_yeswehack_report(report_id)`
   - map each to `{source:"ywh-own", program, title, vuln_class:<bug_type>, url:<endpoint>, status, link}`
2. **Public HackerOne Hacktivity** for the program: `WebFetch` the disclosed-reports view, pull
   title / weakness / severity / report URL → `source:"h1-public"`.
3. **Public Bugcrowd crowdstream** (if the program discloses): `WebFetch` → `source:"bugcrowd-public"`.
4. Ingest:

```bash
echo "$RECORDS_JSON" | python3 engine/dedup.py ingest --program <program> --source <src> --stdin
python3 engine/dedup.py stats --program <program>
```

Idempotent — safe to re-run; only new report ids are added. Do this at the START of a session on a target.

## /dedup check

Run before drafting ANY finding. Pull `{class,url,title}` from the current candidate:

```bash
python3 engine/dedup.py check --program <program> \
  --class <vuln-class> --url "<endpoint>" --title "<your working title>"
```

- ✅ `NOVEL` → proceed to `/validate` → `/report`.
- ⚠ `REVIEW` → draft only with a written "why this differs from <match link>" paragraph.
- ⛔ `LIKELY_DUP` → stop. Only continue if you can prove a concrete differentiator (different
  endpoint/param, different impact, or a bypass of the deployed fix) — then report it as a
  regression and link the original. No differentiator = kill it, move on.

Record the verdict in your hunt notes beside the finding. `/validate`'s duplicate question is this check.

## /dedup watch <target>

Feed the latest recon observation; get back the surface that CHANGED since last time — your
lowest-dup, highest-signal worklist.

```bash
# obs.json: {subdomains[], hosts[{url,status,title,tech}], js[{url,hash}], endpoints[], params[]}
python3 engine/novelty.py watch --target <target> --file obs.json          # diff + advance baseline
python3 engine/novelty.py diff  --target <target> --file obs.json --json   # just look, keep baseline
```

Hunt `new_subdomains` / `new_hosts` / `changed_js` (a redeploy — re-diff the bundle for new
routes/secrets) / `new_endpoints` / `new_params` BEFORE the surface everyone already scanned.

## /dedup stats

```bash
python3 engine/dedup.py stats                 # all programs
python3 engine/dedup.py stats --program <p>   # one program, by source
```

## Where data lives

`~/.bughunter-engagements/_dedup/corpus/<program>.jsonl` and
`~/.bughunter-engagements/_novelty/<target>/` (override with `--base`). Both are plain JSON/JSONL
— inspectable, diffable, and safe to delete to reset.

## Rules

- Never draft without a `check`. A `LIKELY_DUP` is a stop, not a suggestion.
- Refresh (`sync`) at session start — a stale corpus produces false `NOVEL` verdicts.
- The oracle rates DUP-RISK only. A `NOVEL` finding still must pass `/validate` and prove impact.
