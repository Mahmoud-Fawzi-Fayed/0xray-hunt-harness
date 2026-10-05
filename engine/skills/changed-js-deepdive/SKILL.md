---
name: changed-js-deepdive
description: Turn a redeployed or newly-discovered JavaScript bundle into first-mover findings. Use when the novelty monitor flags a changed_js / new_js, when a target ships a new build, or whenever you spot a fresh JS bundle. A redeploy ships new API routes, new parameters, and sometimes leaked keys that nobody has hunted yet, so being first on the delta is the cleanest way to avoid duplicates. Wraps engine/jsdiff.py (diff two bundles into new endpoints/params/secrets/routes) and chains into the right hunt-* skill per candidate.
---

# changed-js-deepdive — hunt the delta of a redeployed bundle before anyone else

A bundle whose hash just moved almost always carries new code: a new endpoint, a hidden
parameter, a feature flag, occasionally a committed key. That delta is unhunted and un-reported —
the highest novelty-to-effort ratio on the whole target. Don't re-read the whole app; diff the
bundle and attack only what's new.

Trigger: `novelty.py` / the n8n monitor reports `changed_js` or `new_js`, OR you notice a new
`main.<hash>.js` / build id.

## Step 1 — get both bundle versions

```bash
curl -sL "https://t/assets/app.<newhash>.js" -o /tmp/new.js
```

Get the OLD version from whichever is available:
- your novelty JS cache / previous recon copy,
- the Wayback Machine (`https://web.archive.org/web/2id_/<bundle-url>`),
- a prior build hash still referenced in an old HTML snapshot.

No old copy anywhere? Use `scan` (treat the whole bundle as new surface):

```bash
python3 engine/jsdiff.py scan --new /tmp/new.js
```

## Step 2 — diff into a hunt list

```bash
python3 engine/jsdiff.py diff --old /tmp/old.js --new /tmp/new.js
# or fetch both directly:
python3 engine/jsdiff.py fetch --old "<OLD_URL>" --new "<NEW_URL>"
```

Output buckets: `new_endpoints`, `new_params`, `new_secrets`, `new_routes`.

## Step 3 — prioritize the delta (highest payoff first)

1. **`new_secrets`** — verify validity READ-ONLY (confirm the key is live + what it unlocks; never
   exercise it). A live key is often High/Critical on its own. See `security-arsenal` / `hunt-source-leak`.
2. **`new_endpoints`** — hit each with your identity and a second identity. New endpoints frequently
   ship without the authz the old ones have (the classic "feature B added after A's checks"):
   `hunt-idor`, `hunt-auth-bypass`, `hunt-api-misconfig`, plus injection via `hunt-sqli` / `hunt-ssrf`.
3. **`new_params`** — hidden/undocumented params = mass assignment, injection, SSRF sinks, debug
   flags: `hunt-api-misconfig` (mass assignment), `hunt-ssrf`, `hunt-idor`.
4. **`new_routes`** — client routes that reveal unreleased features / admin UIs to map next.

If `.js.map` is present, reconstruct the TypeScript source and read the new modules directly
(`hunt-source-leak`).

## Step 4 — exploit, then dedup-gate

For each confirmed candidate, run the dedup gate before drafting — even fresh-bundle findings can
collide with a very recent disclosure:

```bash
python3 engine/dedup.py check --program <program> --class <cls> --url "<new endpoint>" --title "<title>"
```

`NOVEL` → `/validate` → draft. `LIKELY_DUP` → stop unless you prove a differentiator.

## Rules

1. Fresh surface first — the delta is where dups are least likely; spend effort there before the
   picked-over apex.
2. Secrets are READ-ONLY to verify. Prove it's live and state what it unlocks; do not use it.
3. Every candidate still passes `/validate` + the dedup gate. New != automatically valid.
4. Re-diff on every redeploy — a `changed_js` next week is a new delta to hunt again.

## Related Skills & Chains

- **`dedup-novelty`** — this skill is the deep-dive that fires when its novelty monitor reports a
  `changed_js` / `new_js`; it hands each delta item back through the dedup gate.
- **`hunt-source-leak`** — for `new_secrets` and for `.js.map` source reconstruction.
- **`hunt-idor`** / **`hunt-auth-bypass`** / **`hunt-api-misconfig`** — the primary targets for
  `new_endpoints` (new code ships weaker authz) and `new_params` (mass assignment / hidden sinks).
- **`hunt-ssrf`** / **`hunt-sqli`** — injection testing on the new endpoints + params.
- **`security-arsenal`** — payloads for exploiting each class once the delta points you at it.
