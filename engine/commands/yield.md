---
name: yield
description: Print the yield-ranked hunt order for a target — covers ALL vuln classes, sorted by how likely each is to actually land (frequency priors + your own confirmed/dup history, so classes you keep getting duplicated on sink automatically). Usage: /yield [--tech next.js,graphql]
---

# /yield

"Cover everything, but hunt the most-findable first." Prints every vuln class in priority order so
you spend your first hours where findings are most likely and dups least likely.

```bash
python3 engine/yieldrank.py rank                      # global order
python3 engine/yieldrank.py rank --tech next.js,graphql   # boosted for the detected stack
python3 engine/yieldrank.py rank --json               # machine-readable (for the orchestrator)
```

## How the order is computed

- **Frequency priors** — how often each class lands a finding in practice (info-leak / XSS / IDOR /
  API-misconfig high; SAML / smuggling low). This is a *yield* axis, distinct from the engine's
  *impact* axis (`CLASS_WEIGHT`); the engine blends both.
- **Your confirmed history** (+) — classes you've been landing get nudged up.
- **Your dup history** (−) — classes where you keep getting duplicated sink, automatically steering
  effort toward lower-dup surface. Learned from `hunt-memory/journal.jsonl` + your own dedup corpus.
- **Tech match** (+) — classes that fit the detected stack (e.g. GraphQL on a GraphQL API) rise.

## Use it

1. At session start, run `/yield --tech <detected>` and work top-down.
2. The engine already applies the same yield bonus inside `rank()`, so `--hunt` runs follow this order.
3. Nothing is dropped — every class is still listed; this is ordering, not filtering. Pair with
   `/dedup watch` so the fresh surface (lowest dup-risk) is hunted before the picked-over surface.

Full method + the novelty half: `dedup-novelty` and `changed-js-deepdive` skills.
