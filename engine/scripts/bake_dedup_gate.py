#!/usr/bin/env python3
"""
bake_dedup_gate.py — append a standard dedup/novelty footer to every hunt-* skill.

Idempotent: a skill that already references `dedup-novelty` is left untouched. Keeps the "don't ship
duplicates" discipline inline in each vuln-class skill (so it's present whether or not the operator
loaded the dedup-novelty skill separately).

Usage:
    python3 scripts/bake_dedup_gate.py            # apply to skills/hunt-*
    python3 scripts/bake_dedup_gate.py --check     # report which skills WOULD change (exit 1 if any)
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS = os.path.join(REPO, "skills")

FOOTER = """
## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
"""


def targets():
    for d in sorted(os.listdir(SKILLS)):
        if d.startswith("hunt-") and os.path.isfile(os.path.join(SKILLS, d, "SKILL.md")):
            yield os.path.join(SKILLS, d, "SKILL.md")


def main(argv):
    check = "--check" in argv
    changed = []
    for path in targets():
        raw = open(path, encoding="utf-8").read()
        if "dedup-novelty" in raw or "dedup gate" in raw.lower():
            continue
        changed.append(os.path.relpath(path, REPO))
        if not check:
            with open(path, "a", encoding="utf-8") as fh:
                if not raw.endswith("\n"):
                    fh.write("\n")
                fh.write(FOOTER)
    verb = "would change" if check else "updated"
    print(f"bake_dedup_gate: {verb} {len(changed)} hunt-* skill(s)")
    for c in changed:
        print("  " + c)
    return 1 if (check and changed) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
