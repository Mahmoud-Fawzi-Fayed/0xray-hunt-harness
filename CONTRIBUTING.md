# Contributing

## Repository layout
See the [README](README.md#repository-layout). In short: `harness/` is the glue, `.cursor/` holds
the agents + rules, and `engine/` is the vendored engine + skills.

## Adding a hunt skill
1. Create `engine/skills/<name>/SKILL.md` with YAML frontmatter:
   - `name:` — lowercase, hyphenated, and it **must equal the directory name**.
   - `description:` — a one-paragraph trigger surface (**≤ 1024 chars**; longer trips the linter).
2. Keep the body **under 500 lines**; move long payload banks into a `references/` subfolder.
3. Match the house structure: **"What actually pays (and what doesn't)"**, detection, **PoC
   minimums**, the **dedup-gate footer**, and **cross-references** to sibling skills.
4. Name the directory `hunt-<token>` so `skill_map.matching()` picks it up from
   live URL/stack bytes. Do **not** add a class→skill table or a payload catalog
   in engine code.
5. For the live runtime, skills are read from `~/.claude/skills` — copy or symlink
   `engine/skills/<name>` there (the engine installer does this for you).

## Quality gates (run before you push)
```bash
make skills-lint     # engine/scripts/lint_skills.py — frontmatter, naming, secret + identifier scan
make secret-scan     # no secrets in the tree
make selfcheck       # engine crash/loop/hostile-input gauntlet
make e2e             # end-to-end pipeline trace
```

## Hard rules
- **Never commit secrets** or **real client/engagement identifiers.** The linter hashes text
  shingles against a denylist; keep plaintext target names out of the tree.
- **Keep the safety contract intact** (see [SECURITY.md](SECURITY.md)).
- **Triager-grade only:** skills must teach *prove real impact*, never reflection/error-only.

## Commit style
Conventional-ish prefixes: `feat(skill): add hunt-webhook`, `fix(bridge): …`, `docs: …`,
`chore(engine): …`.
