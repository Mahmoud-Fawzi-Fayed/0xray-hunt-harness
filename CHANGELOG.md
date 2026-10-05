# Changelog

All notable changes to the 0xRay Hunt Harness. Format based on
[Keep a Changelog](https://keepachangelog.com/); releases are date-based.

## [0.2.0] - 2026-10-05
### Added
- **Full engine vendored from the live working tree** — previously only the engine's committed
  subset shipped, which omitted the core runtime. Now included: `orchestrator.py`, `bridge.py`,
  and every module (`dedup`, `novelty`, `yieldrank`, `targets`, `notify`, `guardrails`, `identity`,
  `sms`, `websearch`, `learn`, `jsdiff`, `observe`, `scopefetch`, `authsession`) plus the test
  scripts (`selfcheck`, `e2e`, `watchdog`).
- Two previously-missing referenced skills: `changed-js-deepdive`, `dedup-novelty`.
- Two desktop hunt skills: `hunt-desktop-macos`, `hunt-desktop-windows`.
- Three new authored skills — `hunt-webhook`, `hunt-jwt`, `hunt-api-owasp` — registered in
  `skill_map.py` (new `webhook`, `jwt`, `api` classes + starter probes).
- Repo scaffolding: `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `.editorconfig`,
  `Makefile`, GitHub issue/PR templates, and CI (`secret-scan` + `skills-lint`).

### Changed
- Hunt skills synced to their **edited** versions (the dedup-gate footer across the `hunt-*` set).
- README expanded with a full **skills catalog** and a `make`-based setup.
- The skills linter now skips the `learned/` container.

### Security
- Re-scrubbed: no real `.env` values, tokens, or client/engagement identifiers in the tree.
- Learned-skill drafts sanitized to remove hunt-target program names.

## [0.1.0] - 2026-10-05
### Added
- Initial harness: n8n novelty monitor, host bridge, Cursor agents + rules, `MANUAL.md`, and the
  engine (committed subset).
