---
name: bb-methodology
description: Start or resume bug-bounty work with mode selection, the five-phase non-linear workflow, developer-psychology hypotheses, impact escalation, and validation discipline. Routes to phase-specific skills.
---

# Bug Bounty Methodology

Full workflow, examples, timing guidance, and operator lessons: [references/full-guide.md](references/full-guide.md).

## Flow

1. Confirm bug bounty, red team, WAPT, or internal audit mode.
2. Recon and map the application before testing.
3. Form hypotheses from trust boundaries and live responses.
4. Prove and escalate real impact; new surface returns to mapping.
5. Validate, dedup, report, and record outcomes.

## Quality gates

- Unique markers, body diffs, and interleaved timing samples.
- A-owned markers plus owner/accessor controls for authorization bugs.
- No brute force, destructive actions, or theoretical impact.
- Track tested, blocked, inconclusive, not_applicable, and unknown cases explicitly.
- High/Critical claims require independent reproduction; another model's opinion is not reproduction.
