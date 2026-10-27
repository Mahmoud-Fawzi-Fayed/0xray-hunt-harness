---
name: security-arsenal
description: Security payloads, bypass tables, wordlists, gf patterns, rejection rules, and chain-dependent findings. Use for a specific probe or to check whether a finding is submittable.
---

# Security Arsenal

Payloads and detailed tables: [references/full-guide.md](references/full-guide.md). Load only the relevant section and follow the matching hunt skill's authorization and safety limits.

## Proof standard

- Use unique markers and compare bodies, not just status codes.
- Reflection, errors, permissive headers, and timing outliers are signals, not findings.
- Do not brute force, generate load, or send mutation/depth batches for resource exhaustion.
- Prove the exact sink and impact with linked request/response observations, then independently reproduce.
