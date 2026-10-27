---
name: cloud-iam-deep
description: Cloud IAM attack-chain guidance for AWS, Azure, GCP, metadata credentials, role trust, managed identities, service accounts, and post-credential privilege analysis. Use after discovering cloud credentials or IAM exposure.
---

# Cloud IAM Deep

Complete provider-specific enumeration, privilege paths, and validation examples: [references/full-guide.md](references/full-guide.md).

## Discipline

- Start from the credential or exposure actually observed; do not assume its privileges.
- Enumerate read-only first, map trust boundaries, and prove the minimum effective action.
- Do not exercise credentials outside scope or access real victim data for scale.
- A key, policy, or metadata response is not impact until a server authorizes a meaningful action.
- Preserve request evidence and stop after proving the privilege boundary violation.
