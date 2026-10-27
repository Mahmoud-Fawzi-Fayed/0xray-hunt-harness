---
name: bug-bounty
description: Complete bug-bounty workflow for recon, learning, hunting, chaining, validation, evidence, and reporting. Use for any bug-bounty task. 中文触发词：漏洞赏金、安全测试、渗透测试、漏洞挖掘、信息收集、漏洞报告
---

# Bug Bounty Master Workflow

Use: Recon → Learn → Hunt → Validate → Report.

The complete playbooks, bypass tables, payload references, templates, and examples are in [references/full-guide.md](references/full-guide.md). Read the relevant section instead of loading the entire guide.

## Non-negotiables

- Confirm attacker-attainable impact against a real user; reflection, errors, and configuration alone are leads.
- Keep all traffic in scope and follow the program's rate and method policy.
- Use unique markers and body diffs. Similar A/B responses do not prove authorization bypass.
- Track every hypothesis and blocked/inconclusive outcome; do not confuse endpoint count with coverage.
- Reproduce independently, dedup, then stop at a human-reviewed draft.
