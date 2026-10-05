---
name: typo3-cms
description: Playbook for TYPO3 CMS (tech). Auto-authored by the harness after it hit this as a gap. Use when a target involves TYPO3 CMS. Review and refine before relying on it.
auto_authored: true
created: 2026-10-05T06:00:15.891281+00:00
---

# TYPO3 CMS — learned playbook

> Auto-drafted from a capability gap. Context that triggered it: Authorized hunt of a TYPO3 install for info-leak. Need known TYPO3 source-leak paths, backend login disclosure, install tool, typo3conf, composer.json, CHANGELOG, sysext exposure, default credentials NOT to use, version fingerprinting, recent CVEs that leak files or config.

## When to use
- A target involves **TYPO3 CMS** (tech).
- The existing skills have no specific playbook for it.

## Recon / fingerprint
- Confirm TYPO3 CMS is in use (headers, JS bundles, error pages, docs, version strings).
- Map its endpoints, auth model, and any admin/debug surface.

## Likely weak points
- Known CVEs for the detected version (check NVD / GitHub advisories).
- Default configs, exposed debug/actuator/admin, verbose errors.
- The usual class bugs the stack is prone to (injection, authz, deserialization, SSRF).

## Validation discipline
- Prove impact concretely; no "could potentially". OOB confirmation for blind cases.
- Stay in-scope and read-only unless an authorized test account is provisioned.

## Research notes
- (add findings as you learn this stack)

## References
- (add links as you research)
