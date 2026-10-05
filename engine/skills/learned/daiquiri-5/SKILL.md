---
name: daiquiri-5
description: Playbook for daiquiri/5 (tech). Auto-authored by the harness after it hit this as a gap. Use when a target involves daiquiri/5. Review and refine before relying on it.
auto_authored: true
created: 2026-10-05T13:47:17.839185+00:00
---

# daiquiri/5 — learned playbook

> Auto-drafted from a capability gap. Context that triggered it: Detected daiquiri/5, no existing skill

## When to use
- A target involves **daiquiri/5** (tech).
- The existing skills have no specific playbook for it.

## Recon / fingerprint
- Confirm daiquiri/5 is in use (headers, JS bundles, error pages, docs, version strings).
- Map its endpoints, auth model, and any admin/debug surface.

## Likely weak points
- Known CVEs for the detected version (check NVD / GitHub advisories).
- Default configs, exposed debug/actuator/admin, verbose errors.
- The usual class bugs the stack is prone to (injection, authz, deserialization, SSRF).

## Validation discipline
- Prove impact concretely; no "could potentially". OOB confirmation for blind cases.
- Stay in-scope and read-only unless an authorized test account is provisioned.

## Research notes
- High-severity vulnerability in ThemeREX Daiquiri PHP program allows local file inclusion. Organizations must patch immediately to prevent exploitation .
- CVE -2026-28089 is a CVSS 8.1 high-severity vulnerability in ThemeREX Daiquiri. Includes technical details, affected versions, and mitigation steps.
- CVE -2026-28089 is a PHP local file inclusion vulnerability in ThemeREX Daiquiri theme. Learn about its impact, affected versions, and mitigation methods.
- A security flaw has been discovered in ThemeREX Daiquiri Plugin up to 1.2.4 on WordPress. This vulnerability is cataloged as CVE -2026-28089.
- This is the list of security issues and vulnerability checks that the Invicti web application security scanner has. Therefore when you scan a website, web application or web API (web service) with Inv

## References
- [CVE-2026-28089 | High Vulnerability in ThemeREX Daiquiri](https://www.appsecure.security/vulnerability-database/cve-2026-28089/)
- [CVE-2026-28089: ThemeREX Daiquiri Vulnerability | CVETodo](https://cvetodo.com/cve/CVE-2026-28089)
- [CVE-2026-28089: Daiquiri Theme File Inclusion Vulnerability](https://www.sentinelone.com/vulnerability-database/cve-2026-28089/)
- [CVE-2026-28089 in Daiquiri Plugin - vuldb.com](https://vuldb.com/cve/CVE-2026-28089)
- [Version Disclosure (Daiquiri) - Invicti](https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/version-disclosure-daiquiri)
