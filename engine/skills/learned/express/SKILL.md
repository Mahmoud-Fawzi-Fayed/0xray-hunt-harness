---
name: express
description: Playbook for Express (tech). Auto-authored by the harness after it hit this as a gap. Use when a target involves Express. Review and refine before relying on it.
auto_authored: true
created: 2026-10-05T13:47:17.102812+00:00
---

# Express — learned playbook

> Auto-drafted from a capability gap. Context that triggered it: Detected Express, no existing skill

## When to use
- A target involves **Express** (tech).
- The existing skills have no specific playbook for it.

## Recon / fingerprint
- Confirm Express is in use (headers, JS bundles, error pages, docs, version strings).
- Map its endpoints, auth model, and any admin/debug surface.

## Likely weak points
- Known CVEs for the detected version (check NVD / GitHub advisories).
- Default configs, exposed debug/actuator/admin, verbose errors.
- The usual class bugs the stack is prone to (injection, authz, deserialization, SSRF).

## Validation discipline
- Prove impact concretely; no "could potentially". OOB confirmation for blind cases.
- Stay in-scope and read-only unless an authorized test account is provisioned.

## Research notes
- Explore the latest vulnerabilities and security issues of Expresstechsoftware in the CVE database
- Expresstech Vulnerabilities Real-time security vulnerability intelligence feed monitoring actively published CVE security advisories, CVSS ratings, and exploit intelligence worldwide.
- Browse all 44 CVE security advisories affecting ExpressTech. AI-powered Chinese analysis, POCs, and references for each vulnerability.
- 67 vulnerabilities affecting Expresstech. 8 critical, 0 exploited. Browse CVEs , affected products, and intelligence. Recent advisories: JVNDB-2022-000002, JVNDB-2021-000075.
- Track the latest Expresstech vulnerabilities and their associated exploits, patches, CVSS and EPSS scores, proof of concept, links to malware, threat actors, and MITRE ATT&CK TTP information

## References
- [Expresstechsoftware CVEs and Security Vulnerabilities - OpenCVE](https://app.opencve.io/cve/?vendor=expresstechsoftware)
- [Expresstech Vulnerabilities - TheHackerWire](https://www.thehackerwire.com/vendor/expresstech/)
- [ExpressTech Vulnerabilities (44 CVEs) | Shenlong CVE Platform](https://cve.imfht.com/vendor/ExpressTech?lang=en)
- [Expresstech CVEs and Security Vulnerabilities | NotCVE](https://notcve.org/vendors/expresstech/)
- [Latest Expresstech Vulnerabilities](https://feedly.com/cve/vendors/expresstech)
