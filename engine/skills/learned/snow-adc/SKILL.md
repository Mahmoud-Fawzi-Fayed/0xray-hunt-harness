---
name: snow-adc
description: Playbook for snow_adc (tech). Auto-authored by the harness after it hit this as a gap. Use when a target involves snow_adc. Review and refine before relying on it.
auto_authored: true
created: 2026-10-05T14:08:13.529794+00:00
---

# snow_adc — learned playbook

> Auto-drafted from a capability gap. Context that triggered it: Detected snow_adc, no existing skill

## When to use
- A target involves **snow_adc** (tech).
- The existing skills have no specific playbook for it.

## Recon / fingerprint
- Confirm snow_adc is in use (headers, JS bundles, error pages, docs, version strings).
- Map its endpoints, auth model, and any admin/debug surface.

## Likely weak points
- Known CVEs for the detected version (check NVD / GitHub advisories).
- Default configs, exposed debug/actuator/admin, verbose errors.
- The usual class bugs the stack is prone to (injection, authz, deserialization, SSRF).

## Validation discipline
- Prove impact concretely; no "could potentially". OOB confirmation for blind cases.
- Stay in-scope and read-only unless an authorized test account is provisioned.

## Research notes
- Explore the latest vulnerabilities and security issues of Snowsoftware in the CVE database
- Track the latest Snowsoftware vulnerabilities and their associated exploits, patches, CVSS and EPSS scores, proof of concept, links to malware, threat actors, and MITRE ATT&CK TTP information
- A recently disclosed critical security flaw impacting Citrix NetScaler ADC and NetScaler Gateway is witnessing active reconnaissance activity, according to Defused Cyber and watchTowr. The vulnerabili
- Citrix NetScaler ADC and Gateway appliances are under attack again. Researchers have published full technical details of CVE -2026-88772, a critical pre-authentication remote code execution (RCE) vuln
- The Snowflake Security Bulletins page shares information about vulnerabilities that may affect Snowflake services. Bulletins include CVE IDs, severity ratings, affected components, and remediation gui

## References
- [Snowsoftware CVEs and Security Vulnerabilities - OpenCVE](https://app.opencve.io/cve/?vendor=snowsoftware)
- [Latest Snowsoftware Vulnerabilities - Feedly](https://feedly.com/cve/vendors/snowsoftware)
- [Citrix NetScaler Under Active Recon for CVE-2026-3055 (CVSS 9.3) Memory ...](https://thehackernews.com/2026/03/citrix-netscaler-under-active-recon-for.html)
- [Citrix NetScaler CVE-2026-88772: Critical RCE Exploited | The CyberSec Guru](https://thecybersecguru.com/news/citrix-netscaler-cve-2026-88772-rce/)
- [Snowflake Security Bulletins - CVEs & Vulnerability Guidance](https://www.snowflake.com/en/why-snowflake/snowflake-security-hub/security-bulletins/)
